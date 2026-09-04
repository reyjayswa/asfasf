// Package cmsfp implements a CMS-fingerprinting site check.
//
// It identifies the content-management system powering an origin by
// requesting a small set of distinctive marker paths and by inspecting the
// origin root's HTML (a <meta name="generator"> tag) and response headers
// (e.g. X-Generator). A CMS is reported only when a specific, distinctive
// signature matches — never on a bare HTTP 200 — because a catch-all SPA
// answers 200 for every path. Where possible a version string is extracted
// and included in the finding.
//
// One Info-severity finding is emitted per distinct CMS detected. When no
// marker matches, nothing is emitted.
package cmsfp

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// Checker fingerprints the CMS behind an origin.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds a CMS-fingerprint Checker. When aggressive is true a few extra
// confirmation paths (e.g. WordPress /readme.html) are probed to recover a
// version when the root markers do not carry one.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "cms-fingerprint" }

// metaGenerator extracts the content of a <meta name="generator" content="...">
// tag in either attribute order and with single or double quotes.
var (
	metaGenName2Content = regexp.MustCompile(`(?is)<meta[^>]*name\s*=\s*["']?generator["']?[^>]*content\s*=\s*["']([^"']*)["']`)
	metaGenContent2Name = regexp.MustCompile(`(?is)<meta[^>]*content\s*=\s*["']([^"']*)["'][^>]*name\s*=\s*["']?generator["']?`)

	wpVersion      = regexp.MustCompile(`(?i)WordPress[\s/]+([0-9]+(?:\.[0-9]+)+)`)
	joomlaVersion  = regexp.MustCompile(`(?i)Joomla!?[\s/-]*([0-9]+(?:\.[0-9]+)+)`)
	drupalVersion  = regexp.MustCompile(`(?i)Drupal[\s/]+([0-9]+(?:\.[0-9]+)*)`)
	magentoVersion = regexp.MustCompile(`(?i)Magento[\s/]+([0-9]+(?:\.[0-9]+)+)`)
)

// metaGeneratorContent returns the generator meta tag content from an HTML
// body, or "" if absent.
func metaGeneratorContent(body string) string {
	if m := metaGenName2Content.FindStringSubmatch(body); m != nil {
		return strings.TrimSpace(m[1])
	}
	if m := metaGenContent2Name.FindStringSubmatch(body); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// firstSubmatch returns the first capture group of re against s, or "".
func firstSubmatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// Run fingerprints the CMS at origin and returns one Info finding per CMS
// detected.
func (c *Checker) Run(ctx context.Context, origin string) []checks.Finding {
	base := strings.TrimRight(origin, "/")

	// Fetch the root once; both the meta generator and header markers as well
	// as several body-reference signatures are read from it.
	rootBody := ""
	rootGen := ""
	rootXGen := ""
	if resp, err := c.client.Get(ctx, base+"/"); err == nil && resp != nil {
		rootBody = resp.BodyString()
		rootGen = metaGeneratorContent(rootBody)
		rootXGen = resp.Header.Get("X-Generator")
	}

	var findings []checks.Finding

	if f, ok := c.detectWordPress(ctx, base, rootBody, rootGen); ok {
		findings = append(findings, f)
	}
	if f, ok := c.detectJoomla(ctx, base, rootBody, rootGen); ok {
		findings = append(findings, f)
	}
	if f, ok := c.detectDrupal(ctx, base, rootBody, rootGen, rootXGen); ok {
		findings = append(findings, f)
	}
	if f, ok := c.detectMagento(ctx, base, rootBody); ok {
		findings = append(findings, f)
	}

	return findings
}

// finding builds the standard Info-severity CMS finding.
func finding(cms, version, url, evidence string) checks.Finding {
	title := "CMS detected: " + cms
	if version != "" {
		title += " " + version
	}
	desc := fmt.Sprintf("The origin is powered by the %s content-management system", cms)
	if version != "" {
		desc += ", version " + version
	}
	desc += ". Knowing the CMS (and version) lets an attacker target known vulnerabilities, default paths and misconfigurations specific to that platform."
	return checks.Finding{
		Type:        "cms-fingerprint",
		Severity:    checks.SeverityInfo,
		Title:       title,
		URL:         url,
		Method:      "GET",
		Evidence:    checks.Truncate(evidence, 240),
		Description: desc,
		Remediation: "Keep the CMS and its plugins/themes fully patched, remove version-revealing markers (meta generator tags, readme/CHANGELOG files) where feasible, and restrict access to administrative and setup paths.",
		Confidence:  "firm",
		Timestamp:   time.Now(),
	}
}

// ctxDone reports whether ctx has been cancelled.
func ctxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// detectWordPress looks for WordPress via /wp-login.php, the root meta
// generator, /wp-json/, and (aggressive) /readme.html for a version.
func (c *Checker) detectWordPress(ctx context.Context, base, rootBody, rootGen string) (checks.Finding, bool) {
	var evidence string
	version := ""

	if strings.Contains(rootGen, "WordPress") {
		evidence = "root meta generator: " + rootGen
		version = firstSubmatch(wpVersion, rootGen)
	}

	if evidence == "" && !ctxDone(ctx) {
		if resp, err := c.client.Get(ctx, base+"/wp-login.php"); err == nil && resp != nil && resp.Status >= 200 && resp.Status < 400 {
			body := resp.BodyString()
			if strings.Contains(body, "user_login") || strings.Contains(strings.ToLower(body), "wordpress") {
				evidence = "/wp-login.php contains WordPress login markers"
			}
		}
	}

	if evidence == "" && !ctxDone(ctx) {
		if resp, err := c.client.Get(ctx, base+"/wp-json/"); err == nil && resp != nil && resp.Status >= 200 && resp.Status < 400 {
			body := resp.BodyString()
			if strings.Contains(body, "wp/v2") {
				evidence = "/wp-json/ returns REST API JSON containing \"wp/v2\""
			}
		}
	}

	if evidence == "" {
		return checks.Finding{}, false
	}

	// Try to recover a version if we do not have one yet.
	if version == "" && rootBody != "" {
		version = firstSubmatch(wpVersion, metaGeneratorContent(rootBody))
	}
	if version == "" && c.aggressive && !ctxDone(ctx) {
		if resp, err := c.client.Get(ctx, base+"/readme.html"); err == nil && resp != nil && resp.Status >= 200 && resp.Status < 400 {
			if v := firstSubmatch(wpVersion, resp.BodyString()); v != "" {
				version = v
				evidence += " | version from /readme.html: " + v
			}
		}
	}

	return finding("WordPress", version, base+"/", evidence), true
}

// detectJoomla looks for Joomla via /administrator/ and the root meta
// generator.
func (c *Checker) detectJoomla(ctx context.Context, base, rootBody, rootGen string) (checks.Finding, bool) {
	var evidence string
	version := ""

	if strings.Contains(rootGen, "Joomla") {
		evidence = "root meta generator: " + rootGen
		version = firstSubmatch(joomlaVersion, rootGen)
	}

	if evidence == "" && !ctxDone(ctx) {
		if resp, err := c.client.Get(ctx, base+"/administrator/"); err == nil && resp != nil && resp.Status >= 200 && resp.Status < 400 {
			body := resp.BodyString()
			if strings.Contains(body, "Joomla") {
				evidence = "/administrator/ body contains \"Joomla\""
			}
		}
	}

	if evidence == "" {
		return checks.Finding{}, false
	}
	return finding("Joomla", version, base+"/", evidence), true
}

// detectDrupal looks for Drupal via /CHANGELOG.txt, the X-Generator header,
// the root meta generator, and a "/sites/default/" body reference.
func (c *Checker) detectDrupal(ctx context.Context, base, rootBody, rootGen, rootXGen string) (checks.Finding, bool) {
	var evidence string
	version := ""

	if strings.Contains(rootGen, "Drupal") {
		evidence = "root meta generator: " + rootGen
		version = firstSubmatch(drupalVersion, rootGen)
	}
	if evidence == "" && strings.Contains(rootXGen, "Drupal") {
		evidence = "X-Generator header: " + rootXGen
		version = firstSubmatch(drupalVersion, rootXGen)
	}
	if evidence == "" && strings.Contains(rootBody, "/sites/default/") {
		evidence = "root body references \"/sites/default/\""
	}

	if evidence == "" && !ctxDone(ctx) {
		if resp, err := c.client.Get(ctx, base+"/CHANGELOG.txt"); err == nil && resp != nil && resp.Status >= 200 && resp.Status < 400 {
			body := resp.BodyString()
			if strings.Contains(body, "Drupal") {
				evidence = "/CHANGELOG.txt contains \"Drupal\""
				if version == "" {
					version = firstSubmatch(drupalVersion, body)
				}
			}
		}
	}

	if evidence == "" {
		return checks.Finding{}, false
	}
	return finding("Drupal", version, base+"/", evidence), true
}

// detectMagento looks for Magento via a "/static/version" reference or a
// "Magento" mention in the root body.
func (c *Checker) detectMagento(ctx context.Context, base, rootBody string) (checks.Finding, bool) {
	var evidence string
	version := ""

	switch {
	case strings.Contains(rootBody, "/static/version"):
		evidence = "root body references \"/static/version\" (Magento static asset path)"
	case strings.Contains(rootBody, "Magento"):
		evidence = "root body contains \"Magento\""
		version = firstSubmatch(magentoVersion, rootBody)
	}

	if evidence == "" {
		return checks.Finding{}, false
	}
	return finding("Magento", version, base+"/", evidence), true
}
