// Package fingerprint inspects crawled pages to identify server-side
// technologies, surface low-risk recon findings (such as revealed software
// versions), and produce structured Detection records (tech + version) that
// the CVE mapper consumes. Detection is signature-based over response
// headers, cookies, meta generators, and body markers.
package fingerprint

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/crawler"
)

type signature struct {
	tech    string
	header  string         // header to inspect ("" means body)
	pattern *regexp.Regexp // matched against header value or body
}

// signatures is a compact, extensible fingerprint table.
var signatures = []signature{
	{"nginx", "Server", regexp.MustCompile(`(?i)nginx`)},
	{"Apache", "Server", regexp.MustCompile(`(?i)apache`)},
	{"Microsoft-IIS", "Server", regexp.MustCompile(`(?i)iis`)},
	{"PHP", "X-Powered-By", regexp.MustCompile(`(?i)php`)},
	{"ASP.NET", "X-Powered-By", regexp.MustCompile(`(?i)asp\.net`)},
	{"Express", "X-Powered-By", regexp.MustCompile(`(?i)express`)},
	{"WordPress", "", regexp.MustCompile(`(?i)/wp-(content|includes)/`)},
	{"Drupal", "", regexp.MustCompile(`(?i)Drupal.settings|/sites/default/`)},
	{"Django", "", regexp.MustCompile(`(?i)csrfmiddlewaretoken`)},
	{"Laravel", "Set-Cookie", regexp.MustCompile(`(?i)laravel_session`)},
	{"React", "", regexp.MustCompile(`(?i)data-reactroot|__REACT`)},
}

// versionHeaders are headers whose values often leak exact versions.
var versionHeaders = []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"}

var (
	versionPattern = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)
	// metaGenerator captures "<meta name=generator content='WordPress 6.4.2'>".
	metaGenerator = regexp.MustCompile(`(?i)<meta[^>]+name=["']?generator["']?[^>]+content=["']([^"']+)["']`)
	// jqueryPattern captures jQuery versions from script srcs or inline banners.
	jqueryPattern = regexp.MustCompile(`(?i)jquery[-/. ]v?(\d+\.\d+\.\d+)`)
)

// parseNameVersion splits a banner like "nginx/1.18.0" into a tech name and
// version. The name is the leading token before "/" or whitespace; the
// version is the first dotted-number run.
func parseNameVersion(value string) (string, string) {
	value = strings.TrimSpace(value)
	name := value
	if i := strings.IndexAny(value, "/ "); i >= 0 {
		name = value[:i]
	}
	return name, versionPattern.FindString(value)
}

// Analyze runs fingerprinting over all crawled pages. It returns recon
// findings and a deduplicated set of technology detections (with versions
// where recoverable) for downstream CVE matching.
func Analyze(pages []crawler.Page) ([]checks.Finding, []checks.Detection) {
	detected := map[string]string{}             // tech -> example URL (for the recon summary)
	detections := map[string]checks.Detection{} // tech -> best detection (prefers one with a version)
	versionLeaks := map[string]checks.Finding{}

	record := func(tech, version, url string) {
		if tech == "" {
			return
		}
		cur, ok := detections[tech]
		if !ok || (cur.Version == "" && version != "") {
			detections[tech] = checks.Detection{Tech: tech, Version: version, URL: url}
		}
	}

	for _, p := range pages {
		body := string(p.Body)

		for _, sig := range signatures {
			matched := false
			var version string
			if sig.header == "" {
				matched = sig.pattern.MatchString(body)
			} else if v := p.Header.Get(sig.header); v != "" && sig.pattern.MatchString(v) {
				matched = true
				_, version = parseNameVersion(v)
			}
			if matched {
				if _, seen := detected[sig.tech]; !seen {
					detected[sig.tech] = p.URL
				}
				record(sig.tech, version, p.URL)
			}
		}

		// Meta generator often carries CMS name + version.
		if m := metaGenerator.FindStringSubmatch(body); len(m) == 2 {
			name, version := parseNameVersion(m[1])
			if name != "" {
				detected[name] = p.URL
				record(name, version, p.URL)
			}
		}

		// jQuery version from script srcs / banners.
		if m := jqueryPattern.FindStringSubmatch(body); len(m) == 2 {
			detected["jQuery"] = p.URL
			record("jQuery", m[1], p.URL)
		}

		for _, h := range versionHeaders {
			v := p.Header.Get(h)
			if v == "" || !versionPattern.MatchString(v) {
				continue
			}
			name, version := parseNameVersion(v)
			record(name, version, p.URL)

			key := h + ":" + v
			if _, ok := versionLeaks[key]; ok {
				continue
			}
			versionLeaks[key] = checks.Finding{
				Type:        "fingerprint",
				Severity:    checks.SeverityLow,
				Title:       fmt.Sprintf("Software version disclosed via %s header", h),
				URL:         p.URL,
				Method:      "GET",
				Evidence:    checks.Truncate(h+": "+v, 200),
				Description: "The server reveals a specific software name and version in a response header, which helps an attacker match known CVEs to the target.",
				Remediation: "Suppress or genericize version tokens in the " + h + " header at the web server or framework level.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
			}
		}
	}

	var findings []checks.Finding
	if len(detected) > 0 {
		techs := make([]string, 0, len(detected))
		for t := range detected {
			techs = append(techs, t)
		}
		sort.Strings(techs)
		findings = append(findings, checks.Finding{
			Type:        "recon",
			Severity:    checks.SeverityInfo,
			Title:       "Technology stack fingerprinted",
			URL:         detected[techs[0]],
			Method:      "GET",
			Evidence:    checks.Truncate(strings.Join(techs, ", "), 300),
			Description: "The following technologies were identified from response headers and page markers: " + strings.Join(techs, ", ") + ".",
			Remediation: "Informational. Reducing technology disclosure raises the cost of targeted attacks but is not itself a vulnerability.",
			Confidence:  "firm",
			Timestamp:   time.Now(),
		})
	}
	for _, f := range versionLeaks {
		findings = append(findings, f)
	}

	dets := make([]checks.Detection, 0, len(detections))
	for _, d := range detections {
		dets = append(dets, d)
	}
	sort.Slice(dets, func(i, j int) bool { return dets[i].Tech < dets[j].Tech })
	return findings, dets
}
