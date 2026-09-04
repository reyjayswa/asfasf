// Package adminpanel implements an admin-panel / login-surface discovery
// check.
//
// It requests a small built-in list of common administrative and login
// paths under the target origin. A path is only reported when the response
// is a genuine authentication surface, judged by one of:
//
//   - an HTML password input (type="password");
//   - a known panel signature (phpMyAdmin, Adminer, Tomcat Manager, cPanel,
//     WordPress wp-login);
//   - an HTTP auth challenge (401 with a WWW-Authenticate header).
//
// A bare HTTP 200 with no such marker is deliberately NOT reported: a
// catch-all SPA answers 200 for every path, so gating on a distinctive
// content signature keeps the false-positive rate low.
package adminpanel

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// Checker probes an origin for exposed admin / login surfaces.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds an admin-panel Checker. When aggressive is true, an extended
// path list is probed in addition to the default set.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "admin-panel" }

// defaultPaths is the conservative built-in wordlist.
var defaultPaths = []string{
	"/admin",
	"/administrator",
	"/admin/login",
	"/admin.php",
	"/login",
	"/user/login",
	"/wp-admin/",
	"/wp-login.php",
	"/phpmyadmin/",
	"/adminer.php",
	"/manager/html",
	"/cpanel",
	"/panel",
	"/backend",
}

// aggressivePaths is probed only in aggressive mode.
var aggressivePaths = []string{
	"/admin1",
	"/admin2",
	"/adminpanel",
	"/controlpanel",
	"/admin/index.php",
	"/admin_area",
	"/moderator",
	"/webadmin",
	"/admincp",
}

// passwordInput matches an HTML <input ... type="password" ...> field in any
// attribute order and with single or double quotes.
var passwordInput = regexp.MustCompile(`(?is)<input[^>]*type\s*=\s*["']?password["']?`)

// panelSignature is a distinctive marker for a known admin/login product.
type panelSignature struct {
	name    string
	pattern *regexp.Regexp
}

// panelSignatures are checked against the response body (case-insensitive).
var panelSignatures = []panelSignature{
	{"phpMyAdmin", regexp.MustCompile(`(?i)phpmyadmin`)},
	{"Adminer", regexp.MustCompile(`(?i)adminer`)},
	{"Tomcat Manager", regexp.MustCompile(`(?i)tomcat[^<]*manager|manager\s+application|/manager/status`)},
	{"cPanel", regexp.MustCompile(`(?i)cpanel`)},
	{"WordPress wp-login", regexp.MustCompile(`(?i)wp-login|wp-submit|id=["']?loginform`)},
}

// Run probes the built-in path list under origin and returns findings for
// every genuine admin/login surface discovered.
func (c *Checker) Run(ctx context.Context, origin string) []checks.Finding {
	var findings []checks.Finding
	base := strings.TrimRight(origin, "/")

	paths := make([]string, 0, len(defaultPaths)+len(aggressivePaths))
	paths = append(paths, defaultPaths...)
	if c.aggressive {
		paths = append(paths, aggressivePaths...)
	}

	for _, p := range paths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		target := base + p
		resp, err := c.client.Get(ctx, target)
		if err != nil || resp == nil {
			continue
		}

		if f, ok := classify(target, p, resp); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

// classify decides whether a response is a real admin/login surface and, if
// so, builds the corresponding Finding.
func classify(target, path string, resp *httpclient.Response) (checks.Finding, bool) {
	body := resp.BodyString()

	// 1. HTTP auth challenge: a protected surface behind Basic/Digest auth.
	if resp.Status == http.StatusUnauthorized && resp.Header.Get("Www-Authenticate") != "" {
		return checks.Finding{
			Type:        "admin-panel",
			Severity:    checks.SeverityInfo,
			Title:       "Protected admin/login surface (HTTP auth challenge)",
			URL:         target,
			Method:      http.MethodGet,
			Evidence:    checks.Truncate("401 WWW-Authenticate: "+resp.Header.Get("Www-Authenticate"), 240),
			Description: fmt.Sprintf("The path %q returns an HTTP 401 authentication challenge, revealing an administrative surface that is protected by HTTP authentication.", path),
			Remediation: "Confirm the endpoint should be internet-exposed. Restrict it by network/IP allow-listing where possible and ensure strong credentials and rate limiting are in place.",
			Confidence:  "firm",
			Timestamp:   time.Now(),
		}, true
	}

	// 2. Known panel product signature in the body.
	if resp.Status >= 200 && resp.Status < 400 {
		for _, sig := range panelSignatures {
			if sig.pattern.MatchString(body) {
				return checks.Finding{
					Type:        "admin-panel",
					Severity:    checks.SeverityLow,
					Title:       "Exposed admin panel: " + sig.name,
					URL:         target,
					Method:      http.MethodGet,
					Evidence:    checks.Truncate("signature: "+sig.name+" | "+bodySnippet(body, sig.pattern), 240),
					Description: fmt.Sprintf("The path %q serves a recognizable %s administrative interface. Publicly reachable management panels expand the attack surface and are prime targets for credential attacks and known-vulnerability exploitation.", path, sig.name),
					Remediation: "Restrict access to the panel by IP allow-listing or VPN, keep the software patched, and enforce strong, unique credentials with MFA.",
					Confidence:  "firm",
					Timestamp:   time.Now(),
				}, true
			}
		}
	}

	// 3. Generic login form: an HTML password input on a 2xx response.
	if resp.Status >= 200 && resp.Status < 300 && passwordInput.MatchString(body) {
		return checks.Finding{
			Type:        "admin-panel",
			Severity:    checks.SeverityLow,
			Title:       "Discovered login page",
			URL:         target,
			Method:      http.MethodGet,
			Evidence:    checks.Truncate("HTML password input at "+path+" | "+bodySnippet(body, passwordInput), 240),
			Description: fmt.Sprintf("The path %q returns a login form (an HTML password input is present). A publicly reachable authentication surface is subject to credential-stuffing and brute-force attempts.", path),
			Remediation: "Ensure the login endpoint has brute-force protection (rate limiting, lockout, CAPTCHA), enforces strong credentials and MFA, and restrict administrative logins to trusted networks where feasible.",
			Confidence:  "tentative",
			Timestamp:   time.Now(),
		}, true
	}

	return checks.Finding{}, false
}

// bodySnippet returns a short window of the body around the first regex match.
func bodySnippet(body string, re *regexp.Regexp) string {
	loc := re.FindStringIndex(body)
	if loc == nil {
		return ""
	}
	start := loc[0] - 30
	if start < 0 {
		start = 0
	}
	end := loc[1] + 30
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(strings.Join(strings.Fields(body[start:end]), " "))
}
