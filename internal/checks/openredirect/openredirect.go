// Package openredirect implements an open-redirect check.
//
// For each parameter of an endpoint it injects a payload pointing at a unique
// external canary host and inspects the response. Because the HTTP client does
// not follow redirects, the check can observe a 3xx Status together with a
// Location header (the high-confidence case) or a 200 body that redirects the
// browser via a meta refresh or a window.location assignment (the tentative
// case). Gating on the canary host keeps the signal specific and avoids
// flagging benign in-app redirects.
package openredirect

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// canaryHost is the distinctive external host we try to redirect to. A real
// open redirect will send the browser to this host; a scoped application never
// legitimately redirects here.
const canaryHost = "openredir-canary.example"

// Checker probes endpoint parameters for open redirects.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds an open-redirect Checker. When aggressive is true, additional
// bypass payloads are attempted per parameter.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "open-redirect" }

// payloads returns the redirect payloads to try. All of them target canaryHost
// through a variety of encodings that commonly bypass naive validators.
func (c *Checker) payloads() []string {
	p := []string{
		"https://" + canaryHost + "/",
		"//" + canaryHost + "/",
		"https:/\\/\\" + canaryHost,
	}
	if c.aggressive {
		p = append(p, "/\\"+canaryHost)
	}
	return p
}

// metaRefreshRe matches a meta refresh whose URL points at the canary host.
var metaRefreshRe = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']?refresh["']?[^>]*url=([^"'>\s]+)`)

// jsLocationRe matches a window.location / location.href assignment pointing at
// the canary host.
var jsLocationRe = regexp.MustCompile(`(?i)(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']`)

// Run tests every parameter of the endpoint and returns any findings.
func (c *Checker) Run(ctx context.Context, ep checks.Endpoint) []checks.Finding {
	var findings []checks.Finding
	for _, param := range ep.Params {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		if f, ok := c.testParam(ctx, ep, param); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

func (c *Checker) testParam(ctx context.Context, ep checks.Endpoint, param string) (checks.Finding, bool) {
	for _, payload := range c.payloads() {
		select {
		case <-ctx.Done():
			return checks.Finding{}, false
		default:
		}
		resp, err := c.send(ctx, ep, param, payload)
		if err != nil || resp == nil {
			continue
		}

		// (a) Location-header redirect on a 3xx response.
		if resp.Status >= 300 && resp.Status < 400 {
			loc := resp.Header.Get("Location")
			if loc != "" && locationHostIsCanary(loc) {
				return c.finding(ep, param, payload, "firm",
					checks.Truncate(loc, 240),
					fmt.Sprintf("Parameter %q controls a redirect target. The application returned HTTP %d with a Location header pointing at the attacker-controlled host %q.", param, resp.Status, canaryHost)), true
			}
		}

		// (b) Client-side redirect in a 200 body (meta refresh / JS location).
		if snip, ok := bodyRedirectsToCanary(resp.BodyString()); ok {
			return c.finding(ep, param, payload, "tentative",
				checks.Truncate(snip, 240),
				fmt.Sprintf("Parameter %q is reflected into a client-side redirect (meta refresh or window.location) pointing at the attacker-controlled host %q.", param, canaryHost)), true
		}
	}
	return checks.Finding{}, false
}

func (c *Checker) finding(ep checks.Endpoint, param, payload, confidence, evidence, desc string) checks.Finding {
	return checks.Finding{
		Type:        "open-redirect",
		Severity:    checks.SeverityMedium,
		Title:       "Open redirect: user-controlled redirect target",
		URL:         ep.URL,
		Method:      ep.Method,
		Parameter:   param,
		Payload:     payload,
		Evidence:    evidence,
		Description: desc,
		Remediation: "Do not build redirect targets from user input. Redirect only to a server-side allow-list of paths or hosts, or force relative paths and reject absolute/protocol-relative URLs.",
		Confidence:  confidence,
		Timestamp:   time.Now(),
		CWE:         "CWE-601",
	}
}

// send injects payload into param and issues the request for the endpoint's
// method, filling other parameters with a benign default.
func (c *Checker) send(ctx context.Context, ep checks.Endpoint, param, payload string) (*httpclient.Response, error) {
	values := url.Values{}
	for _, p := range ep.Params {
		if p == param {
			values.Set(p, payload)
		} else {
			values.Set(p, "1")
		}
	}
	if ep.Method == http.MethodPost {
		return c.client.PostForm(ctx, ep.URL, values.Encode())
	}
	sep := "?"
	if strings.Contains(ep.URL, "?") {
		sep = "&"
	}
	return c.client.Get(ctx, ep.URL+sep+values.Encode())
}

// locationHostIsCanary reports whether a Location header value redirects to the
// canary host. It handles absolute, protocol-relative, and backslash-obfuscated
// forms.
func locationHostIsCanary(loc string) bool {
	return hostOf(loc) == canaryHost
}

// bodyRedirectsToCanary looks for a meta-refresh or JS location redirect in the
// body whose target host is the canary. It returns the matched snippet.
func bodyRedirectsToCanary(body string) (string, bool) {
	if m := metaRefreshRe.FindStringSubmatch(body); m != nil {
		target := strings.TrimSpace(m[1])
		if hostOf(target) == canaryHost {
			return m[0], true
		}
	}
	if m := jsLocationRe.FindStringSubmatch(body); m != nil {
		if hostOf(strings.TrimSpace(m[1])) == canaryHost {
			return m[0], true
		}
	}
	return "", false
}

// hostOf extracts the host from a possibly-obfuscated redirect target so it can
// be compared against the canary. Backslashes are normalised to forward slashes
// (browsers treat them alike in URLs) before parsing.
func hostOf(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, "\\", "/")

	// Protocol-relative: //host/...
	if strings.HasPrefix(s, "//") {
		return hostFromAuthority(s[2:])
	}
	// scheme://host/... — collapse any accidental scheme:/host too.
	if i := strings.Index(s, "://"); i >= 0 {
		return hostFromAuthority(s[i+3:])
	}
	if i := strings.Index(s, ":/"); i >= 0 {
		return hostFromAuthority(s[i+2:])
	}
	// Fall back to url.Parse for well-formed absolute URLs.
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

// hostFromAuthority returns the lowercased host from an authority component
// (host[:port]) that may be followed by a path, query, or fragment.
func hostFromAuthority(s string) string {
	// Collapse leading slashes left by multi-slash/backslash obfuscation.
	s = strings.TrimLeft(s, "/")
	// Strip anything after the authority.
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	// Drop userinfo.
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// Drop port.
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}
