// Package secheaders is a passive page analyzer that inspects HTTP response
// headers for missing or weak security headers. It makes no network requests;
// it only reads the headers already captured on crawled pages.
package secheaders

import (
	"net/url"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/crawler"
)

// Analyze inspects response headers across pages, deduplicated per origin
// (scheme+host), and returns one finding per missing/weak header per origin.
// Pages with Status 0 (never fetched) are skipped.
func Analyze(pages []crawler.Page) []checks.Finding {
	var findings []checks.Finding
	seenOrigin := make(map[string]bool)

	for _, p := range pages {
		if p.Status == 0 {
			continue
		}
		u, err := url.Parse(p.URL)
		if err != nil || u.Host == "" {
			continue
		}
		origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
		if seenOrigin[origin] {
			continue
		}
		seenOrigin[origin] = true

		h := p.Header
		now := time.Now()
		isHTTPS := strings.EqualFold(u.Scheme, "https")

		csp := get(h, "Content-Security-Policy")
		xcto := get(h, "X-Content-Type-Options")
		xfo := get(h, "X-Frame-Options")
		refPol := get(h, "Referrer-Policy")
		permPol := get(h, "Permissions-Policy")
		hsts := get(h, "Strict-Transport-Security")

		add := func(f checks.Finding) {
			f.Type = "secheaders"
			f.URL = origin
			f.Method = "GET"
			f.Confidence = "firm"
			f.Timestamp = now
			findings = append(findings, f)
		}

		// Missing Content-Security-Policy -> Medium
		if csp == "" {
			add(checks.Finding{
				Severity:    checks.SeverityMedium,
				Title:       "Missing Content-Security-Policy header",
				CWE:         "CWE-693",
				Description: "The response does not set a Content-Security-Policy header. CSP is a key defense-in-depth control that mitigates cross-site scripting and data-injection attacks by restricting the sources from which content may be loaded.",
				Remediation: "Define and deploy a Content-Security-Policy header with a restrictive default-src policy, and tighten script-src/style-src to trusted origins.",
			})
		}

		// On an https page, missing Strict-Transport-Security -> Medium
		if isHTTPS && hsts == "" {
			add(checks.Finding{
				Severity:    checks.SeverityMedium,
				Title:       "Missing Strict-Transport-Security header",
				CWE:         "CWE-319",
				Evidence:    checks.Truncate("scheme=https origin="+origin, 240),
				Description: "The HTTPS response does not set a Strict-Transport-Security header, leaving clients exposed to SSL-stripping and protocol-downgrade attacks over the network.",
				Remediation: "Send Strict-Transport-Security with a long max-age (e.g. max-age=31536000; includeSubDomains) on all HTTPS responses.",
			})
		}

		// Missing X-Content-Type-Options: nosniff -> Low
		if !strings.Contains(strings.ToLower(xcto), "nosniff") {
			add(checks.Finding{
				Severity:    checks.SeverityLow,
				Title:       "Missing X-Content-Type-Options: nosniff header",
				CWE:         "CWE-693",
				Evidence:    checks.Truncate("X-Content-Type-Options: "+xcto, 240),
				Description: "The response does not set X-Content-Type-Options: nosniff, allowing browsers to MIME-sniff the response body and potentially interpret it as a different content type than declared.",
				Remediation: "Add the header X-Content-Type-Options: nosniff to all responses.",
			})
		}

		// Missing X-Frame-Options AND no frame-ancestors in CSP -> Medium (clickjacking)
		if xfo == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
			add(checks.Finding{
				Severity:    checks.SeverityMedium,
				Title:       "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
				CWE:         "CWE-1021",
				Description: "The response neither sets X-Frame-Options nor a CSP frame-ancestors directive, so the page can be framed by arbitrary origins and is vulnerable to clickjacking.",
				Remediation: "Set X-Frame-Options: DENY (or SAMEORIGIN) and/or a Content-Security-Policy frame-ancestors directive restricting who may frame the page.",
			})
		}

		// Missing Referrer-Policy -> Low
		if refPol == "" {
			add(checks.Finding{
				Severity:    checks.SeverityLow,
				Title:       "Missing Referrer-Policy header",
				CWE:         "CWE-693",
				Description: "The response does not set a Referrer-Policy header, so full referrer URLs (which may contain sensitive path or query data) can leak to third-party origins.",
				Remediation: "Set a Referrer-Policy header such as strict-origin-when-cross-origin or no-referrer.",
			})
		}

		// Missing Permissions-Policy -> Info/Low
		if permPol == "" {
			add(checks.Finding{
				Severity:    checks.SeverityInfo,
				Title:       "Missing Permissions-Policy header",
				CWE:         "CWE-693",
				Description: "The response does not set a Permissions-Policy header, which is used to selectively enable or disable powerful browser features (camera, microphone, geolocation, etc.).",
				Remediation: "Set a Permissions-Policy header disabling unused browser features, e.g. geolocation=(), camera=(), microphone=().",
			})
		}
	}

	return findings
}

// get returns the first value of the named header, or "" if absent.
func get(h map[string][]string, name string) string {
	if h == nil {
		return ""
	}
	// http.Header uses canonical keys; use case-insensitive lookup as a fallback.
	if v, ok := h[name]; ok && len(v) > 0 {
		return v[0]
	}
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
