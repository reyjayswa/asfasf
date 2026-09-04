// Package csrf provides a passive analyzer that flags state-changing HTML
// forms (POST) that carry no recognizable anti-CSRF token parameter. It makes
// no network requests; it only inspects endpoints discovered by the crawler.
package csrf

import (
	"regexp"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
)

// tokenRe matches parameter names that commonly hold an anti-CSRF token.
var tokenRe = regexp.MustCompile(`(?i)csrf|xsrf|_token|authenticity_token|nonce|__requestverificationtoken|verificationtoken`)

// Analyze inspects endpoints and reports POST forms that appear to lack an
// anti-CSRF token. Only endpoints with Method == "POST" and Source == "form"
// are considered; all others are ignored.
func Analyze(eps []checks.Endpoint) []checks.Finding {
	var findings []checks.Finding

	for _, ep := range eps {
		if !strings.EqualFold(ep.Method, "POST") || ep.Source != "form" {
			continue
		}

		hasToken := false
		for _, p := range ep.Params {
			if tokenRe.MatchString(p) {
				hasToken = true
				break
			}
		}
		if hasToken {
			continue
		}

		params := strings.Join(ep.Params, ", ")
		if params == "" {
			params = "(none)"
		}
		evidence := checks.Truncate("POST "+ep.URL+" params=["+params+"]", 240)

		findings = append(findings, checks.Finding{
			Type:     "csrf",
			Severity: checks.SeverityMedium,
			Title:    "State-changing POST form without an anti-CSRF token",
			URL:      ep.URL,
			Method:   "POST",
			Evidence: evidence,
			Description: "This form submits a state-changing POST request but none of its " +
				"parameters look like an anti-CSRF token (e.g. csrf, xsrf, _token, " +
				"authenticity_token, nonce). If the application relies solely on cookies " +
				"for authentication, an attacker could forge cross-site requests on behalf " +
				"of an authenticated victim. Note: this is a passive observation — a header " +
				"or SameSite cookie based defense would not be visible here.",
			Remediation: "Include a per-session or per-request anti-CSRF token in state-changing " +
				"forms and validate it server-side. Additionally set SameSite=Lax or Strict on " +
				"session cookies as a defense in depth.",
			Confidence: "tentative",
			Timestamp:  time.Now(),
			CWE:        "CWE-352",
		})
	}

	return findings
}
