// Package cookies is a passive page analyzer that inspects Set-Cookie response
// headers for missing security attributes (HttpOnly, Secure, SameSite).
package cookies

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/crawler"
)

var sessionNameRe = regexp.MustCompile(`(?i)sess|sid|auth|token`)

// Analyze inspects Set-Cookie headers across the supplied pages and reports
// cookies that are missing recommended security attributes. It makes no
// network requests.
func Analyze(pages []crawler.Page) []checks.Finding {
	var findings []checks.Finding
	seen := make(map[string]bool) // dedup by origin + cookie name

	for _, page := range pages {
		if page.Header == nil {
			continue
		}

		origin, isHTTPS := originOf(page.URL)

		for _, sc := range page.Header.Values("Set-Cookie") {
			name, attrs, ok := parseSetCookie(sc)
			if !ok {
				continue
			}

			key := origin + "\x00" + strings.ToLower(name)
			if seen[key] {
				continue
			}
			seen[key] = true

			hasHTTPOnly := attrs["httponly"]
			hasSecure := attrs["secure"]
			hasSameSite := attrs["samesite"]

			var missing []string
			severity := checks.SeverityInfo
			bump := func(s checks.Severity) {
				if s.Rank() > severity.Rank() {
					severity = s
				}
			}

			if !hasHTTPOnly {
				missing = append(missing, "HttpOnly")
				if sessionNameRe.MatchString(name) {
					bump(checks.SeverityMedium)
				} else {
					bump(checks.SeverityLow)
				}
			}
			if isHTTPS && !hasSecure {
				missing = append(missing, "Secure")
				bump(checks.SeverityMedium)
			}
			if !hasSameSite {
				missing = append(missing, "SameSite")
				bump(checks.SeverityLow)
			}

			if len(missing) == 0 {
				continue
			}

			missingList := strings.Join(missing, ", ")
			findings = append(findings, checks.Finding{
				Type:      "insecure-cookie",
				Severity:  severity,
				Title:     fmt.Sprintf("Cookie %q missing security attributes: %s", name, missingList),
				URL:       page.URL,
				Parameter: name,
				Evidence:  checks.Truncate(strings.TrimSpace(sc), 240),
				Description: fmt.Sprintf(
					"The cookie %q is set without the following recommended security attribute(s): %s. "+
						"Missing HttpOnly exposes the cookie to theft via cross-site scripting; missing Secure "+
						"allows transmission over unencrypted HTTP; missing SameSite increases exposure to "+
						"cross-site request forgery.", name, missingList),
				Remediation: "Set the HttpOnly, Secure, and SameSite attributes on cookies as appropriate. " +
					"Use HttpOnly for session/authentication cookies, Secure on all cookies served over HTTPS, " +
					"and an explicit SameSite policy (Lax or Strict) to mitigate CSRF.",
				Confidence: "firm",
				Timestamp:  time.Now(),
				CWE:        "CWE-614",
			})
		}
	}

	return findings
}

// originOf returns the scheme+host origin of rawURL and whether it is https.
func originOf(rawURL string) (origin string, isHTTPS bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL, strings.HasPrefix(strings.ToLower(rawURL), "https://")
	}
	scheme := strings.ToLower(u.Scheme)
	return scheme + "://" + strings.ToLower(u.Host), scheme == "https"
}

// parseSetCookie splits a Set-Cookie header value into the cookie name and a
// set of lowercased attribute names that are present. It returns ok=false when
// the value has no name=value pair.
func parseSetCookie(raw string) (name string, attrs map[string]bool, ok bool) {
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return "", nil, false
	}

	nv := strings.TrimSpace(parts[0])
	eq := strings.IndexByte(nv, '=')
	if eq <= 0 {
		return "", nil, false
	}
	name = strings.TrimSpace(nv[:eq])
	if name == "" {
		return "", nil, false
	}

	attrs = make(map[string]bool)
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		attrName := p
		if i := strings.IndexByte(p, '='); i >= 0 {
			attrName = p[:i]
		}
		attrs[strings.ToLower(strings.TrimSpace(attrName))] = true
	}
	return name, attrs, true
}
