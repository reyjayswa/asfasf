// Package jwt is a passive page analyzer that finds JSON Web Tokens exposed in
// response bodies, URLs, and Set-Cookie headers, and flags weak ones (the
// "none" algorithm or a missing expiry claim). It makes no network requests.
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/crawler"
)

// jwtRe matches the three dot-separated base64url segments of a JWT. The token
// must start with "eyJ" (the base64url prefix of a JSON object "{" ) so we only
// latch onto plausible JWTs rather than any dotted string.
var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

// Analyze scans each page's Set-Cookie headers and body for JWTs. For every
// distinct token it decodes the header and payload and reports weak-signature
// or exposure issues. It makes no network requests.
func Analyze(pages []crawler.Page) []checks.Finding {
	var findings []checks.Finding
	seen := make(map[string]bool) // dedup by the token's first 24 chars

	for _, page := range pages {
		if page.Status == 0 {
			continue
		}

		// Collect candidate tokens along with whether each source counts as
		// "exposed" (body or URL) rather than only a cookie.
		type cand struct {
			token   string
			exposed bool
		}
		var cands []cand

		// Cookie header values: not treated as body/URL exposure on their own.
		if page.Header != nil {
			for _, sc := range page.Header.Values("Set-Cookie") {
				for _, tok := range jwtRe.FindAllString(sc, -1) {
					cands = append(cands, cand{token: tok, exposed: false})
				}
			}
		}
		// Response body: exposure.
		for _, tok := range jwtRe.FindAllString(string(page.Body), -1) {
			cands = append(cands, cand{token: tok, exposed: true})
		}
		// URL: exposure.
		for _, tok := range jwtRe.FindAllString(page.URL, -1) {
			cands = append(cands, cand{token: tok, exposed: true})
		}

		for _, c := range cands {
			key := dedupKey(c.token)
			if seen[key] {
				continue
			}
			seen[key] = true

			parts := strings.Split(c.token, ".")
			if len(parts) != 3 {
				continue
			}

			headerJSON, ok := decodeSegment(parts[0])
			if !ok {
				continue
			}
			var header map[string]interface{}
			if err := json.Unmarshal(headerJSON, &header); err != nil {
				continue
			}
			// Every JOSE header (RFC 7515/7516) carries an "alg" member.
			// Requiring it avoids latching onto arbitrary base64 blobs that
			// merely happen to decode to a JSON object.
			if _, hasAlg := header["alg"]; !hasAlg {
				continue
			}

			// Decode the payload (may be absent/opaque for encrypted tokens).
			var payload map[string]interface{}
			payloadOK := false
			if payloadJSON, ok := decodeSegment(parts[1]); ok {
				if err := json.Unmarshal(payloadJSON, &payload); err == nil {
					payloadOK = true
				}
			}

			prefix := c.token
			if len(prefix) > 12 {
				prefix = prefix[:12]
			}
			evidence := checks.Truncate(string(headerJSON), 240)

			// 1) alg: none.
			if alg, ok := header["alg"].(string); ok && strings.EqualFold(alg, "none") {
				findings = append(findings, checks.Finding{
					Type:        "jwt",
					Severity:    checks.SeverityHigh,
					Title:       "JWT using 'none' algorithm",
					URL:         page.URL,
					Evidence:    evidence,
					Payload:     prefix + "…",
					Description: "JWT accepts the 'none' algorithm; signatures may not be verified.",
					Remediation: "Reject the 'none' algorithm server-side and pin an expected signing algorithm (e.g. RS256/HS256). Verify the signature on every request.",
					Confidence:  "firm",
					CWE:         "CWE-347",
					Timestamp:   time.Now(),
				})
			}

			// 2) Token exposed in body or URL.
			if c.exposed {
				findings = append(findings, checks.Finding{
					Type:        "jwt",
					Severity:    checks.SeverityLow,
					Title:       "JWT exposed in response body or URL",
					URL:         page.URL,
					Evidence:    evidence,
					Payload:     prefix + "…",
					Description: "A JSON Web Token was found in the response body or URL, where it may be logged, cached, or leaked via referrer headers.",
					Remediation: "Deliver session tokens only in HttpOnly cookies or authorization headers; never place them in URLs or render them in page content.",
					Confidence:  "tentative",
					CWE:         "CWE-347",
					Timestamp:   time.Now(),
				})
			}

			// 3) No expiry claim.
			if payloadOK {
				if _, hasExp := payload["exp"]; !hasExp {
					findings = append(findings, checks.Finding{
						Type:        "jwt",
						Severity:    checks.SeverityLow,
						Title:       "JWT without expiry claim",
						URL:         page.URL,
						Evidence:    evidence,
						Payload:     prefix + "…",
						Description: "The JWT payload has no 'exp' claim, so the token does not expire and remains valid indefinitely if leaked.",
						Remediation: "Include a short 'exp' claim on issued tokens and reject tokens without one.",
						Confidence:  "tentative",
						CWE:         "CWE-347",
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}

	return findings
}

// dedupKey keys a token by its first 24 characters (or the whole token if
// shorter), so the same token seen across sources is analyzed once.
func dedupKey(token string) string {
	if len(token) > 24 {
		return token[:24]
	}
	return token
}

// decodeSegment base64url-decodes a JWT segment, trying raw (unpadded) URL
// encoding first and falling back to standard/padded encodings.
func decodeSegment(seg string) ([]byte, bool) {
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b, true
	}
	// Add padding and try padded URL encoding.
	if pad := len(seg) % 4; pad != 0 {
		padded := seg + strings.Repeat("=", 4-pad)
		if b, err := base64.URLEncoding.DecodeString(padded); err == nil {
			return b, true
		}
		if b, err := base64.StdEncoding.DecodeString(padded); err == nil {
			return b, true
		}
	}
	if b, err := base64.StdEncoding.DecodeString(seg); err == nil {
		return b, true
	}
	return nil, false
}
