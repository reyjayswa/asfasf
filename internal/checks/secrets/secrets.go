// Package secrets is a passive analyzer that scans fetched page bodies
// (HTML and inline JS) for high-confidence leaked secrets and API keys.
//
// It performs NO network requests; it only inspects crawler.Page bodies.
package secrets

import (
	"regexp"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/crawler"
)

// pattern describes a single secret signature.
type pattern struct {
	name       string
	re         *regexp.Regexp
	severity   checks.Severity
	confidence string
	cwe        string
	title      string
	// group is the regex submatch index that holds the actual secret value
	// to mask. 0 means the whole match.
	group int
}

var patterns = []pattern{
	{
		name:       "aws-access-key-id",
		re:         regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		severity:   checks.SeverityHigh,
		confidence: "firm",
		cwe:        "CWE-798",
		title:      "Leaked AWS Access Key ID",
		group:      0,
	},
	{
		name:       "google-api-key",
		re:         regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
		severity:   checks.SeverityHigh,
		confidence: "firm",
		cwe:        "CWE-798",
		title:      "Leaked Google API Key",
		group:      0,
	},
	{
		name:       "slack-token",
		re:         regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),
		severity:   checks.SeverityHigh,
		confidence: "firm",
		cwe:        "CWE-798",
		title:      "Leaked Slack Token",
		group:      0,
	},
	{
		name:       "private-key-block",
		re:         regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
		severity:   checks.SeverityCritical,
		confidence: "firm",
		cwe:        "CWE-798",
		title:      "Leaked Private Key",
		group:      0,
	},
	{
		name:       "github-token",
		re:         regexp.MustCompile(`ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,}`),
		severity:   checks.SeverityHigh,
		confidence: "firm",
		cwe:        "CWE-798",
		title:      "Leaked GitHub Token",
		group:      0,
	},
	{
		name:       "generic-secret-assignment",
		re:         regexp.MustCompile(`(?i)(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']`),
		severity:   checks.SeverityMedium,
		confidence: "tentative",
		cwe:        "CWE-798",
		title:      "Possible Hardcoded Secret",
		group:      1,
	},
}

// mask reveals only the first 4 and last 2 characters of a secret value,
// replacing the middle with a fixed marker so the raw secret is not echoed.
func mask(s string) string {
	if len(s) <= 6 {
		return "****"
	}
	return s[:4] + "***" + s[len(s)-2:]
}

// Analyze scans each page body for high-confidence secret patterns and
// returns one Finding per distinct leak. Findings are deduplicated by
// (page URL, pattern name, masked value prefix) so the same secret repeated
// across a body is reported once.
func Analyze(pages []crawler.Page) []checks.Finding {
	var findings []checks.Finding
	seen := make(map[string]struct{})

	for _, page := range pages {
		body := string(page.Body)
		if body == "" {
			continue
		}
		for _, p := range patterns {
			matches := p.re.FindAllStringSubmatch(body, -1)
			for _, m := range matches {
				value := m[p.group]
				if value == "" {
					continue
				}
				masked := mask(value)
				key := page.URL + "|" + p.name + "|" + masked
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}

				findings = append(findings, checks.Finding{
					Type:     "leaked-secret",
					Severity: p.severity,
					Title:    p.title,
					URL:      page.URL,
					Method:   "GET",
					Payload:  p.name,
					Evidence: checks.Truncate("matched "+p.name+": "+masked, 240),
					Description: "A high-confidence secret pattern (" + p.name + ") was found exposed in the response body. " +
						"Secrets embedded in client-delivered HTML or JavaScript are accessible to anyone who can load the page.",
					Remediation: "Remove the secret from client-delivered code, rotate/revoke the exposed credential immediately, " +
						"and move secrets to server-side storage or a secrets manager.",
					Confidence: p.confidence,
					Timestamp:  time.Now(),
					CWE:        p.cwe,
				})
			}
		}
	}

	return findings
}
