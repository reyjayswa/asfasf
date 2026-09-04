// Package checks defines the shared types used across the scanner: the
// vulnerability Finding model and the Endpoint model produced by the
// crawler. Each detection module (xss, sqli) lives in its own subpackage
// and is wired together by the engine package.
package checks

import "time"

// Severity is the qualitative impact rating of a finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityRank is used to sort findings from most to least severe.
var severityRank = map[Severity]int{
	SeverityCritical: 5,
	SeverityHigh:     4,
	SeverityMedium:   3,
	SeverityLow:      2,
	SeverityInfo:     1,
}

// Rank returns a numeric weight for a severity (higher is worse).
func (s Severity) Rank() int { return severityRank[s] }

// Finding is a single result produced by a check or the recon stage.
type Finding struct {
	Type        string    `json:"type"`        // e.g. "xss", "sqli", "recon", "fingerprint"
	Severity    Severity  `json:"severity"`    // impact rating
	Title       string    `json:"title"`       // short human-readable summary
	URL         string    `json:"url"`         // affected URL
	Method      string    `json:"method"`      // HTTP method used
	Parameter   string    `json:"parameter"`   // affected parameter, if any
	Payload     string    `json:"payload"`     // payload that triggered it, if any
	Evidence    string    `json:"evidence"`    // proof snippet (bounded length)
	Description string    `json:"description"` // what the issue is
	Remediation string    `json:"remediation"` // how to fix it
	Confidence  string    `json:"confidence"`  // "firm" or "tentative"
	Timestamp   time.Time `json:"timestamp"`   // when it was found

	// Classification and scoring. Checks may set these directly; the engine's
	// enrichment step fills any left empty based on the finding Type.
	CWE   string  `json:"cwe,omitempty"`   // e.g. "CWE-79"
	OWASP string  `json:"owasp,omitempty"` // e.g. "A03:2021-Injection"
	Score float64 `json:"score,omitempty"` // indicative 0-10 severity score
}

// Endpoint is a discovered request target that checks can probe.
type Endpoint struct {
	URL    string   `json:"url"`    // base URL without the tested query
	Method string   `json:"method"` // GET or POST
	Params []string `json:"params"` // parameter names discovered here
	Source string   `json:"source"` // where it was discovered (link, form, query)
}

// Detection is a technology identified on the target, optionally with a
// version. The CVE mapper consumes these to flag known vulnerabilities.
type Detection struct {
	Tech    string `json:"tech"`    // e.g. "nginx", "WordPress", "PHP"
	Version string `json:"version"` // e.g. "1.18.0"; empty if unknown
	URL     string `json:"url"`     // where it was observed
}

// Truncate bounds a string to n runes, appending an ellipsis if cut.
// Checks use it to keep evidence snippets short and safe to render.
func Truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
