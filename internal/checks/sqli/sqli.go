// Package sqli implements a SQL-injection check using non-destructive
// techniques:
//
//   - Error-based: inject quote/paren payloads and look for database error
//     signatures that indicate input reached a SQL parser unsanitized.
//   - Boolean-based: send a logically-true and a logically-false condition
//     and compare the responses against a baseline.
//   - Time-based (opt-in): send one short, bounded delay payload and confirm
//     against a zero-delay control to rule out network jitter. This detects
//     fully blind injection. It is bounded and never looped, so it is a
//     detection probe, not a denial-of-service test.
//
// Stacked queries and any high-delay or repeated payloads are intentionally
// excluded: they risk disruption and are out of scope for a scanner.
package sqli

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

// dbErrorSignatures are substrings that strongly indicate a leaked SQL error.
var dbErrorSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)you have an error in your SQL syntax`),
	regexp.MustCompile(`(?i)warning:\s+mysqli?`),
	regexp.MustCompile(`(?i)unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),
	regexp.MustCompile(`(?i)pg_query\(\)|PostgreSQL.*ERROR`),
	regexp.MustCompile(`(?i)SQLite/JDBCDriver|SQLite3::`),
	regexp.MustCompile(`(?i)ORA-\d{5}`),
	regexp.MustCompile(`(?i)Microsoft OLE DB Provider for SQL Server`),
	regexp.MustCompile(`(?i)ODBC SQL Server Driver`),
	regexp.MustCompile(`(?i)SQLSTATE\[`),
}

// Checker probes endpoints for SQL injection.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
	timeBased  bool
	delay      time.Duration
}

// New builds a SQLi Checker. aggressive adds extra error/boolean variants;
// timeBased enables the bounded blind time-based probe using delaySeconds.
func New(client *httpclient.Client, aggressive, timeBased bool, delaySeconds int) *Checker {
	if delaySeconds < 1 {
		delaySeconds = 1
	}
	if delaySeconds > 10 {
		delaySeconds = 10
	}
	return &Checker{
		client:     client,
		aggressive: aggressive,
		timeBased:  timeBased,
		delay:      time.Duration(delaySeconds) * time.Second,
	}
}

// Name identifies the check.
func (c *Checker) Name() string { return "sqli" }

// errorPayloads returns the payloads used for the error-based probe.
func (c *Checker) errorPayloads() []string {
	if c.aggressive {
		return []string{"1'", `1"`, "1')", `1"))`, "1`"}
	}
	return []string{"1'"}
}

// booleanPairs returns (truePayload, falsePayload) pairs for boolean testing.
func (c *Checker) booleanPairs() [][2]string {
	pairs := [][2]string{
		{"1' AND '1'='1", "1' AND '1'='2"},
	}
	if c.aggressive {
		pairs = append(pairs, [2]string{"1 AND 1=1", "1 AND 1=2"})
	}
	return pairs
}

// Run tests every parameter of the endpoint and returns any findings.
func (c *Checker) Run(ctx context.Context, ep checks.Endpoint) []checks.Finding {
	var findings []checks.Finding
	for _, param := range ep.Params {
		if f, ok := c.testParam(ctx, ep, param); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

func (c *Checker) testParam(ctx context.Context, ep checks.Endpoint, param string) (checks.Finding, bool) {
	// 1) Error-based.
	for _, payload := range c.errorPayloads() {
		resp, err := c.send(ctx, ep, param, payload)
		if err != nil || resp == nil {
			continue
		}
		if sig := matchError(resp.BodyString()); sig != "" {
			return checks.Finding{
				Type:        "sqli",
				Severity:    checks.SeverityCritical,
				Title:       "SQL injection: database error triggered",
				URL:         ep.URL,
				Method:      ep.Method,
				Parameter:   param,
				Payload:     payload,
				Evidence:    checks.Truncate(sig, 240),
				Description: fmt.Sprintf("Injecting %q into parameter %q caused the application to return a database error, proving unsanitized input reaches the SQL engine.", payload, param),
				Remediation: "Use parameterized queries / prepared statements for all database access and never build SQL by string concatenation. Disable verbose DB errors in production.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
			}, true
		}
	}

	// 2) Boolean-based.
	baseResp, err := c.send(ctx, ep, param, "1")
	if err == nil && baseResp != nil {
		baseLen := normLen(baseResp.BodyString())
		for _, pair := range c.booleanPairs() {
			trueResp, err1 := c.send(ctx, ep, param, pair[0])
			falseResp, err2 := c.send(ctx, ep, param, pair[1])
			if err1 != nil || err2 != nil || trueResp == nil || falseResp == nil {
				continue
			}
			trueLen := normLen(trueResp.BodyString())
			falseLen := normLen(falseResp.BodyString())
			if similar(baseLen, trueLen) && !similar(trueLen, falseLen) &&
				significant(trueLen, falseLen) && trueResp.Status == baseResp.Status {
				return checks.Finding{
					Type:      "sqli",
					Severity:  checks.SeverityHigh,
					Title:     "SQL injection: boolean condition alters response",
					URL:       ep.URL,
					Method:    ep.Method,
					Parameter: param,
					Payload:   pair[0] + "  /  " + pair[1],
					Evidence: checks.Truncate(fmt.Sprintf(
						"baseline=%dB true=%dB false=%dB (true matches baseline, false diverges)",
						baseLen, trueLen, falseLen), 240),
					Description: fmt.Sprintf("Parameter %q shows a boolean-based SQL injection signal: a logically-true condition returns a baseline-sized response while a logically-false condition returns a materially different one.", param),
					Remediation: "Use parameterized queries / prepared statements and validate input types server-side.",
					Confidence:  "tentative",
					Timestamp:   time.Now(),
				}, true
			}
		}
	}

	// 3) Time-based blind (opt-in, bounded).
	if c.timeBased {
		if f, ok := c.testTimeBased(ctx, ep, param); ok {
			return f, true
		}
	}
	return checks.Finding{}, false
}

// timeTemplates are (name, template) pairs where %d is the delay seconds.
// Each is tried once at 0 seconds (control) and once at the configured delay.
var timeTemplates = []struct{ name, tmpl string }{
	{"mysql", "1' AND SLEEP(%d)-- -"},
	{"postgres", "1' || pg_sleep(%d)-- -"},
	{"mssql", "1'; WAITFOR DELAY '0:0:%d'-- -"},
}

func (c *Checker) testTimeBased(ctx context.Context, ep checks.Endpoint, param string) (checks.Finding, bool) {
	secs := int(c.delay / time.Second)
	for _, t := range timeTemplates {
		control := strings.Replace(t.tmpl, "%d", "0", 1)
		delayed := fmt.Sprintf(t.tmpl, secs)

		cResp, err := c.send(ctx, ep, param, control)
		if err != nil || cResp == nil {
			continue
		}
		dResp, err := c.send(ctx, ep, param, delayed)
		if err != nil || dResp == nil {
			continue
		}
		// Require the delayed request to take at least ~80% of the delay
		// longer than the control, and the control itself to be fast.
		threshold := time.Duration(float64(c.delay) * 0.8)
		if cResp.Elapsed < c.delay && (dResp.Elapsed-cResp.Elapsed) >= threshold {
			return checks.Finding{
				Type:        "sqli",
				Severity:    checks.SeverityCritical,
				Title:       "Blind SQL injection: time-based delay confirmed",
				URL:         ep.URL,
				Method:      ep.Method,
				Parameter:   param,
				Payload:     delayed,
				Evidence:    checks.Truncate(fmt.Sprintf("%s: control=%s delayed=%s (delay=%ds)", t.name, cResp.Elapsed.Round(time.Millisecond), dResp.Elapsed.Round(time.Millisecond), secs), 240),
				Description: fmt.Sprintf("Parameter %q is vulnerable to blind time-based SQL injection: a %s sleep payload delayed the response by the injected amount while a zero-second control returned promptly.", param, t.name),
				Remediation: "Use parameterized queries / prepared statements. Blind injection is exploitable even without visible output.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
			}, true
		}
	}
	return checks.Finding{}, false
}

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

func matchError(body string) string {
	for _, re := range dbErrorSignatures {
		if loc := re.FindString(body); loc != "" {
			return loc
		}
	}
	return ""
}

func normLen(s string) int { return len(strings.Join(strings.Fields(s), " ")) }

func similar(a, b int) bool {
	if a == 0 && b == 0 {
		return true
	}
	max := a
	if b > max {
		max = b
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return float64(diff)/float64(max) <= 0.03
}

func significant(a, b int) bool {
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return diff >= 32
}
