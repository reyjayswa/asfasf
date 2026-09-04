// Package nosql implements an error-based NoSQL (MongoDB) injection check.
//
// It injects payloads that break typical MongoDB query construction — bare
// quotes, JavaScript-string breakouts, and operator objects such as [$ne] —
// and inspects the response for database driver/error signatures. A match
// proves that attacker-controlled input reaches the query layer unsanitized.
//
// This module is intentionally error-based only: it does not implement
// time-based ($where sleep) detection, which risks disruption and is out of
// scope for a non-destructive scanner.
package nosql

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// errorSignatures are case-insensitive substrings that strongly indicate a
// leaked NoSQL/MongoDB error reached the response.
var errorSignatures = []string{
	"MongoError",
	"MongoServerError",
	"BSONError",
	"E11000",
	"$where",
	"unexpected token",
	"MongoDB",
	"CastError",
	"failed to parse",
}

// Checker probes endpoint parameters for error-based NoSQL injection.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds a NoSQL injection Checker. When aggressive is true a couple of
// additional breakout payloads are tried per parameter.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "nosql-injection" }

// payloads returns the injection strings used against each parameter.
func (c *Checker) payloads() []string {
	p := []string{
		"'",
		"\";return true//",
		"'\"",
		"[$ne]",
		"{\"$gt\":\"\"}",
	}
	if c.aggressive {
		p = append(p, "';sleep(0)//", "'||'1'=='1")
	}
	return p
}

// Run tests every parameter of the endpoint and returns any findings.
func (c *Checker) Run(ctx context.Context, ep checks.Endpoint) []checks.Finding {
	var findings []checks.Finding
	for _, param := range ep.Params {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if f, ok := c.testParam(ctx, ep, param); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

func (c *Checker) testParam(ctx context.Context, ep checks.Endpoint, param string) (checks.Finding, bool) {
	// Establish a benign baseline: send a neutral value and record which
	// signatures already appear in normal output (e.g. a "Powered by MongoDB"
	// footer, or documentation containing "$where"). We only flag signatures
	// the injection payload *introduces*, so such constant tokens never trip a
	// false positive.
	baseline := map[string]struct{}{}
	if resp, err := c.send(ctx, ep, param, "1"); err == nil && resp != nil {
		for sig := range foundSignatures(resp.BodyString()) {
			baseline[sig] = struct{}{}
		}
	}

	for _, payload := range c.payloads() {
		if err := ctx.Err(); err != nil {
			return checks.Finding{}, false
		}
		resp, err := c.send(ctx, ep, param, payload)
		if err != nil || resp == nil {
			continue
		}
		if sig := matchSignatureExcluding(resp.BodyString(), baseline); sig != "" {
			return checks.Finding{
				Type:        "nosql-injection",
				Severity:    checks.SeverityHigh,
				Title:       "NoSQL injection: database error triggered",
				URL:         ep.URL,
				Method:      ep.Method,
				Parameter:   param,
				Payload:     payload,
				Evidence:    checks.Truncate(sig, 240),
				Description: fmt.Sprintf("Injecting %q into parameter %q caused the application to return a NoSQL/MongoDB error, proving unsanitized input reaches the database query layer.", payload, param),
				Remediation: "Validate and type-check all user input before using it in queries; reject query operators ($ne, $gt, $where, ...) in user-supplied values and use a schema/ODM with strict casting. Disable verbose database errors in production.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
				CWE:         "CWE-943",
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

// matchSignatureExcluding returns the first NoSQL error signature found in body
// (case-insensitive) that is NOT in the baseline set, or "" if none qualifies.
// The returned string is the substring exactly as it appears in the response.
func matchSignatureExcluding(body string, baseline map[string]struct{}) string {
	lower := strings.ToLower(body)
	for _, sig := range errorSignatures {
		if _, seen := baseline[sig]; seen {
			continue
		}
		if idx := strings.Index(lower, strings.ToLower(sig)); idx >= 0 {
			return body[idx : idx+len(sig)]
		}
	}
	return ""
}

// foundSignatures returns the set of NoSQL error signatures present in body
// (keyed by the canonical signature string), matched case-insensitively.
func foundSignatures(body string) map[string]struct{} {
	lower := strings.ToLower(body)
	out := map[string]struct{}{}
	for _, sig := range errorSignatures {
		if strings.Contains(lower, strings.ToLower(sig)) {
			out[sig] = struct{}{}
		}
	}
	return out
}
