// Package xss implements a reflected cross-site-scripting check.
//
// For each parameter it injects a uniquely tagged payload containing HTML
// breakout characters, then inspects the response. If the breakout marker
// ("<token>") appears in the body unencoded, the application reflects
// attacker input into HTML without escaping — the core condition for
// reflected XSS. The random token keeps the signal specific.
//
// In safe mode a single breakout payload is tried per parameter. In
// aggressive mode several context-breakout prefixes are tried to catch
// reflections inside attributes, <title>, <textarea>, and <script>.
package xss

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// Checker probes endpoints for reflected XSS.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds an XSS Checker. When aggressive is true, extra breakout
// contexts are attempted per parameter.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "xss" }

func randToken() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return "xss" + string(b)
}

// prefixes returns the breakout prefixes to prepend before the "<token>"
// marker. Safe mode uses one; aggressive mode uses several contexts.
func (c *Checker) prefixes() []string {
	if c.aggressive {
		return []string{`"'`, `">`, `'>`, `</title>`, `</textarea>`, `</script>`}
	}
	return []string{`"'`}
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
	var (
		reflectedToken string
		reflectedBody  string
	)
	for _, prefix := range c.prefixes() {
		token := randToken()
		marker := "<" + token + ">"
		payload := prefix + marker

		resp, err := c.send(ctx, ep, param, payload)
		if err != nil || resp == nil {
			continue
		}
		body := resp.BodyString()
		if strings.Contains(body, marker) {
			return checks.Finding{
				Type:        "xss",
				Severity:    checks.SeverityHigh,
				Title:       "Reflected XSS: unescaped HTML injection",
				URL:         ep.URL,
				Method:      ep.Method,
				Parameter:   param,
				Payload:     payload,
				Evidence:    checks.Truncate(snippet(body, marker), 240),
				Description: fmt.Sprintf("Input in parameter %q is reflected into the response as raw HTML. The injected marker %q appears unencoded, so a real script or event-handler payload would execute in the victim's browser.", param, marker),
				Remediation: "Contextually output-encode all user input (HTML-encode for element content, attribute-encode for attributes) and apply a restrictive Content-Security-Policy.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
			}, true
		}
		if strings.Contains(body, token) {
			reflectedToken, reflectedBody = token, body
		}
	}

	// Reflected but encoded in every attempt: tentative sink worth review.
	if reflectedToken != "" {
		return checks.Finding{
			Type:        "xss",
			Severity:    checks.SeverityLow,
			Title:       "Input reflected (encoded) — potential XSS sink",
			URL:         ep.URL,
			Method:      ep.Method,
			Parameter:   param,
			Payload:     "<" + reflectedToken + ">",
			Evidence:    checks.Truncate(snippet(reflectedBody, reflectedToken), 240),
			Description: fmt.Sprintf("Parameter %q is reflected in the response but HTML metacharacters appear encoded. Depending on the reflection context (JavaScript string, attribute, URL) this may still be exploitable and warrants manual review.", param),
			Remediation: "Confirm the reflection context and ensure encoding matches it. Prefer framework auto-escaping and a strict CSP.",
			Confidence:  "tentative",
			Timestamp:   time.Now(),
		}, true
	}
	return checks.Finding{}, false
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

// snippet returns a window of text around the first occurrence of needle.
func snippet(body, needle string) string {
	i := strings.Index(body, needle)
	if i < 0 {
		return ""
	}
	start := i - 40
	if start < 0 {
		start = 0
	}
	end := i + len(needle) + 40
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(body[start:end])
}
