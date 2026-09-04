// Package ssti implements a server-side template injection (SSTI) check.
//
// For each parameter it injects template expressions whose evaluation
// yields a distinctive arithmetic product (1337*1337 = 1787569). If that
// product appears in the response while the raw expression does NOT, the
// application evaluated the injected template — the core condition for
// SSTI. The unusual product keeps coincidental matches to a minimum.
//
// Expressions cover the common engines: "{{1337*1337}}" (Jinja2/Twig),
// "${1337*1337}" (JSP/Spring EL/Freemarker), "#{1337*1337}" (Ruby/JSF),
// and "<%= 1337*1337 %>" (ERB/EJS). In aggressive mode an additional
// mixed-type expression "{{1337*'1337'}}" is tried.
package ssti

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

// product is the evaluated result of every injected expression.
const product = "1787569"

// Checker probes endpoint parameters for server-side template injection.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds an SSTI Checker. When aggressive is true, an extra
// mixed-type expression is attempted per parameter.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "ssti" }

// payloads returns the template expressions to try. Safe mode uses a small
// cross-engine set; aggressive mode adds a mixed-type variant.
func (c *Checker) payloads() []string {
	p := []string{
		"{{1337*1337}}",    // Jinja2 / Twig
		"${1337*1337}",     // JSP / Spring EL / Freemarker
		"#{1337*1337}",     // Ruby / JSF
		"<%= 1337*1337 %>", // ERB / EJS
	}
	if c.aggressive {
		p = append(p, "{{1337*'1337'}}")
	}
	return p
}

// Run tests every parameter of the endpoint and returns any findings.
func (c *Checker) Run(ctx context.Context, ep checks.Endpoint) []checks.Finding {
	var findings []checks.Finding
	for _, param := range ep.Params {
		if ctx.Err() != nil {
			return findings
		}
		if f, ok := c.testParam(ctx, ep, param); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

func (c *Checker) testParam(ctx context.Context, ep checks.Endpoint, param string) (checks.Finding, bool) {
	for _, payload := range c.payloads() {
		if ctx.Err() != nil {
			return checks.Finding{}, false
		}
		resp, err := c.send(ctx, ep, param, payload)
		if err != nil || resp == nil {
			continue
		}
		body := resp.BodyString()
		// Require the evaluated product to appear AND the raw expression to
		// be absent: presence of the verbatim payload means it was merely
		// reflected, not evaluated.
		if strings.Contains(body, product) && !strings.Contains(body, payload) {
			return checks.Finding{
				Type:        "ssti",
				Severity:    checks.SeverityHigh,
				Title:       "Server-side template injection",
				URL:         ep.URL,
				Method:      ep.Method,
				Parameter:   param,
				Payload:     payload,
				Evidence:    checks.Truncate(snippet(body, product), 240),
				Description: fmt.Sprintf("Input in parameter %q is evaluated by a server-side template engine. The injected expression %q was computed to %s in the response, proving the template context executes attacker-controlled expressions. This commonly leads to remote code execution.", param, payload, product),
				Remediation: "Never pass user input into template source. Render untrusted data only through the engine's data/context binding, use a sandboxed or logic-less template configuration, and validate/allowlist any user-supplied template names.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
				CWE:         "CWE-1336",
			}, true
		}
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
