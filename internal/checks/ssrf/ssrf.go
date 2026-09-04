// Package ssrf detects server-side request forgery using out-of-band
// interaction. It injects a unique callback URL (pointing at the tester's
// interaction server) into each parameter; if the target fetches it
// server-side, the interaction server records the hit and the injection is
// confirmed — even when the HTTP response shows nothing.
package ssrf

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
	"github.com/reyjayswa/asfasf/internal/oob"
)

// Checker probes endpoints for SSRF via an out-of-band callback.
type Checker struct {
	client     *httpclient.Client
	oob        *oob.Server
	aggressive bool
	wait       time.Duration
}

// New builds an SSRF Checker bound to an interaction server.
func New(client *httpclient.Client, srv *oob.Server, aggressive bool) *Checker {
	return &Checker{client: client, oob: srv, aggressive: aggressive, wait: 3 * time.Second}
}

// Name identifies the check.
func (c *Checker) Name() string { return "ssrf" }

// Run tests every parameter of the endpoint for an out-of-band callback.
func (c *Checker) Run(ctx context.Context, ep checks.Endpoint) []checks.Finding {
	if c.oob == nil {
		return nil
	}
	var findings []checks.Finding
	for _, param := range ep.Params {
		if ctx.Err() != nil {
			break
		}
		token, callback := c.oob.Payload("ssrf")
		if _, err := c.send(ctx, ep, param, callback); err != nil {
			continue
		}
		if hit, ok := c.oob.WaitFor(ctx, token, c.wait); ok {
			findings = append(findings, checks.Finding{
				Type:        "ssrf",
				Severity:    checks.SeverityCritical,
				Title:       "Server-side request forgery (out-of-band confirmed)",
				URL:         ep.URL,
				Method:      ep.Method,
				Parameter:   param,
				Payload:     callback,
				Evidence:    checks.Truncate(fmt.Sprintf("target contacted the interaction server from %s at %s", hit.RemoteAddr, hit.When.Format(time.RFC3339)), 240),
				Description: fmt.Sprintf("Parameter %q caused the server to make an outbound request to an attacker-controlled URL. This is server-side request forgery and may allow access to internal services or cloud metadata.", param),
				Remediation: "Validate and allowlist outbound request destinations, disable unused URL schemes, and block access to internal/link-local addresses and cloud metadata endpoints.",
				Confidence:  "firm",
				CWE:         "CWE-918",
				Timestamp:   time.Now(),
			})
		}
	}
	return findings
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
