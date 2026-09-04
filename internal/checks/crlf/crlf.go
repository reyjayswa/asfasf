// Package crlf implements a CRLF / HTTP response-header-injection check.
//
// For each parameter of an endpoint it injects a value containing a CR/LF
// sequence followed by a uniquely tagged marker header. url.Values.Encode
// percent-encodes the CR and LF, so a safe server round-trips them as literal
// text; a vulnerable server decodes them and writes the parameter into a
// response header, causing the header to split and the marker header to appear
// in the response. Detection gates on the presence of that marker header (or a
// Set-Cookie carrying the unique token), which keeps the signal specific and
// avoids false positives from mere reflection in the body.
package crlf

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

// Checker probes endpoint parameters for CRLF response-header injection.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds a CRLF-injection Checker. When aggressive is true, an additional
// payload that injects a Set-Cookie header is attempted per parameter.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "crlf-injection" }

// token returns a short unique alphanumeric token used to tag the injected
// header so it can be recognised unambiguously in the response.
func token() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// injection describes a single CRLF payload attempt: the raw value to place in
// the parameter, the response header name whose presence proves the split, and
// the unique token that a Set-Cookie may alternatively carry.
type injection struct {
	value  string // raw parameter value containing CR/LF and the marker
	header string // marker header name expected in the response
	token  string // unique token, also searched for in Set-Cookie
}

// injections builds the payloads to try for one parameter. The header-splitting
// payload is always tried; the aggressive mode adds a Set-Cookie injection.
func (c *Checker) injections() []injection {
	tok := token()
	hdr := "X-Crlf-" + tok
	inj := []injection{
		{value: "1\r\n" + hdr + ": injected", header: hdr, token: tok},
	}
	if c.aggressive {
		ctok := token()
		inj = append(inj, injection{
			value:  "1\r\nSet-Cookie: crlf" + ctok + "=injected",
			header: "",
			token:  "crlf" + ctok,
		})
	}
	return inj
}

// Run tests every parameter of the endpoint and returns any findings.
func (c *Checker) Run(ctx context.Context, ep checks.Endpoint) []checks.Finding {
	var findings []checks.Finding
	for _, param := range ep.Params {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		if f, ok := c.testParam(ctx, ep, param); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

func (c *Checker) testParam(ctx context.Context, ep checks.Endpoint, param string) (checks.Finding, bool) {
	for _, inj := range c.injections() {
		select {
		case <-ctx.Done():
			return checks.Finding{}, false
		default:
		}
		resp, err := c.send(ctx, ep, param, inj.value)
		if err != nil || resp == nil {
			continue
		}

		// (a) The tagged marker header is present in the response: the
		// parameter split the header block.
		if inj.header != "" {
			if v := resp.Header.Get(inj.header); v != "" {
				return c.finding(ep, param, inj.value,
					fmt.Sprintf("response contains injected header %s: %s", inj.header, v),
					fmt.Sprintf("Parameter %q is written into a response header without stripping CR/LF. The injected header %q appeared in the response, proving the header block can be split (HTTP response splitting / header injection).", param, inj.header)), true
			}
		}

		// (b) A Set-Cookie in the response carries our unique token: an
		// injected Set-Cookie header took effect.
		for _, sc := range resp.Header.Values("Set-Cookie") {
			if strings.Contains(sc, inj.token) {
				return c.finding(ep, param, inj.value,
					"response contains injected Set-Cookie: "+sc,
					fmt.Sprintf("Parameter %q is written into a response header without stripping CR/LF, allowing an attacker-controlled Set-Cookie header to be injected (HTTP response splitting).", param)), true
			}
		}
	}
	return checks.Finding{}, false
}

func (c *Checker) finding(ep checks.Endpoint, param, payload, evidence, desc string) checks.Finding {
	return checks.Finding{
		Type:        "crlf-injection",
		Severity:    checks.SeverityHigh,
		Title:       "CRLF injection: user input splits response headers",
		URL:         ep.URL,
		Method:      ep.Method,
		Parameter:   param,
		Payload:     payload,
		Evidence:    checks.Truncate(evidence, 240),
		Description: desc,
		Remediation: "Strip or reject CR (\\r) and LF (\\n) from any user input placed into response headers (redirect targets, cookies, custom headers). Prefer framework APIs that encode header values and never build headers by string concatenation.",
		Confidence:  "firm",
		Timestamp:   time.Now(),
		CWE:         "CWE-113",
	}
}

// send injects value into param and issues the request for the endpoint's
// method, filling other parameters with a benign default. url.Values.Encode
// percent-encodes the CR/LF in value; a vulnerable server decodes and reflects
// them.
func (c *Checker) send(ctx context.Context, ep checks.Endpoint, param, value string) (*httpclient.Response, error) {
	values := url.Values{}
	for _, p := range ep.Params {
		if p == param {
			values.Set(p, value)
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
