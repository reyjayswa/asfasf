// Package cmdinjection implements an output-based OS command injection check.
//
// It appends shell metacharacter payloads that run the harmless 'id' command
// to each parameter and looks for the distinctive output of that command in
// the response (uid=NN(name) gid=NN...). Requiring the command-output
// signature — rather than a bare HTTP 200 — keeps false positives low. When
// aggressive is set, a Windows "ver" payload is also tried and the Windows
// version banner is matched.
//
// Only output-based payloads are used. No time-based/sleep payloads are sent,
// so this is a bounded detection probe and never a denial-of-service test.
package cmdinjection

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

// unixSig matches the output of the Unix `id` command, e.g.
// "uid=1000(www-data) gid=1000". This is a distinctive proof of execution.
var unixSig = regexp.MustCompile(`uid=\d+\(\w+\) gid=\d+`)

// winSig matches the Windows `ver` command banner, e.g.
// "Microsoft Windows [Version 10.0.19045.4046]".
var winSig = regexp.MustCompile(`Microsoft Windows \[Version`)

// unixPayloads are shell metacharacter injections that run `id`.
var unixPayloads = []string{";id", "|id", "&&id", "`id`", "$(id)"}

// Checker probes endpoints for OS command injection.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds a command-injection Checker. When aggressive is true a Windows
// "ver" payload is additionally sent.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "command-injection" }

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
	// Unix output-based payloads.
	for _, payload := range unixPayloads {
		if err := ctx.Err(); err != nil {
			return checks.Finding{}, false
		}
		resp, err := c.send(ctx, ep, param, payload)
		if err != nil || resp == nil {
			continue
		}
		if sig := unixSig.FindString(resp.BodyString()); sig != "" {
			return checks.Finding{
				Type:        "command-injection",
				Severity:    checks.SeverityCritical,
				Title:       "OS command injection: command output returned",
				URL:         ep.URL,
				Method:      ep.Method,
				Parameter:   param,
				Payload:     payload,
				Evidence:    checks.Truncate(sig, 240),
				Description: fmt.Sprintf("Injecting %q into parameter %q caused the application to execute the Unix 'id' command and return its output (%s), proving unsanitized input reaches an OS shell.", payload, param, sig),
				Remediation: "Never pass user input to a shell. Use language-native APIs and pass arguments as an explicit argument vector (no shell interpretation). Apply strict allow-list input validation.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
				CWE:         "CWE-78",
			}, true
		}
	}

	// Windows output-based payload (aggressive only).
	if c.aggressive {
		payload := "&& ver"
		resp, err := c.send(ctx, ep, param, payload)
		if err == nil && resp != nil {
			if sig := winSig.FindString(resp.BodyString()); sig != "" {
				return checks.Finding{
					Type:        "command-injection",
					Severity:    checks.SeverityCritical,
					Title:       "OS command injection: Windows command output returned",
					URL:         ep.URL,
					Method:      ep.Method,
					Parameter:   param,
					Payload:     payload,
					Evidence:    checks.Truncate(sig, 240),
					Description: fmt.Sprintf("Injecting %q into parameter %q caused the application to execute the Windows 'ver' command and return its version banner, proving unsanitized input reaches an OS shell.", payload, param),
					Remediation: "Never pass user input to a shell. Use language-native APIs and pass arguments as an explicit argument vector (no shell interpretation). Apply strict allow-list input validation.",
					Confidence:  "firm",
					Timestamp:   time.Now(),
					CWE:         "CWE-78",
				}, true
			}
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
