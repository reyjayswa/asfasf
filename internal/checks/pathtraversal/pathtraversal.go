// Package pathtraversal implements a directory-traversal / local file
// read check. It injects traversal sequences into each endpoint parameter
// and confirms the vulnerability only when the response contains the
// contents of a well-known system file (Unix /etc/passwd or Windows
// win.ini). Detection is gated on distinctive file signatures rather than a
// bare HTTP 200, which keeps false positives low.
package pathtraversal

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

// unixPasswd matches a canonical /etc/passwd root entry. The trailing
// ":0:0:" makes it specific to real passwd content, not an arbitrary
// mention of the word "root".
var unixPasswd = regexp.MustCompile(`root:.*:0:0:`)

// winIni matches distinctive markers from a Windows win.ini file.
var winIni = regexp.MustCompile(`(?i)\[extensions\]|for 16-bit app support`)

// Checker probes endpoint parameters for path traversal.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds a path-traversal Checker. When aggressive is true it adds
// Windows and absolute-path payloads to the default Unix set.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "path-traversal" }

// payloads returns the traversal strings to inject, from least to most
// intrusive. The list stays small by default; aggressive adds variants.
func (c *Checker) payloads() []string {
	p := []string{
		"../../../../../../etc/passwd",
		"....//....//....//etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
	}
	if c.aggressive {
		p = append(p,
			`..\..\..\windows\win.ini`,
			"/etc/passwd",
		)
	}
	return p
}

// Run tests every parameter of the endpoint and returns any findings. At
// most one finding is reported per parameter.
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
	for _, payload := range c.payloads() {
		if err := ctx.Err(); err != nil {
			return checks.Finding{}, false
		}
		resp, err := c.send(ctx, ep, param, payload)
		if err != nil || resp == nil {
			continue
		}
		body := resp.BodyString()
		if line, kind := matchFile(body); line != "" {
			return checks.Finding{
				Type:        "path-traversal",
				Severity:    checks.SeverityHigh,
				Title:       "Path traversal: local file contents disclosed",
				URL:         ep.URL,
				Method:      ep.Method,
				Parameter:   param,
				Payload:     payload,
				Evidence:    checks.Truncate(line, 240),
				Description: fmt.Sprintf("Injecting the traversal sequence %q into parameter %q caused the application to return the contents of a %s system file, proving user input is used to build a filesystem path without sanitization.", payload, param, kind),
				Remediation: "Never build filesystem paths from user input. Resolve the path and verify it stays within an allowed base directory (e.g. filepath.Clean + prefix check), reject traversal sequences, or map inputs to a fixed allow-list of identifiers.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
				CWE:         "CWE-22",
			}, true
		}
	}
	return checks.Finding{}, false
}

// send injects payload into the named parameter (others get a benign "1")
// and issues the request. The payload is placed into the query/body raw so
// that pre-encoded variants like "..%2f.." travel on the wire unchanged
// rather than being double-encoded.
func (c *Checker) send(ctx context.Context, ep checks.Endpoint, param, payload string) (*httpclient.Response, error) {
	var parts []string
	for _, p := range ep.Params {
		if p == param {
			parts = append(parts, url.QueryEscape(p)+"="+payload)
		} else {
			parts = append(parts, url.QueryEscape(p)+"=1")
		}
	}
	query := strings.Join(parts, "&")

	if ep.Method == http.MethodPost {
		return c.client.PostForm(ctx, ep.URL, query)
	}
	sep := "?"
	if strings.Contains(ep.URL, "?") {
		sep = "&"
	}
	return c.client.Get(ctx, ep.URL+sep+query)
}

// matchFile returns the first line of body matching a known file signature
// and the kind of file ("Unix passwd" or "Windows win.ini"), or "" if none.
func matchFile(body string) (line, kind string) {
	if loc := unixPasswd.FindString(body); loc != "" {
		return lineContaining(body, loc), "Unix passwd"
	}
	if loc := winIni.FindString(body); loc != "" {
		return lineContaining(body, loc), "Windows win.ini"
	}
	return "", ""
}

// lineContaining returns the whole line of body that contains match,
// falling back to match itself if it cannot be located.
func lineContaining(body, match string) string {
	for _, ln := range strings.Split(body, "\n") {
		if strings.Contains(ln, match) {
			return strings.TrimRight(ln, "\r")
		}
	}
	return match
}
