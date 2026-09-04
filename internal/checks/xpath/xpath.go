// Package xpath implements an XPath-injection check. It injects
// XPath-breaking payloads into each endpoint parameter and looks for
// distinctive XPath error signatures in the response body. Only a matched
// error signature is reported, which keeps false positives low: a bare HTTP
// 200 or a size change is never enough to flag.
//
// This is a non-destructive detection probe. The payloads either break XPath
// syntax (quotes, unbalanced brackets) or form a trivially-true predicate;
// none attempt data extraction or state change.
package xpath

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

// errorSignatures are case-insensitive substrings that strongly indicate an
// XPath engine choked on injected input (PHP, .NET, libxml, Java, etc.).
var errorSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)XPathException`),
	regexp.MustCompile(`(?i)Invalid XPath`),
	regexp.MustCompile(`(?i)XPath syntax`),
	regexp.MustCompile(`(?i)MS\.Internal\.Xml`),
	regexp.MustCompile(`(?i)System\.Xml\.XPath`),
	regexp.MustCompile(`(?i)xmlXPathEval`),
	regexp.MustCompile(`(?i)SimpleXMLElement::xpath`),
	regexp.MustCompile(`(?i)Warning: xpath`),
}

// Checker probes endpoint parameters for XPath injection.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds an XPath-injection Checker. When aggressive is true a couple of
// extra payload variants are tried.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "xpath-injection" }

// payloads returns the XPath-breaking strings to inject.
func (c *Checker) payloads() []string {
	p := []string{"'", `"`, "1' or '1'='1", "]]]]"}
	if c.aggressive {
		p = append(p, " or 1=1 or ''='", "count(//*)")
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
	for _, payload := range c.payloads() {
		if err := ctx.Err(); err != nil {
			return checks.Finding{}, false
		}
		resp, err := c.send(ctx, ep, param, payload)
		if err != nil || resp == nil {
			continue
		}
		if sig := matchError(resp.BodyString()); sig != "" {
			return checks.Finding{
				Type:        "xpath-injection",
				Severity:    checks.SeverityHigh,
				Title:       "XPath injection: XPath error triggered",
				URL:         ep.URL,
				Method:      ep.Method,
				Parameter:   param,
				Payload:     payload,
				Evidence:    checks.Truncate(sig, 240),
				Description: fmt.Sprintf("Injecting %q into parameter %q caused the application to return an XPath error, proving unsanitized input reaches an XPath query and can be manipulated to bypass authentication or extract XML data.", payload, param),
				Remediation: "Do not build XPath expressions by concatenating user input. Use parameterized/precompiled XPath with variable binding, and validate or whitelist input server-side. Suppress verbose error output in production.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
				CWE:         "CWE-643",
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
	for _, re := range errorSignatures {
		if loc := re.FindString(body); loc != "" {
			return loc
		}
	}
	return ""
}
