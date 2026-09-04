// Package headerinj tests HTTP request headers as an injection surface that
// parameter-based checks miss. It probes host-routing headers for host-header
// injection (redirect/cache poisoning) and probes other client-controlled
// headers for unsafe reflection into the response.
package headerinj

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// Checker probes headers on an origin.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds a header-injection Checker.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "header-injection" }

// hostHeaders route requests and can enable host-header injection.
func (c *Checker) hostHeaders() []string {
	h := []string{"X-Forwarded-Host", "X-Host", "X-Forwarded-Server"}
	if c.aggressive {
		h = append(h, "X-Original-URL", "X-Rewrite-URL", "Forwarded")
	}
	return h
}

// reflectHeaders are client-controlled and interesting if reflected.
func (c *Checker) reflectHeaders() []string {
	h := []string{"Referer", "User-Agent", "X-Forwarded-For"}
	if c.aggressive {
		h = append(h, "X-Requested-With", "Origin", "True-Client-IP")
	}
	return h
}

func token() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return "hdr" + string(b)
}

// Run probes the origin root with tagged headers.
func (c *Checker) Run(ctx context.Context, origin string) []checks.Finding {
	var findings []checks.Finding
	target := origin + "/"

	// Host-header injection: the marker host appearing in a redirect Location
	// or an absolute URL in the body indicates the app trusts the header.
	for _, hdr := range c.hostHeaders() {
		if ctx.Err() != nil {
			break
		}
		tok := token() + ".example"
		resp, err := c.client.Do(ctx, http.MethodGet, target, nil, map[string]string{hdr: tok})
		if err != nil || resp == nil {
			continue
		}
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, tok) {
			findings = append(findings, mk("Host header injection via "+hdr,
				checks.SeverityMedium, "firm", target, hdr, tok,
				"redirect Location reflects the injected host: "+loc,
				fmt.Sprintf("The application builds a redirect from the %s header, so an attacker can control the redirect target (open redirect / cache poisoning).", hdr)))
		} else if strings.Contains(resp.BodyString(), "://"+tok) {
			findings = append(findings, mk("Host header reflected in absolute URL via "+hdr,
				checks.SeverityLow, "tentative", target, hdr, tok,
				"injected host reflected in an absolute URL in the body",
				fmt.Sprintf("The %s header is reflected into absolute URLs in the page, which can enable cache poisoning or password-reset poisoning.", hdr)))
		}
	}

	// Reflection of other client headers.
	for _, hdr := range c.reflectHeaders() {
		if ctx.Err() != nil {
			break
		}
		tok := token()
		resp, err := c.client.Do(ctx, http.MethodGet, target, nil, map[string]string{hdr: tok})
		if err != nil || resp == nil {
			continue
		}
		if strings.Contains(resp.BodyString(), tok) {
			findings = append(findings, mk("Request header reflected in response: "+hdr,
				checks.SeverityLow, "tentative", target, hdr, tok,
				"header value reflected unencoded in the body",
				fmt.Sprintf("The %s header is reflected into the response. Depending on context this can be an XSS sink or enable log/response injection; review the reflection context.", hdr)))
		}
	}
	return findings
}

func mk(title string, sev checks.Severity, conf, url, param, payload, evidence, desc string) checks.Finding {
	return checks.Finding{
		Type:        "header-injection",
		Severity:    sev,
		Title:       title,
		URL:         url,
		Method:      "GET",
		Parameter:   param,
		Payload:     param + ": " + payload,
		Evidence:    checks.Truncate(evidence, 240),
		Description: desc,
		Remediation: "Do not build URLs, redirects, or output from client-controllable headers; use a fixed canonical host and encode any reflected values.",
		Confidence:  conf,
		CWE:         "CWE-644",
		Timestamp:   time.Now(),
	}
}
