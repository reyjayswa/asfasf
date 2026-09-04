// Package cors implements a CORS misconfiguration check.
//
// It probes a single origin ("https://host[:port]") by issuing a GET with an
// attacker-controlled Origin header and inspecting the CORS response headers.
// The most dangerous case is a server that reflects an arbitrary Origin into
// Access-Control-Allow-Origin (ACAO) while also setting
// Access-Control-Allow-Credentials (ACAC) to "true": that lets any site read
// authenticated responses on behalf of a victim (account-takeover risk).
//
// The check gates on a distinctive, never-legitimate evil origin so that a
// server which merely echoes a same-site or allow-listed origin is not
// flagged. Only genuine misconfigurations produce findings.
package cors

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// evilOrigin is a distinctive, attacker-controlled origin that a correctly
// configured application would never reflect or allow. Reflecting it back in
// ACAO is a reliable signal of an origin-reflection misconfiguration.
const evilOrigin = "https://evil-cors-canary.example"

// Checker probes an origin for CORS misconfigurations.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds a CORS Checker. When aggressive is true the checker additionally
// tests the special "null" origin.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "cors" }

// Run probes origin and returns any CORS misconfiguration findings. origin is
// like "https://host[:port]" with no trailing slash.
func (c *Checker) Run(ctx context.Context, origin string) []checks.Finding {
	var findings []checks.Finding

	target := strings.TrimRight(origin, "/") + "/"

	// (1) Reflect an arbitrary evil origin.
	if resp, err := c.probe(ctx, target, evilOrigin); err == nil && resp != nil {
		acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
		acac := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true")
		if f, ok := classify(origin, evilOrigin, acao, acac); ok {
			findings = append(findings, f)
		}
	}

	// (2) Aggressive: the "null" origin, commonly allow-listed by mistake and
	// forgeable from sandboxed iframes / data: URLs.
	if c.aggressive {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		if resp, err := c.probe(ctx, target, "null"); err == nil && resp != nil {
			acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
			acac := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true")
			if strings.EqualFold(acao, "null") && acac {
				findings = append(findings, checks.Finding{
					Type:        "cors",
					Severity:    checks.SeverityHigh,
					Title:       "CORS: \"null\" origin allowed with credentials",
					URL:         origin,
					Method:      http.MethodGet,
					Payload:     "Origin: null",
					Evidence:    checks.Truncate(fmt.Sprintf("Access-Control-Allow-Origin: %s; Access-Control-Allow-Credentials: %s", acao, resp.Header.Get("Access-Control-Allow-Credentials")), 240),
					Description: "The server reflects the \"null\" origin in Access-Control-Allow-Origin while allowing credentials. The null origin is forgeable from sandboxed iframes, data: and file: URLs, so an attacker-controlled page can read authenticated responses.",
					Remediation: "Never allow the \"null\" origin. Validate the Origin header against a strict server-side allow-list and only echo trusted origins; do not combine a wildcard or null origin with Access-Control-Allow-Credentials: true.",
					Confidence:  "firm",
					Timestamp:   time.Now(),
					CWE:         "CWE-942",
				})
			}
		}
	}

	return findings
}

// classify turns the observed ACAO/ACAC values (from the evil-origin probe)
// into a finding, or reports that no misconfiguration is present.
func classify(origin, sentOrigin, acao string, acac bool) (checks.Finding, bool) {
	evidence := checks.Truncate(fmt.Sprintf("Access-Control-Allow-Origin: %s; Access-Control-Allow-Credentials: %t", acao, acac), 240)

	base := checks.Finding{
		Type:        "cors",
		URL:         origin,
		Method:      http.MethodGet,
		Payload:     "Origin: " + sentOrigin,
		Evidence:    evidence,
		Confidence:  "firm",
		Timestamp:   time.Now(),
		CWE:         "CWE-942",
		Remediation: "Validate the Origin header against a strict server-side allow-list and echo only trusted origins. Never reflect arbitrary origins, and never combine a wildcard (\"*\") or reflected origin with Access-Control-Allow-Credentials: true.",
	}

	switch {
	case strings.EqualFold(acao, sentOrigin) && acac:
		base.Severity = checks.SeverityHigh
		base.Title = "CORS: arbitrary origin reflected with credentials"
		base.Description = "The server reflects an arbitrary attacker-supplied Origin into Access-Control-Allow-Origin and sets Access-Control-Allow-Credentials: true. Any external site can issue credentialed cross-origin requests and read the authenticated responses, enabling data theft and account takeover."
		return base, true

	case strings.EqualFold(acao, sentOrigin):
		base.Severity = checks.SeverityMedium
		base.Title = "CORS: arbitrary origin reflected"
		base.Description = "The server reflects an arbitrary attacker-supplied Origin into Access-Control-Allow-Origin. Although credentials are not allowed, any site can read non-credentialed cross-origin responses, which may expose sensitive data returned without cookies (e.g. via bearer tokens or IP-based trust)."
		return base, true

	case acao == "*" && acac:
		// Invalid per spec (browsers reject "*" with credentials) but still a
		// clear server-side misconfiguration worth flagging.
		base.Severity = checks.SeverityHigh
		base.Title = "CORS: wildcard origin with credentials"
		base.Description = "The server returns Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. This is an invalid combination browsers reject, but it signals a broken CORS policy that likely also reflects specific origins with credentials."
		return base, true

	case acao == "*":
		base.Severity = checks.SeverityLow
		base.Title = "CORS: wildcard origin allowed"
		base.Confidence = "firm"
		base.Description = "The server returns Access-Control-Allow-Origin: *, permitting any origin to make non-credentialed cross-origin requests. This is only a concern if the endpoint exposes data that should not be world-readable."
		return base, true
	}

	return checks.Finding{}, false
}

// probe issues a GET to target with the given Origin header.
func (c *Checker) probe(ctx context.Context, target, origin string) (*httpclient.Response, error) {
	return c.client.Do(ctx, http.MethodGet, target, nil, map[string]string{"Origin": origin})
}
