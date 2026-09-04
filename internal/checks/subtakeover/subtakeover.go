// Package subtakeover detects dangling-DNS subdomain takeover conditions.
//
// A subdomain takeover happens when a DNS record (typically a CNAME) points at
// a third-party service (GitHub Pages, S3, Heroku, ...) for a resource that no
// longer exists there. An attacker who can register that resource on the
// provider then controls content served from the victim's subdomain.
//
// The checker resolves the origin host's CNAME and fetches the origin over the
// scope-enforced HTTP client, then matches the response body against a table of
// known provider "not found" fingerprints. A match on both the CNAME suffix and
// the body signature is reported firm/High; a body-only match (no confirming
// CNAME) is reported tentative/Medium.
package subtakeover

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// service is a single takeover fingerprint entry.
type service struct {
	name          string   // provider name
	cnameSuffixes []string // CNAME suffixes that indicate this provider
	bodySigs      []string // distinctive "not found" body markers
	severity      checks.Severity
}

// fingerprints is the built-in table of dangling-service takeover signatures.
var fingerprints = []service{
	{
		name:          "GitHub Pages",
		cnameSuffixes: []string{".github.io", "github.io"},
		bodySigs:      []string{"There isn't a GitHub Pages site here"},
		severity:      checks.SeverityHigh,
	},
	{
		name:          "AWS S3",
		cnameSuffixes: []string{"amazonaws.com", "s3"},
		bodySigs:      []string{"NoSuchBucket", "The specified bucket does not exist"},
		severity:      checks.SeverityHigh,
	},
	{
		name:          "Heroku",
		cnameSuffixes: []string{"herokuapp.com", "herokudns"},
		bodySigs:      []string{"No such app", "herokucdn.com/error-pages/no-such-app.html"},
		severity:      checks.SeverityHigh,
	},
	{
		name:          "Fastly",
		cnameSuffixes: nil,
		bodySigs:      []string{"Fastly error: unknown domain"},
		severity:      checks.SeverityHigh,
	},
	{
		name:          "Shopify",
		cnameSuffixes: []string{"myshopify.com"},
		bodySigs:      []string{"Sorry, this shop is currently unavailable"},
		severity:      checks.SeverityHigh,
	},
	{
		name:          "Zendesk",
		cnameSuffixes: []string{"zendesk.com"},
		bodySigs:      []string{"Help Center Closed"},
		severity:      checks.SeverityHigh,
	},
	{
		name:          "Surge.sh",
		cnameSuffixes: nil,
		bodySigs:      []string{"project not found"},
		severity:      checks.SeverityHigh,
	},
	{
		name:          "Bitbucket",
		cnameSuffixes: []string{"bitbucket.io"},
		bodySigs:      []string{"Repository not found"},
		severity:      checks.SeverityHigh,
	},
}

// Checker performs subdomain-takeover detection for a single origin.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New constructs a takeover Checker using the given scope-enforced client.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name returns the stable identifier for this check.
func (c *Checker) Name() string { return "subdomain-takeover" }

// hostFromOrigin strips scheme and port, returning the bare host.
func hostFromOrigin(origin string) string {
	h := origin
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	// drop path/query
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	// drop userinfo
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	// strip port (guard IPv6 literals in brackets)
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i >= 0 {
			h = h[1:i]
		}
	} else if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

// Run resolves the origin host, fetches the origin body, and reports any
// takeover fingerprint match.
func (c *Checker) Run(ctx context.Context, origin string) []checks.Finding {
	if err := ctx.Err(); err != nil {
		return nil
	}

	host := hostFromOrigin(origin)

	// DNS resolution is best-effort: errors (NXDOMAIN, no CNAME) must not
	// prevent the body-signature checks from running.
	cname := ""
	if host != "" {
		if resolved, err := net.LookupCNAME(host); err == nil {
			cname = strings.ToLower(strings.TrimSuffix(resolved, "."))
		}
	}

	resp, err := c.client.Get(ctx, origin)
	if err != nil {
		return nil
	}
	body := resp.BodyString()
	lower := strings.ToLower(body)

	var findings []checks.Finding
	for _, svc := range fingerprints {
		matchedSig := ""
		for _, sig := range svc.bodySigs {
			if strings.Contains(lower, strings.ToLower(sig)) {
				matchedSig = sig
				break
			}
		}
		if matchedSig == "" {
			continue
		}

		cnameMatch := ""
		for _, suf := range svc.cnameSuffixes {
			if cname != "" && strings.Contains(cname, strings.ToLower(suf)) {
				cnameMatch = suf
				break
			}
		}

		f := checks.Finding{
			Type:        "subdomain-takeover",
			Title:       "Potential subdomain takeover (" + svc.name + ")",
			URL:         origin,
			Method:      "GET",
			Remediation: "Remove or repoint the dangling DNS record, or reclaim the resource on " + svc.name + ". Ensure no DNS record points to an unclaimed third-party endpoint.",
			Timestamp:   time.Now(),
		}

		if cnameMatch != "" {
			f.Severity = svc.severity
			f.Confidence = "firm"
			f.Description = "The host resolves via CNAME to " + svc.name + " and the origin returns that provider's \"resource not found\" page, indicating the backing resource is unclaimed and can be taken over by registering it on " + svc.name + "."
			f.Evidence = checks.Truncate("cname="+cname+" service="+svc.name+" signature="+matchedSig, 240)
		} else {
			// Body signature only, no confirming CNAME -> lower confidence.
			f.Severity = checks.SeverityMedium
			f.Confidence = "tentative"
			f.Description = "The origin returns " + svc.name + "'s \"resource not found\" page. If a DNS record delegates this host to " + svc.name + ", the unclaimed resource may be registered by an attacker to take over the subdomain. No confirming CNAME was resolved."
			cnameEvidence := cname
			if cnameEvidence == "" {
				cnameEvidence = "(none resolved)"
			}
			f.Evidence = checks.Truncate("cname="+cnameEvidence+" service="+svc.name+" signature="+matchedSig, 240)
		}

		findings = append(findings, f)
	}

	return findings
}
