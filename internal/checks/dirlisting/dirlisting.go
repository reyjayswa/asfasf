// Package dirlisting is a passive analyzer that flags pages whose bodies
// contain autoindex / directory-listing signatures (CWE-548).
package dirlisting

import (
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/crawler"
)

// signatures are distinctive markers emitted by server-generated directory
// index pages. Each entry is matched case-sensitively against the page body.
var signatures = []string{
	"<title>Index of /",     // Apache / nginx autoindex
	"<h1>Index of /",        // Apache / nginx autoindex
	"Directory Listing For", // Apache Tomcat
	"[To Parent Directory]", // Microsoft IIS
}

// Analyze scans each page body for directory-listing signatures and returns
// one finding per URL that matches. It performs no network requests.
func Analyze(pages []crawler.Page) []checks.Finding {
	var findings []checks.Finding
	for _, p := range pages {
		if p.Status == 0 {
			continue
		}
		body := string(p.Body)
		for _, sig := range signatures {
			if strings.Contains(body, sig) {
				findings = append(findings, checks.Finding{
					Type:        "directory-listing",
					Severity:    checks.SeverityLow,
					Title:       "Directory listing enabled",
					URL:         p.URL,
					Evidence:    checks.Truncate(sig, 240),
					Description: "The server returned an auto-generated directory index, exposing the contents of a directory. This can reveal source files, backups, or other resources not intended to be publicly enumerated.",
					Remediation: "Disable automatic directory indexing (e.g. Apache 'Options -Indexes', nginx 'autoindex off', Tomcat 'listings=false', IIS directory browsing off) and add an index document where appropriate.",
					Confidence:  "firm",
					CWE:         "CWE-548",
					Timestamp:   time.Now(),
				})
				break // one finding per URL
			}
		}
	}
	return findings
}
