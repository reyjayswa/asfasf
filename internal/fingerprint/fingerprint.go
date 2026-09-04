// Package fingerprint inspects crawled pages to identify server-side
// technologies and to surface low-risk recon findings such as revealed
// software versions. Detection is signature-based over response headers,
// cookies, and body markers.
package fingerprint

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/crawler"
)

type signature struct {
	tech    string
	header  string         // header to inspect ("" means body)
	pattern *regexp.Regexp // matched against header value or body
}

// signatures is a compact, extensible fingerprint table.
var signatures = []signature{
	{"nginx", "Server", regexp.MustCompile(`(?i)nginx`)},
	{"Apache", "Server", regexp.MustCompile(`(?i)apache`)},
	{"Microsoft-IIS", "Server", regexp.MustCompile(`(?i)iis`)},
	{"PHP", "X-Powered-By", regexp.MustCompile(`(?i)php`)},
	{"ASP.NET", "X-Powered-By", regexp.MustCompile(`(?i)asp\.net`)},
	{"Express", "X-Powered-By", regexp.MustCompile(`(?i)express`)},
	{"WordPress", "", regexp.MustCompile(`(?i)/wp-(content|includes)/`)},
	{"Drupal", "", regexp.MustCompile(`(?i)Drupal.settings|/sites/default/`)},
	{"Django", "", regexp.MustCompile(`(?i)csrfmiddlewaretoken`)},
	{"Laravel", "Set-Cookie", regexp.MustCompile(`(?i)laravel_session`)},
	{"React", "", regexp.MustCompile(`(?i)data-reactroot|__REACT`)},
}

// versionHeaders are headers whose values often leak exact versions.
var versionHeaders = []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"}

var versionPattern = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

// Analyze runs fingerprinting over all crawled pages and returns findings.
// It detects technologies once (deduplicated) and flags version leaks.
func Analyze(pages []crawler.Page) []checks.Finding {
	detected := map[string]string{} // tech -> example URL
	versionLeaks := map[string]checks.Finding{}

	for _, p := range pages {
		body := string(p.Body)
		for _, sig := range signatures {
			if _, seen := detected[sig.tech]; seen {
				continue
			}
			if sig.header == "" {
				if sig.pattern.MatchString(body) {
					detected[sig.tech] = p.URL
				}
			} else if v := p.Header.Get(sig.header); v != "" && sig.pattern.MatchString(v) {
				detected[sig.tech] = p.URL
			}
		}
		for _, h := range versionHeaders {
			v := p.Header.Get(h)
			if v == "" || !versionPattern.MatchString(v) {
				continue
			}
			key := h + ":" + v
			if _, ok := versionLeaks[key]; ok {
				continue
			}
			versionLeaks[key] = checks.Finding{
				Type:        "fingerprint",
				Severity:    checks.SeverityLow,
				Title:       fmt.Sprintf("Software version disclosed via %s header", h),
				URL:         p.URL,
				Method:      "GET",
				Evidence:    checks.Truncate(h+": "+v, 200),
				Description: "The server reveals a specific software name and version in a response header, which helps an attacker match known CVEs to the target.",
				Remediation: "Suppress or genericize version tokens in the " + h + " header at the web server or framework level.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
			}
		}
	}

	var findings []checks.Finding
	if len(detected) > 0 {
		techs := make([]string, 0, len(detected))
		for t := range detected {
			techs = append(techs, t)
		}
		sort.Strings(techs)
		findings = append(findings, checks.Finding{
			Type:        "recon",
			Severity:    checks.SeverityInfo,
			Title:       "Technology stack fingerprinted",
			URL:         detected[techs[0]],
			Method:      "GET",
			Evidence:    checks.Truncate(strings.Join(techs, ", "), 300),
			Description: "The following technologies were identified from response headers and page markers: " + strings.Join(techs, ", ") + ".",
			Remediation: "Informational. Reducing technology disclosure raises the cost of targeted attacks but is not itself a vulnerability.",
			Confidence:  "firm",
			Timestamp:   time.Now(),
		})
	}
	for _, f := range versionLeaks {
		findings = append(findings, f)
	}
	return findings
}
