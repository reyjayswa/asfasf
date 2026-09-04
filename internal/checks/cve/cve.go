// Package cve maps detected software technologies and their version banners
// to a small built-in table of well-known CVEs. It performs pure post-analysis
// of []checks.Detection produced by the fingerprint stage and makes no network
// requests. Findings are emitted with Confidence "tentative" because version
// banners can be spoofed, back-ported, or simply inaccurate.
package cve

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
)

// version is a parsed dotted-numeric version, e.g. "2.4.49" -> [2 4 49].
type version []int

// parseVersion parses a dotted numeric version string into a version. Any
// non-numeric trailing segment (build metadata, pre-release suffixes, etc.) is
// ignored. Returns ok=false if there is not at least one numeric component.
func parseVersion(s string) (version, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	// Trim a leading "v" if present (e.g. "v1.2.3").
	if len(s) > 1 && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	var v version
	for _, part := range strings.Split(s, ".") {
		// Extract the leading numeric run. A component like "3" or "49"
		// yields that number; "0-beta" yields 0; a purely alphabetic run
		// (e.g. a pre-release tag) ends the parse.
		i := 0
		for i < len(part) && part[i] >= '0' && part[i] <= '9' {
			i++
		}
		if i == 0 {
			// No leading digits: stop parsing further components.
			break
		}
		n, err := strconv.Atoi(part[:i])
		if err != nil {
			break
		}
		v = append(v, n)

		// OpenSSL-style release letter, e.g. the "f" in "1.0.1f". Encode a
		// single trailing lowercase/uppercase letter as an extra component
		// (a=1 .. z=26) so that 1.0.1 < 1.0.1a < 1.0.1f < 1.0.1g. Anything
		// else after the digits (e.g. "-beta") terminates the parse.
		if i < len(part) {
			c := part[i]
			isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			// Only treat it as a release letter if it is the sole trailing
			// character of this component.
			if isLetter && i == len(part)-1 {
				lc := c
				if lc >= 'A' && lc <= 'Z' {
					lc = lc - 'A' + 'a'
				}
				v = append(v, int(lc-'a')+1)
			}
			break
		}
	}
	if len(v) == 0 {
		return nil, false
	}
	return v, true
}

// compare returns -1 if a < b, 0 if a == b, 1 if a > b. Missing trailing
// components are treated as zero, so "1.21" == "1.21.0".
func compare(a, b version) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(a) {
			ai = a[i]
		}
		if i < len(b) {
			bi = b[i]
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

// rule decides whether a parsed version is affected by a CVE entry.
type rule func(v version) bool

// lessThan matches any version strictly below the given bound.
func lessThan(bound string) rule {
	b, ok := parseVersion(bound)
	if !ok {
		return func(version) bool { return false }
	}
	return func(v version) bool { return compare(v, b) < 0 }
}

// inRange matches a version in the half-open interval [lo, hi).
func inRange(lo, hi string) rule {
	l, okl := parseVersion(lo)
	h, okh := parseVersion(hi)
	if !okl || !okh {
		return func(version) bool { return false }
	}
	return func(v version) bool {
		return compare(v, l) >= 0 && compare(v, h) < 0
	}
}

// exactSet matches a version equal to any of the listed versions.
func exactSet(versions ...string) rule {
	var set []version
	for _, s := range versions {
		if pv, ok := parseVersion(s); ok {
			set = append(set, pv)
		}
	}
	return func(v version) bool {
		for _, pv := range set {
			if compare(v, pv) == 0 {
				return true
			}
		}
		return false
	}
}

// entry is one CVE record in the built-in table.
type entry struct {
	// techAliases are the lowercase tech names this entry applies to. A
	// Detection matches if any whole token of its (lowercased) Tech equals an
	// alias, so "Apache", "Apache httpd" and "httpd" all map to the httpd
	// entries.
	techAliases []string
	// disqualify lists lowercase tokens that VETO a match even when an alias
	// token is present. This separates products that share a word from the
	// intended target: "Apache Tomcat" and "Apache Kafka" share the "apache"
	// token with Apache HTTP Server but are unrelated, and "jQuery UI"/"jQuery
	// Mobile" share "jquery" with jQuery core but ship their own versions.
	disqualify []string
	cveID      string
	// techName is the canonical name used in the Finding title.
	techName     string
	affected     rule
	fixedVersion string
	severity     checks.Severity
	description  string
}

// table is the built-in list of well-known CVEs. It is intentionally small
// and focused on high-signal, widely exploited issues.
var table = []entry{
	{
		techAliases:  []string{"nginx"},
		cveID:        "CVE-2021-23017",
		techName:     "nginx",
		affected:     lessThan("1.21.0"),
		fixedVersion: "1.21.0",
		severity:     checks.SeverityHigh,
		description:  "A one-byte memory overwrite (off-by-one) in the nginx DNS resolver can be triggered by a crafted DNS response, potentially leading to worker process crash or remote code execution when the resolver directive is used.",
	},
	{
		techAliases:  []string{"apache", "httpd"},
		disqualify:   []string{"tomcat", "kafka", "solr", "spark", "camel"},
		cveID:        "CVE-2021-41773",
		techName:     "Apache",
		affected:     exactSet("2.4.49"),
		fixedVersion: "2.4.51",
		severity:     checks.SeverityCritical,
		description:  "A path traversal and file disclosure flaw in Apache HTTP Server 2.4.49 allows attackers to map URLs to files outside the configured document root and, when mod_cgi is enabled, achieve remote code execution.",
	},
	{
		techAliases:  []string{"apache", "httpd"},
		disqualify:   []string{"tomcat", "kafka", "solr", "spark", "camel"},
		cveID:        "CVE-2021-42013",
		techName:     "Apache",
		affected:     exactSet("2.4.49", "2.4.50"),
		fixedVersion: "2.4.51",
		severity:     checks.SeverityCritical,
		description:  "An incomplete fix for CVE-2021-41773 in Apache HTTP Server 2.4.49 and 2.4.50 still permits path traversal, file disclosure, and remote code execution via encoded traversal sequences.",
	},
	{
		techAliases:  []string{"php"},
		cveID:        "CVE-2022-31625",
		techName:     "PHP",
		affected:     lessThan("7.4.33"),
		fixedVersion: "7.4.33",
		severity:     checks.SeverityHigh,
		description:  "PHP versions before 7.4.33 are end-of-life and affected by numerous known vulnerabilities (for example an uninitialized-memory / use-after-free issue in the PostgreSQL extension, CVE-2022-31625) with no further security support.",
	},
	{
		techAliases:  []string{"wordpress"},
		cveID:        "CVE-2022-21661",
		techName:     "WordPress",
		affected:     lessThan("5.8.3"),
		fixedVersion: "5.8.3",
		severity:     checks.SeverityHigh,
		description:  "A SQL injection vulnerability via the WP_Query class in WordPress before 5.8.3 allows authenticated attackers, or plugins/themes passing untrusted input to WP_Query, to inject SQL and extract data from the database.",
	},
	{
		techAliases:  []string{"openssl"},
		cveID:        "CVE-2014-0160",
		techName:     "OpenSSL",
		affected:     inRange("1.0.1", "1.0.1g"),
		fixedVersion: "1.0.1g",
		severity:     checks.SeverityCritical,
		description:  "The Heartbleed bug in the OpenSSL TLS heartbeat extension (1.0.1 through 1.0.1f) allows a remote attacker to read up to 64KB of process memory per request, exposing private keys, session tokens, and other secrets.",
	},
	{
		techAliases:  []string{"jquery"},
		disqualify:   []string{"ui", "mobile"},
		cveID:        "CVE-2020-11022",
		techName:     "jQuery",
		affected:     lessThan("3.5.0"),
		fixedVersion: "3.5.0",
		severity:     checks.SeverityMedium,
		description:  "In jQuery before 3.5.0, passing HTML from untrusted sources to DOM-manipulation methods such as .html(), .append(), or jQuery() could execute untrusted code (cross-site scripting) even after sanitization.",
	},
}

// techTokens splits a tech name into lowercase alphanumeric tokens, breaking on
// any non-alphanumeric separator. "Apache httpd" -> ["apache","httpd"];
// "PHP/7.4" -> ["php","7","4"]; "phpMyAdmin" -> ["phpmyadmin"] (no separator, so
// it stays a single token and does NOT match the "php" alias).
func techTokens(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
}

// matchesTech reports whether a Detection's tech name maps to an entry.
// Matching is case-insensitive and token-based, not raw substring: an alias
// must equal a whole token of the tech name. This keeps the flexible mapping
// the fingerprint stage relies on ("Apache", "Apache httpd", "httpd" all map to
// the httpd entries) while avoiding false positives where a shorter alias is a
// substring of an unrelated product ("php" inside "phpMyAdmin"). A match is
// additionally vetoed when any disqualify token is present, which separates
// distinct products that merely share a word ("Apache Tomcat" vs Apache HTTP
// Server, "jQuery UI" vs jQuery core).
func matchesTech(detTech string, aliases, disqualify []string) bool {
	tokens := techTokens(detTech)
	if len(tokens) == 0 {
		return false
	}
	for _, tok := range tokens {
		for _, bad := range disqualify {
			if tok == bad {
				return false
			}
		}
	}
	for _, alias := range aliases {
		for _, tok := range tokens {
			if tok == alias {
				return true
			}
		}
	}
	return false
}

// Analyze inspects the detected technologies and returns a Finding for each
// Detection whose technology and version match a known CVE in the built-in
// table. Detections with an empty version are skipped (no guessing). No
// network requests are made.
func Analyze(dets []checks.Detection) []checks.Finding {
	var findings []checks.Finding
	now := time.Now()

	for _, det := range dets {
		if strings.TrimSpace(det.Version) == "" {
			continue
		}
		v, ok := parseVersion(det.Version)
		if !ok {
			continue
		}
		for _, e := range table {
			if !matchesTech(det.Tech, e.techAliases, e.disqualify) {
				continue
			}
			if !e.affected(v) {
				continue
			}
			findings = append(findings, checks.Finding{
				Type:        "cve",
				Severity:    e.severity,
				Title:       fmt.Sprintf("Potential %s in %s %s", e.cveID, e.techName, det.Version),
				URL:         det.URL,
				Parameter:   "",
				Payload:     "",
				Evidence:    checks.Truncate(fmt.Sprintf("%s %s detected", det.Tech, det.Version), 240),
				Description: e.description,
				Remediation: fmt.Sprintf("Upgrade to >= %s.", e.fixedVersion),
				Confidence:  "tentative",
				Timestamp:   now,
			})
		}
	}
	return findings
}
