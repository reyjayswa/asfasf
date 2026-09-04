// Package enrich annotates findings with a CWE id, an OWASP Top 10 (2021)
// category, and an indicative 0-10 severity score, based on the finding type.
// Checks may set these directly; enrich only fills fields left empty, so a
// check with a more specific CWE (e.g. from a CVE) is never overwritten.
//
// The score is a simple severity-derived indicator for sorting and reporting,
// not a computed CVSS vector.
package enrich

import "github.com/reyjayswa/asfasf/internal/checks"

type meta struct {
	cwe   string
	owasp string
}

// table maps a finding Type to its default classification.
var table = map[string]meta{
	"xss":                {"CWE-79", "A03:2021-Injection"},
	"dom-xss":            {"CWE-79", "A03:2021-Injection"},
	"sqli":               {"CWE-89", "A03:2021-Injection"},
	"sql-dumper":         {"CWE-89", "A03:2021-Injection"},
	"command-injection":  {"CWE-78", "A03:2021-Injection"},
	"ssti":               {"CWE-1336", "A03:2021-Injection"},
	"path-traversal":     {"CWE-22", "A01:2021-Broken Access Control"},
	"open-redirect":      {"CWE-601", "A01:2021-Broken Access Control"},
	"csrf":               {"CWE-352", "A01:2021-Broken Access Control"},
	"cors":               {"CWE-942", "A05:2021-Security Misconfiguration"},
	"secheaders":         {"CWE-693", "A05:2021-Security Misconfiguration"},
	"insecure-cookie":    {"CWE-614", "A05:2021-Security Misconfiguration"},
	"config-exposure":    {"CWE-538", "A05:2021-Security Misconfiguration"},
	"admin-panel":        {"CWE-668", "A05:2021-Security Misconfiguration"},
	"subdomain-takeover": {"CWE-284", "A05:2021-Security Misconfiguration"},
	"shell-exposure":     {"CWE-506", "A08:2021-Software and Data Integrity Failures"},
	"cve":                {"", "A06:2021-Vulnerable and Outdated Components"},
	"cms-fingerprint":    {"", "A06:2021-Vulnerable and Outdated Components"},
	"fingerprint":        {"", "A06:2021-Vulnerable and Outdated Components"},
	"recon":              {"", ""},
}

// scoreFor returns the indicative score for a severity.
func scoreFor(s checks.Severity) float64 {
	switch s {
	case checks.SeverityCritical:
		return 9.5
	case checks.SeverityHigh:
		return 8.0
	case checks.SeverityMedium:
		return 5.5
	case checks.SeverityLow:
		return 3.0
	default:
		return 1.0
	}
}

// Apply fills empty CWE/OWASP/Score fields on each finding in place.
func Apply(findings []checks.Finding) {
	for i := range findings {
		m := table[findings[i].Type]
		if findings[i].CWE == "" {
			findings[i].CWE = m.cwe
		}
		if findings[i].OWASP == "" {
			findings[i].OWASP = m.owasp
		}
		if findings[i].Score == 0 {
			findings[i].Score = scoreFor(findings[i].Severity)
		}
	}
}
