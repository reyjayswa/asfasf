package cve

import (
	"testing"

	"github.com/reyjayswa/asfasf/internal/checks"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want version
		ok   bool
	}{
		{"1.21.0", version{1, 21, 0}, true},
		{"2.4.49", version{2, 4, 49}, true},
		{"v3.5.0", version{3, 5, 0}, true},
		{"3.5.0-beta", version{3, 5, 0}, true},
		{"1.0.1f", version{1, 0, 1, 6}, true}, // release letter f -> extra component
		{"1.0.1", version{1, 0, 1}, true},
		{"", nil, false},
		{"abc", nil, false},
	}
	for _, c := range cases {
		got, ok := parseVersion(c.in)
		if ok != c.ok {
			t.Fatalf("parseVersion(%q) ok=%v want %v", c.in, ok, c.ok)
		}
		if !ok {
			continue
		}
		if compare(got, c.want) != 0 {
			t.Fatalf("parseVersion(%q) = %v want %v", c.in, got, c.want)
		}
	}
}

func TestCompare(t *testing.T) {
	mk := func(s string) version { v, _ := parseVersion(s); return v }
	cases := []struct {
		a, b string
		want int
	}{
		{"1.21", "1.21.0", 0},
		{"1.20.9", "1.21.0", -1},
		{"1.21.1", "1.21.0", 1},
		{"2.4.50", "2.4.49", 1},
		{"1.0.1", "1.0.1g", -1},  // base release precedes lettered release
		{"1.0.1f", "1.0.1g", -1}, // f < g
		{"1.0.1g", "1.0.1f", 1},
	}
	for _, c := range cases {
		got := compare(mk(c.a), mk(c.b))
		if got != c.want {
			t.Fatalf("compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestRules(t *testing.T) {
	mk := func(s string) version { v, _ := parseVersion(s); return v }

	lt := lessThan("1.21.0")
	if !lt(mk("1.20.0")) {
		t.Error("lessThan: 1.20.0 should be affected")
	}
	if lt(mk("1.21.0")) {
		t.Error("lessThan: 1.21.0 should NOT be affected")
	}

	rg := inRange("1.0.1", "1.0.1g")
	if !rg(mk("1.0.1")) {
		t.Error("inRange: 1.0.1 should be affected")
	}
	// 1.0.1g parses to 1.0.1 which is >= lo but not < hi (equal) -> excluded.
	if rg(mk("1.0.2")) {
		t.Error("inRange: 1.0.2 should NOT be affected")
	}

	es := exactSet("2.4.49", "2.4.50")
	if !es(mk("2.4.49")) || !es(mk("2.4.50")) {
		t.Error("exactSet: 2.4.49/2.4.50 should be affected")
	}
	if es(mk("2.4.51")) {
		t.Error("exactSet: 2.4.51 should NOT be affected")
	}
}

func findByCVE(fs []checks.Finding, cveID string) *checks.Finding {
	for i := range fs {
		if containsCVE(fs[i].Title, cveID) {
			return &fs[i]
		}
	}
	return nil
}

func containsCVE(title, cveID string) bool {
	return len(title) > 0 && len(cveID) > 0 && indexOf(title, cveID) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestAnalyzePositiveMatches(t *testing.T) {
	dets := []checks.Detection{
		{Tech: "Apache httpd", Version: "2.4.49", URL: "http://127.0.0.1/"},
		{Tech: "nginx", Version: "1.20.0", URL: "http://127.0.0.1/"},
		{Tech: "jQuery", Version: "3.4.1", URL: "http://127.0.0.1/app.js"},
	}
	fs := Analyze(dets)

	// Apache 2.4.49 hits BOTH CVE-2021-41773 and CVE-2021-42013.
	if f := findByCVE(fs, "CVE-2021-41773"); f == nil {
		t.Error("expected CVE-2021-41773 for Apache 2.4.49")
	} else {
		if f.Severity != checks.SeverityCritical {
			t.Errorf("CVE-2021-41773 severity = %q want critical", f.Severity)
		}
		if f.Confidence != "tentative" {
			t.Errorf("confidence = %q want tentative", f.Confidence)
		}
		if f.Type != "cve" {
			t.Errorf("type = %q want cve", f.Type)
		}
		if f.URL != "http://127.0.0.1/" {
			t.Errorf("url = %q", f.URL)
		}
		if f.Timestamp.IsZero() {
			t.Error("timestamp not set")
		}
		if f.Remediation == "" || f.Description == "" {
			t.Error("remediation/description must be set")
		}
	}
	if findByCVE(fs, "CVE-2021-42013") == nil {
		t.Error("expected CVE-2021-42013 for Apache 2.4.49")
	}

	// nginx 1.20.0 < 1.21.0 -> CVE-2021-23017
	if f := findByCVE(fs, "CVE-2021-23017"); f == nil {
		t.Error("expected CVE-2021-23017 for nginx 1.20.0")
	} else if f.Severity != checks.SeverityHigh {
		t.Errorf("nginx severity = %q want high", f.Severity)
	}

	// jQuery 3.4.1 < 3.5.0 -> CVE-2020-11022
	if findByCVE(fs, "CVE-2020-11022") == nil {
		t.Error("expected CVE-2020-11022 for jQuery 3.4.1")
	}
}

func TestAnalyzeHeartbleed(t *testing.T) {
	dets := []checks.Detection{
		{Tech: "OpenSSL", Version: "1.0.1", URL: "http://127.0.0.1/"},
	}
	fs := Analyze(dets)
	if findByCVE(fs, "CVE-2014-0160") == nil {
		t.Error("expected Heartbleed CVE-2014-0160 for OpenSSL 1.0.1")
	}
}

func TestAnalyzeNonMatches(t *testing.T) {
	dets := []checks.Detection{
		// Patched versions -> no finding.
		{Tech: "nginx", Version: "1.21.0", URL: "http://127.0.0.1/"},
		{Tech: "Apache", Version: "2.4.51", URL: "http://127.0.0.1/"},
		// Unknown tech.
		{Tech: "SomeCustomServer", Version: "1.0.0", URL: "http://127.0.0.1/"},
		// Empty version must be skipped (no guessing).
		{Tech: "nginx", Version: "", URL: "http://127.0.0.1/"},
		{Tech: "WordPress", Version: "", URL: "http://127.0.0.1/"},
	}
	fs := Analyze(dets)
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings for clean/patched/empty input, got %d: %+v", len(fs), fs)
	}
}

func TestAnalyzeEmptyInput(t *testing.T) {
	if fs := Analyze(nil); len(fs) != 0 {
		t.Fatalf("nil input should yield 0 findings, got %d", len(fs))
	}
}

// TestMatchesTech verifies token-based matching: aliases match whole tokens
// (so "Apache httpd"/"httpd" map to the httpd entries) but a shorter alias
// that is only a substring of an unrelated product name must NOT match.
func TestMatchesTech(t *testing.T) {
	apacheDQ := []string{"tomcat", "kafka", "solr", "spark", "camel"}
	jqueryDQ := []string{"ui", "mobile"}
	cases := []struct {
		tech       string
		aliases    []string
		disqualify []string
		want       bool
	}{
		{"Apache", []string{"apache", "httpd"}, apacheDQ, true},
		{"Apache httpd", []string{"apache", "httpd"}, apacheDQ, true},
		{"httpd", []string{"apache", "httpd"}, apacheDQ, true},
		{"PHP", []string{"php"}, nil, true},
		{"PHP/7.4.10", []string{"php"}, nil, true},
		// False-positive guards.
		{"phpMyAdmin", []string{"php"}, nil, false},                     // substring-only, not a token
		{"Apache Tomcat", []string{"apache", "httpd"}, apacheDQ, false}, // disqualified
		{"Apache Kafka", []string{"apache", "httpd"}, apacheDQ, false},  // disqualified
		{"jquery-ui", []string{"jquery"}, jqueryDQ, false},              // disqualified
		{"jQuery Mobile", []string{"jquery"}, jqueryDQ, false},          // disqualified
		{"jQuery", []string{"jquery"}, jqueryDQ, true},
		{"", []string{"php"}, nil, false},
	}
	for _, c := range cases {
		if got := matchesTech(c.tech, c.aliases, c.disqualify); got != c.want {
			t.Errorf("matchesTech(%q,%v)=%v want %v", c.tech, c.aliases, got, c.want)
		}
	}
}

// TestAnalyzeNoSubstringFalsePositive ensures unrelated products whose names
// merely contain a CVE alias as a substring are not flagged, even with a low
// version that would satisfy the alias's version rule.
func TestAnalyzeNoSubstringFalsePositive(t *testing.T) {
	dets := []checks.Detection{
		// 5.2.0 < 7.4.33, but phpMyAdmin is not PHP -> must NOT flag PHP CVE.
		{Tech: "phpMyAdmin", Version: "5.2.0", URL: "http://127.0.0.1/pma/"},
		// Tomcat is not httpd; even the exact 2.4.49 version must not map.
		{Tech: "Apache Tomcat", Version: "2.4.49", URL: "http://127.0.0.1/"},
		// jQuery UI 1.13.0 < 3.5.0 but is a distinct library -> no jQuery CVE.
		{Tech: "jQuery UI", Version: "1.13.0", URL: "http://127.0.0.1/ui.js"},
	}
	if fs := Analyze(dets); len(fs) != 0 {
		t.Fatalf("expected 0 findings for unrelated products, got %d: %+v", len(fs), fs)
	}
}
