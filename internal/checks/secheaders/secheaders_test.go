package secheaders

import (
	"net/http"
	"testing"

	"github.com/reyjayswa/asfasf/internal/crawler"
)

func TestAnalyze_FlagsMissingHeaders(t *testing.T) {
	// An HTTPS page with no security headers at all.
	h := http.Header{}
	pages := []crawler.Page{
		{URL: "https://vuln.example.com/", Status: 200, Header: h},
	}
	fs := Analyze(pages)
	if len(fs) == 0 {
		t.Fatalf("expected findings for a page missing all security headers, got 0")
	}
	want := map[string]bool{
		"Missing Content-Security-Policy header":                              false,
		"Missing Strict-Transport-Security header":                            false,
		"Missing X-Content-Type-Options: nosniff header":                      false,
		"Missing clickjacking protection (X-Frame-Options / frame-ancestors)": false,
		"Missing Referrer-Policy header":                                      false,
		"Missing Permissions-Policy header":                                   false,
	}
	for _, f := range fs {
		if _, ok := want[f.Title]; ok {
			want[f.Title] = true
		}
		if f.Confidence != "firm" {
			t.Errorf("expected firm confidence, got %q", f.Confidence)
		}
		if f.URL != "https://vuln.example.com" {
			t.Errorf("expected origin URL, got %q", f.URL)
		}
	}
	for title, found := range want {
		if !found {
			t.Errorf("expected a finding for %q, missing", title)
		}
	}
}

func TestAnalyze_DedupPerOrigin(t *testing.T) {
	h := http.Header{}
	pages := []crawler.Page{
		{URL: "https://vuln.example.com/a", Status: 200, Header: h},
		{URL: "https://vuln.example.com/b", Status: 200, Header: h},
	}
	fs := Analyze(pages)
	// Two pages, same origin -> should produce the same count as one page (6).
	if len(fs) != 6 {
		t.Fatalf("expected 6 deduped findings for one origin, got %d", len(fs))
	}
}

func TestAnalyze_CleanNoFindings(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "geolocation=(), camera=()")
	pages := []crawler.Page{
		{URL: "https://secure.example.com/", Status: 200, Header: h},
	}
	fs := Analyze(pages)
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings for a fully hardened page, got %d: %+v", len(fs), fs)
	}
}

func TestAnalyze_HTTPSkipsHSTS(t *testing.T) {
	// Plain HTTP page missing HSTS should NOT flag HSTS (only applies to https).
	h := http.Header{}
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "geolocation=()")
	pages := []crawler.Page{
		{URL: "http://plain.example.com/", Status: 200, Header: h},
	}
	fs := Analyze(pages)
	for _, f := range fs {
		if f.Title == "Missing Strict-Transport-Security header" {
			t.Fatalf("HSTS should not be flagged on an http page")
		}
	}
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings on hardened http page, got %d", len(fs))
	}
}

func TestAnalyze_SkipsStatusZero(t *testing.T) {
	pages := []crawler.Page{
		{URL: "https://never.example.com/", Status: 0, Header: http.Header{}},
	}
	fs := Analyze(pages)
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings for Status 0 page, got %d", len(fs))
	}
}
