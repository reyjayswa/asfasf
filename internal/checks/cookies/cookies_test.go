package cookies

import (
	"net/http"
	"testing"

	"github.com/reyjayswa/asfasf/internal/crawler"
)

func hdr(values ...string) http.Header {
	h := http.Header{}
	for _, v := range values {
		h.Add("Set-Cookie", v)
	}
	return h
}

func TestAnalyze_FindsInsecureCookies(t *testing.T) {
	pages := []crawler.Page{
		{
			URL:    "https://127.0.0.1/app",
			Status: 200,
			// session cookie missing HttpOnly (Medium), Secure (Medium), SameSite (Low)
			Header: hdr("SESSIONID=abc123; Path=/"),
		},
	}

	findings := Analyze(pages)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "medium" {
		t.Errorf("expected medium severity for session cookie missing HttpOnly/Secure, got %q", f.Severity)
	}
	if f.Parameter != "SESSIONID" {
		t.Errorf("expected parameter SESSIONID, got %q", f.Parameter)
	}
	if f.Confidence != "firm" {
		t.Errorf("expected firm confidence, got %q", f.Confidence)
	}
}

func TestAnalyze_DedupByOriginAndName(t *testing.T) {
	pages := []crawler.Page{
		{URL: "https://127.0.0.1/a", Header: hdr("foo=1; Path=/")},
		{URL: "https://127.0.0.1/b", Header: hdr("foo=1; Path=/")},
	}
	findings := Analyze(pages)
	if len(findings) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(findings))
	}
}

func TestAnalyze_CleanNoFindings(t *testing.T) {
	pages := []crawler.Page{
		{
			URL:    "https://127.0.0.1/secure",
			Status: 200,
			Header: hdr("SESSIONID=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"),
		},
		{
			// no Set-Cookie headers at all
			URL:    "https://127.0.0.1/plain",
			Status: 200,
			Header: http.Header{"Content-Type": []string{"text/html"}},
		},
	}
	findings := Analyze(pages)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for fully-attributed cookie, got %d: %+v", len(findings), findings)
	}
}

func TestAnalyze_HTTPOriginDoesNotFlagSecure(t *testing.T) {
	// On plain http, missing Secure should NOT be flagged; only SameSite (Low)
	// is missing here since HttpOnly is present and name is non-session.
	pages := []crawler.Page{
		{URL: "http://127.0.0.1/x", Header: hdr("pref=dark; Path=/; HttpOnly")},
	}
	findings := Analyze(pages)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "low" {
		t.Errorf("expected low severity (only SameSite missing), got %q", findings[0].Severity)
	}
}
