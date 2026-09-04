package csrf

import "testing"

import "github.com/reyjayswa/asfasf/internal/checks"

func TestAnalyze_FindsFormWithoutToken(t *testing.T) {
	eps := []checks.Endpoint{
		{URL: "http://127.0.0.1/transfer", Method: "POST", Source: "form", Params: []string{"amount", "to_account"}},
	}
	got := Analyze(eps)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Type != "csrf" || f.Severity != checks.SeverityMedium || f.Confidence != "tentative" {
		t.Errorf("unexpected finding fields: %+v", f)
	}
	if f.CWE != "CWE-352" {
		t.Errorf("expected CWE-352, got %q", f.CWE)
	}
	if f.URL != "http://127.0.0.1/transfer" {
		t.Errorf("unexpected URL %q", f.URL)
	}
}

func TestAnalyze_CleanCases(t *testing.T) {
	eps := []checks.Endpoint{
		// POST form WITH a CSRF token param -> no finding.
		{URL: "http://127.0.0.1/a", Method: "POST", Source: "form", Params: []string{"user", "csrf_token"}},
		{URL: "http://127.0.0.1/b", Method: "POST", Source: "form", Params: []string{"x", "__RequestVerificationToken"}},
		{URL: "http://127.0.0.1/c", Method: "POST", Source: "form", Params: []string{"nonce", "data"}},
		// GET form -> ignored.
		{URL: "http://127.0.0.1/d", Method: "GET", Source: "form", Params: []string{"q"}},
		// POST but not a form (query) -> ignored.
		{URL: "http://127.0.0.1/e", Method: "POST", Source: "query", Params: []string{"id"}},
		// link source -> ignored.
		{URL: "http://127.0.0.1/f", Method: "POST", Source: "link", Params: []string{"a"}},
	}
	got := Analyze(eps)
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(got), got)
	}
}
