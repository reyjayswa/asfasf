package scope

import (
	"testing"

	"github.com/reyjayswa/asfasf/internal/config"
)

func mustMatcher(t *testing.T, in, out []string) *Matcher {
	t.Helper()
	m, err := New(config.Scope{InScope: in, OutOfScope: out})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestExactAndWildcard(t *testing.T) {
	m := mustMatcher(t, []string{"example.com", "*.example.com"}, nil)
	cases := map[string]bool{
		"https://example.com/":         true,
		"https://api.example.com/x":    true,
		"https://a.b.example.com/":     true,
		"https://example.com:8443/":    true, // port ignored
		"https://notexample.com/":      false,
		"https://example.com.evil.com": false,
		"https://evil.com/":            false,
	}
	for url, want := range cases {
		if got := m.AllowsURL(url); got != want {
			t.Errorf("AllowsURL(%q)=%v want %v", url, got, want)
		}
	}
}

func TestWildcardExcludesApex(t *testing.T) {
	m := mustMatcher(t, []string{"*.example.com"}, nil)
	if m.AllowsURL("https://example.com/") {
		t.Error("wildcard should not match the apex domain")
	}
	if !m.AllowsURL("https://www.example.com/") {
		t.Error("wildcard should match a subdomain")
	}
}

func TestOutOfScopeWins(t *testing.T) {
	m := mustMatcher(t, []string{"*.example.com"}, []string{"admin.example.com"})
	if m.AllowsURL("https://admin.example.com/") {
		t.Error("out_of_scope host must be blocked even when in_scope matches")
	}
	if !m.AllowsURL("https://app.example.com/") {
		t.Error("non-excluded subdomain should be allowed")
	}
}

func TestMalformedIsBlocked(t *testing.T) {
	m := mustMatcher(t, []string{"example.com"}, nil)
	for _, u := range []string{"", "not a url", "ftp://example.com", "://x"} {
		if m.AllowsURL(u) {
			t.Errorf("AllowsURL(%q) should be false", u)
		}
	}
}
