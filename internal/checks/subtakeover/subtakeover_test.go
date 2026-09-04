package subtakeover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/httpclient"
	"github.com/reyjayswa/asfasf/internal/scope"
)

func newClient(t *testing.T) *httpclient.Client {
	t.Helper()
	sc, err := scope.New(config.Scope{InScope: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return httpclient.New(config.HTTP{RatePerSecond: 500, Concurrency: 4, TimeoutSeconds: 10}, sc)
}

// takeover body served independently of DNS: the checker cannot control real
// CNAMEs in a unit test, so the body-only path must yield a tentative finding.
func TestRun_DetectsTakeoverBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>There isn't a GitHub Pages site here.</body></html>"))
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	findings := c.Run(context.Background(), srv.URL)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Type != "subdomain-takeover" {
		t.Errorf("Type = %q", f.Type)
	}
	// No real CNAME to github.io from 127.0.0.1, so this must be tentative.
	if f.Confidence != "tentative" {
		t.Errorf("Confidence = %q, want tentative", f.Confidence)
	}
	if f.Severity != "medium" {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
	if f.Evidence == "" {
		t.Errorf("Evidence empty")
	}
	if f.Timestamp.IsZero() {
		t.Errorf("Timestamp not set")
	}
}

func TestRun_CleanServerNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Welcome to my real site. Nothing to see here.</body></html>"))
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	findings := c.Run(context.Background(), srv.URL)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on clean server, got %d: %+v", len(findings), findings)
	}
}

// A 200-returning SPA catch-all must not trip the check without a real
// provider signature.
func TestRun_SPACatchAllNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!doctype html><div id=\"app\"></div><script src=/main.js></script>"))
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	if got := c.Run(context.Background(), srv.URL); len(got) != 0 {
		t.Fatalf("SPA catch-all produced findings: %+v", got)
	}
}

func TestName(t *testing.T) {
	if got := New(nil, false).Name(); got != "subdomain-takeover" {
		t.Errorf("Name() = %q", got)
	}
}

func TestHostFromOrigin(t *testing.T) {
	cases := map[string]string{
		"https://sub.example.com:8443/path?q=1": "sub.example.com",
		"http://user@Example.COM":               "example.com",
		"http://[::1]:9000/x":                   "::1",
		"example.org":                           "example.org",
	}
	for in, want := range cases {
		if got := hostFromOrigin(in); got != want {
			t.Errorf("hostFromOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}
