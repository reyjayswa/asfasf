package openredirect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/reyjayswa/asfasf/internal/checks"
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

// Vulnerable server: echoes the "next" parameter straight into a 302 Location.
func TestRun_LocationHeaderRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		w.Header().Set("Location", next)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	ep := checks.Endpoint{URL: srv.URL + "/login", Method: http.MethodGet, Params: []string{"next"}, Source: "query"}
	findings := c.Run(context.Background(), ep)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Type != "open-redirect" {
		t.Errorf("Type = %q", f.Type)
	}
	if f.Severity != checks.SeverityMedium {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
	if f.Confidence != "firm" {
		t.Errorf("Confidence = %q, want firm", f.Confidence)
	}
	if f.Parameter != "next" {
		t.Errorf("Parameter = %q", f.Parameter)
	}
	if f.CWE != "CWE-601" {
		t.Errorf("CWE = %q", f.CWE)
	}
	if f.Evidence == "" {
		t.Errorf("Evidence empty")
	}
	if f.Timestamp.IsZero() {
		t.Errorf("Timestamp not set")
	}
}

// Vulnerable server: reflects the target into a client-side meta refresh.
func TestRun_BodyMetaRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		to := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><meta http-equiv="refresh" content="0;url=` + to + `"></head></html>`))
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	ep := checks.Endpoint{URL: srv.URL + "/go", Method: http.MethodGet, Params: []string{"url"}, Source: "query"}
	findings := c.Run(context.Background(), ep)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != "tentative" {
		t.Errorf("Confidence = %q, want tentative", findings[0].Confidence)
	}
}

// POST form target that redirects: exercises the PostForm path.
func TestRun_PostFormRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Location", r.PostFormValue("return_to"))
		w.WriteHeader(http.StatusSeeOther)
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	ep := checks.Endpoint{URL: srv.URL + "/submit", Method: http.MethodPost, Params: []string{"return_to"}, Source: "form"}
	findings := c.Run(context.Background(), ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != "firm" {
		t.Errorf("Confidence = %q, want firm", findings[0].Confidence)
	}
}

// Clean server: redirects only to its own host regardless of input. Must not flag.
func TestRun_SafeInternalRedirectNoFindings(t *testing.T) {
	var self string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignore user input; always redirect to a fixed internal path.
		w.Header().Set("Location", self+"/dashboard")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	self = srv.URL

	c := New(newClient(t), false)
	ep := checks.Endpoint{URL: srv.URL + "/login", Method: http.MethodGet, Params: []string{"next"}, Source: "query"}
	if got := c.Run(context.Background(), ep); len(got) != 0 {
		t.Fatalf("expected 0 findings on safe internal redirect, got %d: %+v", len(got), got)
	}
}

// Clean server: 200 that reflects input as plain text, no redirect mechanism.
func TestRun_ReflectNoRedirectNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("You searched for: " + r.URL.Query().Get("q")))
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	ep := checks.Endpoint{URL: srv.URL + "/search", Method: http.MethodGet, Params: []string{"q"}, Source: "query"}
	if got := c.Run(context.Background(), ep); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(got), got)
	}
}

func TestName(t *testing.T) {
	if got := New(nil, false).Name(); got != "open-redirect" {
		t.Errorf("Name() = %q", got)
	}
}

func TestAggressiveAddsPayload(t *testing.T) {
	if len(New(nil, true).payloads()) <= len(New(nil, false).payloads()) {
		t.Errorf("aggressive should add payloads")
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://openredir-canary.example/":            "openredir-canary.example",
		"//openredir-canary.example/path":              "openredir-canary.example",
		"https:/\\/\\openredir-canary.example":         "openredir-canary.example",
		"/\\openredir-canary.example":                  "openredir-canary.example",
		"https://user@openredir-canary.example:8443/x": "openredir-canary.example",
		"/relative/path":                               "",
		"https://self.example/dashboard":               "self.example",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// Ensure the checker's own payload strings all resolve to the canary host,
// so a server that echoes any of them is detected.
func TestPayloadsResolveToCanary(t *testing.T) {
	for _, p := range New(nil, true).payloads() {
		if hostOf(p) != canaryHost {
			t.Errorf("payload %q resolves to host %q, want %q", p, hostOf(p), canaryHost)
		}
		// sanity: payload should URL-encode without altering scheme detection
		_ = url.QueryEscape(p)
	}
}
