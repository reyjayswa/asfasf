package ssti

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

// vulnerable engine: when the "name" parameter contains a "1337*1337"
// arithmetic expression it evaluates it, emitting the product 1787569
// (and NOT the raw expression) into the rendered page.
func vulnHandler(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	v := r.FormValue("name")
	rendered := v
	if strings.Contains(v, "1337*1337") || strings.Contains(v, "1337*'1337'") {
		rendered = "1787569"
	}
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte("<html><body>Hello " + rendered + "</body></html>"))
}

func TestRun_DetectsSSTI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(vulnHandler))
	defer srv.Close()

	c := New(newClient(t), false)
	ep := checks.Endpoint{URL: srv.URL + "/", Method: http.MethodGet, Params: []string{"name"}, Source: "query"}
	findings := c.Run(context.Background(), ep)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Type != "ssti" {
		t.Errorf("Type = %q, want ssti", f.Type)
	}
	if f.Severity != checks.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.Confidence != "firm" {
		t.Errorf("Confidence = %q, want firm", f.Confidence)
	}
	if f.Parameter != "name" {
		t.Errorf("Parameter = %q, want name", f.Parameter)
	}
	if !strings.Contains(f.Evidence, "1787569") {
		t.Errorf("Evidence missing product: %q", f.Evidence)
	}
}

// reflecting-only endpoint: echoes input verbatim without evaluating it, so
// the raw expression is present and the product never appears on its own.
func reflectHandler(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte("<html><body>Hello " + r.FormValue("name") + "</body></html>"))
}

func TestRun_CleanReflectionNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(reflectHandler))
	defer srv.Close()

	c := New(newClient(t), true)
	ep := checks.Endpoint{URL: srv.URL + "/", Method: http.MethodGet, Params: []string{"name"}, Source: "query"}
	findings := c.Run(context.Background(), ep)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}
