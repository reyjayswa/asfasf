package cors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

// reflectServer echoes the request Origin into ACAO and, if withCreds is set,
// adds ACAC: true.
func reflectServer(withCreds bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			if withCreds {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
}

func TestReflectedOriginWithCredentials_High(t *testing.T) {
	srv := reflectServer(true)
	defer srv.Close()

	c := New(newClient(t), false)
	findings := c.Run(context.Background(), srv.URL)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "high" {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.Confidence != "firm" {
		t.Errorf("confidence = %q, want firm", f.Confidence)
	}
	if f.CWE != "CWE-942" {
		t.Errorf("cwe = %q, want CWE-942", f.CWE)
	}
	if !strings.Contains(f.Evidence, evilOrigin) {
		t.Errorf("evidence missing evil origin: %q", f.Evidence)
	}
}

func TestReflectedOriginNoCredentials_Medium(t *testing.T) {
	srv := reflectServer(false)
	defer srv.Close()

	c := New(newClient(t), false)
	findings := c.Run(context.Background(), srv.URL)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("severity = %q, want medium", findings[0].Severity)
	}
}

func TestWildcardWithCredentials_High(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	findings := c.Run(context.Background(), srv.URL)
	if len(findings) != 1 || findings[0].Severity != "high" {
		t.Fatalf("expected 1 high finding, got %+v", findings)
	}
}

func TestWildcardOnly_Low(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	findings := c.Run(context.Background(), srv.URL)
	if len(findings) != 1 || findings[0].Severity != "low" {
		t.Fatalf("expected 1 low finding, got %+v", findings)
	}
}

func TestNullOriginAggressive_High(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only allow the null origin; do NOT reflect the evil origin, so the
		// finding must come from the aggressive null probe.
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Non-aggressive: no reflection of evil origin -> nothing.
	if fs := New(newClient(t), false).Run(context.Background(), srv.URL); len(fs) != 0 {
		t.Fatalf("non-aggressive expected 0 findings, got %+v", fs)
	}
	// Aggressive: null-origin misconfig flagged.
	fs := New(newClient(t), true).Run(context.Background(), srv.URL)
	if len(fs) != 1 || fs[0].Severity != "high" {
		t.Fatalf("aggressive expected 1 high finding, got %+v", fs)
	}
	if !strings.Contains(strings.ToLower(fs[0].Title), "null") {
		t.Errorf("title should mention null: %q", fs[0].Title)
	}
}

func TestCleanServer_NoFindings(t *testing.T) {
	// A well-behaved server that only allows a specific trusted origin and
	// never reflects the evil origin or wildcards.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "https://trusted.example" {
			w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	}))
	defer srv.Close()

	if fs := New(newClient(t), true).Run(context.Background(), srv.URL); len(fs) != 0 {
		t.Fatalf("clean server expected 0 findings, got %+v", fs)
	}
}

func TestName(t *testing.T) {
	if got := New(newClient(t), false).Name(); got != "cors" {
		t.Errorf("Name() = %q, want cors", got)
	}
}
