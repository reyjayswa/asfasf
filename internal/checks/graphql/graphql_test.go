package graphql

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

// introspectionResponse is a realistic successful introspection reply.
const introspectionResponse = `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`

func TestRunFindsIntrospection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(introspectionResponse))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	findings := c.Run(context.Background(), srv.URL)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Type != "graphql" {
		t.Errorf("Type = %q, want graphql", f.Type)
	}
	if f.Severity != "medium" {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
	if f.Confidence != "firm" {
		t.Errorf("Confidence = %q, want firm", f.Confidence)
	}
	if f.CWE != "CWE-200" {
		t.Errorf("CWE = %q, want CWE-200", f.CWE)
	}
	if !strings.Contains(f.URL, "/graphql") {
		t.Errorf("URL = %q, want it to contain /graphql", f.URL)
	}
	if f.Title == "" || f.Description == "" || f.Remediation == "" {
		t.Errorf("missing required text fields: %+v", f)
	}
}

func TestRunErrorEndpointIsInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// GraphQL-shaped error, no schema echoed back.
			w.Write([]byte(`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	findings := c.Run(context.Background(), srv.URL)

	if len(findings) != 1 {
		t.Fatalf("expected 1 info finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "info" {
		t.Errorf("Severity = %q, want info", findings[0].Severity)
	}
}

func TestRunCleanNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No GraphQL anywhere: a plain app that returns 200 HTML on every path.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>hello world</body></html>"))
	}))
	defer srv.Close()

	c := New(newClient(t), true) // aggressive: probe every path, still nothing
	findings := c.Run(context.Background(), srv.URL)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on clean target, got %d: %+v", len(findings), findings)
	}
}
