package nosql

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

// vulnerable server: when the injected value contains a query-breaking
// character, it leaks a MongoDB driver error.
func TestRun_DetectsNoSQLError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("user")
		if strings.ContainsAny(v, "'\"[{") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"MongoServerError: E11000 duplicate key / unexpected token"}`))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	ep := checks.Endpoint{URL: srv.URL + "/api", Method: http.MethodGet, Params: []string{"user"}}
	findings := New(newClient(t), false).Run(context.Background(), ep)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Type != "nosql-injection" {
		t.Errorf("Type = %q, want nosql-injection", f.Type)
	}
	if f.Severity != checks.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.Confidence != "firm" {
		t.Errorf("Confidence = %q, want firm", f.Confidence)
	}
	if f.CWE != "CWE-943" {
		t.Errorf("CWE = %q, want CWE-943", f.CWE)
	}
	if f.Parameter != "user" {
		t.Errorf("Parameter = %q, want user", f.Parameter)
	}
	if f.Evidence == "" {
		t.Errorf("Evidence should not be empty")
	}
}

// constant-token server: the string "MongoDB" appears in every response
// (e.g. a "Powered by MongoDB" footer) regardless of input. Because the
// signature is present in the benign baseline too, it must NOT be flagged.
func TestRun_ConstantTokenNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>results<footer>Powered by MongoDB</footer></body></html>`))
	}))
	defer srv.Close()

	ep := checks.Endpoint{URL: srv.URL + "/api", Method: http.MethodGet, Params: []string{"user"}}
	findings := New(newClient(t), true).Run(context.Background(), ep)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for constant token, got %d: %+v", len(findings), findings)
	}
}

// clean server: never leaks any NoSQL error signature.
func TestRun_CleanNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echoes input but with no database error signatures.
		w.Write([]byte(`{"result":"no records found","query":"` + r.URL.Query().Get("user") + `"}`))
	}))
	defer srv.Close()

	ep := checks.Endpoint{URL: srv.URL + "/api", Method: http.MethodGet, Params: []string{"user"}}
	findings := New(newClient(t), true).Run(context.Background(), ep)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}
