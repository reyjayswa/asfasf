package crlf

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

// vulnHandler emulates an application that writes a request parameter into a
// response header without stripping CR/LF. Go's net/url decodes the percent-
// encoded payload back into literal \r\n; the handler naively treats each
// subsequent line as an extra header, reproducing a header split.
func vulnHandler(paramFrom func(r *http.Request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := paramFrom(r)
		lines := strings.Split(raw, "\r\n")
		for _, line := range lines[1:] {
			if i := strings.Index(line, ": "); i >= 0 {
				w.Header().Add(line[:i], line[i+2:])
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

// GET target vulnerable via the query parameter.
func TestRun_HeaderSplitGET(t *testing.T) {
	srv := httptest.NewServer(vulnHandler(func(r *http.Request) string {
		return r.URL.Query().Get("q")
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	ep := checks.Endpoint{URL: srv.URL + "/page", Method: http.MethodGet, Params: []string{"q"}, Source: "query"}
	findings := c.Run(context.Background(), ep)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Type != "crlf-injection" {
		t.Errorf("Type = %q", f.Type)
	}
	if f.Severity != checks.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.Confidence != "firm" {
		t.Errorf("Confidence = %q, want firm", f.Confidence)
	}
	if f.Parameter != "q" {
		t.Errorf("Parameter = %q", f.Parameter)
	}
	if f.CWE != "CWE-113" {
		t.Errorf("CWE = %q", f.CWE)
	}
	if f.Evidence == "" {
		t.Errorf("Evidence empty")
	}
	if f.Timestamp.IsZero() {
		t.Errorf("Timestamp not set")
	}
}

// POST form target vulnerable via a posted parameter: exercises the PostForm path.
func TestRun_HeaderSplitPOST(t *testing.T) {
	srv := httptest.NewServer(vulnHandler(func(r *http.Request) string {
		_ = r.ParseForm()
		return r.PostFormValue("redir")
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	ep := checks.Endpoint{URL: srv.URL + "/submit", Method: http.MethodPost, Params: []string{"redir"}, Source: "form"}
	findings := c.Run(context.Background(), ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Parameter != "redir" {
		t.Errorf("Parameter = %q", findings[0].Parameter)
	}
}

// Aggressive mode: a server that only reflects a split Set-Cookie (not an
// arbitrary marker header) is still detected via the Set-Cookie token.
func TestRun_SetCookieInjectionAggressive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("q")
		lines := strings.Split(raw, "\r\n")
		for _, line := range lines[1:] {
			// Only honour an injected Set-Cookie, ignore other headers.
			if strings.HasPrefix(line, "Set-Cookie: ") {
				w.Header().Add("Set-Cookie", strings.TrimPrefix(line, "Set-Cookie: "))
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Non-aggressive must NOT find it (it only sends the marker-header payload).
	if got := New(newClient(t), false).Run(context.Background(),
		checks.Endpoint{URL: srv.URL + "/p", Method: http.MethodGet, Params: []string{"q"}, Source: "query"}); len(got) != 0 {
		t.Fatalf("non-aggressive expected 0 findings, got %d: %+v", len(got), got)
	}

	// Aggressive sends the Set-Cookie payload and detects the token.
	got := New(newClient(t), true).Run(context.Background(),
		checks.Endpoint{URL: srv.URL + "/p", Method: http.MethodGet, Params: []string{"q"}, Source: "query"})
	if len(got) != 1 {
		t.Fatalf("aggressive expected 1 finding, got %d: %+v", len(got), got)
	}
	if !strings.Contains(strings.ToLower(got[0].Evidence), "set-cookie") {
		t.Errorf("Evidence = %q, want Set-Cookie mention", got[0].Evidence)
	}
}

// Clean server: reflects the parameter only into the body, never into a header.
// Must produce zero findings.
func TestRun_CleanNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		// Echo the raw value in the body; CR/LF in the body do not split headers.
		_, _ = w.Write([]byte("You said: " + r.URL.Query().Get("q")))
	}))
	defer srv.Close()

	c := New(newClient(t), true)
	ep := checks.Endpoint{URL: srv.URL + "/echo", Method: http.MethodGet, Params: []string{"q"}, Source: "query"}
	if got := c.Run(context.Background(), ep); len(got) != 0 {
		t.Fatalf("expected 0 findings on clean server, got %d: %+v", len(got), got)
	}
}

func TestName(t *testing.T) {
	if got := New(nil, false).Name(); got != "crlf-injection" {
		t.Errorf("Name() = %q", got)
	}
}

func TestAggressiveAddsInjection(t *testing.T) {
	if len(New(nil, true).injections()) <= len(New(nil, false).injections()) {
		t.Errorf("aggressive should add an injection")
	}
}
