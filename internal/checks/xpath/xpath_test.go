package xpath

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// Vulnerable server: any single-quote in "user" breaks the XPath query and
// leaks a PHP libxml-style error signature.
func TestRun_XPathErrorLeaked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("user")
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			u = r.PostFormValue("user")
		}
		if containsQuote(u) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Warning: xpath(): Invalid expression in /var/www/login.php on line 42\nSimpleXMLElement::xpath(): Invalid predicate"))
			return
		}
		_, _ = w.Write([]byte("<html>welcome</html>"))
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	ep := checks.Endpoint{URL: srv.URL + "/login", Method: http.MethodGet, Params: []string{"user"}, Source: "query"}
	findings := c.Run(context.Background(), ep)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Type != "xpath-injection" {
		t.Errorf("Type = %q", f.Type)
	}
	if f.Severity != checks.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.Confidence != "firm" {
		t.Errorf("Confidence = %q, want firm", f.Confidence)
	}
	if f.Parameter != "user" {
		t.Errorf("Parameter = %q", f.Parameter)
	}
	if f.CWE != "CWE-643" {
		t.Errorf("CWE = %q, want CWE-643", f.CWE)
	}
	if f.Evidence == "" {
		t.Errorf("Evidence empty")
	}
	if f.Timestamp.IsZero() {
		t.Errorf("Timestamp zero")
	}
}

// Clean server: reflects input but never emits an XPath error signature, so
// there must be zero findings even though every request returns 200.
func TestRun_CleanNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("user")
		_, _ = w.Write([]byte("<html>hello " + u + "</html>"))
	}))
	defer srv.Close()

	c := New(newClient(t), true)
	ep := checks.Endpoint{URL: srv.URL + "/login", Method: http.MethodGet, Params: []string{"user"}, Source: "query"}
	findings := c.Run(context.Background(), ep)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func containsQuote(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' || s[i] == '"' {
			return true
		}
	}
	return false
}
