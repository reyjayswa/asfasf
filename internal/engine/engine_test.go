package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/config"
)

// vulnServer returns a deliberately vulnerable test server:
//   - "/"        links to /search and /item
//   - "/search"  reflects q into HTML unescaped (reflected XSS)
//   - "/item"    emits a SQL error when id contains a single quote
func vulnServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<a href="/search?q=hello">search</a>
			<a href="/item?id=1">item</a>
			</body></html>`)
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Unescaped reflection -> reflected XSS.
		fmt.Fprintf(w, "<html><body>Results for: %s</body></html>", r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			fmt.Fprint(w, "You have an error in your SQL syntax; check the manual")
			return
		}
		fmt.Fprintf(w, "<html><body>item %s</body></html>", id)
	})
	return httptest.NewServer(mux)
}

func testConfig(t *testing.T, base string, mode string) *config.Config {
	t.Helper()
	u, _ := url.Parse(base)
	cfg := &config.Config{
		Mode:  mode,
		Scope: config.Scope{InScope: []string{u.Hostname()}},
		Seeds: []string{base + "/"},
		Crawl: config.Crawl{MaxDepth: 2, MaxPages: 50, SameHostOnly: true},
		HTTP:  config.HTTP{RatePerSecond: 500, Concurrency: 4, TimeoutSeconds: 10},
		Check: config.Checks{XSS: true, SQLi: true},
	}
	return cfg
}

func hasFinding(rep *Report, typ string, sev checks.Severity) bool {
	for _, f := range rep.Findings {
		if f.Type == typ && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestDetectsXSSAndSQLi(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()

	cfg := testConfig(t, srv.URL, config.ModeSafe)
	eng, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rep := eng.Run(context.Background())

	if rep.PagesCrawled == 0 {
		t.Fatal("expected pages to be crawled")
	}
	if !hasFinding(rep, "xss", checks.SeverityHigh) {
		t.Errorf("expected a high-severity XSS finding, got: %+v", rep.Findings)
	}
	if !hasFinding(rep, "sqli", checks.SeverityCritical) {
		t.Errorf("expected a critical SQLi finding, got: %+v", rep.Findings)
	}
	if rep.Blocked != 0 {
		t.Errorf("no requests should be blocked in this scope, got %d", rep.Blocked)
	}
}

func TestPassiveModeSendsNoPayloads(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()

	cfg := testConfig(t, srv.URL, config.ModePassive)
	eng, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rep := eng.Run(context.Background())

	for _, f := range rep.Findings {
		if f.Type == "xss" || f.Type == "sqli" {
			t.Errorf("passive mode must not produce active-check findings, got %s", f.Type)
		}
	}
}

func TestSeedOutOfScopeRejected(t *testing.T) {
	cfg := &config.Config{
		Mode:  config.ModeSafe,
		Scope: config.Scope{InScope: []string{"example.com"}},
		Seeds: []string{"https://evil.com/"},
		HTTP:  config.HTTP{RatePerSecond: 5, Concurrency: 2, TimeoutSeconds: 5},
	}
	if _, err := New(cfg, nil); err == nil {
		t.Fatal("expected New to reject an out-of-scope seed")
	}
}
