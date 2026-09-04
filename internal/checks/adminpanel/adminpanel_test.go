package adminpanel

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
	return httpclient.New(config.HTTP{
		RatePerSecond:  500,
		Concurrency:    4,
		TimeoutSeconds: 10,
	}, sc)
}

// vulnServer reproduces several genuine admin/login surfaces:
//   - /login          -> HTML password input (generic login form)
//   - /phpmyadmin/     -> phpMyAdmin signature
//   - /manager/html    -> 401 WWW-Authenticate challenge
//
// Every other path returns a bare 200 SPA shell (must NOT be flagged).
func vulnServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><form method="post">
			<input type="text" name="user">
			<input type="password" name="pass">
			<button>Sign in</button></form></body></html>`))
	})
	mux.HandleFunc("/phpmyadmin/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>phpMyAdmin</title></head>
			<body>Welcome to phpMyAdmin</body></html>`))
	})
	mux.HandleFunc("/manager/html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("401 Unauthorized"))
	})
	// Catch-all SPA: 200 for everything, no distinctive marker.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><div id="app">loading...</div></body></html>`))
	})
	return httptest.NewServer(mux)
}

// cleanServer answers 200 with a harmless SPA shell for every path, with no
// login form, panel signature, or auth challenge anywhere.
func cleanServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><div id="root">Hello world</div></body></html>`))
	}))
}

func TestRun_FindsAdminSurfaces(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()

	c := New(newClient(t), false)
	findings := c.Run(context.Background(), srv.URL)

	if len(findings) == 0 {
		t.Fatalf("expected findings, got none")
	}

	byURL := map[string]bool{}
	for _, f := range findings {
		if f.Type != "admin-panel" {
			t.Errorf("unexpected finding type %q", f.Type)
		}
		if f.Confidence != "firm" && f.Confidence != "tentative" {
			t.Errorf("finding %q has bad confidence %q", f.Title, f.Confidence)
		}
		if f.URL == "" || f.Title == "" || f.Description == "" || f.Remediation == "" {
			t.Errorf("finding %q missing required fields", f.Title)
		}
		if f.Timestamp.IsZero() {
			t.Errorf("finding %q has zero timestamp", f.Title)
		}
		byURL[f.URL] = true
	}

	want := []string{"/login", "/phpmyadmin/", "/manager/html"}
	for _, p := range want {
		found := false
		for u := range byURL {
			if strings.HasSuffix(u, p) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected a finding for path %q, got none (findings: %v)", p, byURL)
		}
	}
}

func TestRun_CleanServerNoFindings(t *testing.T) {
	srv := cleanServer()
	defer srv.Close()

	c := New(newClient(t), true) // aggressive: probes more paths, still clean
	findings := c.Run(context.Background(), srv.URL)

	if len(findings) != 0 {
		t.Fatalf("expected zero findings on clean server, got %d: %+v", len(findings), findings)
	}
}
