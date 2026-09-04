package cmsfp

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

// wpServer serves a WordPress site: the root carries a versioned meta
// generator tag and /wp-login.php carries the login markers.
func wpServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body>hi</body></html>`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<form><input name="user_login" type="text"></form>`))
	})
	return httptest.NewServer(mux)
}

// drupalServer serves Drupal only via the X-Generator header and a
// /CHANGELOG.txt file (root has no generator marker).
func drupalServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Generator", "Drupal 9 (https://www.drupal.org)")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>welcome</body></html>`))
	})
	mux.HandleFunc("/CHANGELOG.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Drupal 9.5.0, 2023-01-05\n-----------------------"))
	})
	return httptest.NewServer(mux)
}

// cleanServer is a catch-all SPA: HTTP 200 with a generic shell for every
// path and no CMS markers whatsoever. It must yield zero findings.
func cleanServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>`))
	}))
}

func TestDetectsWordPressWithVersion(t *testing.T) {
	srv := wpServer()
	defer srv.Close()

	c := New(newClient(t), false)
	findings := c.Run(context.Background(), srv.URL)

	var got *string
	for i := range findings {
		if strings.Contains(findings[i].Title, "WordPress") {
			got = &findings[i].Title
		}
	}
	if got == nil {
		t.Fatalf("expected a WordPress finding, got %d findings: %+v", len(findings), findings)
	}
	if !strings.Contains(*got, "6.4.2") {
		t.Errorf("expected version 6.4.2 in title, got %q", *got)
	}
	for _, f := range findings {
		if f.Type != "cms-fingerprint" || f.Severity != "info" || f.Confidence != "firm" {
			t.Errorf("finding fields wrong: %+v", f)
		}
		if f.Timestamp.IsZero() {
			t.Errorf("timestamp not set: %+v", f)
		}
	}
}

func TestDetectsDrupalViaHeaderAndChangelog(t *testing.T) {
	srv := drupalServer()
	defer srv.Close()

	c := New(newClient(t), false)
	findings := c.Run(context.Background(), srv.URL)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Drupal") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a Drupal finding, got %d findings: %+v", len(findings), findings)
	}
}

func TestCleanServerNoFindings(t *testing.T) {
	srv := cleanServer()
	defer srv.Close()

	c := New(newClient(t), true)
	findings := c.Run(context.Background(), srv.URL)
	if len(findings) != 0 {
		t.Fatalf("expected zero findings on clean SPA, got %d: %+v", len(findings), findings)
	}
}
