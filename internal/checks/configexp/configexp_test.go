package configexp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/httpclient"
	"github.com/reyjayswa/asfasf/internal/scope"
)

func newTestClient(t *testing.T) *httpclient.Client {
	t.Helper()
	sc, err := scope.New(config.Scope{InScope: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return httpclient.New(config.HTTP{RatePerSecond: 500, Concurrency: 4, TimeoutSeconds: 10}, sc)
}

// originOf converts an httptest server URL (http://127.0.0.1:PORT) into an
// origin string with no trailing slash and no path.
func originOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	return u.Scheme + "://" + u.Host
}

// vulnHandler serves realistic sensitive-file content for several paths.
func vulnHandler() http.Handler {
	dsStore := append([]byte{0x00, 0x00, 0x00, 0x01}, []byte("Bud1")...)
	dsStore = append(dsStore, make([]byte, 32)...)

	responses := map[string][]byte{
		"/.env":              []byte("APP_KEY=base64:abcd1234\nDB_PASSWORD=s3cr3t\nDB_HOST=localhost\n"),
		"/.git/config":       []byte("[core]\n\trepositoryformatversion = 0\n\tbare = false\n"),
		"/.git/HEAD":         []byte("ref: refs/heads/main\n"),
		"/wp-config.php.bak": []byte("<?php\ndefine('DB_NAME', 'wp');\ndefine('DB_PASSWORD', 'hunter2');\n"),
		"/config.php.bak":    []byte("<?php\n$password = 'secret';\n$db = 'app';\n"),
		"/.DS_Store":         dsStore,
		"/phpinfo.php":       []byte("<html><body>PHP Version 8.1.2</body></html>"),
		"/backup.sql":        []byte("CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n"),
		"/.htaccess":         []byte("RewriteEngine On\nRewriteRule ^ index.php [L]\n"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if body, ok := responses[r.URL.Path]; ok {
			w.WriteHeader(http.StatusOK)
			w.Write(body)
			return
		}
		http.NotFound(w, r)
	})
	return mux
}

// cleanHandler is a catch-all SPA: everything returns 200 with the same HTML.
func cleanHandler() http.Handler {
	page := []byte("<!DOCTYPE html><html><head><title>App</title></head><body><div id=\"root\"></div></body></html>")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write(page)
	})
}

func TestRunDetectsExposures(t *testing.T) {
	srv := httptest.NewServer(vulnHandler())
	defer srv.Close()

	c := New(newTestClient(t), false)
	findings := c.Run(context.Background(), originOf(t, srv.URL))

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	wantPaths := []string{
		"/.env", "/.git/config", "/.git/HEAD", "/wp-config.php.bak",
		"/config.php.bak", "/.DS_Store", "/phpinfo.php", "/backup.sql", "/.htaccess",
	}
	got := map[string]bool{}
	for _, f := range findings {
		if f.Type != "config-exposure" {
			t.Errorf("unexpected finding type %q", f.Type)
		}
		if f.Confidence != "firm" {
			t.Errorf("expected firm confidence, got %q", f.Confidence)
		}
		if f.Timestamp.IsZero() {
			t.Error("finding has zero timestamp")
		}
		if f.Remediation == "" || f.Description == "" || f.Title == "" {
			t.Errorf("finding missing required fields: %+v", f)
		}
		for _, p := range wantPaths {
			if strings.HasSuffix(f.URL, p) {
				got[p] = true
			}
		}
	}
	for _, p := range wantPaths {
		if !got[p] {
			t.Errorf("expected a finding for path %s", p)
		}
	}
}

func TestRunCleanServerNoFindings(t *testing.T) {
	srv := httptest.NewServer(cleanHandler())
	defer srv.Close()

	c := New(newTestClient(t), true) // aggressive: probe everything
	findings := c.Run(context.Background(), originOf(t, srv.URL))

	if len(findings) != 0 {
		t.Fatalf("expected zero findings on clean SPA, got %d: %+v", len(findings), findings)
	}
}

func TestName(t *testing.T) {
	c := New(newTestClient(t), false)
	if c.Name() != "config-exposure" {
		t.Errorf("Name() = %q, want config-exposure", c.Name())
	}
}
