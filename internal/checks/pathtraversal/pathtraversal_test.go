package pathtraversal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/httpclient"
	"github.com/reyjayswa/asfasf/internal/scope"
)

const passwdContents = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

const winIniContents = "; for 16-bit app support\n[extensions]\nwav=mplayer.exe\n"

func newClient(t *testing.T) *httpclient.Client {
	t.Helper()
	sc, err := scope.New(config.Scope{InScope: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return httpclient.New(config.HTTP{RatePerSecond: 500, Concurrency: 4, TimeoutSeconds: 10}, sc)
}

// looksLikeTraversal reports whether the (already percent-decoded) value
// resolves to a system file a traversal payload would target.
func looksLikeTraversal(v string) (string, bool) {
	if strings.Contains(v, "etc/passwd") {
		return passwdContents, true
	}
	if strings.Contains(strings.ToLower(v), "win.ini") {
		return winIniContents, true
	}
	return "", false
}

func TestPositiveTraversal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if body, ok := looksLikeTraversal(file); ok {
			w.Write([]byte(body))
			return
		}
		w.Write([]byte("<html>welcome</html>"))
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	ep := checks.Endpoint{URL: srv.URL + "/view", Method: http.MethodGet, Params: []string{"file"}, Source: "query"}

	findings := c.Run(context.Background(), ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Type != "path-traversal" || f.Severity != checks.SeverityHigh {
		t.Errorf("unexpected type/severity: %s / %s", f.Type, f.Severity)
	}
	if f.Parameter != "file" || f.Confidence != "firm" {
		t.Errorf("unexpected parameter/confidence: %s / %s", f.Parameter, f.Confidence)
	}
	if !strings.Contains(f.Evidence, "root:") {
		t.Errorf("evidence should contain matched passwd line, got %q", f.Evidence)
	}
	if f.CWE != "CWE-22" {
		t.Errorf("expected CWE-22, got %q", f.CWE)
	}
}

func TestPositiveWindowsAggressive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This host only leaks win.ini (a Windows target); the passwd
		// payloads return nothing, so detection must come from win.ini.
		file := strings.ToLower(r.URL.Query().Get("file"))
		if strings.Contains(file, "win.ini") {
			w.Write([]byte(winIniContents))
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Only aggressive mode sends the win.ini payload.
	c := New(newClient(t), true)
	ep := checks.Endpoint{URL: srv.URL + "/load", Method: http.MethodGet, Params: []string{"file"}, Source: "query"}

	findings := c.Run(context.Background(), ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(strings.ToLower(findings[0].Evidence), "extensions") &&
		!strings.Contains(strings.ToLower(findings[0].Evidence), "16-bit") {
		t.Errorf("evidence should contain win.ini marker, got %q", findings[0].Evidence)
	}
}

func TestNegativeClean(t *testing.T) {
	// A server that safely echoes the requested name and never serves file
	// contents must produce zero findings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		w.Write([]byte("<html>you requested: " + url.QueryEscape(file) + " (not found)</html>"))
	}))
	defer srv.Close()

	c := New(newClient(t), true)
	ep := checks.Endpoint{URL: srv.URL + "/view", Method: http.MethodGet, Params: []string{"file", "page"}, Source: "query"}

	findings := c.Run(context.Background(), ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on clean server, got %d: %+v", len(findings), findings)
	}
}

func TestNegativeMentionsRootOnly(t *testing.T) {
	// Body mentions the word "root" but is not passwd content: must not fire.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Login as root to continue. root privileges required."))
	}))
	defer srv.Close()

	c := New(newClient(t), false)
	ep := checks.Endpoint{URL: srv.URL + "/x", Method: http.MethodGet, Params: []string{"file"}, Source: "query"}

	if findings := c.Run(context.Background(), ep); len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}
