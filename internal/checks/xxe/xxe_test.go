package xxe

import (
	"context"
	"io"
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

// etcPasswd is a realistic /etc/passwd body carrying the root:...:0:0: line.
const etcPasswd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

// winIni is a realistic win.ini body carrying the [extensions] section.
const winIni = "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n"

// vulnHandler simulates a naive XML parser that resolves external entities:
// if the posted document references file:///etc/passwd (or win.ini), it
// substitutes the file contents into the response.
func vulnHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	doc := string(body)
	if strings.Contains(doc, "file:///etc/passwd") {
		w.Write([]byte("<result>" + etcPasswd + "</result>"))
		return
	}
	if strings.Contains(doc, "file:///c:/windows/win.ini") {
		w.Write([]byte("<result>" + winIni + "</result>"))
		return
	}
	w.Write([]byte("<result>ok</result>"))
}

func TestRun_DetectsXXE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(vulnHandler))
	defer srv.Close()

	client := newClient(t)
	c := New(client, false)
	if c.Name() != "xxe" {
		t.Fatalf("Name() = %q, want xxe", c.Name())
	}

	// Params are intentionally set; the check must ignore them.
	ep := checks.Endpoint{URL: srv.URL, Method: http.MethodPost, Params: []string{"q"}, Source: "form"}
	findings := c.Run(context.Background(), ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != checks.SeverityCritical {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
	if f.Confidence != "firm" {
		t.Errorf("confidence = %q, want firm", f.Confidence)
	}
	if f.Type != "xxe" {
		t.Errorf("type = %q, want xxe", f.Type)
	}
	if f.Method != "POST" {
		t.Errorf("method = %q, want POST", f.Method)
	}
	if f.CWE != "CWE-611" {
		t.Errorf("cwe = %q, want CWE-611", f.CWE)
	}
	if !strings.HasPrefix(f.Evidence, "root:x:0:0:") {
		t.Errorf("evidence = %q, want root:...:0:0: snippet", f.Evidence)
	}
}

func TestRun_DedupsRepeatedURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(vulnHandler))
	defer srv.Close()

	c := New(newClient(t), false)
	ep := checks.Endpoint{URL: srv.URL, Method: http.MethodPost, Source: "form"}

	if fs := c.Run(context.Background(), ep); len(fs) != 1 {
		t.Fatalf("first run: expected 1 finding, got %d", len(fs))
	}
	// Same URL again must be skipped.
	if fs := c.Run(context.Background(), ep); len(fs) != 0 {
		t.Fatalf("second run (same URL): expected 0 findings, got %d", len(fs))
	}
}

func TestRun_WindowsAggressive(t *testing.T) {
	// A parser that resolves ONLY the Windows file (e.g. a Windows host).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "file:///c:/windows/win.ini") {
			w.Write([]byte("<result>" + winIni + "</result>"))
			return
		}
		w.Write([]byte("<result>ok</result>"))
	}))
	defer srv.Close()

	client := newClient(t)
	ep := checks.Endpoint{URL: srv.URL, Method: http.MethodPost, Source: "form"}

	// Non-aggressive only sends the /etc/passwd probe -> no finding here.
	if fs := New(client, false).Run(context.Background(), ep); len(fs) != 0 {
		t.Fatalf("non-aggressive expected 0 findings, got %d", len(fs))
	}

	// Aggressive additionally sends the win.ini probe and detects it.
	fs := New(client, true).Run(context.Background(), ep)
	if len(fs) != 1 {
		t.Fatalf("aggressive expected 1 finding, got %d: %+v", len(fs), fs)
	}
	if !strings.Contains(fs[0].Evidence, "[extensions]") {
		t.Errorf("evidence = %q, want [extensions]", fs[0].Evidence)
	}
}

func TestRun_CleanEndpoint(t *testing.T) {
	// A safe endpoint: it echoes the raw XML but never resolves entities, so
	// the file-content signatures never appear.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Echo the literal document (entity NOT expanded).
		w.Write([]byte("received " + string(body)))
	}))
	defer srv.Close()

	c := New(newClient(t), true)
	ep := checks.Endpoint{URL: srv.URL, Method: http.MethodPost, Params: []string{"q"}, Source: "form"}
	findings := c.Run(context.Background(), ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on clean endpoint, got %d: %+v", len(findings), findings)
	}
}
