package shellexp

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// vulnServer reproduces several genuine exposed web shells:
//   - /c99.php      -> c99shell signature
//   - /wso.php      -> "WSO 2" signature
//   - /cmd.php      -> command-execution form (cmd input + submit + uname)
//   - /r57.php      -> "Safe Mode:" + "Server IP" status panel
//
// Every other path returns a bare 200 SPA shell (must NOT be flagged).
func vulnServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/c99.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>c99shell v1.0</title></head>
			<body>c99shell powered backdoor</body></html>`))
	})
	mux.HandleFunc("/wso.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><h1>WSO 2.5</h1> web shell by orb</body></html>`))
	})
	mux.HandleFunc("/cmd.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<pre>Linux uname -a output here</pre>
			<form method="post">
			<input type="text" name="cmd">
			<button type="submit">execute</button>
			</form>
			<div>system() enabled</div>
			</body></html>`))
	})
	mux.HandleFunc("/r57.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<table><tr><td>Safe Mode: OFF</td></tr>
			<tr><td>Server IP: 10.0.0.5</td></tr></table>
			</body></html>`))
	})
	// Catch-all SPA: 200 for everything, no distinctive marker.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><div id="app">loading...</div></body></html>`))
	})
	return httptest.NewServer(mux)
}

// cleanServer answers 200 with a harmless SPA shell for every path, with no
// web-shell signature anywhere. It deliberately includes a benign search
// form and the words "shell" and "system" in ordinary prose to confirm the
// check does not fire on incidental occurrences.
func cleanServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>Seashell Store</title></head>
			<body><p>Our system ships worldwide.</p>
			<form><input type="text" name="q"><button>Search</button></form>
			</body></html>`))
	}))
}

func TestRun_FindsExposedShells(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()

	c := New(newClient(t), false)
	findings := c.Run(context.Background(), srv.URL)

	if len(findings) < 4 {
		t.Fatalf("expected at least 4 findings, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Type != "shell-exposure" {
			t.Errorf("unexpected Type %q", f.Type)
		}
		if f.Severity != "critical" {
			t.Errorf("expected critical severity, got %q for %s", f.Severity, f.URL)
		}
		if f.Confidence != "firm" {
			t.Errorf("expected firm confidence, got %q", f.Confidence)
		}
		if f.Timestamp.IsZero() {
			t.Errorf("expected non-zero timestamp for %s", f.URL)
		}
		if f.Evidence == "" || f.URL == "" || f.Description == "" || f.Remediation == "" {
			t.Errorf("missing required field on finding: %+v", f)
		}
	}
}

func TestRun_CleanServerNoFindings(t *testing.T) {
	srv := cleanServer()
	defer srv.Close()

	c := New(newClient(t), true)
	findings := c.Run(context.Background(), srv.URL)

	if len(findings) != 0 {
		t.Fatalf("expected zero findings on clean server, got %d: %+v", len(findings), findings)
	}
}

func TestName(t *testing.T) {
	if got := New(newClient(t), false).Name(); got != "shell-exposure" {
		t.Fatalf("Name() = %q, want shell-exposure", got)
	}
}

func TestRun_RespectsCancellation(t *testing.T) {
	srv := vulnServer()
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := New(newClient(t), false)
	findings := c.Run(ctx, srv.URL)
	if len(findings) != 0 {
		t.Fatalf("expected no findings after cancellation, got %d", len(findings))
	}
}
