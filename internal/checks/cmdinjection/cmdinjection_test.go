package cmdinjection

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

func newClient(t *testing.T) *httpclient.Client {
	t.Helper()
	sc, err := scope.New(config.Scope{InScope: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return httpclient.New(config.HTTP{RatePerSecond: 500, Concurrency: 4, TimeoutSeconds: 10}, sc)
}

// containsInjection reports whether the value carries a shell metacharacter
// running `id`, i.e. it simulates a vulnerable OS-command sink.
func containsInjection(v string) bool {
	return strings.Contains(v, "id")
}

func TestRun_DetectsCommandInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		host := r.FormValue("host")
		// Simulate a vulnerable sink: when a shell metacharacter that runs
		// `id` is present, the "shell" output is reflected in the response.
		if containsInjection(host) {
			w.Write([]byte("PING output\nuid=33(apache) gid=33(apache) groups=33(apache)\n"))
			return
		}
		w.Write([]byte("PING output for " + host))
	}))
	defer srv.Close()

	client := newClient(t)
	c := New(client, false)
	if c.Name() != "command-injection" {
		t.Fatalf("Name() = %q", c.Name())
	}

	ep := checks.Endpoint{URL: srv.URL, Method: http.MethodGet, Params: []string{"host"}, Source: "query"}
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
	if f.Parameter != "host" {
		t.Errorf("parameter = %q, want host", f.Parameter)
	}
	if !strings.HasPrefix(f.Evidence, "uid=33(apache) gid=33") {
		t.Errorf("evidence = %q, want uid=...gid=... snippet", f.Evidence)
	}
	if f.Type != "command-injection" {
		t.Errorf("type = %q", f.Type)
	}
}

func TestRun_DetectsWindowsAggressive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("host")
		if strings.Contains(q, "ver") {
			w.Write([]byte("Microsoft Windows [Version 10.0.19045.4046]\n"))
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := newClient(t)

	ep := checks.Endpoint{URL: srv.URL, Method: http.MethodGet, Params: []string{"host"}, Source: "query"}

	// Non-aggressive must not send the Windows payload -> no finding.
	if fs := New(client, false).Run(context.Background(), ep); len(fs) != 0 {
		t.Fatalf("non-aggressive expected 0 findings, got %d", len(fs))
	}

	// Aggressive detects the Windows version banner.
	fs := New(client, true).Run(context.Background(), ep)
	if len(fs) != 1 {
		t.Fatalf("aggressive expected 1 finding, got %d: %+v", len(fs), fs)
	}
	if !strings.Contains(fs[0].Evidence, "Microsoft Windows [Version") {
		t.Errorf("evidence = %q", fs[0].Evidence)
	}
}

func TestRun_CleanEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A well-behaved endpoint that safely echoes the raw parameter and
		// never executes anything. It even echoes payloads verbatim, but
		// never emits an `id`-style signature.
		_ = r.ParseForm()
		w.Write([]byte("You searched for: " + r.FormValue("q")))
	}))
	defer srv.Close()

	client := newClient(t)
	c := New(client, true)

	ep := checks.Endpoint{URL: srv.URL, Method: http.MethodGet, Params: []string{"q"}, Source: "query"}
	findings := c.Run(context.Background(), ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on clean endpoint, got %d: %+v", len(findings), findings)
	}
}

// sanity: ensure our injected payloads actually form valid query encodings.
func TestPayloadsEncodeCleanly(t *testing.T) {
	for _, p := range unixPayloads {
		v := url.Values{"host": {p}}
		if v.Encode() == "" {
			t.Fatalf("payload %q encoded empty", p)
		}
	}
}
