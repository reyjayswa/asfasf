package ssrf

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/httpclient"
	"github.com/reyjayswa/asfasf/internal/oob"
	"github.com/reyjayswa/asfasf/internal/scope"
)

func newClient(t *testing.T) *httpclient.Client {
	t.Helper()
	sc, _ := scope.New(config.Scope{InScope: []string{"127.0.0.1"}})
	return httpclient.New(config.HTTP{RatePerSecond: 500, Concurrency: 4, TimeoutSeconds: 10}, sc)
}

func TestSSRFDetectedOutOfBand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := oob.New("127.0.0.1:0", "")
	if err != nil {
		t.Fatalf("oob: %v", err)
	}
	srv.Start(ctx)
	defer srv.Close()

	// A vulnerable endpoint that fetches whatever URL it is given (SSRF).
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" {
			resp, err := http.Get(u) // server-side fetch of attacker input
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
		fmt.Fprint(w, "ok")
	}))
	defer vuln.Close()

	ep := checks.Endpoint{URL: vuln.URL + "/fetch", Method: "GET", Params: []string{"url"}}
	c := New(newClient(t), srv, false)
	fs := c.Run(ctx, ep)
	if len(fs) == 0 {
		t.Fatal("expected an out-of-band SSRF finding")
	}
	if fs[0].Type != "ssrf" || fs[0].Severity != checks.SeverityCritical {
		t.Errorf("unexpected finding: %+v", fs[0])
	}
}

func TestSSRFCleanEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, _ := oob.New("127.0.0.1:0", "")
	srv.Start(ctx)
	defer srv.Close()

	// Ignores the url parameter -> no outbound request.
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer vuln.Close()

	ep := checks.Endpoint{URL: vuln.URL + "/fetch", Method: "GET", Params: []string{"url"}}
	c := New(newClient(t), srv, false)
	c.wait = 500000000 // 0.5s
	if fs := c.Run(ctx, ep); len(fs) != 0 {
		t.Errorf("clean endpoint must not be flagged, got %+v", fs)
	}
}
