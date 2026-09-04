package headerinj

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/httpclient"
	"github.com/reyjayswa/asfasf/internal/scope"
)

func client(t *testing.T) *httpclient.Client {
	t.Helper()
	sc, _ := scope.New(config.Scope{InScope: []string{"127.0.0.1"}})
	return httpclient.New(config.HTTP{RatePerSecond: 500, Concurrency: 4, TimeoutSeconds: 10}, sc)
}

func origin(srv *httptest.Server) string {
	u, _ := url.Parse(srv.URL)
	return u.Scheme + "://" + u.Host
}

func TestHostHeaderInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Trusts X-Forwarded-Host to build a redirect.
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			w.Header().Set("Location", "https://"+xfh+"/next")
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "home")
	}))
	defer srv.Close()

	c := New(client(t), false)
	fs := c.Run(context.Background(), origin(srv))
	found := false
	for _, f := range fs {
		if f.Type == "header-injection" && f.Severity == checks.SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected host-header injection finding, got %+v", fs)
	}
}

func TestHeaderReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html>Welcome %s</html>", r.Header.Get("User-Agent"))
	}))
	defer srv.Close()

	c := New(client(t), false)
	fs := c.Run(context.Background(), origin(srv))
	if len(fs) == 0 {
		t.Fatal("expected a reflected-header finding")
	}
}

func TestHeaderClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "static page, ignores headers")
	}))
	defer srv.Close()

	c := New(client(t), false)
	if fs := c.Run(context.Background(), origin(srv)); len(fs) != 0 {
		t.Errorf("clean server must not be flagged, got %+v", fs)
	}
}
