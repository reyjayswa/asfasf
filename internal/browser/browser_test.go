package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/scope"
)

func newBrowser(t *testing.T) *Browser {
	t.Helper()
	if !Available() {
		t.Skip("no chromium available")
	}
	sc, err := scope.New(config.Scope{InScope: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	b, err := New(sc, 25)
	if err != nil {
		t.Fatalf("browser: %v", err)
	}
	return b
}

// A page with a DOM-XSS sink: it writes the q parameter into innerHTML.
func domXSSServer(safe bool) *httptest.Server {
	sink := "innerHTML"
	if safe {
		sink = "textContent"
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><div id="out"></div><script>
			var q = new URLSearchParams(location.search).get('q');
			if (q) { document.getElementById('out').%s = q; }
		</script></body></html>`, sink)
	}))
}

func TestDOMXSSDetected(t *testing.T) {
	b := newBrowser(t)
	defer b.Close()
	srv := domXSSServer(false)
	defer srv.Close()

	ep := checks.Endpoint{URL: srv.URL + "/", Method: "GET", Params: []string{"q"}}
	fs := b.TestDOMXSS(context.Background(), ep, "q", true)
	if len(fs) == 0 {
		t.Fatal("expected a DOM-XSS finding on an innerHTML sink")
	}
	if fs[0].Type != "dom-xss" || fs[0].Severity != checks.SeverityHigh {
		t.Errorf("unexpected finding: %+v", fs[0])
	}
}

func TestDOMXSSCleanSink(t *testing.T) {
	b := newBrowser(t)
	defer b.Close()
	srv := domXSSServer(true) // textContent: not exploitable
	defer srv.Close()

	ep := checks.Endpoint{URL: srv.URL + "/", Method: "GET", Params: []string{"q"}}
	if fs := b.TestDOMXSS(context.Background(), ep, "q", true); len(fs) != 0 {
		t.Errorf("textContent sink must not be flagged, got %+v", fs)
	}
}

func TestDiscoverRendersJSLinks(t *testing.T) {
	b := newBrowser(t)
	defer b.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div id="nav"></div><script>
			var a = document.createElement('a');
			a.href = '/spa/dashboard';
			a.textContent = 'Dashboard';
			document.getElementById('nav').appendChild(a);
		</script></body></html>`)
	}))
	defer srv.Close()

	_, links, err := b.Discover(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	found := false
	for _, l := range links {
		if strings.HasSuffix(l, "/spa/dashboard") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the JS-added link to be discovered, got %v", links)
	}
}
