package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/httpclient"
	"github.com/reyjayswa/asfasf/internal/scope"
)

func TestDiscoverRobotsAndSitemap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			fmt.Fprint(w, "User-agent: *\nDisallow: /search?q=secret\nSitemap: "+baseURL(r)+"/sitemap.xml\n")
		case "/sitemap.xml":
			fmt.Fprint(w, `<?xml version="1.0"?><urlset><url><loc>`+baseURL(r)+`/item?id=5</loc></url></urlset>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	sc, _ := scope.New(config.Scope{InScope: []string{"127.0.0.1"}})
	client := httpclient.New(config.HTTP{RatePerSecond: 500, Concurrency: 4, TimeoutSeconds: 10}, sc)

	eps := Discover(context.Background(), client, sc, []string{srv.URL}, nil)

	var gotSearch, gotItem bool
	for _, e := range eps {
		if len(e.Params) == 1 && e.Params[0] == "q" {
			gotSearch = true
		}
		if len(e.Params) == 1 && e.Params[0] == "id" {
			gotItem = true
		}
	}
	if !gotSearch {
		t.Error("expected the robots.txt Disallow endpoint (?q=) to be discovered")
	}
	if !gotItem {
		t.Error("expected the sitemap.xml URL (?id=) to be discovered")
	}
}

func baseURL(r *http.Request) string {
	u := &url.URL{Scheme: "http", Host: r.Host}
	return u.String()
}
