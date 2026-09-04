// Package discovery widens endpoint coverage beyond the HTML crawl by reading
// robots.txt and sitemap.xml and by mining referenced JavaScript files for URL
// paths. Every discovered URL is scope-checked; only in-scope, parameterized
// URLs are returned as endpoints for the injection checks to probe.
package discovery

import (
	"context"
	"encoding/xml"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/crawler"
	"github.com/reyjayswa/asfasf/internal/httpclient"
	"github.com/reyjayswa/asfasf/internal/scope"
)

// maxJSFiles bounds how many script files are fetched and mined.
const maxJSFiles = 15

var (
	scriptSrc = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
	// jsPath captures quoted absolute paths, optionally with a query string.
	jsPath = regexp.MustCompile(`["'` + "`" + `](/[A-Za-z0-9_\-./]+\?[A-Za-z0-9_\-.=&%]+)["'` + "`" + `]`)
)

// Discover fetches robots.txt and sitemap.xml for each origin and mines JS
// referenced by the crawled pages, returning new in-scope parameterized
// endpoints (deduplicated).
func Discover(ctx context.Context, client *httpclient.Client, sc *scope.Matcher, origins []string, pages []crawler.Page) []checks.Endpoint {
	d := &discoverer{client: client, scope: sc, seen: map[string]bool{}}
	for _, o := range origins {
		if ctx.Err() != nil {
			break
		}
		d.fromRobots(ctx, o)
		d.fromSitemap(ctx, o+"/sitemap.xml")
	}
	d.fromJS(ctx, pages)
	sort.Slice(d.out, func(i, j int) bool { return d.out[i].URL < d.out[j].URL })
	return d.out
}

type discoverer struct {
	client  *httpclient.Client
	scope   *scope.Matcher
	seen    map[string]bool
	out     []checks.Endpoint
	jsCount int
}

// add records a candidate URL as an endpoint if it is in scope and has params.
func (d *discoverer) add(raw, source string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || len(u.Query()) == 0 {
		return
	}
	if !d.scope.AllowsURL(raw) {
		return
	}
	params := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		params = append(params, k)
	}
	sort.Strings(params)
	base := *u
	base.RawQuery = ""
	key := base.String() + "?" + strings.Join(params, ",")
	if d.seen[key] {
		return
	}
	d.seen[key] = true
	d.out = append(d.out, checks.Endpoint{URL: base.String(), Method: "GET", Params: params, Source: source})
}

func (d *discoverer) fromRobots(ctx context.Context, origin string) {
	resp, err := d.client.Get(ctx, origin+"/robots.txt")
	if err != nil || resp.Status != 200 {
		return
	}
	for _, line := range strings.Split(resp.BodyString(), "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "disallow:"), strings.HasPrefix(lower, "allow:"):
			path := strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
			if strings.HasPrefix(path, "/") {
				d.add(origin+path, "robots")
			}
		case strings.HasPrefix(lower, "sitemap:"):
			sm := strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
			if d.scope.AllowsURL(sm) {
				d.fromSitemap(ctx, sm)
			}
		}
	}
}

func (d *discoverer) fromSitemap(ctx context.Context, sitemapURL string) {
	resp, err := d.client.Get(ctx, sitemapURL)
	if err != nil || resp.Status != 200 {
		return
	}
	var doc struct {
		URLs []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
		Sitemaps []struct {
			Loc string `xml:"loc"`
		} `xml:"sitemap"`
	}
	if err := xml.Unmarshal(resp.Body, &doc); err != nil {
		return
	}
	for _, u := range doc.URLs {
		d.add(strings.TrimSpace(u.Loc), "sitemap")
	}
	// One level of nested sitemap index.
	for _, sm := range doc.Sitemaps {
		loc := strings.TrimSpace(sm.Loc)
		if loc != "" && d.scope.AllowsURL(loc) {
			d.fromNestedSitemap(ctx, loc)
		}
	}
}

func (d *discoverer) fromNestedSitemap(ctx context.Context, sitemapURL string) {
	resp, err := d.client.Get(ctx, sitemapURL)
	if err != nil || resp.Status != 200 {
		return
	}
	var doc struct {
		URLs []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
	}
	if err := xml.Unmarshal(resp.Body, &doc); err != nil {
		return
	}
	for _, u := range doc.URLs {
		d.add(strings.TrimSpace(u.Loc), "sitemap")
	}
}

func (d *discoverer) fromJS(ctx context.Context, pages []crawler.Page) {
	fetched := map[string]bool{}
	for _, p := range pages {
		base, err := url.Parse(p.URL)
		if err != nil {
			continue
		}
		for _, m := range scriptSrc.FindAllStringSubmatch(string(p.Body), -1) {
			if d.jsCount >= maxJSFiles || ctx.Err() != nil {
				return
			}
			ref, err := url.Parse(m[1])
			if err != nil {
				continue
			}
			abs := base.ResolveReference(ref).String()
			if fetched[abs] || !d.scope.AllowsURL(abs) {
				continue
			}
			fetched[abs] = true
			d.jsCount++
			resp, err := d.client.Get(ctx, abs)
			if err != nil || resp.Status != 200 {
				continue
			}
			for _, pm := range jsPath.FindAllStringSubmatch(resp.BodyString(), -1) {
				d.add(base.Scheme+"://"+base.Host+pm[1], "js")
			}
		}
	}
}
