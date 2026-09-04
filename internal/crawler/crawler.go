// Package crawler performs bounded, scope-aware discovery. Starting from the
// configured seeds it walks links breadth-first up to a depth and page
// limit, and along the way records every request target it can probe later:
// links carrying query parameters and HTML forms with their fields.
package crawler

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/httpclient"
	"github.com/reyjayswa/asfasf/internal/scope"
	"golang.org/x/net/html"
)

// Page is a fetched resource kept for recon and fingerprinting.
type Page struct {
	URL    string
	Status int
	Header http.Header
	Body   []byte
}

// Result is the output of a crawl.
type Result struct {
	Endpoints []checks.Endpoint
	Pages     []Page
}

// Crawler walks a site within scope.
type Crawler struct {
	cfg    config.Crawl
	client *httpclient.Client
	scope  *scope.Matcher

	mu        sync.Mutex
	visited   map[string]bool
	endpoints map[string]checks.Endpoint // keyed by method+url+params
	pages     []Page
	pageCount int
}

// New builds a Crawler.
func New(cfg config.Crawl, client *httpclient.Client, sc *scope.Matcher) *Crawler {
	return &Crawler{
		cfg:       cfg,
		client:    client,
		scope:     sc,
		visited:   make(map[string]bool),
		endpoints: make(map[string]checks.Endpoint),
	}
}

// Run crawls from the seeds and returns discovered endpoints and pages.
func (c *Crawler) Run(ctx context.Context, seeds []string) *Result {
	frontier := c.normalizeFrontier(seeds)
	for depth := 0; depth <= c.cfg.MaxDepth && len(frontier) > 0; depth++ {
		if c.reachedPageLimit() {
			break
		}
		frontier = c.crawlLevel(ctx, frontier)
	}
	eps := make([]checks.Endpoint, 0, len(c.endpoints))
	for _, e := range c.endpoints {
		eps = append(eps, e)
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].URL < eps[j].URL })
	return &Result{Endpoints: eps, Pages: c.pages}
}

func (c *Crawler) reachedPageLimit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pageCount >= c.cfg.MaxPages
}

// crawlLevel fetches every URL in the current frontier concurrently and
// returns the deduplicated set of newly discovered in-scope links.
func (c *Crawler) crawlLevel(ctx context.Context, frontier []string) []string {
	var (
		wg   sync.WaitGroup
		nmu  sync.Mutex
		next = map[string]bool{}
	)
	for _, raw := range frontier {
		if c.reachedPageLimit() {
			break
		}
		if !c.markVisited(raw) {
			continue
		}
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			links := c.fetchAndParse(ctx, target)
			nmu.Lock()
			for _, l := range links {
				next[l] = true
			}
			nmu.Unlock()
		}(raw)
	}
	wg.Wait()

	out := make([]string, 0, len(next))
	for l := range next {
		if !c.seenVisited(l) {
			out = append(out, l)
		}
	}
	return out
}

// fetchAndParse retrieves one page, records it, and extracts links/forms.
func (c *Crawler) fetchAndParse(ctx context.Context, target string) []string {
	resp, err := c.client.Get(ctx, target)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	c.pageCount++
	c.pages = append(c.pages, Page{URL: target, Status: resp.Status, Header: resp.Header, Body: resp.Body})
	c.mu.Unlock()

	// Record this URL itself as an endpoint if it carries query params.
	c.recordQueryEndpoint(target)

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "html") && ct != "" {
		return nil
	}
	doc, err := html.Parse(strings.NewReader(resp.BodyString()))
	if err != nil {
		return nil
	}
	base, _ := url.Parse(target)
	links := c.extract(base, doc)
	return links
}

// extract walks the HTML tree collecting in-scope links and form endpoints.
func (c *Crawler) extract(base *url.URL, n *html.Node) []string {
	var links []string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "a":
				if href, ok := attr(node, "href"); ok {
					if abs := c.resolve(base, href); abs != "" {
						links = append(links, abs)
						c.recordQueryEndpoint(abs)
					}
				}
			case "form":
				c.recordForm(base, node)
			}
		}
		for ch := node.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(n)
	return links
}

// recordQueryEndpoint stores a GET endpoint if the URL has query params.
func (c *Crawler) recordQueryEndpoint(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil || len(u.Query()) == 0 {
		return
	}
	params := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		params = append(params, k)
	}
	base := *u
	base.RawQuery = ""
	c.addEndpoint(checks.Endpoint{
		URL:    base.String(),
		Method: http.MethodGet,
		Params: params,
		Source: "query",
	}, u.Query())
}

// recordForm stores an endpoint for an HTML form and its fields.
func (c *Crawler) recordForm(base *url.URL, form *html.Node) {
	method := http.MethodGet
	if m, ok := attr(form, "method"); ok && strings.EqualFold(m, "post") {
		method = http.MethodPost
	}
	action, _ := attr(form, "action")
	abs := c.resolve(base, action)
	if abs == "" {
		abs = base.String()
	}
	if !c.scope.AllowsURL(abs) {
		return
	}
	var params []string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "input", "textarea", "select":
				if name, ok := attr(node, "name"); ok && name != "" {
					params = append(params, name)
				}
			}
		}
		for ch := node.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(form)
	if len(params) == 0 {
		return
	}
	u, _ := url.Parse(abs)
	if method == http.MethodGet {
		u.RawQuery = ""
	}
	c.addEndpoint(checks.Endpoint{
		URL:    u.String(),
		Method: method,
		Params: params,
		Source: "form",
	}, nil)
}

// resolve turns a possibly relative href into an absolute, in-scope URL, or
// returns "" if it is off-scope or not http(s).
func (c *Crawler) resolve(base *url.URL, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") ||
		strings.HasPrefix(strings.ToLower(href), "javascript:") ||
		strings.HasPrefix(strings.ToLower(href), "mailto:") {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(ref)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	abs.Fragment = ""
	if c.cfg.SameHostOnly && abs.Host != base.Host {
		return ""
	}
	if !c.scope.AllowsURL(abs.String()) {
		return ""
	}
	return abs.String()
}

// addEndpoint deduplicates and stores an endpoint. When a param carries a
// sample value in vals it is remembered on the endpoint's base for checks.
func (c *Crawler) addEndpoint(ep checks.Endpoint, _ url.Values) {
	sort.Strings(ep.Params)
	key := ep.Method + " " + ep.URL + " " + strings.Join(ep.Params, ",")
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.endpoints[key]; !ok {
		c.endpoints[key] = ep
	}
}

// markVisited records a URL as visited, returning false if already seen or
// out of scope.
func (c *Crawler) markVisited(rawURL string) bool {
	if !c.scope.AllowsURL(rawURL) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.visited[rawURL] {
		return false
	}
	c.visited[rawURL] = true
	return true
}

func (c *Crawler) seenVisited(rawURL string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.visited[rawURL]
}

// normalizeFrontier filters seeds down to in-scope http(s) URLs.
func (c *Crawler) normalizeFrontier(seeds []string) []string {
	var out []string
	for _, s := range seeds {
		if c.scope.AllowsURL(s) {
			out = append(out, s)
		}
	}
	return out
}

// attr returns the value of the named attribute on an element node.
func attr(n *html.Node, name string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val, true
		}
	}
	return "", false
}
