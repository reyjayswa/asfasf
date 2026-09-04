// Package engine wires the stages together: crawl, fingerprint + CVE mapping,
// optional headless-browser discovery, passive analyzers, then (unless running
// passively) the active site and injection checks. Findings are enriched with
// CWE/OWASP/score, de-duplicated, and returned as a single Report.
package engine

import (
	"context"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/reyjayswa/asfasf/internal/browser"
	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/checks/adminpanel"
	"github.com/reyjayswa/asfasf/internal/checks/cmdinjection"
	"github.com/reyjayswa/asfasf/internal/checks/cmsfp"
	"github.com/reyjayswa/asfasf/internal/checks/configexp"
	"github.com/reyjayswa/asfasf/internal/checks/cookies"
	"github.com/reyjayswa/asfasf/internal/checks/cors"
	"github.com/reyjayswa/asfasf/internal/checks/csrf"
	"github.com/reyjayswa/asfasf/internal/checks/cve"
	"github.com/reyjayswa/asfasf/internal/checks/openredirect"
	"github.com/reyjayswa/asfasf/internal/checks/pathtraversal"
	"github.com/reyjayswa/asfasf/internal/checks/secheaders"
	"github.com/reyjayswa/asfasf/internal/checks/shellexp"
	"github.com/reyjayswa/asfasf/internal/checks/sqldumper"
	"github.com/reyjayswa/asfasf/internal/checks/sqli"
	"github.com/reyjayswa/asfasf/internal/checks/ssti"
	"github.com/reyjayswa/asfasf/internal/checks/subtakeover"
	"github.com/reyjayswa/asfasf/internal/checks/xss"
	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/crawler"
	"github.com/reyjayswa/asfasf/internal/enrich"
	"github.com/reyjayswa/asfasf/internal/fingerprint"
	"github.com/reyjayswa/asfasf/internal/httpclient"
	"github.com/reyjayswa/asfasf/internal/scope"
)

// Report is the full result of a scan.
type Report struct {
	Mode           string            `json:"mode"`
	StartedAt      time.Time         `json:"started_at"`
	FinishedAt     time.Time         `json:"finished_at"`
	Seeds          []string          `json:"seeds"`
	InScope        []string          `json:"in_scope"`
	OutOfScope     []string          `json:"out_of_scope"`
	PagesCrawled   int               `json:"pages_crawled"`
	OriginsScanned int               `json:"origins_scanned"`
	Headless       bool              `json:"headless"`
	Endpoints      []checks.Endpoint `json:"endpoints"`
	Findings       []checks.Finding  `json:"findings"`
	RequestsSent   int64             `json:"requests_sent"`
	Blocked        int64             `json:"blocked_out_of_scope"`
	RateLimited    int64             `json:"rate_limited"`
}

// Logger receives human-readable progress lines.
type Logger func(format string, args ...interface{})

// siteChecker is implemented by every origin-scoped check module.
type siteChecker interface {
	Name() string
	Run(ctx context.Context, origin string) []checks.Finding
}

// endpointChecker is implemented by every parameter-scoped check module.
type endpointChecker interface {
	Run(ctx context.Context, ep checks.Endpoint) []checks.Finding
}

// Engine runs a scan for one configuration.
type Engine struct {
	cfg    *config.Config
	client *httpclient.Client
	scope  *scope.Matcher
	crawl  *crawler.Crawler
	log    Logger
}

// New constructs an Engine from validated config.
func New(cfg *config.Config, log Logger) (*Engine, error) {
	sc, err := scope.New(cfg.Scope)
	if err != nil {
		return nil, err
	}
	for _, s := range cfg.Seeds {
		if !sc.AllowsURL(s) {
			return nil, errSeedOutOfScope(s)
		}
	}
	client := httpclient.New(cfg.HTTP, sc)
	if log == nil {
		log = func(string, ...interface{}) {}
	}
	return &Engine{
		cfg:    cfg,
		client: client,
		scope:  sc,
		crawl:  crawler.New(cfg.Crawl, client, sc),
		log:    log,
	}, nil
}

// Run executes the scan and returns a Report.
func (e *Engine) Run(ctx context.Context) *Report {
	rep := &Report{
		Mode:       e.cfg.Mode,
		StartedAt:  time.Now(),
		Seeds:      e.cfg.Seeds,
		InScope:    e.cfg.Scope.InScope,
		OutOfScope: e.cfg.Scope.OutOfScope,
	}

	e.log("crawling from %d seed(s) in %s mode…", len(e.cfg.Seeds), e.cfg.Mode)
	cr := e.crawl.Run(ctx, e.cfg.Seeds)
	rep.PagesCrawled = len(cr.Pages)
	e.log("crawl complete: %d page(s), %d endpoint(s) discovered", len(cr.Pages), len(cr.Endpoints))

	fpFindings, detections := fingerprint.Analyze(cr.Pages)
	findings := fpFindings
	if e.cfg.Check.CVEFingerprint {
		findings = append(findings, cve.Analyze(detections)...)
	}

	origins := e.computeOrigins(cr.Pages)
	rep.OriginsScanned = len(origins)
	endpoints := cr.Endpoints

	// Optional headless-browser stage: render JS apps to discover extra routes.
	var b *browser.Browser
	if e.cfg.ActiveChecks() && e.cfg.Headless.Enabled {
		if browser.Available() {
			bb, err := browser.New(e.scope, e.cfg.Headless.TimeoutSeconds)
			if err == nil {
				b = bb
				defer b.Close()
				rep.Headless = true
				extra := e.headlessDiscover(ctx, b, origins)
				if len(extra) > 0 {
					endpoints = mergeEndpoints(endpoints, extra)
					e.log("headless discovery added %d endpoint(s)", len(extra))
				}
			} else {
				e.log("headless requested but unavailable: %v", err)
			}
		} else {
			e.log("headless requested but no chromium binary was found")
		}
	}
	rep.Endpoints = endpoints

	// Passive analyzers (no new requests; run in every mode).
	if e.cfg.Check.SecurityHeaders {
		findings = append(findings, secheaders.Analyze(cr.Pages)...)
	}
	if e.cfg.Check.Cookies {
		findings = append(findings, cookies.Analyze(cr.Pages)...)
	}
	if e.cfg.Check.CSRF {
		findings = append(findings, csrf.Analyze(endpoints)...)
	}

	if e.cfg.ActiveChecks() {
		findings = append(findings, e.runSiteChecks(ctx, origins)...)
		findings = append(findings, e.runEndpointChecks(ctx, endpoints)...)
		if b != nil {
			findings = append(findings, e.runDOMXSS(ctx, b, endpoints)...)
		}
	} else {
		e.log("passive mode: skipping active site and injection checks")
	}

	enrich.Apply(findings)
	findings = dedupe(findings)
	sortFindings(findings)

	rep.Findings = findings
	rep.RequestsSent, rep.Blocked = e.client.Stats()
	rep.RateLimited = e.client.RateLimited()
	rep.FinishedAt = time.Now()
	return rep
}

// computeOrigins returns the deduplicated, in-scope scheme://host origins.
func (e *Engine) computeOrigins(pages []crawler.Page) []string {
	set := map[string]bool{}
	add := func(raw string) {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return
		}
		origin := u.Scheme + "://" + u.Host
		if e.scope.AllowsURL(origin) {
			set[origin] = true
		}
	}
	for _, s := range e.cfg.Seeds {
		add(s)
	}
	for _, p := range pages {
		add(p.URL)
	}
	out := make([]string, 0, len(set))
	for o := range set {
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

func (e *Engine) takeoverOrigins(origins []string) []string {
	set := map[string]bool{}
	for _, o := range origins {
		set[o] = true
	}
	for _, host := range e.cfg.Takeover.ExtraSubdomains {
		origin := "https://" + host
		if e.scope.AllowsURL(origin) {
			set[origin] = true
		}
	}
	out := make([]string, 0, len(set))
	for o := range set {
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

type siteJob struct {
	origin  string
	checker siteChecker
}

// runSiteChecks runs every enabled origin-scoped check across all origins.
func (e *Engine) runSiteChecks(ctx context.Context, origins []string) []checks.Finding {
	aggressive := e.cfg.Aggressive()
	var general []siteChecker
	if e.cfg.Check.ConfigExposure {
		general = append(general, configexp.New(e.client, aggressive))
	}
	if e.cfg.Check.AdminPanel {
		general = append(general, adminpanel.New(e.client, aggressive))
	}
	if e.cfg.Check.CMSFingerprint {
		general = append(general, cmsfp.New(e.client, aggressive))
	}
	if e.cfg.Check.ShellExposure {
		general = append(general, shellexp.New(e.client, aggressive))
	}
	if e.cfg.Check.CORS {
		general = append(general, cors.New(e.client, aggressive))
	}

	var jobs []siteJob
	for _, o := range origins {
		for _, chk := range general {
			jobs = append(jobs, siteJob{origin: o, checker: chk})
		}
	}
	if e.cfg.Check.SubdomainTakeover {
		st := subtakeover.New(e.client, aggressive)
		for _, o := range e.takeoverOrigins(origins) {
			jobs = append(jobs, siteJob{origin: o, checker: st})
		}
	}

	var (
		mu       sync.Mutex
		findings []checks.Finding
		wg       sync.WaitGroup
		sem      = make(chan struct{}, e.cfg.HTTP.Concurrency)
	)
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(j siteJob) {
			defer wg.Done()
			defer func() { <-sem }()
			if res := j.checker.Run(ctx, j.origin); len(res) > 0 {
				mu.Lock()
				findings = append(findings, res...)
				mu.Unlock()
			}
		}(j)
	}
	wg.Wait()
	return findings
}

// runEndpointChecks probes every parameterized endpoint with the enabled
// injection checks, escalating firm SQLi to the bounded dumper.
func (e *Engine) runEndpointChecks(ctx context.Context, endpoints []checks.Endpoint) []checks.Finding {
	aggr := e.cfg.Aggressive()
	var generic []endpointChecker
	if e.cfg.Check.XSS {
		generic = append(generic, xss.New(e.client, aggr))
	}
	if e.cfg.Check.OpenRedirect {
		generic = append(generic, openredirect.New(e.client, aggr))
	}
	if e.cfg.Check.PathTraversal {
		generic = append(generic, pathtraversal.New(e.client, aggr))
	}
	if e.cfg.Check.CommandInjection {
		generic = append(generic, cmdinjection.New(e.client, aggr))
	}
	if e.cfg.Check.SSTI {
		generic = append(generic, ssti.New(e.client, aggr))
	}
	var sqliChk *sqli.Checker
	var dumper *sqldumper.Checker
	if e.cfg.Check.SQLi {
		sqliChk = sqli.New(e.client, aggr, e.cfg.Check.SQLiTimeBased, e.cfg.Check.SQLiDelaySeconds)
	}
	if e.cfg.Check.SQLDump {
		dumper = sqldumper.New(e.client, sqldumper.Options{
			MaxTables:  e.cfg.Dump.MaxTables,
			MaxColumns: e.cfg.Dump.MaxColumns,
			MaxRows:    e.cfg.Dump.MaxRows,
			SampleData: e.cfg.Dump.SampleData,
		})
	}
	if len(generic) == 0 && sqliChk == nil {
		return nil
	}

	var (
		mu       sync.Mutex
		findings []checks.Finding
		wg       sync.WaitGroup
		sem      = make(chan struct{}, e.cfg.HTTP.Concurrency)
	)
	for _, ep := range endpoints {
		if len(ep.Params) == 0 {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ep checks.Endpoint) {
			defer wg.Done()
			defer func() { <-sem }()
			var local []checks.Finding
			for _, chk := range generic {
				local = append(local, chk.Run(ctx, ep)...)
			}
			if sqliChk != nil {
				sqliFindings := sqliChk.Run(ctx, ep)
				local = append(local, sqliFindings...)
				if dumper != nil {
					for _, f := range sqliFindings {
						if f.Type == "sqli" && f.Confidence == "firm" && f.Parameter != "" {
							local = append(local, dumper.Dump(ctx, ep, f.Parameter)...)
						}
					}
				}
			}
			if len(local) > 0 {
				mu.Lock()
				findings = append(findings, local...)
				mu.Unlock()
			}
		}(ep)
	}
	wg.Wait()
	return findings
}

// headlessDiscover renders origins in a real browser and returns any new
// in-scope, parameterized endpoints found in the rendered DOM.
func (e *Engine) headlessDiscover(ctx context.Context, b *browser.Browser, origins []string) []checks.Endpoint {
	seen := map[string]bool{}
	var out []checks.Endpoint
	budget := e.cfg.Headless.MaxURLs
	for _, o := range origins {
		if budget <= 0 || ctx.Err() != nil {
			break
		}
		budget--
		_, links, err := b.Discover(ctx, o+"/")
		if err != nil {
			continue
		}
		for _, l := range links {
			u, err := url.Parse(l)
			if err != nil || len(u.Query()) == 0 || !e.scope.AllowsURL(l) {
				continue
			}
			params := make([]string, 0, len(u.Query()))
			for k := range u.Query() {
				params = append(params, k)
			}
			sort.Strings(params)
			base := *u
			base.RawQuery = ""
			key := base.String() + "?" + join(params)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, checks.Endpoint{URL: base.String(), Method: "GET", Params: params, Source: "headless"})
		}
	}
	return out
}

// runDOMXSS tests parameterized endpoints for DOM-based XSS in the browser,
// bounded by the headless URL budget.
func (e *Engine) runDOMXSS(ctx context.Context, b *browser.Browser, endpoints []checks.Endpoint) []checks.Finding {
	var findings []checks.Finding
	budget := e.cfg.Headless.MaxURLs
	for _, ep := range endpoints {
		if budget <= 0 || ctx.Err() != nil {
			break
		}
		for _, p := range ep.Params {
			if budget <= 0 {
				break
			}
			budget--
			findings = append(findings, b.TestDOMXSS(ctx, ep, p, e.cfg.Aggressive())...)
		}
	}
	return findings
}

// mergeEndpoints appends new endpoints not already present (by method+url+params).
func mergeEndpoints(base, extra []checks.Endpoint) []checks.Endpoint {
	seen := map[string]bool{}
	key := func(ep checks.Endpoint) string {
		ps := append([]string{}, ep.Params...)
		sort.Strings(ps)
		return ep.Method + " " + ep.URL + " " + join(ps)
	}
	for _, ep := range base {
		seen[key(ep)] = true
	}
	for _, ep := range extra {
		if !seen[key(ep)] {
			seen[key(ep)] = true
			base = append(base, ep)
		}
	}
	return base
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}

// dedupe collapses findings that share type, URL, parameter, and title.
func dedupe(findings []checks.Finding) []checks.Finding {
	seen := map[string]bool{}
	out := findings[:0]
	for _, f := range findings {
		key := f.Type + "|" + f.URL + "|" + f.Parameter + "|" + f.Title
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// sortFindings orders findings by severity (desc) then type and URL.
func sortFindings(f []checks.Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Severity.Rank() != f[j].Severity.Rank() {
			return f[i].Severity.Rank() > f[j].Severity.Rank()
		}
		if f[i].Type != f[j].Type {
			return f[i].Type < f[j].Type
		}
		return f[i].URL < f[j].URL
	})
}
