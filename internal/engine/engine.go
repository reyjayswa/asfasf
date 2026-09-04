// Package engine wires the stages together: crawl, fingerprint + CVE mapping,
// then (unless running passively) the active site checks and the parameter
// injection checks. It produces a single Report that the report and dashboard
// packages render.
package engine

import (
	"context"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/checks/adminpanel"
	"github.com/reyjayswa/asfasf/internal/checks/cmsfp"
	"github.com/reyjayswa/asfasf/internal/checks/configexp"
	"github.com/reyjayswa/asfasf/internal/checks/cve"
	"github.com/reyjayswa/asfasf/internal/checks/shellexp"
	"github.com/reyjayswa/asfasf/internal/checks/sqldumper"
	"github.com/reyjayswa/asfasf/internal/checks/sqli"
	"github.com/reyjayswa/asfasf/internal/checks/subtakeover"
	"github.com/reyjayswa/asfasf/internal/checks/xss"
	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/crawler"
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
	Endpoints      []checks.Endpoint `json:"endpoints"`
	Findings       []checks.Finding  `json:"findings"`
	RequestsSent   int64             `json:"requests_sent"`
	Blocked        int64             `json:"blocked_out_of_scope"`
}

// Logger receives human-readable progress lines.
type Logger func(format string, args ...interface{})

// siteChecker is implemented by every origin-scoped check module.
type siteChecker interface {
	Name() string
	Run(ctx context.Context, origin string) []checks.Finding
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
	rep.Endpoints = cr.Endpoints
	e.log("crawl complete: %d page(s), %d endpoint(s) discovered", len(cr.Pages), len(cr.Endpoints))

	// Recon / fingerprinting always runs; it is passive.
	fpFindings, detections := fingerprint.Analyze(cr.Pages)
	findings := fpFindings
	e.log("fingerprinting complete: %d recon finding(s), %d tech detection(s)", len(fpFindings), len(detections))

	// CVE mapping is pure analysis of the passive fingerprint data.
	if e.cfg.Check.CVEFingerprint {
		cveFindings := cve.Analyze(detections)
		findings = append(findings, cveFindings...)
		e.log("CVE mapping complete: %d potential CVE(s)", len(cveFindings))
	}

	origins := e.computeOrigins(cr.Pages)
	rep.OriginsScanned = len(origins)

	if e.cfg.ActiveChecks() {
		site := e.runSiteChecks(ctx, origins)
		findings = append(findings, site...)
		e.log("site checks complete: %d finding(s)", len(site))

		active := e.runEndpointChecks(ctx, cr.Endpoints)
		findings = append(findings, active...)
		e.log("injection checks complete: %d finding(s)", len(active))
	} else {
		e.log("passive mode: skipping active site and injection checks")
	}

	sortFindings(findings)
	rep.Findings = findings
	rep.RequestsSent, rep.Blocked = e.client.Stats()
	rep.FinishedAt = time.Now()
	return rep
}

// computeOrigins returns the deduplicated, in-scope set of scheme://host
// origins derived from the seeds and every crawled page.
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

// takeoverOrigins is the origin set the subdomain-takeover check runs over:
// the crawled origins plus any configured extra subdomains that are in scope.
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

// runSiteChecks runs every enabled origin-scoped check across all origins,
// bounded by the configured concurrency.
func (e *Engine) runSiteChecks(ctx context.Context, origins []string) []checks.Finding {
	aggressive := e.cfg.Aggressive()

	// Non-DNS site checks run over the crawled origins.
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

	var jobs []siteJob
	for _, o := range origins {
		for _, chk := range general {
			jobs = append(jobs, siteJob{origin: o, checker: chk})
		}
	}
	// Subdomain takeover runs over the extended origin set (adds configured
	// extra subdomains) since dangling records are often on unused hosts.
	if e.cfg.Check.SubdomainTakeover {
		st := subtakeover.New(e.client, aggressive)
		for _, o := range e.takeoverOrigins(origins) {
			jobs = append(jobs, siteJob{origin: o, checker: st})
		}
	}

	return e.runJobs(ctx, jobs)
}

func (e *Engine) runJobs(ctx context.Context, jobs []siteJob) []checks.Finding {
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
			res := j.checker.Run(ctx, j.origin)
			if len(res) > 0 {
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
// injection checks, and (when enabled) runs the bounded SQL dumper against
// any endpoint/parameter with a firmly-confirmed SQL injection.
func (e *Engine) runEndpointChecks(ctx context.Context, endpoints []checks.Endpoint) []checks.Finding {
	var (
		xssChk  *xss.Checker
		sqliChk *sqli.Checker
		dumper  *sqldumper.Checker
	)
	if e.cfg.Check.XSS {
		xssChk = xss.New(e.client, e.cfg.Aggressive())
	}
	if e.cfg.Check.SQLi {
		sqliChk = sqli.New(e.client, e.cfg.Aggressive(), e.cfg.Check.SQLiTimeBased, e.cfg.Check.SQLiDelaySeconds)
	}
	if e.cfg.Check.SQLDump {
		dumper = sqldumper.New(e.client, sqldumper.Options{
			MaxTables:  e.cfg.Dump.MaxTables,
			MaxColumns: e.cfg.Dump.MaxColumns,
			MaxRows:    e.cfg.Dump.MaxRows,
			SampleData: e.cfg.Dump.SampleData,
		})
	}
	if xssChk == nil && sqliChk == nil {
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
			if xssChk != nil {
				local = append(local, xssChk.Run(ctx, ep)...)
			}
			if sqliChk != nil {
				sqliFindings := sqliChk.Run(ctx, ep)
				local = append(local, sqliFindings...)
				// Escalate firmly-confirmed SQLi with bounded extraction.
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
