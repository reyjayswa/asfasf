// Package engine wires the stages together: crawl, fingerprint, then (unless
// running passively) the active injection checks. It produces a single
// Report that the report and dashboard packages render.
package engine

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/checks/sqli"
	"github.com/reyjayswa/asfasf/internal/checks/xss"
	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/crawler"
	"github.com/reyjayswa/asfasf/internal/fingerprint"
	"github.com/reyjayswa/asfasf/internal/httpclient"
	"github.com/reyjayswa/asfasf/internal/scope"
)

// Report is the full result of a scan.
type Report struct {
	Mode         string            `json:"mode"`
	StartedAt    time.Time         `json:"started_at"`
	FinishedAt   time.Time         `json:"finished_at"`
	Seeds        []string          `json:"seeds"`
	InScope      []string          `json:"in_scope"`
	OutOfScope   []string          `json:"out_of_scope"`
	PagesCrawled int               `json:"pages_crawled"`
	Endpoints    []checks.Endpoint `json:"endpoints"`
	Findings     []checks.Finding  `json:"findings"`
	RequestsSent int64             `json:"requests_sent"`
	Blocked      int64             `json:"blocked_out_of_scope"`
}

// Logger receives human-readable progress lines.
type Logger func(format string, args ...interface{})

// Engine runs a scan for one configuration.
type Engine struct {
	cfg    *config.Config
	client *httpclient.Client
	crawl  *crawler.Crawler
	log    Logger
}

// New constructs an Engine from validated config.
func New(cfg *config.Config, log Logger) (*Engine, error) {
	sc, err := scope.New(cfg.Scope)
	if err != nil {
		return nil, err
	}
	// Enforce that every seed is itself in scope before anything runs.
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
	findings := fingerprint.Analyze(cr.Pages)
	e.log("fingerprinting complete: %d recon finding(s)", len(findings))

	if e.cfg.ActiveChecks() {
		active := e.runActiveChecks(ctx, cr.Endpoints)
		findings = append(findings, active...)
		e.log("active checks complete: %d finding(s)", len(active))
	} else {
		e.log("passive mode: skipping active injection checks")
	}

	sortFindings(findings)
	rep.Findings = findings
	rep.RequestsSent, rep.Blocked = e.client.Stats()
	rep.FinishedAt = time.Now()
	return rep
}

// runActiveChecks probes every endpoint with the enabled checks, bounded by
// the configured concurrency.
func (e *Engine) runActiveChecks(ctx context.Context, endpoints []checks.Endpoint) []checks.Finding {
	var (
		xssChk  *xss.Checker
		sqliChk *sqli.Checker
	)
	if e.cfg.Check.XSS {
		xssChk = xss.New(e.client, e.cfg.Aggressive())
	}
	if e.cfg.Check.SQLi {
		sqliChk = sqli.New(e.client, e.cfg.Aggressive(), e.cfg.Check.SQLiTimeBased, e.cfg.Check.SQLiDelaySeconds)
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
				local = append(local, sqliChk.Run(ctx, ep)...)
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
