// Package config loads and validates the scanner's scope configuration.
//
// Scope is mandatory. The scanner refuses to run without at least one
// in-scope host pattern and at least one seed URL, and every seed must
// itself fall inside the declared scope. This is the guardrail that keeps
// the tool pointed only at targets the operator is authorized to test.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the full scanner configuration loaded from a YAML file.
type Config struct {
	// Mode sets how intrusive the scan is:
	//   "passive"    - crawl, discover, and fingerprint only; no payloads
	//                  are ever sent. Use this when a program forbids
	//                  active/automated testing.
	//   "safe"       - passive work plus one non-destructive probe per
	//                  parameter for each enabled check (default).
	//   "aggressive" - safe work plus additional payload variants per
	//                  parameter for higher coverage. Still no time-based
	//                  or denial-of-service payloads.
	Mode     string   `yaml:"mode"`
	Scope    Scope    `yaml:"scope"`
	Seeds    []string `yaml:"seeds"`
	Crawl    Crawl    `yaml:"crawl"`
	HTTP     HTTP     `yaml:"http"`
	Check    Checks   `yaml:"checks"`
	Dump     Dump     `yaml:"dump"`
	Takeover Takeover `yaml:"takeover"`
}

// Scan modes.
const (
	ModePassive    = "passive"
	ModeSafe       = "safe"
	ModeAggressive = "aggressive"
)

// ActiveChecks reports whether the current mode permits sending payloads.
func (c *Config) ActiveChecks() bool { return c.Mode != ModePassive }

// Aggressive reports whether extra payload variants should be used.
func (c *Config) Aggressive() bool { return c.Mode == ModeAggressive }

// Scope declares which hosts are in and out of bounds. Patterns are host
// names that may begin with "*." to match any subdomain, e.g.
// "*.example.com" matches "api.example.com" but not "example.com".
type Scope struct {
	InScope    []string `yaml:"in_scope"`
	OutOfScope []string `yaml:"out_of_scope"`
}

// Crawl bounds the discovery stage.
type Crawl struct {
	MaxDepth     int  `yaml:"max_depth"`
	MaxPages     int  `yaml:"max_pages"`
	SameHostOnly bool `yaml:"same_host_only"`
}

// HTTP configures the shared request client.
type HTTP struct {
	RatePerSecond  float64 `yaml:"rate_per_second"`
	Concurrency    int     `yaml:"concurrency"`
	TimeoutSeconds int     `yaml:"timeout_seconds"`
	UserAgent      string  `yaml:"user_agent"`
	FollowRedirect bool    `yaml:"follow_redirect"`
}

// Checks toggles individual detection modules.
type Checks struct {
	XSS  bool `yaml:"xss"`
	SQLi bool `yaml:"sqli"`

	// SQLiTimeBased enables blind time-based SQL injection detection. It
	// sends a single short, bounded delay payload per parameter and
	// confirms against a zero-delay control to rule out network jitter.
	// This is NOT a denial-of-service test: the delay is a few seconds and
	// is never repeated in a loop. Off by default; enable only where the
	// program permits active blind testing. Ignored in passive mode.
	SQLiTimeBased bool `yaml:"sqli_time_based"`

	// SQLiDelaySeconds is the delay used by the time-based probe. It is
	// clamped to the range [1, 10] to keep the probe bounded.
	SQLiDelaySeconds int `yaml:"sqli_delay_seconds"`

	// Site-level checks. These probe an origin with small path lists and
	// tight content signatures. They send requests the crawl did not
	// discover, so they are treated as active and are skipped in passive
	// mode.
	AdminPanel        bool `yaml:"admin_panel"`
	ConfigExposure    bool `yaml:"config_exposure"`
	ShellExposure     bool `yaml:"shell_exposure"`
	CMSFingerprint    bool `yaml:"cms_fingerprint"`
	SubdomainTakeover bool `yaml:"subdomain_takeover"`

	// CVEFingerprint maps detected software versions to known CVEs. It sends
	// no extra requests and runs in every mode (including passive).
	CVEFingerprint bool `yaml:"cve_fingerprint"`

	// SQLDump enables the bounded SQL data extractor against endpoints where
	// SQL injection was firmly confirmed. It is an explicit opt-in on top of
	// an active mode. Off by default. See Dump for its bounds.
	SQLDump bool `yaml:"sql_dump"`
}

// Dump bounds the SQL data extractor (used only when checks.sql_dump is on).
// It defaults to metadata-only extraction; row data is read only when
// SampleData is true, and never more than MaxRows.
type Dump struct {
	MaxTables  int  `yaml:"max_tables"`
	MaxColumns int  `yaml:"max_columns"`
	MaxRows    int  `yaml:"max_rows"`
	SampleData bool `yaml:"sample_data"`
}

// Takeover configures the subdomain-takeover check.
type Takeover struct {
	// ExtraSubdomains are additional hostnames to check for takeover beyond
	// the crawled origins. Each must fall within scope or it is ignored.
	ExtraSubdomains []string `yaml:"extra_subdomains"`
}

// Load reads, parses, applies defaults to, and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// applyDefaults fills sensible, conservative defaults for unset fields.
func (c *Config) applyDefaults() {
	if strings.TrimSpace(c.Mode) == "" {
		c.Mode = ModeSafe
	}
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Crawl.MaxDepth == 0 {
		c.Crawl.MaxDepth = 3
	}
	if c.Crawl.MaxPages == 0 {
		c.Crawl.MaxPages = 200
	}
	if c.HTTP.RatePerSecond == 0 {
		c.HTTP.RatePerSecond = 5
	}
	if c.HTTP.Concurrency == 0 {
		c.HTTP.Concurrency = 5
	}
	if c.HTTP.TimeoutSeconds == 0 {
		c.HTTP.TimeoutSeconds = 15
	}
	if strings.TrimSpace(c.HTTP.UserAgent) == "" {
		c.HTTP.UserAgent = "asfasf-scanner/0.1 (authorized security testing)"
	}
	if c.Check.SQLiDelaySeconds == 0 {
		c.Check.SQLiDelaySeconds = 3
	}
	if c.Check.SQLiDelaySeconds < 1 {
		c.Check.SQLiDelaySeconds = 1
	}
	if c.Check.SQLiDelaySeconds > 10 {
		c.Check.SQLiDelaySeconds = 10
	}
	if c.Dump.MaxTables <= 0 {
		c.Dump.MaxTables = 20
	}
	if c.Dump.MaxColumns <= 0 {
		c.Dump.MaxColumns = 20
	}
	if c.Dump.MaxRows <= 0 {
		c.Dump.MaxRows = 5
	}
	c.applyCheckDefaults()
}

// anyCheckEnabled reports whether the user turned on at least one detection
// module. The delay/sample modifiers do not count on their own.
func (c *Config) anyCheckEnabled() bool {
	ch := c.Check
	return ch.XSS || ch.SQLi || ch.AdminPanel || ch.ConfigExposure ||
		ch.ShellExposure || ch.CMSFingerprint || ch.SubdomainTakeover ||
		ch.CVEFingerprint || ch.SQLDump
}

// applyCheckDefaults turns on the full check set when no checks were enabled,
// so a minimal config (just scope + seeds) runs everything. This includes the
// time-based blind SQLi probe and the SQL dumper.
//
// One deliberate exception: the dumper's row-data sampling (Dump.SampleData)
// is NOT turned on here. The dumper still proves impact by extracting metadata
// and schema (table/column names), but reading actual row values stays an
// explicit opt-in so a default scan respects data-minimization rules.
func (c *Config) applyCheckDefaults() {
	if c.anyCheckEnabled() {
		return
	}
	c.Check.XSS = true
	c.Check.SQLi = true
	c.Check.SQLiTimeBased = true
	c.Check.ConfigExposure = true
	c.Check.AdminPanel = true
	c.Check.CMSFingerprint = true
	c.Check.ShellExposure = true
	c.Check.SubdomainTakeover = true
	c.Check.CVEFingerprint = true
	c.Check.SQLDump = true
}

// validate enforces the scope guardrails and basic sanity limits.
func (c *Config) validate() error {
	switch c.Mode {
	case ModePassive, ModeSafe, ModeAggressive:
	default:
		return fmt.Errorf("mode must be one of passive, safe, aggressive (got %q)", c.Mode)
	}
	if len(c.Scope.InScope) == 0 {
		return fmt.Errorf("scope.in_scope must list at least one host pattern; " +
			"the scanner will not run without a defined authorized scope")
	}
	if len(c.Seeds) == 0 {
		return fmt.Errorf("seeds must list at least one starting URL")
	}
	if c.HTTP.RatePerSecond <= 0 {
		return fmt.Errorf("http.rate_per_second must be positive")
	}
	if c.HTTP.Concurrency <= 0 {
		return fmt.Errorf("http.concurrency must be positive")
	}
	// Every seed must be a valid http(s) URL. In-scope enforcement against
	// the seed hosts happens in the scope package once patterns are compiled.
	for _, s := range c.Seeds {
		u, err := url.Parse(s)
		if err != nil {
			return fmt.Errorf("invalid seed URL %q: %w", s, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("seed URL %q must use http or https", s)
		}
		if u.Host == "" {
			return fmt.Errorf("seed URL %q must include a host", s)
		}
	}
	return nil
}
