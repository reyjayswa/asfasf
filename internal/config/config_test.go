package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// A minimal config (only scope + seeds) must still enable a useful set of
// checks, while leaving the higher-risk opt-ins off.
func TestMinimalConfigEnablesDefaultChecks(t *testing.T) {
	cfg, err := Load(writeCfg(t, `
scope:
  in_scope: ["example.com"]
seeds: ["https://example.com/"]
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for name, on := range map[string]bool{
		"xss":                cfg.Check.XSS,
		"sqli":               cfg.Check.SQLi,
		"sqli_time_based":    cfg.Check.SQLiTimeBased,
		"config_exposure":    cfg.Check.ConfigExposure,
		"admin_panel":        cfg.Check.AdminPanel,
		"cms_fingerprint":    cfg.Check.CMSFingerprint,
		"shell_exposure":     cfg.Check.ShellExposure,
		"subdomain_takeover": cfg.Check.SubdomainTakeover,
		"cve_fingerprint":    cfg.Check.CVEFingerprint,
		"sql_dump":           cfg.Check.SQLDump,
	} {
		if !on {
			t.Errorf("expected %s to default ON in a minimal config", name)
		}
	}
	// Row-data sampling is the one thing that must NOT default on: the dumper
	// extracts metadata/schema by default, but reading real rows is opt-in.
	if cfg.Dump.SampleData {
		t.Error("dump.sample_data must not be enabled by default")
	}
}

// When the user enables specific checks, the defaults must NOT be applied.
func TestExplicitChecksAreRespected(t *testing.T) {
	cfg, err := Load(writeCfg(t, `
scope:
  in_scope: ["example.com"]
seeds: ["https://example.com/"]
checks:
  xss: true
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Check.XSS {
		t.Error("xss should stay enabled")
	}
	if cfg.Check.SQLi || cfg.Check.ConfigExposure || cfg.Check.AdminPanel {
		t.Error("with an explicit checks block, other checks must stay off")
	}
}
