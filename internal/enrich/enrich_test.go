package enrich

import (
	"testing"

	"github.com/reyjayswa/asfasf/internal/checks"
)

func TestApplyFillsAndPreserves(t *testing.T) {
	fs := []checks.Finding{
		{Type: "sqli", Severity: checks.SeverityCritical},
		{Type: "cve", Severity: checks.SeverityHigh, CWE: "CWE-2021-41773"}, // preserved
	}
	Apply(fs)
	if fs[0].CWE != "CWE-89" || fs[0].OWASP == "" {
		t.Errorf("sqli not enriched: %+v", fs[0])
	}
	if fs[0].Score != 9.5 {
		t.Errorf("expected critical score 9.5, got %v", fs[0].Score)
	}
	if fs[1].CWE != "CWE-2021-41773" {
		t.Error("existing CWE must be preserved")
	}
	if fs[1].OWASP == "" {
		t.Error("cve OWASP category should be filled")
	}
}
