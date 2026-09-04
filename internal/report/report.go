// Package report renders a scan Report as machine-readable JSON and as a
// self-contained HTML page. The HTML renderer is shared with the dashboard
// so the on-disk report and the live view look identical.
package report

import (
	"encoding/json"
	"html/template"
	"os"
	"sort"
	"strings"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/engine"
)

// Counts summarizes findings per severity.
type Counts struct {
	Critical, High, Medium, Low, Info int
	Total                             int
}

// Summarize tallies findings by severity.
func Summarize(rep *engine.Report) Counts {
	var c Counts
	for _, f := range rep.Findings {
		switch f.Severity {
		case checks.SeverityCritical:
			c.Critical++
		case checks.SeverityHigh:
			c.High++
		case checks.SeverityMedium:
			c.Medium++
		case checks.SeverityLow:
			c.Low++
		default:
			c.Info++
		}
	}
	c.Total = len(rep.Findings)
	return c
}

// WriteJSON writes the report as indented JSON to path.
func WriteJSON(rep *engine.Report, path string) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// RenderHTML renders the report to a self-contained HTML document.
func RenderHTML(rep *engine.Report) ([]byte, error) {
	var sb strings.Builder
	data := struct {
		Rep    *engine.Report
		Counts Counts
	}{Rep: rep, Counts: Summarize(rep)}
	if err := tmpl.Execute(&sb, data); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// WriteHTML renders and writes the HTML report to path.
func WriteHTML(rep *engine.Report, path string) error {
	data, err := RenderHTML(rep)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// SortedEndpoints returns endpoints sorted for stable display.
func SortedEndpoints(rep *engine.Report) []checks.Endpoint {
	eps := make([]checks.Endpoint, len(rep.Endpoints))
	copy(eps, rep.Endpoints)
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].URL != eps[j].URL {
			return eps[i].URL < eps[j].URL
		}
		return eps[i].Method < eps[j].Method
	})
	return eps
}

var funcs = template.FuncMap{
	"join":  func(s []string) string { return strings.Join(s, ", ") },
	"upper": strings.ToUpper,
}

var tmpl = template.Must(template.New("report").Funcs(funcs).Parse(reportHTML))
