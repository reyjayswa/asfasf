// Markdown report. Renders each finding as a self-contained, submission-ready
// section (title, severity/score, CWE/OWASP, affected URL, reproduction, and
// evidence) suitable for pasting into a bug bounty report.
package report

import (
	"fmt"
	"os"
	"strings"

	"github.com/reyjayswa/asfasf/internal/engine"
)

// RenderMarkdown renders the report as Markdown text.
func RenderMarkdown(rep *engine.Report) string {
	c := Summarize(rep)
	var b strings.Builder

	fmt.Fprintf(&b, "# Web Vulnerability Scan Report\n\n")
	fmt.Fprintf(&b, "- **Mode:** %s\n", rep.Mode)
	fmt.Fprintf(&b, "- **Seeds:** %s\n", strings.Join(rep.Seeds, ", "))
	fmt.Fprintf(&b, "- **In scope:** %s\n", strings.Join(rep.InScope, ", "))
	fmt.Fprintf(&b, "- **Started:** %s\n", rep.StartedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "- **Pages crawled:** %d · **Endpoints:** %d · **Requests:** %d\n\n",
		rep.PagesCrawled, len(rep.Endpoints), rep.RequestsSent)

	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n|---|---|\n")
	fmt.Fprintf(&b, "| Critical | %d |\n", c.Critical)
	fmt.Fprintf(&b, "| High | %d |\n", c.High)
	fmt.Fprintf(&b, "| Medium | %d |\n", c.Medium)
	fmt.Fprintf(&b, "| Low | %d |\n", c.Low)
	fmt.Fprintf(&b, "| Info | %d |\n\n", c.Info)

	b.WriteString("> Scores are indicative severity values, not computed CVSS vectors. ")
	b.WriteString("Verify each finding before reporting; automated results can include false positives.\n\n")

	b.WriteString("## Findings\n\n")
	if len(rep.Findings) == 0 {
		b.WriteString("_No findings._\n")
		return b.String()
	}
	for i, f := range rep.Findings {
		fmt.Fprintf(&b, "### %d. %s\n\n", i+1, f.Title)
		fmt.Fprintf(&b, "**Severity:** %s (score %.1f) · **Confidence:** %s",
			strings.ToUpper(string(f.Severity)), f.Score, f.Confidence)
		if f.CWE != "" {
			fmt.Fprintf(&b, " · %s", f.CWE)
		}
		if f.OWASP != "" {
			fmt.Fprintf(&b, " · %s", f.OWASP)
		}
		b.WriteString("\n\n")

		fmt.Fprintf(&b, "- **URL:** %s\n", f.URL)
		if f.Method != "" {
			fmt.Fprintf(&b, "- **Method:** %s\n", f.Method)
		}
		if f.Parameter != "" {
			fmt.Fprintf(&b, "- **Parameter:** `%s`\n", f.Parameter)
		}
		b.WriteString("\n")

		if f.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", f.Description)
		}
		if f.Payload != "" {
			fmt.Fprintf(&b, "**Reproduction (payload):**\n\n```\n%s\n```\n\n", f.Payload)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "**Evidence:**\n\n```\n%s\n```\n\n", f.Evidence)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "**Remediation:** %s\n\n", f.Remediation)
		}
		b.WriteString("---\n\n")
	}
	return b.String()
}

// WriteMarkdown writes the Markdown report to path.
func WriteMarkdown(rep *engine.Report, path string) error {
	return os.WriteFile(path, []byte(RenderMarkdown(rep)), 0o644)
}
