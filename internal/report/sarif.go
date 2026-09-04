// SARIF 2.1.0 export. SARIF is the standard static-analysis result format
// consumed by CI systems and GitHub code scanning, so a scan can be uploaded
// and tracked like any other code-scanning tool.
package report

import (
	"encoding/json"
	"os"
	"sort"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/engine"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifText         `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifText              `json:"message"`
	Locations  []sarifLocation        `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func sarifLevel(s checks.Severity) string {
	switch s {
	case checks.SeverityCritical, checks.SeverityHigh:
		return "error"
	case checks.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// BuildSARIF converts a report into a SARIF log.
func BuildSARIF(rep *engine.Report) sarifLog {
	ruleSet := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range rep.Findings {
		if _, ok := ruleSet[f.Type]; !ok {
			props := map[string]string{}
			if f.CWE != "" {
				props["cwe"] = f.CWE
			}
			if f.OWASP != "" {
				props["owasp"] = f.OWASP
			}
			ruleSet[f.Type] = sarifRule{
				ID:               f.Type,
				Name:             f.Type,
				ShortDescription: sarifText{Text: f.Type + " finding"},
				Properties:       props,
			}
		}
		results = append(results, sarifResult{
			RuleID:    f.Type,
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: f.Title + " — " + f.Description},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.URL}}}},
			Properties: map[string]interface{}{
				"severity":  string(f.Severity),
				"score":     f.Score,
				"cwe":       f.CWE,
				"owasp":     f.OWASP,
				"parameter": f.Parameter,
			},
		})
	}
	rules := make([]sarifRule, 0, len(ruleSet))
	for _, r := range ruleSet {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	return sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "asfasf-scanner",
				InformationURI: "https://github.com/reyjayswa/asfasf",
				Version:        "0.2",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// WriteSARIF writes the report as SARIF 2.1.0 JSON to path.
func WriteSARIF(rep *engine.Report, path string) error {
	data, err := json.MarshalIndent(BuildSARIF(rep), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
