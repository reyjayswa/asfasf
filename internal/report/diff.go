// Diff support: filter a report down to findings not present in a baseline
// report, so scheduled/continuous scans surface only what is new.
package report

import (
	"encoding/json"
	"os"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/engine"
)

func findingKey(f checks.Finding) string {
	return f.Type + "|" + f.URL + "|" + f.Parameter + "|" + f.Title
}

// FilterToNew removes from rep any finding that also appears in the baseline
// JSON report at path, returning how many were removed. A missing or unreadable
// baseline is treated as empty (nothing removed).
func FilterToNew(rep *engine.Report, baselinePath string) (int, error) {
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var base engine.Report
	if err := json.Unmarshal(data, &base); err != nil {
		return 0, err
	}
	seen := make(map[string]bool, len(base.Findings))
	for _, f := range base.Findings {
		seen[findingKey(f)] = true
	}
	kept := rep.Findings[:0]
	removed := 0
	for _, f := range rep.Findings {
		if seen[findingKey(f)] {
			removed++
			continue
		}
		kept = append(kept, f)
	}
	rep.Findings = kept
	return removed, nil
}
