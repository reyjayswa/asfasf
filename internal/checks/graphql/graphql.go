// Package graphql implements a GraphQL introspection exposure check.
//
// It probes an origin ("https://host[:port]") for common GraphQL endpoint
// paths and POSTs a minimal introspection query as JSON. When the response
// echoes the schema back (both "__schema" and "queryType" present, or a JSON
// "data" object carrying the schema), introspection is enabled and the full
// API schema is exposed to anonymous clients — a reconnaissance aid that
// widens the attack surface.
//
// To minimise false positives the check gates on distinctive introspection
// signatures rather than a bare HTTP 200. A path that returns a GraphQL-shaped
// error (an "errors" array mentioning "GraphQL") but no schema is reported at
// most as Info: a GraphQL endpoint exists but introspection appears disabled.
package graphql

import (
	"context"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// introspectionQuery is a minimal introspection request. If the server answers
// it with schema data, introspection is enabled.
const introspectionQuery = `{"query":"query{__schema{queryType{name}}}"}`

// basePaths are GraphQL endpoint paths probed on every run.
var basePaths = []string{
	"/graphql",
	"/api/graphql",
	"/graphql/console",
	"/v1/graphql",
	"/query",
}

// aggressivePaths are additional paths probed only when aggressive is true.
var aggressivePaths = []string{
	"/graphiql",
	"/playground",
	"/gql",
}

// Checker probes an origin for exposed GraphQL introspection.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds a GraphQL Checker. When aggressive is true the checker probes an
// extended set of common GraphQL paths.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "graphql" }

// Run probes origin's GraphQL paths and returns any findings. origin is like
// "https://host[:port]" with no trailing slash.
func (c *Checker) Run(ctx context.Context, origin string) []checks.Finding {
	var findings []checks.Finding

	base := strings.TrimRight(origin, "/")

	paths := basePaths
	if c.aggressive {
		paths = append(append([]string{}, basePaths...), aggressivePaths...)
	}

	for _, p := range paths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		target := base + p
		resp, err := c.client.Do(ctx, "POST", target,
			strings.NewReader(introspectionQuery),
			map[string]string{"Content-Type": "application/json"})
		if err != nil || resp == nil {
			continue
		}

		body := resp.BodyString()

		if schemaExposed(body) {
			findings = append(findings, checks.Finding{
				Type:       "graphql",
				Severity:   checks.SeverityMedium,
				Title:      "GraphQL introspection enabled",
				URL:        target,
				Method:     "POST",
				Payload:    introspectionQuery,
				Evidence:   checks.Truncate(body, 240),
				Confidence: "firm",
				CWE:        "CWE-200",
				Timestamp:  time.Now(),
				Description: "The GraphQL endpoint answers an unauthenticated introspection query " +
					"with schema data (__schema/queryType). Introspection exposes the entire API " +
					"schema — types, fields, arguments and mutations — giving an attacker a complete " +
					"map of the API and accelerating discovery of sensitive or unguarded operations.",
				Remediation: "Disable introspection in production (e.g. disable the introspection/" +
					"__schema resolver or set the framework's introspection flag to false), and require " +
					"authentication and authorization on the GraphQL endpoint. Consider query depth/" +
					"complexity limits and persisted queries.",
			})
			continue
		}

		if graphQLError(body) {
			findings = append(findings, checks.Finding{
				Type:       "graphql",
				Severity:   checks.SeverityInfo,
				Title:      "GraphQL endpoint detected",
				URL:        target,
				Method:     "POST",
				Payload:    introspectionQuery,
				Evidence:   checks.Truncate(body, 240),
				Confidence: "firm",
				CWE:        "CWE-200",
				Timestamp:  time.Now(),
				Description: "A GraphQL endpoint responds at this path but did not return schema data " +
					"to an anonymous introspection query, suggesting introspection is disabled or the " +
					"query was rejected. The presence of the endpoint is informational for mapping the " +
					"application's attack surface.",
				Remediation: "Confirm that introspection is disabled in production and that the endpoint " +
					"enforces authentication, authorization and rate/complexity limits.",
			})
		}
	}

	return findings
}

// schemaExposed reports whether body looks like a successful introspection
// response: it names both __schema and queryType (the fields requested), and
// carries a JSON "data" object rather than only an errors array.
func schemaExposed(body string) bool {
	if !strings.Contains(body, "__schema") || !strings.Contains(body, "queryType") {
		return false
	}
	// Require a data object echoing the schema, not merely the words appearing
	// inside an error message.
	return strings.Contains(body, `"data"`)
}

// graphQLError reports whether body is a GraphQL-shaped error response: an
// "errors" array from a GraphQL processor. Used only to note that an endpoint
// exists when the schema was not exposed.
func graphQLError(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, `"errors"`) && strings.Contains(lower, "graphql")
}
