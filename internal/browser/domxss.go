package browser

import (
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/chromedp"

	"github.com/reyjayswa/asfasf/internal/checks"
)

// domPayloads returns the DOM-XSS payload templates (one %s for a token). Each
// only executes if the input reaches an HTML/JS sink in the browser.
func domPayloads(aggressive bool) []string {
	base := []string{
		`<img src=x onerror="window.__scanxss='%s'">`,
		`"><img src=x onerror="window.__scanxss='%s'">`,
	}
	if aggressive {
		base = append(base,
			`<svg onload="window.__scanxss='%s'">`,
			`<img src=x onerror="alert('%s')">`,
			`'><script>window.__scanxss='%s'</script>`,
		)
	}
	return base
}

func randToken() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return "dx" + string(b)
}

// TestDOMXSS injects DOM-XSS payloads into a parameter and confirms, inside
// the real browser, whether any reaches a client-side sink and executes. It
// tries the payload in both the query string and the URL fragment (the latter
// catches fragment-only DOM XSS the server never sees).
func (b *Browser) TestDOMXSS(ctx context.Context, ep checks.Endpoint, param string, aggressive bool) []checks.Finding {
	for _, tmpl := range domPayloads(aggressive) {
		token := randToken()
		payload := fmt.Sprintf(tmpl, token)

		q := injectQuery(ep.URL, ep.Params, param, payload)
		for _, target := range []string{q, q + "#" + payload} {
			if b.scope != nil && !b.scope.AllowsURL(target) {
				continue
			}
			if b.executes(ctx, target, token) {
				return []checks.Finding{{
					Type:        "dom-xss",
					Severity:    checks.SeverityHigh,
					Title:       "DOM-based XSS: payload executed in the browser",
					URL:         ep.URL,
					Method:      "GET",
					Parameter:   param,
					Payload:     payload,
					Evidence:    checks.Truncate("payload executed via a client-side sink at "+target, 240),
					Description: fmt.Sprintf("Input in parameter %q flows into a client-side sink (innerHTML, document.write, eval, or location) and executed in a headless browser. This is DOM-based XSS and may not appear in the raw server response.", param),
					Remediation: "Avoid writing untrusted input into dangerous DOM sinks; use textContent or safe DOM APIs, sanitize with a trusted library, and apply a strict Content-Security-Policy.",
					Confidence:  "firm",
					CWE:         "CWE-79",
					Timestamp:   time.Now(),
				}}
			}
		}
	}
	return nil
}

// executes navigates to target and reports whether the injected token ran
// (either by setting the sentinel global or firing a dialog).
func (b *Browser) executes(ctx context.Context, target, token string) bool {
	dc := &dialogCapture{}
	tctx, cancel := b.tab(b.allocCtx, dc)
	defer cancel()
	tctx, tcancel := context.WithTimeout(tctx, b.timeout)
	defer tcancel()

	var got string
	err := chromedp.Run(tctx,
		fetch.Enable(),
		chromedp.Navigate(target),
		chromedp.Sleep(500*time.Millisecond),
		chromedp.Evaluate(`window.__scanxss || ""`, &got),
	)
	if err != nil {
		return false
	}
	return got == token || dc.seen(token)
}

// injectQuery builds a URL with param set to payload and other params to "1".
func injectQuery(rawURL string, params []string, param, payload string) string {
	values := url.Values{}
	found := false
	for _, p := range params {
		if p == param {
			values.Set(p, payload)
			found = true
		} else {
			values.Set(p, "1")
		}
	}
	if !found {
		values.Set(param, payload)
	}
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + values.Encode()
}
