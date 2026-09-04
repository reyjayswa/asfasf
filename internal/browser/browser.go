// Package browser drives the pre-installed headless Chromium (via chromedp)
// to scan JavaScript-heavy applications the plain HTML crawler cannot:
//
//   - Discover renders a page, runs its scripts, and returns the post-render
//     HTML plus links the DOM produced (SPA routes, JS-built menus).
//   - TestDOMXSS injects payloads that only fire if attacker input reaches a
//     client-side sink (innerHTML, document.write, eval, location), and
//     confirms execution inside the real browser — catching DOM-based XSS
//     that never touches the server response body.
//
// Scope is still enforced: the browser never navigates to an out-of-scope URL,
// and every subresource the page tries to load is checked against the same
// scope matcher and aborted if it points off-scope.
package browser

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/reyjayswa/asfasf/internal/scope"
)

// chromePath returns a usable Chromium/Chrome executable path, or "".
func chromePath() string {
	candidates := []string{
		os.Getenv("SCANNER_CHROME"),
		"/opt/pw-browsers/chromium",
		"/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/usr/bin/google-chrome",
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// Available reports whether a headless browser can be launched here.
func Available() bool { return chromePath() != "" }

// Browser is a scope-aware headless Chromium driver.
type Browser struct {
	allocCtx context.Context
	cancel   context.CancelFunc
	scope    *scope.Matcher
	timeout  time.Duration
}

// New launches a shared headless browser allocator. Callers must Close it.
func New(sc *scope.Matcher, timeoutSeconds int) (*Browser, error) {
	path := chromePath()
	if path == "" {
		return nil, fmt.Errorf("no chromium/chrome executable found (set SCANNER_CHROME)")
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 20
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(path),
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		// Keep Chromium from making its own external calls (connectivity
		// checks, component/safebrowsing updates, sync, telemetry), so the
		// browser only ever talks to in-scope targets.
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-component-update", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("safebrowsing-disable-auto-update", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("mute-audio", true),
	)
	alloc, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	return &Browser{
		allocCtx: alloc,
		cancel:   cancel,
		scope:    sc,
		timeout:  time.Duration(timeoutSeconds) * time.Second,
	}, nil
}

// Close releases the browser.
func (b *Browser) Close() {
	if b.cancel != nil {
		b.cancel()
	}
}

// tab creates a fresh browser tab whose subresource requests are filtered by
// scope. dialog, if non-nil, receives the text of any JavaScript dialog
// (alert/confirm) that opens, which is auto-dismissed.
func (b *Browser) tab(parent context.Context, dialog *dialogCapture) (context.Context, context.CancelFunc) {
	ctx, cancel := chromedp.NewContext(parent)
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *fetch.EventRequestPaused:
			go func() {
				c := chromedp.FromContext(ctx)
				ectx := cdp.WithExecutor(ctx, c.Target)
				if b.scope != nil && !b.scope.AllowsURL(e.Request.URL) {
					_ = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(ectx)
					return
				}
				_ = fetch.ContinueRequest(e.RequestID).Do(ectx)
			}()
		case *page.EventJavascriptDialogOpening:
			go func() {
				c := chromedp.FromContext(ctx)
				ectx := cdp.WithExecutor(ctx, c.Target)
				if dialog != nil {
					dialog.record(e.Message)
				}
				_ = page.HandleJavaScriptDialog(false).Do(ectx)
			}()
		}
	})
	return ctx, cancel
}

// dialogCapture collects JavaScript dialog messages seen in a tab.
type dialogCapture struct {
	mu   sync.Mutex
	msgs []string
}

func (d *dialogCapture) record(m string) {
	d.mu.Lock()
	d.msgs = append(d.msgs, m)
	d.mu.Unlock()
}

func (d *dialogCapture) seen(token string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, m := range d.msgs {
		if strings.Contains(m, token) {
			return true
		}
	}
	return false
}

// Discover renders url and returns the post-JavaScript HTML and the absolute
// links present in the rendered DOM. Out-of-scope URLs return an error.
func (b *Browser) Discover(ctx context.Context, url string) (html string, links []string, err error) {
	if b.scope != nil && !b.scope.AllowsURL(url) {
		return "", nil, fmt.Errorf("refusing out-of-scope navigation to %s", url)
	}
	tctx, cancel := b.tab(b.allocCtx, nil)
	defer cancel()
	tctx, tcancel := context.WithTimeout(tctx, b.timeout)
	defer tcancel()

	err = chromedp.Run(tctx,
		fetch.Enable(),
		chromedp.Navigate(url),
		chromedp.Sleep(400*time.Millisecond),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
		chromedp.Evaluate(linksJS, &links),
	)
	if err != nil {
		return "", nil, err
	}
	return html, links, nil
}

// linksJS collects absolute hrefs from the rendered DOM.
const linksJS = `Array.from(document.querySelectorAll('a[href]')).map(function(a){return a.href;})`
