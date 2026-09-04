// Package httpclient provides the one HTTP client the whole scanner shares.
//
// It centralizes three concerns so no other package has to worry about
// them: a global rate limit (requests per second), a hard scope check on
// every outbound URL, and consistent timeouts, headers, and body-size
// caps. Because scope is enforced here as well as in the crawler, a bug in
// a check can never cause a request to a host outside the authorized list.
package httpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/scope"
)

// maxBodyBytes bounds how much of any response we read into memory.
const maxBodyBytes = 2 << 20 // 2 MiB

// Response is a captured HTTP response with its body already read.
type Response struct {
	Status  int
	Header  http.Header
	Body    []byte
	URL     string
	Elapsed time.Duration
}

// Client is a scope-aware, rate-limited HTTP client.
type Client struct {
	hc      *http.Client
	scope   *scope.Matcher
	ua      string
	limiter <-chan time.Time
	stop    chan struct{}

	// counters (read via Stats); guarded loosely since exact counts under
	// concurrency are informational only.
	requests int64
	blocked  int64
}

// New builds a Client from config and a compiled scope matcher.
func New(cfg config.HTTP, sc *scope.Matcher) *Client {
	interval := time.Duration(float64(time.Second) / cfg.RatePerSecond)
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: cfg.Concurrency,
		IdleConnTimeout:     30 * time.Second,
	}

	c := &Client{
		hc: &http.Client{
			Timeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
			Transport: transport,
		},
		scope:   sc,
		ua:      cfg.UserAgent,
		limiter: ticker.C,
		stop:    make(chan struct{}),
	}
	// By default we do not follow redirects: the raw 3xx and Location are
	// more useful for detection (open redirect, auth boundaries).
	if !cfg.FollowRedirect {
		c.hc.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}

// Do issues a request after waiting for a rate-limit token and confirming
// the target URL is in scope. An out-of-scope URL returns an error and is
// never sent on the wire.
func (c *Client) Do(ctx context.Context, method, rawURL string, body io.Reader, headers map[string]string) (*Response, error) {
	if !c.scope.AllowsURL(rawURL) {
		c.blocked++
		return nil, fmt.Errorf("refusing out-of-scope request to %s", rawURL)
	}

	// Wait for a rate-limit token or cancellation.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.limiter:
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "*/*")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	start := time.Now()
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.requests++

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	return &Response{
		Status:  resp.StatusCode,
		Header:  resp.Header,
		Body:    data,
		URL:     rawURL,
		Elapsed: time.Since(start),
	}, nil
}

// Get is a convenience wrapper for GET requests.
func (c *Client) Get(ctx context.Context, rawURL string) (*Response, error) {
	return c.Do(ctx, http.MethodGet, rawURL, nil, nil)
}

// PostForm issues a urlencoded POST.
func (c *Client) PostForm(ctx context.Context, rawURL, form string) (*Response, error) {
	return c.Do(ctx, http.MethodPost, rawURL, strings.NewReader(form), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

// Stats returns the number of sent and scope-blocked requests.
func (c *Client) Stats() (sent, blocked int64) {
	return c.requests, c.blocked
}

// BodyString returns the response body as a string.
func (r *Response) BodyString() string { return string(r.Body) }
