// Package httpclient provides the one HTTP client the whole scanner shares.
//
// It centralizes three concerns so no other package has to worry about
// them: a global rate limit (requests per second), a hard scope check on
// every outbound URL, and consistent timeouts, headers, and body-size
// caps. Because scope is enforced here as well as in the crawler, a bug in
// a check can never cause a request to a host outside the authorized list.
package httpclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
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

	// backoffMs is an adaptive extra delay (milliseconds) applied before each
	// request. It grows when the target returns HTTP 429 and decays on
	// success, so the scanner automatically slows down under rate limiting.
	backoffMs   int64
	rateLimited int64
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

// Do issues a request after waiting for a rate-limit token and confirming the
// target URL is in scope. An out-of-scope URL returns an error and is never
// sent on the wire. On HTTP 429 the client honors Retry-After, grows an
// adaptive backoff, and retries the request once.
func (c *Client) Do(ctx context.Context, method, rawURL string, body io.Reader, headers map[string]string) (*Response, error) {
	if !c.scope.AllowsURL(rawURL) {
		atomic.AddInt64(&c.blocked, 1)
		return nil, fmt.Errorf("refusing out-of-scope request to %s", rawURL)
	}

	// Buffer the body so the request can be retried after a 429.
	var buf []byte
	if body != nil {
		var err error
		buf, err = io.ReadAll(body)
		if err != nil {
			return nil, err
		}
	}

	const maxRetries = 1
	for attempt := 0; ; attempt++ {
		if err := c.waitTurn(ctx); err != nil {
			return nil, err
		}
		resp, err := c.send(ctx, method, rawURL, buf, headers)
		if err != nil {
			return nil, err
		}
		if resp.Status == http.StatusTooManyRequests && attempt < maxRetries {
			atomic.AddInt64(&c.rateLimited, 1)
			c.growBackoff()
			if err := c.honorRetryAfter(ctx, resp.Header.Get("Retry-After")); err != nil {
				return nil, err
			}
			continue
		}
		c.decayBackoff()
		return resp, nil
	}
}

// waitTurn blocks for a rate-limit token, then for any adaptive backoff delay.
func (c *Client) waitTurn(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.limiter:
	}
	if b := atomic.LoadInt64(&c.backoffMs); b > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(b) * time.Millisecond):
		}
	}
	return nil
}

// send performs one HTTP request and reads its (bounded) body.
func (c *Client) send(ctx context.Context, method, rawURL string, buf []byte, headers map[string]string) (*Response, error) {
	var body io.Reader
	if buf != nil {
		body = bytes.NewReader(buf)
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
	if buf != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	start := time.Now()
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	atomic.AddInt64(&c.requests, 1)

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

// growBackoff increases the adaptive delay (capped at 10s).
func (c *Client) growBackoff() {
	for {
		old := atomic.LoadInt64(&c.backoffMs)
		next := old + 500
		if next > 10000 {
			next = 10000
		}
		if atomic.CompareAndSwapInt64(&c.backoffMs, old, next) {
			return
		}
	}
}

// decayBackoff eases the adaptive delay back toward zero on success.
func (c *Client) decayBackoff() {
	for {
		old := atomic.LoadInt64(&c.backoffMs)
		if old == 0 {
			return
		}
		next := old - 100
		if next < 0 {
			next = 0
		}
		if atomic.CompareAndSwapInt64(&c.backoffMs, old, next) {
			return
		}
	}
}

// honorRetryAfter sleeps for a Retry-After header value (seconds form),
// bounded to 30s, respecting context cancellation.
func (c *Client) honorRetryAfter(ctx context.Context, header string) error {
	secs, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || secs <= 0 {
		return nil
	}
	if secs > 30 {
		secs = 30
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Duration(secs) * time.Second):
		return nil
	}
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
	return atomic.LoadInt64(&c.requests), atomic.LoadInt64(&c.blocked)
}

// RateLimited returns how many times the target responded with HTTP 429.
func (c *Client) RateLimited() int64 { return atomic.LoadInt64(&c.rateLimited) }

// BodyString returns the response body as a string.
func (r *Response) BodyString() string { return string(r.Body) }
