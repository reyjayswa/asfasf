// Package oob provides an out-of-band interaction server used to confirm
// "blind" vulnerabilities — bugs that produce no visible change in the HTTP
// response but cause the target to reach out to a server the tester controls.
//
// The scanner injects a unique per-payload URL that points back at this
// listener. If the target performs a server-side request to it (SSRF), or a
// planted script later executes and calls it (blind XSS), the listener records
// the interaction and the matching check reports a confirmed finding.
//
// The callback host is intentionally outside the scan scope: the scanner only
// ever sends the primary request to an in-scope target; the target itself is
// what contacts the listener.
package oob

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Interaction records one hit on the listener.
type Interaction struct {
	Token      string    `json:"token"`
	RemoteAddr string    `json:"remote_addr"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	When       time.Time `json:"when"`
}

// Server is the interaction listener.
type Server struct {
	base    string
	srv     *http.Server
	ln      net.Listener
	mu      sync.Mutex
	hits    map[string][]Interaction
	counter int64
	nowFn   func() time.Time
}

// New creates an interaction server. listenAddr is the local bind address
// (e.g. "127.0.0.1:0" for a random port). callbackBase, if set, is the URL the
// target should reach (e.g. "http://your-host:9000"); when empty it is derived
// from the actual listen address, which is correct for local testing but must
// be set to a target-reachable address for real engagements.
func New(listenAddr, callbackBase string) (*Server, error) {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("oob listen: %w", err)
	}
	base := strings.TrimRight(callbackBase, "/")
	if base == "" {
		base = "http://" + ln.Addr().String()
	}
	s := &Server{
		base:  base,
		ln:    ln,
		hits:  make(map[string][]Interaction),
		nowFn: time.Now,
	}
	s.srv = &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 5 * time.Second}
	return s, nil
}

// Start begins serving until ctx is cancelled or Close is called.
func (s *Server) Start(ctx context.Context) {
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	go func() { _ = s.srv.Serve(s.ln) }()
}

// Close stops the listener.
func (s *Server) Close() { _ = s.srv.Close() }

// CallbackBase returns the base URL targets should call.
func (s *Server) CallbackBase() string { return s.base }

// Payload returns a fresh token and the callback URL embedding it. The prefix
// labels the source (e.g. "ssrf") for readability.
func (s *Server) Payload(prefix string) (token, url string) {
	s.mu.Lock()
	s.counter++
	n := s.counter
	s.mu.Unlock()
	token = fmt.Sprintf("%s%dz%d", prefix, n, s.nowFn().UnixNano()%100000)
	return token, s.base + "/" + token
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	token := strings.Trim(r.URL.Path, "/")
	if i := strings.IndexByte(token, '/'); i >= 0 {
		token = token[:i]
	}
	if token != "" {
		s.mu.Lock()
		s.hits[token] = append(s.hits[token], Interaction{
			Token:      token,
			RemoteAddr: r.RemoteAddr,
			Method:     r.Method,
			Path:       r.URL.Path,
			When:       s.nowFn(),
		})
		s.mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// Seen reports whether the token was called back.
func (s *Server) Seen(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.hits[token]) > 0
}

// WaitFor polls up to timeout for an interaction on token.
func (s *Server) WaitFor(ctx context.Context, token string, timeout time.Duration) (Interaction, bool) {
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		hs := s.hits[token]
		s.mu.Unlock()
		if len(hs) > 0 {
			return hs[0], true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return Interaction{}, false
		}
		select {
		case <-ctx.Done():
			return Interaction{}, false
		case <-time.After(50 * time.Millisecond):
		}
	}
}
