// Package dashboard serves a scan Report over HTTP as a local web UI. It
// renders the same HTML as the file report, exposes the raw JSON, and lets
// the operator trigger a re-scan from the browser. It binds to localhost by
// default so results are not exposed to the network.
package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/reyjayswa/asfasf/internal/config"
	"github.com/reyjayswa/asfasf/internal/engine"
	"github.com/reyjayswa/asfasf/internal/report"
)

// Server hosts the dashboard for a single configuration.
type Server struct {
	cfg  *config.Config
	addr string
	log  engine.Logger

	mu       sync.RWMutex
	rep      *engine.Report
	scanning bool
	lastErr  string
}

// NewServer builds a dashboard server. addr is a host:port bind address.
func NewServer(cfg *config.Config, addr string, log engine.Logger) *Server {
	if log == nil {
		log = func(string, ...interface{}) {}
	}
	return &Server{cfg: cfg, addr: addr, log: log}
}

// SetReport seeds the dashboard with an already-computed report.
func (s *Server) SetReport(rep *engine.Report) {
	s.mu.Lock()
	s.rep = rep
	s.mu.Unlock()
}

// Scan runs a scan synchronously and caches the result.
func (s *Server) Scan(ctx context.Context) error {
	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		return fmt.Errorf("scan already in progress")
	}
	s.scanning = true
	s.lastErr = ""
	s.mu.Unlock()

	eng, err := engine.New(s.cfg, s.log)
	if err != nil {
		s.mu.Lock()
		s.scanning = false
		s.lastErr = err.Error()
		s.mu.Unlock()
		return err
	}
	rep := eng.Run(ctx)

	s.mu.Lock()
	s.rep = rep
	s.scanning = false
	s.mu.Unlock()
	return nil
}

// ListenAndServe starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/report.json", s.handleJSON)
	mux.HandleFunc("/rescan", s.handleRescan)

	srv := &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	s.log("dashboard listening on http://%s", s.addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.mu.RLock()
	rep, scanning, lastErr := s.rep, s.scanning, s.lastErr
	s.mu.RUnlock()

	if rep == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, waitingPage, statusText(scanning, lastErr))
		return
	}
	html, err := report.RenderHTML(rep)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Inject a small control bar with the rescan button.
	w.Write(injectControls(html, scanning))
}

func (s *Server) handleJSON(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	rep := s.rep
	s.mu.RUnlock()
	if rep == nil {
		http.Error(w, `{"error":"no report yet"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
}

func (s *Server) handleRescan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if err := s.Scan(ctx); err != nil {
			s.log("rescan error: %v", err)
		}
	}()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func statusText(scanning bool, lastErr string) string {
	if lastErr != "" {
		return "Error: " + lastErr
	}
	if scanning {
		return "Scanning…"
	}
	return "No report yet."
}

const waitingPage = `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Scanner dashboard</title>
<meta http-equiv="refresh" content="3">
<style>body{background:#0f1117;color:#e6e9ef;font:15px system-ui;margin:0;
display:flex;align-items:center;justify-content:center;height:100vh}
.box{text-align:center}form{margin-top:16px}
button{background:#5b9dff;border:0;color:#0b0d12;font-weight:600;
padding:10px 18px;border-radius:8px;cursor:pointer}</style></head>
<body><div class="box"><h1>Web Vulnerability Scanner</h1>
<p>%s</p>
<form method="post" action="/rescan"><button>Run scan</button></form>
</div></body></html>`

// injectControls prepends a small fixed control bar with a rescan button to
// the rendered report HTML.
func injectControls(html []byte, scanning bool) []byte {
	label := "Re-run scan"
	if scanning {
		label = "Scanning…"
	}
	bar := fmt.Sprintf(`<div style="position:sticky;top:0;z-index:10;background:#12151d;
border-bottom:1px solid #2a2f3a;padding:8px 16px;display:flex;gap:10px;align-items:center">
<form method="post" action="/rescan" style="margin:0">
<button style="background:#5b9dff;border:0;color:#0b0d12;font-weight:600;
padding:6px 14px;border-radius:7px;cursor:pointer">%s</button></form>
<a href="/report.json" style="color:#5b9dff;font-size:13px">Raw JSON</a></div>`, label)
	// Insert right after <body>.
	marker := []byte("<body>")
	idx := indexOf(html, marker)
	if idx < 0 {
		return html
	}
	insertAt := idx + len(marker)
	out := make([]byte, 0, len(html)+len(bar))
	out = append(out, html[:insertAt]...)
	out = append(out, []byte(bar)...)
	out = append(out, html[insertAt:]...)
	return out
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}
