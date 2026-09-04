// Package scope compiles the configured host patterns into an efficient
// matcher and answers a single question for every request the scanner is
// about to make: is this URL inside the authorized scope?
//
// Out-of-scope patterns always win over in-scope patterns, so a broad
// "*.example.com" can be safely combined with an explicit
// "admin.example.com" exclusion.
package scope

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/reyjayswa/asfasf/internal/config"
)

// Matcher decides whether URLs are in scope.
type Matcher struct {
	in  []pattern
	out []pattern
}

type pattern struct {
	raw      string
	host     string // the host portion, lower-cased
	wildcard bool   // true when the pattern was "*.something"
}

func compile(raw string) (pattern, error) {
	h := strings.ToLower(strings.TrimSpace(raw))
	if h == "" {
		return pattern{}, fmt.Errorf("empty host pattern")
	}
	// Strip an accidental scheme or path if the user pasted a URL.
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimPrefix(h, "https://")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	p := pattern{raw: raw}
	if strings.HasPrefix(h, "*.") {
		p.wildcard = true
		p.host = h[2:]
	} else {
		p.host = h
	}
	if p.host == "" {
		return pattern{}, fmt.Errorf("invalid host pattern %q", raw)
	}
	return p, nil
}

func (p pattern) matches(host string) bool {
	host = strings.ToLower(host)
	// Ignore any port on the request host.
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if p.wildcard {
		// "*.example.com" matches any strict subdomain, not the apex.
		return strings.HasSuffix(host, "."+p.host)
	}
	return host == p.host
}

// New compiles the in- and out-of-scope patterns from the config.
func New(s config.Scope) (*Matcher, error) {
	m := &Matcher{}
	for _, raw := range s.InScope {
		p, err := compile(raw)
		if err != nil {
			return nil, fmt.Errorf("in_scope: %w", err)
		}
		m.in = append(m.in, p)
	}
	for _, raw := range s.OutOfScope {
		p, err := compile(raw)
		if err != nil {
			return nil, fmt.Errorf("out_of_scope: %w", err)
		}
		m.out = append(m.out, p)
	}
	if len(m.in) == 0 {
		return nil, fmt.Errorf("no in-scope patterns compiled")
	}
	return m, nil
}

// AllowsHost reports whether a bare host is in scope.
func (m *Matcher) AllowsHost(host string) bool {
	for _, p := range m.out {
		if p.matches(host) {
			return false
		}
	}
	for _, p := range m.in {
		if p.matches(host) {
			return true
		}
	}
	return false
}

// AllowsURL parses rawURL and reports whether it is in scope. A URL that
// cannot be parsed, lacks a host, or does not use http/https is treated as
// out of scope. The scheme check is defense-in-depth: the scanner never has
// a reason to touch non-web schemes.
func (m *Matcher) AllowsURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return m.AllowsHost(u.Host)
}
