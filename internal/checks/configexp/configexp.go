// Package configexp detects exposure of sensitive files and configuration
// artifacts on a target origin. It probes a small built-in list of well-known
// sensitive paths and reports a finding only when the response body or headers
// match a signature specific to that file, rather than merely returning HTTP
// 200. This keeps false positives low against catch-all SPAs and soft-404
// handlers that answer 200 for every path.
package configexp

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// Checker probes an origin for exposed sensitive files.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New constructs a config-exposure checker bound to the given HTTP client. When
// aggressive is true, a larger set of paths is probed.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name returns the stable identifier of this check.
func (c *Checker) Name() string { return "config-exposure" }

// probe describes one path to fetch and how to decide whether the response is a
// genuine exposure of the target file.
type probe struct {
	path     string
	severity checks.Severity
	title    string
	desc     string
	remedy   string
	// match inspects the response body and reports whether it is a real
	// signature hit plus a short evidence snippet.
	match func(body []byte) (bool, string)
}

// containsAll reports whether body contains every substring in subs
// (case-insensitive).
func containsAll(body []byte, subs ...string) bool {
	lower := bytes.ToLower(body)
	for _, s := range subs {
		if !bytes.Contains(lower, []byte(strings.ToLower(s))) {
			return false
		}
	}
	return true
}

// containsAny reports whether body contains any substring in subs
// (case-insensitive) and returns the first one matched.
func containsAny(body []byte, subs ...string) (bool, string) {
	lower := bytes.ToLower(body)
	for _, s := range subs {
		if bytes.Contains(lower, []byte(strings.ToLower(s))) {
			return true, s
		}
	}
	return false, ""
}

// envSignature matches a dotenv file: KEY=VALUE lines plus at least one
// high-signal secret key.
func envSignature(body []byte) (bool, string) {
	if ok, hit := containsAny(body, "APP_KEY=", "DB_PASSWORD=", "SECRET"); ok {
		// Confirm dotenv shape: at least one KEY=VALUE line.
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if eq := strings.IndexByte(line, '='); eq > 0 {
				key := strings.TrimSpace(line[:eq])
				if key != "" && !strings.ContainsAny(key, " \t<>") {
					return true, hit + " (dotenv)"
				}
			}
		}
	}
	return false, ""
}

func (c *Checker) probes() []probe {
	ps := []probe{
		{
			path:     "/.env",
			severity: checks.SeverityCritical,
			title:    "Exposed .env environment file",
			desc:     "The application's .env file is publicly retrievable and contains application secrets (keys, database credentials).",
			remedy:   "Remove the .env file from the web root and block access to dotfiles at the web server. Rotate any exposed credentials.",
			match:    envSignature,
		},
		{
			path:     "/.git/config",
			severity: checks.SeverityHigh,
			title:    "Exposed .git/config",
			desc:     "The .git/config file is publicly retrievable, indicating the full Git repository may be downloadable and reveals source code and history.",
			remedy:   "Remove the .git directory from the web root and block access to it at the web server.",
			match: func(b []byte) (bool, string) {
				if containsAll(b, "[core]", "repositoryformatversion") {
					return true, "[core] repositoryformatversion"
				}
				return false, ""
			},
		},
		{
			path:     "/.git/HEAD",
			severity: checks.SeverityMedium,
			title:    "Exposed .git/HEAD",
			desc:     "The .git/HEAD file is publicly retrievable, indicating a Git repository is present under the web root.",
			remedy:   "Remove the .git directory from the web root and block access to it at the web server.",
			match: func(b []byte) (bool, string) {
				if bytes.HasPrefix(bytes.TrimLeft(b, " \t"), []byte("ref: refs/")) {
					return true, "ref: refs/"
				}
				return false, ""
			},
		},
		{
			path:     "/wp-config.php.bak",
			severity: checks.SeverityCritical,
			title:    "Exposed WordPress config backup",
			desc:     "A backup of wp-config.php is publicly retrievable and exposes the WordPress database credentials.",
			remedy:   "Delete backup copies of wp-config.php from the web root and rotate the database credentials.",
			match: func(b []byte) (bool, string) {
				return containsAny(b, "DB_PASSWORD", "DB_NAME")
			},
		},
		{
			path:     "/wp-config.php~",
			severity: checks.SeverityCritical,
			title:    "Exposed WordPress config backup",
			desc:     "A backup of wp-config.php is publicly retrievable and exposes the WordPress database credentials.",
			remedy:   "Delete backup copies of wp-config.php from the web root and rotate the database credentials.",
			match: func(b []byte) (bool, string) {
				return containsAny(b, "DB_PASSWORD", "DB_NAME")
			},
		},
		{
			path:     "/wp-config.php.save",
			severity: checks.SeverityCritical,
			title:    "Exposed WordPress config backup",
			desc:     "A backup of wp-config.php is publicly retrievable and exposes the WordPress database credentials.",
			remedy:   "Delete backup copies of wp-config.php from the web root and rotate the database credentials.",
			match: func(b []byte) (bool, string) {
				return containsAny(b, "DB_PASSWORD", "DB_NAME")
			},
		},
		{
			path:     "/config.php.bak",
			severity: checks.SeverityHigh,
			title:    "Exposed PHP config backup",
			desc:     "A backup of a PHP configuration file is publicly retrievable and may expose credentials.",
			remedy:   "Delete backup copies of PHP source from the web root and rotate any exposed credentials.",
			match:    phpConfigSignature,
		},
		{
			path:     "/config.php~",
			severity: checks.SeverityHigh,
			title:    "Exposed PHP config backup",
			desc:     "A backup of a PHP configuration file is publicly retrievable and may expose credentials.",
			remedy:   "Delete backup copies of PHP source from the web root and rotate any exposed credentials.",
			match:    phpConfigSignature,
		},
		{
			path:     "/.DS_Store",
			severity: checks.SeverityLow,
			title:    "Exposed .DS_Store file",
			desc:     "A macOS .DS_Store file is publicly retrievable and can leak directory and file names.",
			remedy:   "Remove .DS_Store files from the web root and block access to dotfiles at the web server.",
			match: func(b []byte) (bool, string) {
				if len(b) >= 8 && bytes.HasPrefix(b, []byte{0x00, 0x00, 0x00, 0x01}) && bytes.Contains(b[4:8], []byte("Bud1")) {
					return true, "Bud1 .DS_Store header"
				}
				return false, ""
			},
		},
		{
			path:     "/phpinfo.php",
			severity: checks.SeverityMedium,
			title:    "Exposed phpinfo() output",
			desc:     "A phpinfo() page is publicly accessible and discloses PHP configuration, loaded modules, and server paths.",
			remedy:   "Remove phpinfo pages from production servers.",
			match:    phpinfoSignature,
		},
		{
			path:     "/info.php",
			severity: checks.SeverityMedium,
			title:    "Exposed phpinfo() output",
			desc:     "A phpinfo() page is publicly accessible and discloses PHP configuration, loaded modules, and server paths.",
			remedy:   "Remove phpinfo pages from production servers.",
			match:    phpinfoSignature,
		},
		{
			path:     "/backup.sql",
			severity: checks.SeverityHigh,
			title:    "Exposed SQL dump",
			desc:     "A SQL database dump is publicly retrievable and may expose the full contents of the database.",
			remedy:   "Remove database dumps from the web root and rotate any exposed credentials.",
			match:    sqlDumpSignature,
		},
		{
			path:     "/database.sql",
			severity: checks.SeverityHigh,
			title:    "Exposed SQL dump",
			desc:     "A SQL database dump is publicly retrievable and may expose the full contents of the database.",
			remedy:   "Remove database dumps from the web root and rotate any exposed credentials.",
			match:    sqlDumpSignature,
		},
		{
			path:     "/dump.sql",
			severity: checks.SeverityHigh,
			title:    "Exposed SQL dump",
			desc:     "A SQL database dump is publicly retrievable and may expose the full contents of the database.",
			remedy:   "Remove database dumps from the web root and rotate any exposed credentials.",
			match:    sqlDumpSignature,
		},
		{
			path:     "/.htaccess",
			severity: checks.SeverityLow,
			title:    "Exposed .htaccess file",
			desc:     "The Apache .htaccess file is publicly retrievable and can leak rewrite rules and access-control configuration.",
			remedy:   "Block access to .htaccess at the web server (this is the default in modern Apache).",
			match: func(b []byte) (bool, string) {
				return containsAny(b, "RewriteEngine", "Order allow")
			},
		},
	}

	if c.aggressive {
		ps = append(ps,
			probe{
				path:     "/.env.local",
				severity: checks.SeverityCritical,
				title:    "Exposed .env.local environment file",
				desc:     "A local .env override file is publicly retrievable and contains application secrets.",
				remedy:   "Remove the file from the web root, block dotfiles, and rotate exposed credentials.",
				match:    envSignature,
			},
			probe{
				path:     "/.env.production",
				severity: checks.SeverityCritical,
				title:    "Exposed .env.production environment file",
				desc:     "A production .env file is publicly retrievable and contains application secrets.",
				remedy:   "Remove the file from the web root, block dotfiles, and rotate exposed credentials.",
				match:    envSignature,
			},
			probe{
				path:     "/config.json",
				severity: checks.SeverityMedium,
				title:    "Exposed config.json",
				desc:     "A JSON configuration file is publicly retrievable and may expose secrets or credentials.",
				remedy:   "Remove the file from the web root and rotate any exposed secrets.",
				match:    jsonSecretSignature,
			},
			probe{
				path:     "/appsettings.json",
				severity: checks.SeverityHigh,
				title:    "Exposed appsettings.json",
				desc:     "An ASP.NET appsettings.json file is publicly retrievable and commonly exposes connection strings and secrets.",
				remedy:   "Remove the file from the web root and rotate any exposed connection strings and secrets.",
				match: func(b []byte) (bool, string) {
					if ok, hit := jsonSecretSignature(b); ok {
						return ok, hit
					}
					return containsAny(b, "ConnectionStrings", "DefaultConnection")
				},
			},
			probe{
				path:     "/.svn/entries",
				severity: checks.SeverityMedium,
				title:    "Exposed .svn/entries",
				desc:     "A Subversion metadata file is publicly retrievable, indicating a working copy is present under the web root.",
				remedy:   "Remove the .svn directory from the web root and block access to it.",
				match: func(b []byte) (bool, string) {
					trimmed := strings.TrimSpace(string(b))
					// Old format begins with a numeric version; newer working
					// copies use "dir".
					if strings.HasPrefix(trimmed, "12\n") || strings.HasPrefix(trimmed, "10\n") ||
						strings.HasPrefix(trimmed, "8\n") || strings.Contains(trimmed, "\ndir\n") ||
						strings.HasPrefix(trimmed, "dir\n") {
						return true, "svn entries format"
					}
					return false, ""
				},
			},
			probe{
				path:     "/composer.lock",
				severity: checks.SeverityLow,
				title:    "Exposed composer.lock",
				desc:     "The composer.lock file is publicly retrievable and discloses exact PHP dependency versions, aiding targeted attacks.",
				remedy:   "Block access to composer.lock at the web server.",
				match: func(b []byte) (bool, string) {
					if containsAll(b, "\"packages\"", "\"content-hash\"") {
						return true, "composer.lock packages/content-hash"
					}
					return false, ""
				},
			},
			probe{
				path:     "/package.json",
				severity: checks.SeverityLow,
				title:    "Exposed package.json",
				desc:     "The package.json file is publicly retrievable and discloses Node dependency versions, aiding targeted attacks.",
				remedy:   "Block access to package.json if it is not intended to be public.",
				match: func(b []byte) (bool, string) {
					if containsAll(b, "\"dependencies\"") && containsAny2(b, "\"version\"", "\"name\"") {
						return true, "package.json dependencies"
					}
					return false, ""
				},
			},
		)
	}
	return ps
}

// containsAny2 is a boolean-only helper.
func containsAny2(body []byte, subs ...string) bool {
	ok, _ := containsAny(body, subs...)
	return ok
}

func phpConfigSignature(b []byte) (bool, string) {
	if containsAll(b, "<?php") {
		if ok, hit := containsAny(b, "password", "DB_", "DB_PASSWORD", "database"); ok {
			return true, "<?php + " + hit
		}
	}
	return false, ""
}

func phpinfoSignature(b []byte) (bool, string) {
	return containsAny(b, "phpinfo()", "PHP Version")
}

func sqlDumpSignature(b []byte) (bool, string) {
	return containsAny(b, "INSERT INTO", "CREATE TABLE")
}

func jsonSecretSignature(b []byte) (bool, string) {
	// Must look like JSON and carry a secret-ish key.
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false, ""
	}
	return containsAny(b, "password", "secret", "apikey", "api_key", "connectionstring", "token")
}

// Run probes the origin for exposed sensitive files and returns findings.
func (c *Checker) Run(ctx context.Context, origin string) []checks.Finding {
	origin = strings.TrimRight(origin, "/")
	var findings []checks.Finding

	for _, p := range c.probes() {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		url := origin + p.path
		resp, err := c.client.Get(ctx, url)
		if err != nil || resp == nil {
			continue
		}
		// A signature-based match; ignore obvious non-content responses.
		if resp.Status >= 400 || resp.Status == 0 {
			continue
		}
		if len(resp.Body) == 0 {
			continue
		}

		ok, sig := p.match(resp.Body)
		if !ok {
			continue
		}

		evidence := fmt.Sprintf("signature: %s | snippet: %s", sig, previewBody(resp.Body))
		findings = append(findings, checks.Finding{
			Type:        "config-exposure",
			Severity:    p.severity,
			Title:       p.title,
			URL:         url,
			Method:      "GET",
			Evidence:    checks.Truncate(evidence, 240),
			Description: p.desc,
			Remediation: p.remedy,
			Confidence:  "firm",
			Timestamp:   time.Now(),
		})
	}
	return findings
}

// previewBody returns a printable, single-line preview of the response body.
func previewBody(b []byte) string {
	// Replace non-printable bytes so binary files (like .DS_Store) stay readable.
	var sb strings.Builder
	limit := len(b)
	if limit > 160 {
		limit = 160
	}
	for _, r := range string(b[:limit]) {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			sb.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			sb.WriteByte('.')
		default:
			sb.WriteRune(r)
		}
	}
	return strings.TrimSpace(sb.String())
}
