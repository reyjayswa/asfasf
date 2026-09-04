// Package shellexp implements an exposed-web-shell / backdoor detection
// check.
//
// It requests a small built-in list of filenames commonly used by malicious
// PHP web shells (c99, r57, WSO, b374k, alfa, generic cmd/uploader shells)
// under the target origin. A path is reported ONLY when the response body
// carries a distinctive web-shell SIGNATURE — a known shell name, a
// characteristic command/execute form, or a "Safe Mode:" + "Server IP"
// status pair. A bare HTTP 200 is deliberately NOT reported: a catch-all
// SPA answers 200 for every path, so gating on a specific content signature
// keeps the false-positive rate low.
//
// This is DEFENSIVE detection only. It finds a shell that is already present
// on a compromised host so it can be reported and removed. It never uploads
// a shell and never executes any command.
package shellexp

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/reyjayswa/asfasf/internal/checks"
	"github.com/reyjayswa/asfasf/internal/httpclient"
)

// Checker probes an origin for exposed web shells / backdoors.
type Checker struct {
	client     *httpclient.Client
	aggressive bool
}

// New builds a shell-exposure Checker. When aggressive is true, an extended
// filename list is probed in addition to the default set.
func New(client *httpclient.Client, aggressive bool) *Checker {
	return &Checker{client: client, aggressive: aggressive}
}

// Name identifies the check.
func (c *Checker) Name() string { return "shell-exposure" }

// defaultPaths is the conservative built-in wordlist of common web-shell
// filenames.
var defaultPaths = []string{
	"/shell.php",
	"/c99.php",
	"/r57.php",
	"/wso.php",
	"/b374k.php",
	"/alfa.php",
	"/cmd.php",
	"/backdoor.php",
	"/webshell.php",
	"/up.php",
	"/uploader.php",
	"/1.php",
	"/x.php",
}

// aggressivePaths is probed only in aggressive mode.
var aggressivePaths = []string{
	"/c100.php",
	"/wso2.php",
	"/alfa3.php",
	"/0.php",
	"/2.php",
	"/a.php",
	"/sh.php",
	"/gel4y.php",
	"/indoxploit.php",
	"/mini.php",
	"/shell.phtml",
}

// signature is a distinctive marker of a known web shell in the response
// body.
type signature struct {
	name    string
	pattern *regexp.Regexp
}

// signatures are checked against the response body. Each is specific enough
// that a match is strong evidence of a real web shell rather than an
// incidental page. The command-form signature requires an input named "cmd"
// together with an execute/submit control AND a "uname"/"system" reference,
// so a benign search box is not matched.
var signatures = []signature{
	{"c99shell", regexp.MustCompile(`(?i)c99shell`)},
	{"r57shell", regexp.MustCompile(`(?i)r57shell`)},
	{"WSO shell", regexp.MustCompile(`WSO 2`)},
	{"b374k shell", regexp.MustCompile(`(?i)b374k`)},
	{"alfa team shell", regexp.MustCompile(`(?i)alfa\s*team`)},
	{"shell title tag", regexp.MustCompile(`(?is)<title>[^<]*\bshell\b[^<]*</title>`)},
	{"safe-mode status panel", regexp.MustCompile(`(?is)Safe Mode:.*Server IP|Server IP.*Safe Mode:`)},
	{"command-execution form", cmdFormSignature},
}

// cmdFormSignature matches a web-shell command form: an <input> named "cmd"
// on the page, an execute/submit control, and a "uname" or "system"
// reference — the combination that a shell's command console exhibits.
var cmdFormSignature = regexp.MustCompile(`(?is)<input[^>]*name\s*=\s*["']?cmd["']?.*(?:execute|submit).*(?:uname|system)|<input[^>]*name\s*=\s*["']?cmd["']?.*(?:uname|system).*(?:execute|submit)`)

// Run probes the built-in filename list under origin and returns a Finding
// for every path whose body matches a known web-shell signature.
func (c *Checker) Run(ctx context.Context, origin string) []checks.Finding {
	var findings []checks.Finding
	base := strings.TrimRight(origin, "/")

	paths := make([]string, 0, len(defaultPaths)+len(aggressivePaths))
	paths = append(paths, defaultPaths...)
	if c.aggressive {
		paths = append(paths, aggressivePaths...)
	}

	for _, p := range paths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		target := base + p
		resp, err := c.client.Get(ctx, target)
		if err != nil || resp == nil {
			continue
		}
		if resp.Status < 200 || resp.Status >= 400 {
			continue
		}

		if f, ok := classify(target, p, resp); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

// classify reports a Finding only when the body matches a web-shell
// signature.
func classify(target, path string, resp *httpclient.Response) (checks.Finding, bool) {
	body := resp.BodyString()

	for _, sig := range signatures {
		if sig.pattern.MatchString(body) {
			return checks.Finding{
				Type:        "shell-exposure",
				Severity:    checks.SeverityCritical,
				Title:       "Exposed web shell / backdoor: " + sig.name,
				URL:         target,
				Method:      http.MethodGet,
				Evidence:    checks.Truncate("signature "+sig.name+": "+bodySnippet(body, sig.pattern), 240),
				Description: fmt.Sprintf("The path %q serves content matching a known web-shell signature (%s). An exposed web shell is a backdoor that grants an attacker arbitrary command execution on the server, and its presence indicates the host is already compromised.", path, sig.name),
				Remediation: "Treat the host as compromised: take it offline, preserve evidence for forensics, remove the malicious file, rotate all credentials and keys reachable from it, and investigate the initial access vector (typically an unrestricted file-upload or an unpatched RCE) before restoring service from a known-good backup.",
				Confidence:  "firm",
				Timestamp:   time.Now(),
			}, true
		}
	}

	return checks.Finding{}, false
}

// bodySnippet returns a short, whitespace-collapsed window of the body around
// the first regex match, for use as human-readable evidence.
func bodySnippet(body string, re *regexp.Regexp) string {
	loc := re.FindStringIndex(body)
	if loc == nil {
		return ""
	}
	start := loc[0] - 20
	if start < 0 {
		start = 0
	}
	end := loc[1] + 20
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(strings.Join(strings.Fields(body[start:end]), " "))
}
