# asfasf-scanner

A scope-enforced web vulnerability scanner for **authorized** security testing,
such as bug bounty programs where you have explicit permission to test the
in-scope assets. It crawls a target, discovers request endpoints and
parameters, fingerprints the technology stack, and probes for reflected XSS
and SQL injection. Results are available as a CLI summary, a JSON report, an
HTML report, and a local web dashboard.

> ⚠️ **Authorized use only.** Only run this against systems you own or are
> explicitly permitted to test. Scope is mandatory and enforced: the scanner
> refuses to send a request to any host not listed in `scope.in_scope`, and
> there is no flag to bypass it.

## Features

- **Mandatory scope enforcement** — exact hosts and `*.wildcard` subdomains,
  with an `out_of_scope` list that always wins. Enforced twice: in the crawler
  and again in the shared HTTP client, so a bug in a check can never reach an
  unauthorized host.
- **Intensity modes** so you can match a program's rules:
  - `passive` — crawl, discover, and fingerprint only. **No payloads are ever
    sent.** Use this where active/automated testing is disallowed.
  - `safe` (default) — one non-destructive probe per parameter per check.
  - `aggressive` — extra payload variants for higher coverage. Still no
    time-based or denial-of-service payloads.
- **Recon & discovery** — breadth-first crawl with depth/page limits, link and
  HTML-form parameter discovery, and signature-based tech fingerprinting.
- **Injection checks**
  - Reflected XSS via uniquely-tagged HTML breakout markers (multiple contexts
    in aggressive mode).
  - SQL injection: error-based, boolean-based, and an **opt-in** bounded
    time-based blind probe (single short delay with a zero-delay control to
    rule out jitter — a detection probe, not a load test).
- **Global rate limiting** and bounded concurrency to stay polite.
- **Reports**: CLI summary, JSON, self-contained HTML, and a localhost web
  dashboard with a re-scan button.

### Explicitly out of scope

This tool does **not** include denial-of-service or resource-exhaustion
capabilities (traffic floods, giant/looped sleeps, ReDoS bombs). Nearly every
bug bounty program forbids DoS, and it causes real harm. Load testing against a
system you own is a different tool.

## Install / build

```sh
go build -o scanner ./cmd/scanner
```

Requires Go 1.24+.

## Quick start

```sh
# 1. Generate a config and edit the scope + seeds
./scanner init -o scope.yaml

# 2. Run a scan and write reports
./scanner scan -config scope.yaml -json report.json -html report.html

# 3. Or browse results in a local dashboard
./scanner serve -config scope.yaml -addr 127.0.0.1:8080
```

## Configuration

```yaml
mode: safe                 # passive | safe | aggressive

scope:
  in_scope:
    - "example.com"        # exact host
    - "*.example.com"      # any subdomain (not the apex)
  out_of_scope:
    - "admin.example.com"  # excluded even though the wildcard matches it

seeds:
  - "https://example.com/"

crawl:
  max_depth: 3
  max_pages: 200
  same_host_only: true

http:
  rate_per_second: 5
  concurrency: 5
  timeout_seconds: 15
  user_agent: "asfasf-scanner/0.1 (authorized security testing)"
  follow_redirect: false

checks:
  xss: true
  sqli: true
  sqli_time_based: false   # opt-in bounded blind probe
  sqli_delay_seconds: 3    # clamped to 1..10
```

Every seed must itself fall inside `scope.in_scope`, or the scanner refuses to
start. The `mode` in the file can be overridden per run with `-mode`.

## Commands

| Command | Purpose |
|---------|---------|
| `scan`  | Run a scan; write `-json` / `-html` reports; print a summary. |
| `serve` | Run a scan and serve an HTML dashboard on `-addr` (localhost by default), with a re-scan button and a `/report.json` endpoint. |
| `init`  | Write a documented example config. |

Common flags: `-config <file>` (required for scan/serve), `-mode`, `-quiet`.

## Architecture

```
cmd/scanner            CLI (scan / serve / init)
internal/config        scope config loading + validation (scope is mandatory)
internal/scope         host allow/deny matcher (wildcards, out-of-scope wins)
internal/httpclient    shared rate-limited, scope-checked HTTP client
internal/crawler       BFS crawl + link/form/parameter discovery
internal/fingerprint   tech + version-disclosure detection
internal/checks        shared Finding / Endpoint types
internal/checks/xss    reflected XSS check
internal/checks/sqli   error / boolean / time-based SQLi checks
internal/engine        orchestration -> Report
internal/report        JSON + HTML rendering
internal/dashboard     localhost web UI
```

## Notes on accuracy

Findings are automated signals and can include false positives, especially the
`tentative` ones (encoded reflections, boolean-based SQLi). Always manually
verify before reporting to a program.

## Development

```sh
go test ./...
go vet ./...
```
