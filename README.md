# asfasf-scanner

A scope-enforced web vulnerability scanner for **authorized** security testing,
such as bug bounty programs where you have explicit permission to test the
in-scope assets. It crawls a target, discovers request endpoints and
parameters, fingerprints the technology stack, and runs a suite of injection
and exposure checks. Results are available as a CLI summary, a JSON report, an
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
  - `passive` — crawl, discover, fingerprint, and CVE-map only. **No payloads
    or path-probing requests are ever sent.** Use this where active/automated
    testing is disallowed.
  - `safe` (default) — one non-destructive probe per parameter per check, plus
    the site checks.
  - `aggressive` — extra payload variants and larger path lists for higher
    coverage. Still no time-based-by-default or denial-of-service payloads.
- **Global rate limiting** and bounded concurrency to stay polite.
- **Reports**: CLI summary, JSON, self-contained HTML, and a localhost web
  dashboard with a re-scan button.

### Checks

| Check | Type | What it does | Gated by |
|-------|------|--------------|----------|
| **Recon & discovery** | passive | BFS crawl with depth/page limits, link + form parameter discovery, tech fingerprinting | always |
| **CVE fingerprint** | passive | Maps detected software + versions to a built-in table of known CVEs; sends no extra requests | `cve_fingerprint` |
| **Reflected XSS** | active | Uniquely-tagged HTML breakout markers, multiple contexts in aggressive mode | `xss` |
| **SQL injection** | active | Error-based, boolean-based, and opt-in bounded time-based blind | `sqli` (+ `sqli_time_based`) |
| **SQL dumper** | exploit | Bounded proof-of-impact extraction on **firmly-confirmed** SQLi: version, user, database, table/column enumeration, and an optional tiny row sample | `sql_dump` |
| **Config exposure** | active | `.env`, `.git/config`, source/config backups, `phpinfo`, SQL dumps — matched by file-specific signatures | `config_exposure` |
| **Admin panel finder** | active | Common admin/login panels, gated on password fields, panel signatures, or auth challenges | `admin_panel` |
| **CMS fingerprint** | active | WordPress / Joomla / Drupal / Magento, with version where available | `cms_fingerprint` |
| **Shell exposure** | active | Detects an **already-exposed** web shell / backdoor (a sign of compromise) by known shell signatures | `shell_exposure` |
| **Subdomain takeover** | active | Resolves CNAMEs and matches dangling-service takeover fingerprints (GitHub Pages, S3, Heroku, Fastly, Shopify, …) | `subdomain_takeover` |

All active checks are skipped in `passive` mode. Site checks run once per
in-scope origin; injection checks run per discovered parameter.

### The SQL dumper and data minimization

The SQL dumper proves the impact of a confirmed injection the way `sqlmap`
does under an authorized engagement, but it is deliberately **data-minimizing**:

- It defaults to **metadata only** (version, current user, current database,
  and bounded table/column names).
- It reads actual **row data only when `dump.sample_data: true`**, and never
  more than `dump.max_rows` rows, clearly marked as a truncated sample.

Extract no more than you need to demonstrate the finding, and follow the
program's data-handling rules.

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
# 1. Generate a short starter config (only scope + seeds to fill in)
./scanner init -minimal -o scope.yaml
#    ...or the fully-documented one:  ./scanner init -o scope.yaml

# 2. Run a scan and write reports
./scanner scan -config scope.yaml -json report.json -html report.html

# 3. Or browse results in a local dashboard
./scanner serve -config scope.yaml -addr 127.0.0.1:8080
```

**Only `in_scope` and `seeds` are required.** Everything else has safe
defaults, and if you leave out the `checks` block a useful set of checks turns
on automatically (the SQL dumper and the time-based probe stay off until you
enable them). You do **not** need a proxy: if a target rate-limits you (HTTP
429), lower `http.rate_per_second` rather than adding one.

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

  config_exposure: true    # .env, .git/config, backups, phpinfo
  admin_panel: true        # admin/login panels
  cms_fingerprint: true    # WordPress / Joomla / Drupal / Magento
  shell_exposure: true     # already-exposed web shell (compromise)
  subdomain_takeover: true # dangling DNS -> unclaimed service
  cve_fingerprint: true    # version -> known CVEs (no extra requests)
  sql_dump: false          # bounded extraction on confirmed SQLi (opt-in)

dump:                      # only used when sql_dump is true
  max_tables: 20
  max_columns: 20
  max_rows: 5
  sample_data: false       # true reads at most max_rows rows (bounded)

takeover:
  extra_subdomains: []     # extra in-scope hosts to check for takeover
```

Every seed must itself fall inside `scope.in_scope`, or the scanner refuses to
start. The `mode` in the file can be overridden per run with `-mode`.

## Commands

| Command | Purpose |
|---------|---------|
| `scan`  | Run a scan; write `-json` / `-html` reports; print a summary. |
| `serve` | Run a scan and serve an HTML dashboard on `-addr` (localhost by default), with a re-scan button and a `/report.json` endpoint. |
| `init`  | Write a config. `-minimal` writes a short starter (scope + seeds only); otherwise a fully-documented one. |

Common flags: `-config <file>` (required for scan/serve), `-mode`, `-quiet`.

## Architecture

```
cmd/scanner                   CLI (scan / serve / init)
internal/config               scope config loading + validation (scope is mandatory)
internal/scope                host allow/deny matcher (wildcards, out-of-scope wins)
internal/httpclient           shared rate-limited, scope-checked HTTP client
internal/crawler              BFS crawl + link/form/parameter discovery
internal/fingerprint          tech + version detection -> Detection records
internal/checks               shared Finding / Endpoint / Detection types
internal/checks/xss           reflected XSS check
internal/checks/sqli          error / boolean / time-based SQLi checks
internal/checks/sqldumper     bounded SQL data extraction (exploit)
internal/checks/configexp     sensitive file / config exposure
internal/checks/adminpanel    admin panel / login finder
internal/checks/cmsfp         CMS fingerprint
internal/checks/shellexp      exposed web-shell detection
internal/checks/subtakeover   subdomain takeover (DNS + body fingerprints)
internal/checks/cve           version -> known-CVE mapping
internal/engine               orchestration (crawl -> fingerprint/CVE -> site + injection) -> Report
internal/report               JSON + HTML rendering
internal/dashboard            localhost web UI
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
