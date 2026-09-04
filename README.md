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
- **Adaptive rate limiting**: a global request cap that automatically backs
  off on HTTP 429 (honoring `Retry-After`) and eases back on success, so you
  rarely need a proxy — slowing down is the fix for rate limiting.
- **Headless-browser scanning** (optional): drives the machine's Chromium to
  render JavaScript apps, discover DOM-built routes the HTML crawler misses,
  and detect DOM-based XSS by executing payloads in a real browser. Scope is
  still enforced — it never navigates off-scope and blocks off-scope
  subresource requests.
- **Findings enriched** with a CWE id, an OWASP Top 10 (2021) category, and an
  indicative severity score.
- **Reports**: CLI summary, JSON, self-contained HTML, a localhost web
  dashboard, **SARIF 2.1.0** (for CI / code scanning), and a submission-ready
  **Markdown** writeup.

### Checks

| Check | Type | What it does | Gated by |
|-------|------|--------------|----------|
| **Recon & discovery** | passive | BFS crawl with depth/page limits, link + form parameter discovery, tech fingerprinting | always |
| **CVE fingerprint** | passive | Maps detected software + versions to a built-in table of known CVEs; sends no extra requests | `cve_fingerprint` |
| **Reflected XSS** | active | Uniquely-tagged HTML breakout markers, multiple contexts in aggressive mode | `xss` |
| **SQL injection** | active | Error-based, boolean-based, and bounded time-based blind | `sqli`, `sqli_time_based` |
| **SQL dumper** | exploit | Bounded proof-of-impact extraction on **firmly-confirmed** SQLi: version, user, database, table/column enumeration, and an optional tiny row sample | `sql_dump` |
| **Config exposure** | active | `.env`, `.git/config`, source/config backups, `phpinfo`, SQL dumps — matched by file-specific signatures | `config_exposure` |
| **Admin panel finder** | active | Common admin/login panels, gated on password fields, panel signatures, or auth challenges | `admin_panel` |
| **CMS fingerprint** | active | WordPress / Joomla / Drupal / Magento, with version where available | `cms_fingerprint` |
| **Shell exposure** | active | Detects an **already-exposed** web shell / backdoor (a sign of compromise) by known shell signatures | `shell_exposure` |
| **Subdomain takeover** | active | Resolves CNAMEs and matches dangling-service takeover fingerprints (GitHub Pages, S3, Heroku, Fastly, Shopify, …) | `subdomain_takeover` |
| **Open redirect** | active | Injects an external canary and detects redirects to it (Location header or client-side) | `open_redirect` |
| **Path traversal** | active | Reads known files (`/etc/passwd`, `win.ini`) via traversal payloads | `path_traversal` |
| **Command injection** | active | Detects shell command execution via `id`/`ver` output signatures | `command_injection` |
| **SSTI** | active | Server-side template injection via a distinctive arithmetic product | `ssti` |
| **CORS** | active | Reflected/`null`/`*` origin with credentials | `cors` |
| **Security headers** | passive | Missing/weak CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy | `security_headers` |
| **Cookie flags** | passive | Missing Secure / HttpOnly / SameSite | `cookies` |
| **CSRF** | passive | State-changing forms with no anti-CSRF token | `csrf` |
| **DOM-based XSS** | headless | Executes payloads in a real browser to catch client-side sinks (innerHTML, eval, location) | `headless.enabled` |
| **Header injection** | active | Host-header injection (redirect/cache poisoning) and reflected request headers | `header_injection` |
| **Recon discovery** | active | Mines robots.txt, sitemap.xml, and referenced JS for extra parameterized endpoints | `discovery` |
| **SSRF (blind)** | out-of-band | Confirms server-side request forgery via a callback listener — no visible response needed | `ssrf` + `oob.enabled` |
| **GraphQL introspection** | active | Detects a GraphQL endpoint with introspection enabled (schema disclosure) | `graphql` |
| **CRLF injection** | active | Response header injection via CR/LF in a parameter | `crlf` |
| **XXE** | active | In-band XML external entity file read | `xxe` |
| **XPath injection** | active | XPath error-based injection | `xpath` |
| **NoSQL injection** | active | MongoDB error-based injection | `nosql` |
| **JWT weaknesses** | passive | Exposed tokens and `alg=none` / missing-expiry JWTs | `jwt` |
| **Secret leakage** | passive | AWS/Google/Slack/GitHub keys and private keys in responses | `secrets` |
| **Directory listing** | passive | Autoindex pages (Apache/nginx/Tomcat/IIS) | `directory_listing` |

All non-headless checks are **on by default** (a minimal config with no
`checks` block runs every one), including the time-based blind SQLi probe and
the SQL dumper (with a bounded row sample — set `dump.sample_data: false` to
forbid reading data). Headless scanning stays opt-in because it launches a
browser and is slow. Active checks are skipped in `passive` mode; site checks
run once per in-scope origin; injection checks run per discovered parameter.

### The SQL dumper and data minimization

The SQL dumper proves the impact of a confirmed injection the way `sqlmap`
does under an authorized engagement:

- It extracts metadata and schema (version, current user, current database,
  and bounded table/column names).
- By default it also reads a **bounded sample of real row values**, never more
  than `dump.max_rows` per sampled table, clearly marked as a truncated sample.
  **Reading data is prohibited by many programs** — set `dump.sample_data:
  false` to prove impact from metadata and schema alone.

Extract no more than you need to demonstrate the finding, and follow the
program's data-handling rules.

### Coverage vs. safeguards

The safeguards do not hide findings on an authorized target. Scope enforcement
only blocks hosts you did not list — it never suppresses a result within your
scope. The limits that affect how much a scan finds are all tunable without
weakening safety: raise `http.rate_per_second` / `crawl.max_pages` /
`crawl.max_depth` for reach, use `aggressive` for more payloads, and enable
`headless` and `ssrf` for surfaces the plain HTTP checks can't see. Adaptive
rate limiting only slows down when the target returns HTTP 429.

### Continuous scanning

- `-baseline previous.json` reports only findings that are **not** already in a
  prior JSON report (diff mode), so scheduled scans surface only what's new.
- `.github/workflows/scan.yml` builds, tests, runs a scan when
  `.scanner/scope.yaml` is present, and uploads the SARIF to GitHub code
  scanning.

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
# 1. Build your config by answering a few questions (and optionally scan
#    right away — zero to a report in one command)
./scanner init -interactive -o scope.yaml
#    ...or a short starter to edit:  ./scanner init -minimal -o scope.yaml
#    ...or the fully-documented one: ./scanner init -o scope.yaml

# 2. Run a scan and write reports
./scanner scan -config scope.yaml -html report.html -sarif report.sarif -md report.md


# 3. Or browse results in a local dashboard
./scanner serve -config scope.yaml -addr 127.0.0.1:8080
```

**Only `in_scope` and `seeds` are required.** Everything else has safe
defaults, and if you leave out the `checks` block a useful set of checks turns
on automatically, including the time-based blind SQLi probe and the SQL dumper.
This includes the dumper reading a bounded sample of real row values
(`dump.sample_data`); set it to false if your program forbids reading data.
You do **not** need a proxy: if a target rate-limits you (HTTP 429), lower
`http.rate_per_second` rather than adding one.

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
  sqli_time_based: true    # bounded blind probe (on by default)
  sqli_delay_seconds: 3    # clamped to 1..10

  config_exposure: true    # .env, .git/config, backups, phpinfo
  admin_panel: true        # admin/login panels
  cms_fingerprint: true    # WordPress / Joomla / Drupal / Magento
  shell_exposure: true     # already-exposed web shell (compromise)
  subdomain_takeover: true # dangling DNS -> unclaimed service
  cve_fingerprint: true    # version -> known CVEs (no extra requests)
  sql_dump: true           # bounded extraction on confirmed SQLi (on by default)
  open_redirect: true
  path_traversal: true
  command_injection: true
  ssti: true               # server-side template injection
  cors: true               # CORS misconfiguration
  security_headers: true   # missing/weak CSP, HSTS, X-Frame-Options, ...
  cookies: true            # missing Secure/HttpOnly/SameSite
  csrf: true               # forms without an anti-CSRF token

dump:                      # only used when sql_dump is true
  max_tables: 20
  max_columns: 20
  max_rows: 5
  sample_data: true        # reads a bounded sample of real rows; set false to forbid

takeover:
  extra_subdomains: []     # extra in-scope hosts to check for takeover

headless:                  # JS rendering + DOM XSS (opt-in; launches Chromium)
  enabled: false           # or pass -headless on the scan command
  max_urls: 25
  timeout_seconds: 20
```

Every seed must itself fall inside `scope.in_scope`, or the scanner refuses to
start. The `mode` in the file can be overridden per run with `-mode`.

## Commands

| Command | Purpose |
|---------|---------|
| `scan`  | Run a scan; write `-json` / `-html` / `-sarif` / `-md` reports; `-headless` (browser) and `-oob` (blind SSRF) enable extra stages; `-baseline` shows only new findings. |
| `serve` | Run a scan and serve an HTML dashboard on `-addr` (localhost by default), with a re-scan button and a `/report.json` endpoint. |
| `init`  | Write a config. `-interactive` (or `-i`) asks a few questions, builds it for you, and offers to run the scan immediately; `-minimal` writes a short starter (scope + seeds only); otherwise a fully-documented one. |

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
internal/checks/openredirect  open redirect
internal/checks/pathtraversal path traversal / local file read
internal/checks/cmdinjection  OS command injection
internal/checks/ssti          server-side template injection
internal/checks/cors          CORS misconfiguration
internal/checks/secheaders    missing/weak security headers (passive)
internal/checks/cookies       insecure cookie flags (passive)
internal/checks/csrf          missing anti-CSRF token (passive)
internal/checks/headerinj     host-header injection + reflected headers
internal/checks/ssrf          blind SSRF via out-of-band interaction
internal/checks/graphql       GraphQL introspection exposure
internal/checks/crlf          CRLF / response header injection
internal/checks/xxe           XML external entity (in-band)
internal/checks/xpath         XPath injection
internal/checks/nosql         NoSQL (MongoDB) injection
internal/checks/jwt           exposed / weak JWTs (passive)
internal/checks/secrets       leaked API keys / secrets (passive)
internal/checks/dirlisting    directory listing enabled (passive)
internal/checks/configexp     sensitive file / config exposure
internal/checks/adminpanel    admin panel / login finder
internal/checks/cmsfp         CMS fingerprint
internal/checks/shellexp      exposed web-shell detection
internal/checks/subtakeover   subdomain takeover (DNS + body fingerprints)
internal/checks/cve           version -> known-CVE mapping
internal/discovery            robots.txt / sitemap.xml / JS endpoint mining
internal/oob                  out-of-band interaction listener (blind checks)
internal/browser              headless Chromium (chromedp): JS render, SPA discovery, DOM-XSS
internal/enrich               CWE / OWASP / score annotation
internal/engine               orchestration (crawl -> fingerprint/CVE -> headless -> site + injection) -> Report
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
