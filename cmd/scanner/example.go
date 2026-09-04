package main

// exampleConfig is written by "scanner init". It documents every option and
// ships conservative defaults with a clearly-fake scope the user must edit.
const exampleConfig = `# asfasf-scanner configuration
#
# SCOPE IS MANDATORY. The scanner will not send a request to any host that is
# not matched by scope.in_scope, and out_of_scope always wins. Only list
# assets you own or are explicitly authorized to test.

# Scan intensity:
#   passive    - crawl, discover, fingerprint, and CVE-map only; never sends
#                payloads or path-probing requests. Use when a program forbids
#                active/automated testing.
#   safe       - passive work plus one non-destructive probe per parameter and
#                the site checks below (default).
#   aggressive - safe work plus extra payload variants and larger path lists.
#                Still no time-based-by-default or denial-of-service payloads.
mode: safe

scope:
  in_scope:
    - "example.com"        # exact host
    - "*.example.com"      # any subdomain (not the apex)
  out_of_scope:
    - "admin.example.com"  # excluded even though *.example.com matches it

seeds:
  - "https://example.com/"

crawl:
  max_depth: 3
  max_pages: 200
  same_host_only: true

http:
  rate_per_second: 5       # global request rate limit
  concurrency: 5
  timeout_seconds: 15
  user_agent: "asfasf-scanner/0.1 (authorized security testing)"
  follow_redirect: false

checks:
  # Parameter injection checks (run per discovered parameter).
  xss: true
  sqli: true
  # Blind time-based SQLi. Off by default. Sends ONE short, bounded delay
  # payload per parameter and confirms against a zero-delay control. It is a
  # detection probe, not a load or denial-of-service test.
  sqli_time_based: false
  sqli_delay_seconds: 3    # clamped to 1..10

  # Site checks (run once per in-scope origin). These send path-probing
  # requests, so they are skipped in passive mode.
  config_exposure: true    # .env, .git/config, backups, phpinfo, etc.
  admin_panel: true        # common admin/login panels
  cms_fingerprint: true    # WordPress / Joomla / Drupal / Magento
  shell_exposure: true     # detect an already-exposed web shell (compromise)
  subdomain_takeover: true # dangling DNS -> unclaimed service

  # CVE mapping over fingerprinted software versions. Sends no extra requests;
  # runs in every mode including passive.
  cve_fingerprint: true

  # Bounded SQL data extraction against endpoints with FIRMLY-confirmed SQLi.
  # Off by default. Extracts metadata only unless dump.sample_data is true.
  # Follow the program's data-minimization rules before enabling.
  sql_dump: false

dump:
  max_tables: 20
  max_columns: 20
  max_rows: 5
  sample_data: false       # when true, reads at most max_rows rows (bounded)

takeover:
  extra_subdomains: []     # optional extra in-scope hosts to check for takeover
`
