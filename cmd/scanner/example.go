package main

// exampleConfig is written by "scanner init". It documents every option and
// ships conservative defaults with a clearly-fake scope the user must edit.
const exampleConfig = `# asfasf-scanner configuration
#
# SCOPE IS MANDATORY. The scanner will not send a request to any host that is
# not matched by scope.in_scope, and out_of_scope always wins. Only list
# assets you own or are explicitly authorized to test.

# Scan intensity:
#   passive    - crawl, discover, and fingerprint only; never sends payloads.
#                Use when a program forbids active/automated testing.
#   safe       - passive work plus one non-destructive probe per parameter
#                for each enabled check (default).
#   aggressive - safe work plus extra payload variants for more coverage.
#                Still no time-based or denial-of-service payloads.
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
  xss: true
  sqli: true
  # Blind time-based SQLi. Off by default. Sends ONE short, bounded delay
  # payload per parameter and confirms against a zero-delay control. It is a
  # detection probe, not a load or denial-of-service test. Enable only where
  # the program permits active blind testing.
  sqli_time_based: false
  sqli_delay_seconds: 3    # clamped to 1..10
`
