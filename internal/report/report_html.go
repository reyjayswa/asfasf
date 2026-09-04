package report

// reportHTML is the self-contained HTML template shared by the file report
// and the live dashboard. It has no external assets.
const reportHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan Report — {{ join .Rep.Seeds }}</title>
<style>
  :root {
    --bg:#0f1117; --panel:#171a23; --panel2:#1e222d; --text:#e6e9ef;
    --muted:#9aa3b2; --border:#2a2f3a; --accent:#5b9dff;
    --critical:#ff4d6d; --high:#ff8a3d; --medium:#ffd23f; --low:#6ad1ff; --info:#8a93a5;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
    font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  header { padding:24px 28px; border-bottom:1px solid var(--border); background:var(--panel); }
  h1 { margin:0 0 4px; font-size:20px; }
  .sub { color:var(--muted); font-size:13px; }
  .banner { background:#2a1d12; border:1px solid #5a3a1a; color:#ffcf9e;
    padding:10px 14px; border-radius:8px; margin:14px 0 0; font-size:13px; }
  main { padding:24px 28px; max-width:1100px; margin:0 auto; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:10px;
    padding:14px 18px; min-width:110px; }
  .card .n { font-size:26px; font-weight:700; }
  .card .l { font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }
  .meta { background:var(--panel); border:1px solid var(--border); border-radius:10px;
    padding:16px 18px; margin-bottom:24px; display:grid; grid-template-columns:auto 1fr;
    gap:6px 18px; font-size:13px; }
  .meta b { color:var(--muted); font-weight:600; }
  .finding { background:var(--panel); border:1px solid var(--border); border-left-width:4px;
    border-radius:10px; padding:16px 18px; margin-bottom:14px; }
  .finding.critical { border-left-color:var(--critical); }
  .finding.high { border-left-color:var(--high); }
  .finding.medium { border-left-color:var(--medium); }
  .finding.low { border-left-color:var(--low); }
  .finding.info { border-left-color:var(--info); }
  .ftop { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  .badge { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.05em;
    padding:3px 8px; border-radius:6px; color:#0b0d12; }
  .badge.critical { background:var(--critical); }
  .badge.high { background:var(--high); }
  .badge.medium { background:var(--medium); }
  .badge.low { background:var(--low); }
  .badge.info { background:var(--info); }
  .conf { font-size:11px; color:var(--muted); border:1px solid var(--border);
    padding:2px 7px; border-radius:6px; }
  .ftitle { font-weight:650; }
  .kv { color:var(--muted); font-size:13px; margin-top:8px; word-break:break-all; }
  .kv b { color:var(--text); font-weight:600; }
  pre { background:var(--panel2); border:1px solid var(--border); border-radius:8px;
    padding:10px 12px; overflow-x:auto; font-size:12.5px; margin:10px 0 0; white-space:pre-wrap; }
  .desc { margin-top:10px; font-size:13.5px; }
  .rem { margin-top:8px; font-size:13px; color:var(--muted); }
  h2 { font-size:15px; margin:28px 0 12px; border-bottom:1px solid var(--border); padding-bottom:6px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); word-break:break-all; }
  th { color:var(--muted); font-weight:600; }
  .empty { color:var(--muted); font-style:italic; padding:12px 0; }
  code { background:var(--panel2); padding:1px 5px; border-radius:4px; font-size:12.5px; }
  footer { color:var(--muted); font-size:12px; padding:20px 28px; border-top:1px solid var(--border); }
</style>
</head>
<body>
<header>
  <h1>Web Vulnerability Scan Report</h1>
  <div class="sub">Mode: <b>{{ upper .Rep.Mode }}</b> ·
    Started {{ .Rep.StartedAt.Format "2006-01-02 15:04:05 MST" }} ·
    Finished {{ .Rep.FinishedAt.Format "15:04:05 MST" }}</div>
  <div class="banner">⚠ Authorized use only. Run this scanner exclusively against targets you own
    or are explicitly permitted to test (for example, a bug bounty program's in-scope assets).</div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="n">{{ .Counts.Critical }}</div><div class="l">Critical</div></div>
    <div class="card"><div class="n">{{ .Counts.High }}</div><div class="l">High</div></div>
    <div class="card"><div class="n">{{ .Counts.Medium }}</div><div class="l">Medium</div></div>
    <div class="card"><div class="n">{{ .Counts.Low }}</div><div class="l">Low</div></div>
    <div class="card"><div class="n">{{ .Counts.Info }}</div><div class="l">Info</div></div>
  </div>

  <div class="meta">
    <b>Seeds</b><div>{{ join .Rep.Seeds }}</div>
    <b>In scope</b><div>{{ join .Rep.InScope }}</div>
    <b>Out of scope</b><div>{{ if .Rep.OutOfScope }}{{ join .Rep.OutOfScope }}{{ else }}—{{ end }}</div>
    <b>Pages crawled</b><div>{{ .Rep.PagesCrawled }}</div>
    <b>Endpoints found</b><div>{{ len .Rep.Endpoints }}</div>
    <b>Requests sent</b><div>{{ .Rep.RequestsSent }}</div>
    <b>Out-of-scope blocked</b><div>{{ .Rep.Blocked }}</div>
  </div>

  <h2>Findings</h2>
  {{ if not .Rep.Findings }}<div class="empty">No findings.</div>{{ end }}
  {{ range .Rep.Findings }}
  <div class="finding {{ .Severity }}">
    <div class="ftop">
      <span class="badge {{ .Severity }}">{{ .Severity }}</span>
      <span class="ftitle">{{ .Title }}</span>
      <span class="conf">{{ .Confidence }}</span>
    </div>
    <div class="kv"><b>URL:</b> {{ .URL }}{{ if .Method }} &nbsp;<b>Method:</b> {{ .Method }}{{ end }}{{ if .Parameter }} &nbsp;<b>Param:</b> <code>{{ .Parameter }}</code>{{ end }}</div>
    <div class="desc">{{ .Description }}</div>
    {{ if .Payload }}<pre>payload: {{ .Payload }}</pre>{{ end }}
    {{ if .Evidence }}<pre>evidence: {{ .Evidence }}</pre>{{ end }}
    {{ if .Remediation }}<div class="rem"><b>Fix:</b> {{ .Remediation }}</div>{{ end }}
  </div>
  {{ end }}

  <h2>Discovered endpoints</h2>
  {{ if not .Rep.Endpoints }}<div class="empty">No parameterized endpoints discovered.</div>{{ else }}
  <table>
    <tr><th>Method</th><th>URL</th><th>Parameters</th><th>Source</th></tr>
    {{ range .Rep.Endpoints }}
    <tr><td>{{ .Method }}</td><td>{{ .URL }}</td><td>{{ join .Params }}</td><td>{{ .Source }}</td></tr>
    {{ end }}
  </table>
  {{ end }}
</main>
<footer>Generated by asfasf-scanner. Findings are automated signals and may include false positives; verify before reporting.</footer>
</body>
</html>`
