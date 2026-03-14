package cli

const reportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>lazywp Vulnerability Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;color:#333;line-height:1.6}
.container{max-width:1100px;margin:0 auto;padding:20px}
header{background:#1a1a2e;color:#fff;padding:30px;border-radius:8px;margin-bottom:20px}
header h1{font-size:24px;margin-bottom:5px}
header p{opacity:0.7;font-size:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-bottom:20px}
.card{background:#fff;border-radius:8px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}
.card .num{font-size:32px;font-weight:700}
.card .label{font-size:13px;color:#666;text-transform:uppercase}
.card.critical .num{color:#dc3545}
.card.high .num{color:#e67e22}
.card.medium .num{color:#f1c40f}
.card.safe .num{color:#27ae60}
.bar{height:24px;border-radius:4px;display:flex;overflow:hidden;margin-bottom:20px;background:#e0e0e0}
.bar span{display:block;height:100%;transition:width 0.3s}
.bar .critical{background:#dc3545}
.bar .high{background:#e67e22}
.bar .medium{background:#f1c40f}
.bar .low{background:#3498db}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);margin-bottom:20px}
th{background:#2c3e50;color:#fff;padding:12px 15px;text-align:left;font-size:13px}
td{padding:10px 15px;border-bottom:1px solid #eee;font-size:13px}
tr:hover td{background:#f8f9fa}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600;color:#fff}
.badge.critical{background:#dc3545}
.badge.high{background:#e67e22}
.badge.medium{background:#f1c40f;color:#333}
.badge.low{background:#3498db}
.badge.safe{background:#27ae60}
.badge.exploit{background:#9b59b6}
.section{margin-bottom:20px}
.section h2{font-size:18px;margin-bottom:10px;padding-bottom:5px;border-bottom:2px solid #eee}
.exploit-info{font-size:12px;color:#9b59b6;font-weight:600}
footer{text-align:center;color:#999;font-size:12px;padding:20px}
</style>
</head>
<body>
<div class="container">
<header>
<h1>lazywp Vulnerability Report</h1>
<p>Generated: {{.Generated}} | Source: {{.SourceFile}}</p>
</header>

<div class="cards">
<div class="card"><div class="num">{{.Total}}</div><div class="label">Total Scanned</div></div>
<div class="card critical"><div class="num">{{.VulnCount}}</div><div class="label">Vulnerable</div></div>
<div class="card safe"><div class="num">{{.SafeCount}}</div><div class="label">Safe</div></div>
<div class="card"><div class="num">{{.TotalCVEs}}</div><div class="label">Total CVEs</div></div>
</div>

{{if gt .TotalCVEs 0}}
<div class="section">
<h2>Severity Distribution</h2>
<div class="cards">
<div class="card critical"><div class="num">{{.Critical}}</div><div class="label">Critical (9.0+)</div></div>
<div class="card high"><div class="num">{{.High}}</div><div class="label">High (7.0-8.9)</div></div>
<div class="card medium"><div class="num">{{.Medium}}</div><div class="label">Medium (4.0-6.9)</div></div>
<div class="card"><div class="num">{{.Low}}</div><div class="label">Low (&lt;4.0)</div></div>
</div>
<div class="bar">
{{if gt .Critical 0}}<span class="critical" style="width:{{pct .Critical .TotalCVEs}}%"></span>{{end}}
{{if gt .High 0}}<span class="high" style="width:{{pct .High .TotalCVEs}}%"></span>{{end}}
{{if gt .Medium 0}}<span class="medium" style="width:{{pct .Medium .TotalCVEs}}%"></span>{{end}}
{{if gt .Low 0}}<span class="low" style="width:{{pct .Low .TotalCVEs}}%"></span>{{end}}
</div>
</div>
{{end}}

{{if .HasExploit}}
<div class="section">
<h2>Exploit Intelligence</h2>
<div class="cards">
<div class="card critical"><div class="num">{{.POCCount}}</div><div class="label">Public PoC</div></div>
<div class="card critical"><div class="num">{{.KEVCount}}</div><div class="label">CISA KEV</div></div>
<div class="card"><div class="num">{{.NucleiCount}}</div><div class="label">Nuclei Templates</div></div>
</div>
</div>
{{end}}

<div class="section">
<h2>Detailed Findings</h2>
<table>
<thead>
<tr><th>#</th><th>Plugin</th><th>Version</th><th>Status</th><th>CVEs</th><th>Max CVSS</th><th>Fix Available</th></tr>
</thead>
<tbody>
{{range $i, $r := .Results}}
<tr>
<td>{{$i}}</td>
<td><strong>{{$r.Plugin.Slug}}</strong></td>
<td>{{$r.Plugin.Version}}</td>
<td>{{if $r.IsVulnerable}}<span class="badge critical">VULNERABLE</span>{{else}}<span class="badge safe">SAFE</span>{{end}}</td>
<td>{{$r.ActiveVulns}}</td>
<td>{{if $r.IsVulnerable}}<span class="badge {{severityClass $r.MaxCVSS}}">{{printf "%.1f" $r.MaxCVSS}}</span>{{else}}-{{end}}</td>
<td>{{if $r.MaxFixedIn}}{{$r.MaxFixedIn}}{{else}}-{{end}}</td>
</tr>
{{range $r.Vulns}}
<tr>
<td></td>
<td colspan="2" style="padding-left:30px;color:#666">{{.CVE}}</td>
<td><span class="badge {{severityClass .CVSS}}">{{printf "%.1f" .CVSS}}</span></td>
<td colspan="2">{{.Title}}</td>
<td>{{fixedLabel .FixedIn}}</td>
</tr>
{{end}}
{{end}}
</tbody>
</table>
</div>

<footer>
Generated by lazywp v{{.Version}} | <a href="https://github.com/hieuha/lazywp">github.com/hieuha/lazywp</a>
</footer>
</div>
</body>
</html>`
