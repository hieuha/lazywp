# CI/CD & Automation

Integrate lazywp into CI/CD pipelines, cron jobs, and monitoring workflows.

---

## SARIF Output for GitHub Code Scanning

Generate SARIF v2.1.0 output for GitHub Code Scanning integration:

```bash
# Scan with SARIF output
lazywp scan ./plugins -t plugin -f sarif -o results.sarif

# Vuln check with SARIF
lazywp vuln --slug akismet -f sarif

# Upload to GitHub Code Scanning
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -f "sarif=$(cat results.sarif | base64)"
```

SARIF maps CVEs to rules, CVSS scores to severity levels, and appears as PR annotations in GitHub.

---

## Watch Mode: Continuous Monitoring

Monitor plugins for new versions and CVEs:

### One-Shot (Cron / CI)

```bash
lazywp watch --slug akismet
lazywp watch --list monitored-plugins.txt
```

Exit code 1 when changes detected — ideal for CI pipelines and cron alerting.

### Daemon Mode

```bash
lazywp watch --list plugins.txt --daemon --interval 1h
lazywp watch --list plugins.txt --daemon --interval 6h
```

Runs continuously until SIGINT/SIGTERM.

### Webhook Notifications

POST JSON payload to Slack, Discord, or custom endpoints when changes detected:

```bash
lazywp watch --list plugins.txt --webhook https://hooks.slack.com/services/T.../B.../xxx
```

### JSON Report Output

```bash
lazywp watch --list plugins.txt -o changes.json
```

### Reset State

Clear baseline state to start fresh:

```bash
lazywp watch --reset
```

---

## Example Scenarios

### GitHub Actions: PR Security Check

```yaml
# .github/workflows/wp-security.yml
name: WordPress Plugin Security
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install lazywp
        run: go install github.com/hieuha/lazywp/cmd/lazywp@latest
      - name: Scan plugins
        run: lazywp scan ./wp-content/plugins -t plugin -f sarif -o results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Cron: Daily Vulnerability Alert

```bash
# crontab -e
0 8 * * * lazywp watch --list /etc/lazywp/plugins.txt -o /var/log/lazywp/changes.json --webhook https://hooks.example.com/alert
```

Exit code 1 on changes lets you chain with alerting:

```bash
lazywp watch --list plugins.txt || notify-send "lazywp: new CVEs detected!"
```

### Slack Alert Pipeline

```bash
lazywp watch --list plugins.txt \
  --webhook https://hooks.slack.com/services/T.../B.../xxx \
  --daemon --interval 6h
```

Webhook payload format:

```json
{
  "timestamp": "2026-03-14T08:00:00Z",
  "changes": [
    {"slug": "elementor", "type": "new_version", "old_version": "3.20.0", "new_version": "3.21.0"},
    {"slug": "elementor", "type": "new_cve", "cve": "CVE-2026-1234", "cvss": 8.1, "title": "SQL Injection in..."}
  ]
}
```

### Multi-Environment Monitoring

Monitor plugins across staging and production:

```bash
lazywp scan /staging/wp-content/plugins -t plugin -f json -o staging.json
lazywp scan /prod/wp-content/plugins -t plugin -f json -o prod.json
lazywp watch --list prod-plugins.txt --daemon --interval 12h --webhook https://alerts.example.com
```
