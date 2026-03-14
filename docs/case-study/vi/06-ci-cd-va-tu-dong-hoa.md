# CI/CD & Tự Động Hoá

Tích hợp lazywp vào CI/CD pipeline, cron job, và workflow giám sát.

---

## SARIF Output Cho GitHub Code Scanning

Tạo output SARIF v2.1.0 để tích hợp GitHub Code Scanning:

```bash
# Quét với output SARIF
lazywp scan ./plugins -t plugin -f sarif -o results.sarif

# Vuln check với SARIF
lazywp vuln --slug akismet -f sarif

# Upload lên GitHub Code Scanning
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -f "sarif=$(cat results.sarif | base64)"
```

SARIF map CVE thành rule, CVSS thành severity level, hiển thị annotation trên PR GitHub.

---

## Watch Mode: Giám Sát Liên Tục

Theo dõi plugin phát hiện version mới và CVE mới.

### One-Shot (Cron / CI)

```bash
lazywp watch --slug akismet
lazywp watch --list monitored-plugins.txt
```

Exit code 1 khi phát hiện thay đổi — lý tưởng cho CI pipeline và cron alert.

### Daemon Mode

```bash
lazywp watch --list plugins.txt --daemon --interval 1h
lazywp watch --list plugins.txt --daemon --interval 6h
```

Chạy liên tục cho đến khi nhận SIGINT/SIGTERM.

### Webhook Notification

POST JSON payload đến Slack, Discord, hoặc endpoint tuỳ chỉnh:

```bash
lazywp watch --list plugins.txt --webhook https://hooks.slack.com/services/T.../B.../xxx
```

### Xuất JSON Report

```bash
lazywp watch --list plugins.txt -o changes.json
```

### Reset State

Xoá state baseline để bắt đầu lại:

```bash
lazywp watch --reset
```

---

## Kịch Bản Thực Tế

### GitHub Actions: Kiểm Tra Bảo Mật Trên PR

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

### Cron: Cảnh Báo Lỗ Hổng Hàng Ngày

```bash
# crontab -e
0 8 * * * lazywp watch --list /etc/lazywp/plugins.txt -o /var/log/lazywp/changes.json --webhook https://hooks.example.com/alert
```

Kết hợp exit code 1 với thông báo:

```bash
lazywp watch --list plugins.txt || notify-send "lazywp: phát hiện CVE mới!"
```

### Pipeline Alert Slack

```bash
lazywp watch --list plugins.txt \
  --webhook https://hooks.slack.com/services/T.../B.../xxx \
  --daemon --interval 6h
```

Định dạng webhook payload:

```json
{
  "timestamp": "2026-03-14T08:00:00Z",
  "changes": [
    {"slug": "elementor", "type": "new_version", "old_version": "3.20.0", "new_version": "3.21.0"},
    {"slug": "elementor", "type": "new_cve", "cve": "CVE-2026-1234", "cvss": 8.1, "title": "SQL Injection in..."}
  ]
}
```
