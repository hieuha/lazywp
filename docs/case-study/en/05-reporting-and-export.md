# Reporting & Data Export

Convert, filter, and export scan results in multiple formats for reporting and integration.

---

## HTML Reports

Generate a self-contained HTML report from scan results:

```bash
lazywp report scan.json
lazywp report scan.json -o report.html
```

The report includes:
- Executive summary with severity distribution
- CVSS severity charts
- Exploit intelligence summary
- Detailed CVE findings per plugin

---

## Convert & Filter Scan Results

Re-read a `lazywp scan -f json` output, apply filters, and re-export:

```bash
# Table view with details
lazywp convert scan.json -f table --detail

# Export to CSV
lazywp convert scan.json -f csv -o report.csv

# Filter by plugin slug
lazywp convert scan.json --slug elementor --detail

# Filter by CVSS score
lazywp convert scan.json --vuln-only --min-cvss 7.0
lazywp convert scan.json --max-cvss 5.9 --safe-only

# Filter by specific CVE
lazywp convert scan.json --cve CVE-2024-1234

# Exploitable only (has PoC, KEV, or Nuclei)
lazywp convert scan.json --exploitable -f csv -o critical.csv

# Filter by status
lazywp convert scan.json --status vulnerable -f csv -o vulnerable.csv
```

---

## JSON & CSV Export

Any command supports `-f json` or `-f csv` for machine-readable output:

```bash
lazywp vuln --top 10 --cwe-type sqli -f json > vuln-report.json
lazywp vuln --slug contest-gallery -f csv > contest-gallery.csv
lazywp top --count 100 -f csv > top-plugins.csv
```

### Pipe to jq

```bash
lazywp vuln --top 10 -f json | jq '.[].slug'
lazywp vuln --slug akismet -f json | jq '[.[] | select(.cvss >= 7.0)]'
```

---

## Example Scenarios

### Executive Report for Stakeholders

Scan, then produce a polished HTML report:

```bash
lazywp scan /client/wp-content/plugins -t plugin --check-exploit -f json -o scan.json
lazywp report scan.json -o vulnerability-assessment.html
```

### Extract Critical CVEs to CSV

Pull only critical vulnerabilities into a spreadsheet for tracking:

```bash
lazywp convert scan.json --vuln-only --min-cvss 9.0 -f csv -o critical-vulns.csv
```

### Generate Filtered Reports

Create separate reports for different audiences:

```bash
# For developers: all vulnerable plugins with fix versions
lazywp convert scan.json --vuln-only -f table --detail

# For management: only critical/exploitable
lazywp convert scan.json --exploitable --min-cvss 7.0 -f csv -o action-items.csv

# For security team: full exploit intelligence
lazywp exploit --file scan.json -f json -o full-intel.json
```
