# lazywp - Case Study & Usage Guide

## Overview

lazywp is a CLI tool for security researchers to bulk-download WordPress plugins/themes and cross-reference them against vulnerability databases (Wordfence, WPScan, NVD).

---

## Use Case 1: Discover Most Vulnerable Plugins

Find the top 10 plugins with the most known SQL injection vulnerabilities:

```bash
lazywp vuln --top 10 --cwe-type sqli
```

Add `--detail` to see individual CVEs per plugin:

```bash
lazywp vuln --top 10 --cwe-type sqli --detail
```

Filter by severity:

```bash
lazywp vuln --top 10 --severity critical
lazywp vuln --top 5 --severity high --cwe-type xss
```

Filter by time period:

```bash
lazywp vuln --top 10 --cwe-type rce --year 2025 --month 3
```

---

## Use Case 2: Research a Specific Plugin

Look up all known vulnerabilities for a plugin:

```bash
lazywp vuln --slug contact-form-7
lazywp vuln --slug contest-gallery
```

Check a specific source only:

```bash
lazywp vuln --slug akismet --source wordfence
lazywp vuln --slug akismet --source nvd
```

---

## Use Case 3: Bulk Download for Offline Analysis

### Download top popular plugins

```bash
lazywp top --count 50 --download
```

### Download top new plugins

```bash
lazywp top --browse new --count 20 --download
```

### Download from search results

```bash
lazywp search "ecommerce" --count 10
```

### Download from a list file

Create `plugins.txt`:

```
akismet
contact-form-7:6.1.5
elementor
```

Then download:

```bash
lazywp download --list plugins.txt
```

### Force re-download existing items

```bash
lazywp top --count 10 --download --force
```

---

## Use Case 4: Download Vulnerable Plugins for Audit

Find and download the most vulnerable plugins in one command:

```bash
lazywp vuln --top 20 --cwe-type sqli --download
```

Download a specific vulnerable plugin after reviewing its CVEs:

```bash
lazywp vuln --slug contest-gallery --download
```

---

## Use Case 5: Export Data for Reporting

### JSON output for scripting

```bash
lazywp vuln --top 10 --cwe-type sqli -f json > vuln-report.json
lazywp vuln --top 5 --detail -f json > detailed-report.json
```

### CSV output for spreadsheets

```bash
lazywp vuln --slug contest-gallery -f csv > contest-gallery-vulns.csv
lazywp top --count 100 -f csv > top-plugins.csv
```

### Pipe to jq for filtering

```bash
lazywp vuln --top 10 -f json | jq '.[].slug'
lazywp vuln --slug akismet -f json | jq '[.[] | select(.cvss >= 7.0)]'
```

---

## Use Case 6: Cache Management

### Check cache status

```bash
lazywp cache status
```

Output:

```
Cache directory: ./cache
Cache TTL: 24h

  wordfence     cached at 2026-03-14 11:33:31  (age: 2h15m, size: 127.8MB, status: valid)
  wpscan        no cache
  nvd           cached at 2026-03-14 11:33:31  (age: 2h15m, size: 45.2KB, status: valid)
```

### Force refresh vulnerability data

```bash
lazywp cache update
```

### Clear specific source cache

```bash
lazywp cache clear --source wordfence
lazywp cache clear  # clear all
```

---

## Use Case 7: Working with Themes

All commands support themes via `--type theme` (`-t theme`):

```bash
lazywp top -t theme --count 20
lazywp search "developer" -t theme
lazywp vuln --slug flavor -t theme
lazywp download flavor flavor -t theme
```

---

## Use Case 8: Configuration

### Initialize config

```bash
cp config.yaml.example config.yaml
```

### View current config

```bash
lazywp config list
```

### Set values

```bash
lazywp config set concurrency 10
lazywp config set cache_ttl 12h
lazywp config set output_dir /data/wp-downloads
```

### Use custom config path

```bash
lazywp --config /path/to/config.yaml vuln --top 10
```

---

## Use Case 9: Multi-Key Rotation

Configure multiple API keys for automatic rotation when rate-limited:

```yaml
# config.yaml
wordfence_keys:
  - KEY_1
  - KEY_2
  - KEY_3
wpscan_keys:
  - WPSCAN_KEY_1
  - WPSCAN_KEY_2
```

When a key hits 429 (rate limit), lazywp automatically rotates to the next key and retries.

---

## Tips

- Use `-q` (quiet) to suppress cache/query info for cleaner output
- Use `-f json` for machine-readable output (no text mixing)
- Set `title_max_len: 0` in config to show full vulnerability titles
- Wordfence bulk feed (~128MB) is cached locally, subsequent queries are instant
- NVD queries are per-slug and cached individually
- Use `--force` to re-download plugins you already have
