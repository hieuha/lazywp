# lazywp

A high-performance CLI tool for security researchers to bulk-download WordPress plugins and themes, cross-referencing them against CVE databases (WPScan, NVD, Wordfence) for vulnerability analysis.

## Features

- **Bulk Downloads**: Download multiple WordPress plugins and themes in parallel
- **Local Scan**: Scan local plugin/theme directories, detect versions, and check for vulnerabilities
- **Vulnerability Scanning**: Cross-reference against WPScan, NVD, and Wordfence databases
- **Exploit Lookup**: Look up PoC availability, KEV status, EPSS scores, and Nuclei templates via ProjectDiscovery's vulnx
- **Scan Conversion**: Re-read, filter, and re-export scan JSON results with rich filter options
- **Multi-Key Rotation**: Automatic API key rotation with auto-retry on 429/401
- **Resume Support**: Resume interrupted downloads from where they stopped
- **Rate Limiting**: Per-domain request rate limiting to prevent API throttling
- **Proxy Support**: Multiple proxy strategies (round-robin, failover, random)
- **Multiple Output Formats**: Table, JSON, and CSV output (`-f table|json|csv`)
- **Caching**: File-based vulnerability data caching with configurable TTL (including per-CVE exploit data)
- **Cache Management**: CLI commands to clear, update, and check cache status
- **Watch Mode**: Monitor plugins/themes for new versions and CVEs with one-shot or daemon mode
- **Zip Extraction**: Extract downloaded zips for SAST analysis (Semgrep, CodeQL, etc.)
- **Metadata Tracking**: Comprehensive metadata storage with download history and error logs

## Installation

```bash
go install github.com/hieuha/lazywp/cmd/lazywp@latest
```

Or build from source:

```bash
git clone https://github.com/hieuha/lazywp.git
cd lazywp
make build
make install
```

## Quick Start

### Configure

Copy the example config and add your API keys:

```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your API keys
```

### Browse Top Plugins

```bash
lazywp top --count 20
lazywp top --browse new --count 10 --download
```

### Search Plugins

```bash
lazywp search "security"
lazywp search "ecommerce" --count 20
```

### Download Plugins

```bash
lazywp download akismet
lazywp download akismet hello-dolly --force
lazywp download --list plugins.txt
```

### Extract for SAST

```bash
lazywp extract                              # extract all downloaded plugins
lazywp extract --slug akismet               # all versions of akismet
lazywp extract --slug akismet:5.0.1         # only akismet v5.0.1
lazywp extract --list slugs.txt             # from list (slug or slug:version)
lazywp extract --source-dir ./my-downloads  # custom downloads directory
lazywp extract --output-dir ./sast-target   # custom output dir
lazywp extract --clean                      # clean before extracting
lazywp extract -t theme                     # extract themes
```

| Flag | Description |
|------|-------------|
| `--slug` | Plugin/theme slug (`slug` or `slug:version`) |
| `--list` | File with slugs (one per line, `slug:version` supported) |
| `--source-dir` | Source downloads directory (default: config `output_dir`) |
| `--output-dir` | Output directory (default: `./extracted`) |
| `--clean` | Remove existing extracted files before extracting |

### Check Vulnerabilities

```bash
# By slug
lazywp vuln --slug contest-gallery
lazywp vuln --slug akismet --source wordfence

# Batch check from file (one slug per line)
lazywp vuln --list slugs.txt
lazywp vuln --list slugs.txt --download

# Top vulnerable plugins
lazywp vuln --top 10 --cwe-type sqli
lazywp vuln --top 5 --severity critical --detail
lazywp vuln --top 10 --cwe-type xss --download

# Output formats
lazywp vuln --slug akismet -f json
lazywp vuln --top 5 --detail -f json
lazywp vuln --top 10 --cwe-type sqli --detail -f json -o vuln.json
lazywp vuln --top 10 --detail -f csv -o top10.csv
```

### Scan Local Directory

```bash
lazywp scan /path/to/wp-content/plugins -t plugin
lazywp scan /path/to/wp-content/themes -t theme
lazywp scan ./plugins -t plugin --source wordfence
lazywp scan ./plugins -t plugin --no-cache          # force online lookup
lazywp scan ./plugins -t plugin --check-exploit     # also fetch PoC/KEV/Nuclei per CVE
```

### Exploit Lookup

Look up PoC availability, KEV status, EPSS scores, and Nuclei templates for CVEs via
ProjectDiscovery's [vulnx](https://github.com/projectdiscovery/cvemap) CLI.

Requires vulnx installed:
```bash
go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest
```

```bash
# By CVE ID
lazywp exploit CVE-2024-1234
lazywp exploit CVE-2024-1234 CVE-2024-5678

# From a scan JSON file
lazywp exploit --file scan.json
lazywp exploit --file scan.json --has-poc           # only CVEs with known PoC
lazywp exploit --file scan.json --has-nuclei        # only CVEs with Nuclei templates

# Output formats
lazywp exploit --file scan.json -f json -o enriched.json
lazywp exploit --file scan.json -f csv  -o exploits.csv
```

| Flag | Description |
|------|-------------|
| `--file` | Read CVEs from a scan JSON file instead of CLI args |
| `--has-poc` | Show only CVEs with a known public PoC |
| `--has-nuclei` | Show only CVEs with a Nuclei template |
| `-o` | Write output to file (default: stdout) |

### Convert / Re-export Scan & Vuln Results

Read a JSON file from `lazywp scan` or `lazywp vuln` and re-export with filters. Auto-detects input format.

```bash
# Scan JSON
lazywp convert scan.json -f csv -o report.csv
lazywp convert scan.json --slug elementor --detail
lazywp convert scan.json --vuln-only --min-cvss 7.0
lazywp convert scan.json --exploitable -f csv -o critical.csv

# Vuln JSON (from lazywp vuln --detail -f json)
lazywp convert vuln.json -f csv -o all-cves.csv
lazywp convert vuln.json --slug contact-form --min-cvss 9.0
lazywp convert vuln.json --cve CVE-2024-1234 -f json

# Filter by status (scan JSON only)
lazywp convert scan.json --status vulnerable -f csv -o vulnerable.csv
```

| Flag | Description |
|------|-------------|
| `--slug` | Substring match on plugin slug |
| `--min-cvss` | Minimum CVSS score threshold |
| `--max-cvss` | Maximum CVSS score threshold |
| `--cve` | Substring match on CVE ID |
| `--status` | Filter by `vulnerable` or `safe` |
| `--vuln-only` | Show only vulnerable plugins |
| `--safe-only` | Show only safe plugins |
| `--exploitable` | Show only plugins with PoC/KEV/Nuclei data |
| `-o` | Write output to file (default: stdout) |
| `--detail` | Show full CVE list (table format) |

### Generate HTML Report

```bash
lazywp report scan.json
lazywp report scan.json -o report.html
```

Generates a self-contained HTML report with severity charts, executive summary, exploit intelligence, and detailed CVE findings.

### SARIF Output (CI/CD Integration)

```bash
# Scan with SARIF output for GitHub Code Scanning
lazywp scan ./plugins -t plugin -f sarif -o results.sarif

# Vuln check with SARIF output
lazywp vuln --slug akismet -f sarif

# Upload to GitHub Code Scanning
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -f "sarif=$(cat results.sarif | base64)"
```

### Watch for Updates

```bash
# One-shot check (exit code 1 if changes found — CI-friendly)
lazywp watch --slug akismet
lazywp watch --list slugs.txt

# Daemon mode with interval
lazywp watch --list slugs.txt --daemon --interval 1h

# Output to JSON file
lazywp watch --list slugs.txt -o changes.json

# Send webhook on changes
lazywp watch --list slugs.txt --webhook https://hooks.example.com/notify

# Reset state (start fresh)
lazywp watch --reset
```

| Flag | Description |
|------|-------------|
| `--slug` | Single slug to monitor |
| `--list` | File with slugs (one per line) |
| `--daemon` | Run continuously on an interval |
| `--interval` | Check interval for daemon mode (default: `24h`) |
| `--webhook` | URL to POST JSON changes to |
| `-o` | Write JSON report to file |
| `--reset` | Delete state file and exit |

### Cache Management

```bash
lazywp cache status
lazywp cache update
lazywp cache clear
lazywp cache clear --source wordfence
```

### List Downloaded Items

```bash
lazywp list
```

## Global Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--type` | `-t` | `plugin` | Resource type: `plugin\|theme` |
| `--format` | `-f` | `table` | Output format: `table\|json\|csv\|sarif` |
| `--config` | | `./config.yaml` | Config file path |
| `--force` | | `false` | Force re-download existing items |
| `--verbose` | `-v` | `false` | Enable verbose logging |
| `--quiet` | `-q` | `false` | Suppress non-essential output |

## Configuration

Configuration is stored in `config.yaml` (current directory by default):

```yaml
wpscan_keys:
  - YOUR_WPSCAN_API_KEY_1
  - YOUR_WPSCAN_API_KEY_2
wordfence_keys:
  - YOUR_WORDFENCE_API_KEY_1
  - YOUR_WORDFENCE_API_KEY_2
nvd_keys:
  - YOUR_NVD_API_KEY_1
# ProjectDiscovery API keys for vulnx exploit lookup (supports rotation)
projectdiscovery_api_keys:
  - YOUR_PD_API_KEY_1
  - YOUR_PD_API_KEY_2
key_rotation: round-robin
concurrency: 5
output_dir: ./downloads
cache_dir: ./cache
cache_ttl: 24h
title_max_len: 100        # 0 = no truncation
rate_limits:
  api.wordpress.org: 5
  wpscan.com: 1
  services.nvd.nist.gov: 0.16
  www.wordfence.com: 0.1
retry_max: 3
retry_base_delay: 1s
```

## Storage Layout

```
downloads/
├── plugins/
│   └── akismet/
│       └── 5.0.1/
│           ├── akismet.zip
│           └── metadata.json
├── themes/
│   └── flavor/
│       └── 2.0/
│           └── metadata.json
├── index.json
└── errors.json

cache/
├── wordfence/
├── wpscan/
├── nvd/
└── vulnx/       # per-CVE exploit data (PoC, KEV, EPSS, Nuclei)
```

## License

MIT
