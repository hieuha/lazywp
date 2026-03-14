# lazywp

A high-performance CLI tool for security researchers to bulk-download WordPress plugins and themes, cross-referencing them against CVE databases (WPScan, NVD, Wordfence) for vulnerability analysis.

## Features

- **Bulk Downloads**: Download multiple WordPress plugins and themes in parallel
- **Vulnerability Scanning**: Cross-reference against WPScan, NVD, and Wordfence databases
- **Multi-Key Rotation**: Automatic API key rotation with auto-retry on 429/401
- **Resume Support**: Resume interrupted downloads from where they stopped
- **Rate Limiting**: Per-domain request rate limiting to prevent API throttling
- **Proxy Support**: Multiple proxy strategies (round-robin, failover, random)
- **Multiple Output Formats**: Table, JSON, and CSV output (`-f table|json|csv`)
- **Caching**: File-based vulnerability data caching with configurable TTL
- **Cache Management**: CLI commands to clear, update, and check cache status
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

### Check Vulnerabilities

```bash
# By slug
lazywp vuln --slug contest-gallery
lazywp vuln --slug akismet --source wordfence

# Top vulnerable plugins
lazywp vuln --top 10 --cwe-type sqli
lazywp vuln --top 5 --severity critical --detail
lazywp vuln --top 10 --cwe-type xss --download

# Output formats
lazywp vuln --slug akismet -f json
lazywp vuln --top 5 --detail -f json
```

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
| `--format` | `-f` | `table` | Output format: `table\|json\|csv` |
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
└── nvd/
```

## License

MIT
