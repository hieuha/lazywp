# lazywp

A high-performance CLI tool for bulk downloading WordPress plugins and themes with vulnerability scanning.

## Features

- **Bulk Downloads**: Download multiple WordPress plugins and themes in parallel
- **Vulnerability Scanning**: Integrated vulnerability checks from WPScan and NVD databases
- **Resume Support**: Resume interrupted downloads from where they stopped
- **Rate Limiting**: Per-domain request rate limiting to prevent API throttling
- **Proxy Support**: Multiple proxy strategies (round-robin, failover, random)
- **Key Rotation**: Automatic API key rotation for rate-limited services
- **Multiple Output Formats**: Table, JSON, and CSV output for easy parsing
- **Caching**: Vulnerability data caching with configurable TTL
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

### Configure API Keys

```bash
lazywp config set wpscan-key YOUR_WPSCAN_API_KEY
lazywp config set nvd-key YOUR_NVD_API_KEY
```

### Download a Plugin

```bash
lazywp download plugin akismet
```

### Download Multiple Plugins and Themes

```bash
lazywp download plugin akismet hello-dolly
lazywp download theme twenty-twenty
```

### Check Vulnerabilities

```bash
lazywp vuln check plugin akismet
```

## Command Reference

### download
Download WordPress plugins and themes.

```bash
lazywp download <type> <slug> [<slug> ...]
  type: plugin|theme
  slug: WordPress plugin/theme slug
```

### vuln
Check for known vulnerabilities in downloaded items.

```bash
lazywp vuln check <type> <slug>
  type: plugin|theme
  slug: WordPress plugin/theme slug
```

### list
List downloaded plugins and themes.

```bash
lazywp list [type]
  type: plugin|theme (optional, lists all if omitted)
```

### config
Manage configuration.

```bash
lazywp config show              # Show current configuration
lazywp config set <key> <value> # Set configuration value
```

### search
Search WordPress.org for plugins and themes.

```bash
lazywp search <type> <query>
  type: plugin|theme
  query: Search query
```

### stats
Show download statistics and metadata.

```bash
lazywp stats
```

## Configuration

Configuration is stored in `~/.lazywp/config.json`. Example:

```json
{
  "wpscan_keys": ["key1", "key2"],
  "nvd_key": "your-nvd-api-key",
  "key_rotation": "round-robin",
  "proxy_strategy": "round-robin",
  "concurrency": 5,
  "output_dir": "./downloads",
  "rate_limits": {
    "api.wordpress.org": 5,
    "wpscan.com": 1,
    "services.nvd.nist.gov": 0.16
  },
  "cache_ttl": "24h",
  "retry_max": 3,
  "retry_base_delay": "1s"
}
```

## Storage Layout

Downloaded items are organized in the output directory:

```
downloads/
├── plugins/
│   └── akismet/
│       └── 5.0.1/
│           ├── akismet.zip
│           ├── metadata.json
│           └── .lazywp-state.json
├── themes/
│   └── twenty-twenty/
│       └── 2.0/
│           └── metadata.json
├── index.json    # All downloaded items
└── errors.json   # Download errors and retries
```

## License

MIT
