# lazywp - Project Overview & Product Development Requirements

## Project Summary

**lazywp** is a high-performance Go CLI tool for bulk downloading WordPress plugins and themes with integrated vulnerability scanning across multiple CVE databases.

**Module Path:** `github.com/hieuha/lazywp`
**Language:** Go 1.25+
**Type:** Command-line Application

## Target Users

- Security researchers
- WordPress security auditors
- Vulnerability assessment teams
- Security software developers

## Key Features

1. **Bulk Downloads**
   - Parallel download of multiple plugins/themes
   - Resume support for interrupted downloads
   - SHA256 verification

2. **Vulnerability Scanning**
   - Cross-reference against WPScan, NVD, Wordfence databases
   - Deduplicated CVE aggregation
   - CVSS score integration
   - Caching with configurable TTL

3. **Advanced Rate Limiting**
   - Per-domain request throttling
   - Multiple rate limit strategies
   - Automatic retry with exponential backoff

4. **API Key Management**
   - Support for multiple WPScan keys
   - Automatic key rotation (round-robin/random)
   - NVD API key support

5. **Proxy Support**
   - Multiple proxy strategies (round-robin, failover, random)
   - Configurable proxy rotation

6. **Multiple Output Formats**
   - Table (human-readable)
   - JSON (programmatic)
   - CSV (spreadsheet-friendly)

7. **Metadata Tracking**
   - Plugin/theme information from WordPress.org
   - Download history and checksums
   - Error logging and retry tracking
   - Comprehensive index files

## Functional Requirements

| Requirement | Status | Details |
|---|---|---|
| Download plugins by slug | Complete | Parallel downloads with progress tracking |
| Download themes by slug | Complete | Same infrastructure as plugins |
| Resume failed downloads | Complete | State persistence via .lazywp-state.json |
| Check vulnerabilities | Complete | Aggregator queries WPScan, NVD, Wordfence |
| List downloaded items | Complete | Indexed storage with multiple output formats |
| Search WordPress.org | Complete | Plugin/theme search integration |
| Export results | Complete | JSON, CSV, table formats |
| Show statistics | Complete | Download metrics and metadata |
| Configure API keys | Complete | Config file management (JSON) |
| Top extensions | Complete | Popular items by active installations |

## Non-Functional Requirements

| Requirement | Target | Implementation |
|---|---|---|
| Concurrency | 5 parallel downloads | Configurable via config.json |
| Rate Limiting | Per-domain throttling | token bucket algorithm |
| Cache TTL | 24 hours default | Configurable, reduces API calls |
| Retry Strategy | Exponential backoff | Max 3 attempts, configurable |
| Storage | Organized directory structure | downloads/{type}/{slug}/{version}/ |

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| CLI Framework | Cobra | Command parsing and execution |
| Progress | progressbar/v3 | Download progress visualization |
| Concurrency | goroutines, sync.WaitGroup | Parallel operations |
| Rate Limiting | golang.org/x/time/rate | Token bucket implementation |
| HTTP Client | net/http | API communication |
| Config Storage | JSON | ~/.lazywp/config.json |
| Data Format | JSON | Metadata and index files |

## Architecture Overview

```
CLI Layer (internal/cli/)
    ↓
Dependency Injection (AppDeps)
    ↓
Service Layer (downloader, vuln aggregator, storage)
    ↓
HTTP Client (internal/http/) with rate limiting + key rotation
    ↓
External APIs (WordPress.org, WPScan, NVD, Wordfence)
```

## Storage Structure

```
downloads/
├── plugins/
│   └── {slug}/
│       └── {version}/
│           ├── {slug}.zip
│           ├── metadata.json
│           └── .lazywp-state.json
├── themes/
│   └── {slug}/
│       └── {version}/
│           ├── {slug}.zip
│           ├── metadata.json
│           └── .lazywp-state.json
├── index.json
└── errors.json
```

## Configuration

Default config path: `~/.lazywp/config.json`

| Key | Type | Default | Purpose |
|---|---|---|---|
| wpscan_keys | []string | [] | WPScan API keys |
| nvd_key | string | "" | NVD API key |
| key_rotation | string | "round-robin" | Key rotation strategy |
| proxy_strategy | string | "round-robin" | Proxy selection method |
| concurrency | int | 5 | Max parallel downloads |
| output_dir | string | "./downloads" | Download destination |
| cache_ttl | string | "24h" | Vulnerability data cache |
| retry_max | int | 3 | Max download retries |
| retry_base_delay | string | "1s" | Initial retry delay |
| rate_limits | object | see below | Per-domain limits |

Rate limits defaults:
- api.wordpress.org: 5 req/sec
- wpscan.com: 1 req/sec
- services.nvd.nist.gov: 0.16 req/sec (1 per 6 seconds)

## Success Metrics

- All downloads complete within configured timeout
- Vulnerability data aggregated from all sources
- Resume functionality recovers interrupted downloads
- Rate limiting prevents API throttling
- Output formats render without errors
- Configuration applies correctly across commands

## Dependencies & Constraints

| Item | Details |
|---|---|
| External APIs | WordPress.org, WPScan, NVD, Wordfence |
| Rate Limits | Applied by all external services |
| API Keys | WPScan and NVD require free API keys |
| Storage | Disk space proportional to plugin/theme size |
| Network | Reliable internet connection required |

## Version Info

- **Go Version:** 1.25.0
- **Cobra:** 1.10.2
- **progressbar:** 3.19.0
- **golang.org/x/time:** 0.15.0
