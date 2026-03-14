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

3. **Exploit Lookup**
   - PoC availability detection
   - KEV (Known Exploited Vulnerabilities) integration
   - EPSS scores for exploit probability
   - Nuclei template integration via vulnx

4. **Local Scanning**
   - Detect installed plugin/theme versions
   - Cross-check against vulnerability databases
   - SAST-ready analysis

5. **Advanced Rate Limiting**
   - Per-domain request throttling
   - Token bucket algorithm
   - Automatic retry with exponential backoff

6. **API Key Management**
   - Support for multiple WPScan, Wordfence, NVD, and ProjectDiscovery keys
   - Automatic key rotation (round-robin/random)
   - Bulk key configuration

7. **Proxy Support**
   - Multiple proxy strategies (round-robin, failover, random)
   - Configurable proxy rotation

8. **Multiple Output Formats**
   - Table (human-readable)
   - JSON (programmatic)
   - CSV (spreadsheet-friendly)
   - SARIF (security reporting)

9. **Watch Mode**
   - Daemon mode for continuous monitoring
   - Detect new plugin/theme versions
   - Monitor for new CVE data

10. **Zip Extraction & Analysis**
    - Extract downloaded plugins/themes
    - Support for SAST analysis workflows

11. **Report Generation**
    - HTML reports with severity charts
    - Downloadable vulnerability summaries

12. **Cache Management**
    - Status reporting
    - Manual cache updates
    - Per-CVE exploit data caching

13. **Metadata Tracking**
    - Plugin/theme information from WordPress.org
    - Download history and checksums
    - Error logging and retry tracking
    - Comprehensive index files

## Functional Requirements

| Command | Status | Details |
|---|---|---|
| download | Complete | Parallel downloads with progress tracking, resume, SHA256 |
| vuln | Complete | Vulnerability scanning (WPScan, NVD, Wordfence) |
| scan | Complete | Local scanning with version detection |
| exploit | Complete | PoC, KEV, EPSS, Nuclei integration |
| convert | Complete | Filter and re-export scan JSON |
| report | Complete | Generate HTML reports with severity charts |
| watch | Complete | Daemon mode for continuous monitoring |
| extract | Complete | Zip extraction with slug:version syntax |
| cache | Complete | Status, clear, update operations |
| top | Complete | Popular extensions by installations |
| search | Complete | WordPress.org plugin/theme search |
| list | Complete | List downloaded items with metadata |
| stats | Complete | Download metrics and statistics |
| export | Complete | JSON, CSV, table, SARIF formats |
| config | Complete | Manage configuration settings |
| version | Complete | Display version information |

## Non-Functional Requirements

| Requirement | Target | Implementation |
|---|---|---|
| Concurrency | 5 parallel downloads | Configurable via config.yaml |
| Rate Limiting | Per-domain throttling | token bucket algorithm |
| Cache TTL | 24 hours default | Configurable, reduces API calls |
| Retry Strategy | Exponential backoff | Max 3 attempts, configurable |
| Storage | Organized directory structure | downloads/{type}/{slug}/{version}/ |

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| CLI Framework | github.com/spf13/cobra v1.10.2 | Command parsing and execution |
| Progress | github.com/schollz/progressbar/v3 v3.19.0 | Download progress visualization |
| Concurrency | goroutines, sync.WaitGroup | Parallel operations |
| Rate Limiting | golang.org/x/time v0.15.0 | Token bucket implementation |
| Config Format | YAML (gopkg.in/yaml.v3 v3.0.1) | config.yaml in current directory |
| HTTP Client | net/http | API communication |
| Data Format | JSON | Metadata and index files |

## Architecture Overview

```
CLI Layer (internal/cli/)
    ↓
Dependency Injection (AppDeps)
    ↓
Service Layer (downloader, scanner, exploit, extractor, watch, report)
    ↓
HTTP Client (internal/http/) with rate limiting + key rotation
    ↓
Vulnerability Aggregator (WPScan, NVD, Wordfence)
    ↓
External APIs (WordPress.org, WPScan, NVD, Wordfence, ProjectDiscovery)
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

Config file: `config.yaml` (in current directory)

| Key | Type | Default | Purpose |
|---|---|---|---|
| wpscan_keys | []string | [] | WPScan API keys |
| wordfence_keys | []string | [] | Wordfence API keys |
| nvd_keys | []string | [] | NVD API keys |
| projectdiscovery_api_keys | []string | [] | ProjectDiscovery API keys |
| key_rotation | string | "round-robin" | Key rotation strategy |
| proxies | []string | [] | Proxy servers |
| proxy_strategy | string | "round-robin" | Proxy selection method |
| concurrency | int | 5 | Max parallel downloads |
| output_dir | string | "./downloads" | Download destination |
| cache_dir | string | "./cache" | Cache directory |
| cache_ttl | string | "24h" | Vulnerability data cache TTL |
| retry_max | int | 3 | Max download retries |
| retry_base_delay | string | "1s" | Initial retry delay |
| title_max_len | int | 100 | Max title length for reports |
| rate_limits | object | see below | Per-domain limits |

Rate limits defaults:
- api.wordpress.org: 5 req/sec
- wpscan.com: 1 req/sec
- services.nvd.nist.gov: 0.16 req/sec (1 per 6 seconds)
- www.wordfence.com: 0.1 req/sec

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
- **YAML (gopkg.in/yaml.v3):** 3.0.1
- **Project Version:** 0.7.2
