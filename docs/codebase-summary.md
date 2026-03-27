# Codebase Summary - lazywp

A high-performance Go CLI tool for bulk downloading WordPress plugins/themes with integrated vulnerability scanning.

**Module:** github.com/hieuha/lazywp
**Language:** Go 1.25.0
**Version:** 0.8.0
**Last Updated:** 2026-03-27

## Quick Navigation

| Package | Purpose | Key Files |
|---|---|---|
| cmd/lazywp | Application entry point | main.go |
| internal/cli | Command handlers | root.go, download.go, vuln.go, scan.go, exploit.go, convert.go, list.go, search.go, stats.go, top.go, export.go, config_cmd.go, version.go, formatter.go, deps.go, scan_progress.go, scan_exploit_enrichment.go, cache_cmd.go, extract.go, report.go, report_template.go, sarif.go, watch.go |
| internal/client | External API clients | wordpress.go, wpscan.go, nvd.go, wordfence.go, types.go |
| internal/config | Configuration management | config.go |
| internal/downloader | Download orchestration | engine.go, progress.go, resume.go |
| internal/exploit | vulnx integration | cvemap.go |
| internal/extractor | ZIP extraction | extractor.go |
| internal/http | HTTP utilities | client.go, ratelimit.go, key_rotator.go, proxy.go |
| internal/scanner | Local directory scanning | scanner.go, version.go |
| internal/storage | File persistence | manager.go, models.go, item_type.go |
| internal/vuln | Vulnerability aggregation | aggregator.go, cache.go |
| internal/watch | Watch state management | state.go |

## Package Details

### cmd/lazywp
**Responsibility:** Entry point for the CLI application.
**Files:** 1 file (13 LOC)
- `main.go` - Delegates to internal/cli.Execute()

### internal/cli
**Responsibility:** Command parsing, validation, and output formatting.
**Files:** 23 files, ~1 600 LOC (excluding tests)

| File | Purpose |
|---|---|
| `root.go` | Root command, global flags (verbose, quiet, output format, config path), dependency initialization |
| `download.go` | Download plugin/theme command handler |
| `vuln.go` | Vulnerability check command handler |
| `scan.go` | Scan local directory; `--check-exploit` integrates exploit enrichment |
| `scan_progress.go` | Progress bar helpers for scan operations |
| `scan_exploit_enrichment.go` | Enriches scan results with vulnx exploit data |
| `exploit.go` | Standalone exploit/PoC lookup via vulnx; `--file`, `--has-poc`, `--has-nuclei` |
| `convert.go` | Re-read scan JSON, apply filters, re-export in any format |
| `list.go` | List downloaded items with filtering |
| `search.go` | Search WordPress.org for plugins/themes |
| `stats.go` | Display download statistics |
| `top.go` | Show popular extensions by active installations |
| `export.go` | Export data in JSON/CSV formats |
| `config_cmd.go` | Config management (show, set) |
| `version.go` | Display CLI version |
| `formatter.go` | Output formatting (table, JSON, CSV, SARIF) with pretty-printing |
| `deps.go` | Dependency injection, builds AppDeps struct |
| `cache_cmd.go` | Cache management commands (list, clear, cleanup) |
| `extract.go` | Extract plugin/theme archives with zip-slip protection |
| `report.go` | Generate vulnerability reports from scan results |
| `report_template.go` | HTML/Markdown report templates for rendering |
| `sarif.go` | SARIF format output for security scanning |
| `watch.go` | Watch local directories for WordPress changes |

**Key Interfaces:**
- Formatter - abstracts output formatting

**Flow:** User input → Command handler → Service layer → Output formatter

### internal/client
**Responsibility:** API integrations with external services.
**Files:** 5 files, ~600 LOC (excluding tests)

| File | Purpose |
|---|---|
| `types.go` | Shared types: ItemType (plugin/theme), APIResponse structures |
| `wordpress.go` | WordPress.org REST API (plugin info, theme info, search, download URLs) |
| `wpscan.go` | WPScan API (vulnerability database, requires API key) |
| `nvd.go` | National Vulnerability Database (NVD) API |
| `wordfence.go` | Wordfence threat database (alternative vuln source) |

**Interfaces Implemented:**
- `VulnSource` - Implemented by wpscan.go, nvd.go, wordfence.go

**Data Flow:** CLI → Client → HTTP Client → External API → Response parsing

### internal/config
**Responsibility:** Application configuration management (YAML format).
**Files:** 1 file, ~100 LOC (excluding tests)

**Key Functions:**
- `Load(path string)` - Load config from YAML file
- `Save(path string)` - Save config to YAML file
- `DefaultConfig()` - Create config with sensible defaults
- `CacheTTLDuration()` - Parse cache TTL string to duration
- `RetryBaseDelayDuration()` - Parse retry delay string to duration

**Config Location:** `./config.yaml`

**Config Struct (YAML tags):**
```go
type Config struct {
    WPScanKeys        []string           `yaml:"wpscan_keys,omitempty"`
    WordfenceKeys     []string           `yaml:"wordfence_keys,omitempty"`
    NVDKeys           []string           `yaml:"nvd_keys,omitempty"`
    KeyRotation       string             `yaml:"key_rotation"`
    Proxies           []string           `yaml:"proxies,omitempty"`
    ProxyStrategy     string             `yaml:"proxy_strategy"`
    Concurrency       int                `yaml:"concurrency"`
    OutputDir         string             `yaml:"output_dir"`
    CacheDir          string             `yaml:"cache_dir"`
    RateLimits        map[string]float64 `yaml:"rate_limits"`
    CacheTTL          string             `yaml:"cache_ttl"`
    RetryMax          int                `yaml:"retry_max"`
    RetryBaseDelay    string             `yaml:"retry_base_delay"`
    TitleMaxLen       int                `yaml:"title_max_len"`
    PDAPIKey          string             `yaml:"projectdiscovery_api_key,omitempty"`
    PDAPIKeys         []string           `yaml:"projectdiscovery_api_keys,omitempty"`
}
```

**Example Config:**
```yaml
wpscan_keys:
  - key1
  - key2
wordfence_keys:
  - wordfence-key
nvd_keys:
  - nvd-key
key_rotation: round-robin
proxy_strategy: round-robin
concurrency: 5
output_dir: ./downloads
cache_dir: ./cache
rate_limits:
  api.wordpress.org: 5
  wpscan.com: 1
  services.nvd.nist.gov: 0.16
cache_ttl: 24h
retry_max: 3
retry_base_delay: 1s
title_max_len: 100
projectdiscovery_api_key: your-pd-key
```

### internal/downloader
**Responsibility:** Orchestrate concurrent downloads with resume support.
**Files:** 3 files, ~400 LOC (excluding tests)

| File | Purpose |
|---|---|
| `engine.go` | DownloadEngine struct, batch download orchestration, metadata collection |
| `progress.go` | Progress bar management for individual downloads |
| `resume.go` | Download state persistence (.lazywp-state.json), resume logic |

**Key Types:**
- `Engine` - Main coordinator
- `DownloadJob` - Represents one plugin/theme to download
- `BatchResult` - Summary of batch operation

**Process:**
1. Validate plugin/theme via WordPress.org API
2. Create directory: `downloads/{type}/{slug}/{version}/`
3. Download file with progress tracking
4. Verify SHA256 checksum
5. Store metadata.json
6. Update index.json
7. Record errors in errors.json

**Resume Logic:**
- State saved in `.lazywp-state.json` per download
- On retry, resume from last byte
- Avoids re-downloading completed chunks

### internal/http
**Responsibility:** HTTP communication with rate limiting, key rotation, and proxy support.
**Files:** 4 files, ~400 LOC

| File | Purpose |
|---|---|
| `client.go` | HTTP client wrapper with middleware support |
| `ratelimit.go` | Per-domain token bucket rate limiter |
| `key_rotator.go` | API key rotation strategies (round-robin, random) |
| `proxy.go` | Proxy selection and rotation |

**Rate Limiting:**
- Token bucket algorithm per domain
- Defaults: api.wordpress.org (5/sec), wpscan.com (1/sec), services.nvd.nist.gov (0.16/sec)
- Blocks requests until tokens available

**Key Rotation:**
- Strategies: round-robin, random, fallback
- Applied to WPScan keys (multiple keys supported)

**Proxy Support:**
- Strategies: round-robin, failover, random
- Optional configuration

### internal/storage
**Responsibility:** File and metadata persistence.
**Files:** 3 files, ~200 LOC (excluding tests)

| File | Purpose |
|---|---|
| `manager.go` | StorageManager for file I/O operations |
| `models.go` | Data structure definitions |
| `item_type.go` | ItemType enum (Plugin, Theme) |

**Data Structures:**

**Metadata (per downloaded item):**
- Slug, name, version, type
- SHA256 checksum, file size
- Download URL and timestamp
- WordPress metadata (active installations, tested up to, requires PHP, author, last updated)
- Vulnerabilities array (filled by vuln aggregator)

**IndexEntry (global index):**
- Slug, type, version
- Downloaded timestamp
- Has vulnerabilities flag
- File size

**ErrorEntry (global error log):**
- Slug, version, type
- Error message
- Timestamp
- Retry count

**Storage Layout:**
```
downloads/
├── plugins/{slug}/{version}/
│   ├── {slug}.zip
│   ├── metadata.json
│   └── .lazywp-state.json
├── themes/{slug}/{version}/
│   ├── {slug}.zip
│   ├── metadata.json
│   └── .lazywp-state.json
├── index.json
└── errors.json
```

### internal/extractor
**Responsibility:** ZIP archive extraction with zip-slip protection.
**Files:** 1 file, ~150 LOC (excluding tests)

| File | Purpose |
|---|---|
| `extractor.go` | SafeExtract validates paths, prevents directory traversal attacks |

**Key Functions:**
- `SafeExtract(zipPath, destDir string)` - Extract ZIP with security validation

### internal/scanner
**Responsibility:** Local directory scanning and WordPress version detection.
**Files:** 2 files, ~250 LOC (excluding tests)

| File | Purpose |
|---|---|
| `scanner.go` | Scan directories for WordPress plugins/themes, extract metadata |
| `version.go` | Detect WordPress core version from wp-includes |

### internal/vuln
**Responsibility:** Aggregate vulnerability data from multiple sources.
**Files:** 2 files, ~200 LOC (excluding tests)

| File | Purpose |
|---|---|
| `aggregator.go` | VulnAggregator queries all sources in parallel |
| `cache.go` | Caches vulnerability results with TTL |

### internal/watch
**Responsibility:** Watch state management for directory monitoring.
**Files:** 1 file, ~100 LOC

| File | Purpose |
|---|---|
| `state.go` | Tracks watched directories and change state |

**VulnAggregator Process:**
1. Accept list of VulnSource implementations
2. Query all sources concurrently
3. Merge results, deduplicate by CVE ID
4. Sort by CVSS score (descending)
5. Return merged list + warnings for failed sources

**Cache Strategy:**
- Stores results by (slug, itemType, source) key
- TTL configurable (default 24h)
- Reduces API calls for repeated lookups

**Vulnerability Fields:**
- CVE ID, CVSS score
- Type (authenticated/unauthenticated)
- Title, source (WPScan/NVD/Wordfence)
- Affected versions, fixed in version
- Reference URLs

## Key Algorithms & Patterns

### Concurrency Model
- **Worker Pool:** Batch downloads limited by concurrency config (default 5)
- **Fan-Out/Fan-In:** Vulnerability queries across multiple sources
- **Synchronization:** sync.WaitGroup for batch ops, sync.Mutex for error collection
- **Channels:** Used for source results aggregation

### Rate Limiting
Token bucket implementation per domain:
```go
rateLimits := map[string]float64{
    "api.wordpress.org": 5.0,      // 5 req/sec
    "wpscan.com": 1.0,             // 1 req/sec
    "services.nvd.nist.gov": 0.16, // 1 req/6sec
}
```

### Error Handling
- Non-fatal errors accumulated and reported
- Retry with exponential backoff (configurable max 3 attempts)
- Failed downloads logged in errors.json
- Warnings collected from partial failures

### Dependency Injection
Single AppDeps struct built once during CLI startup:
```go
type AppDeps struct {
    Config        *config.Config
    HTTPClient    *http.Client
    WPClient      *client.WordPressClient
    VulnAgg       *vuln.Aggregator
    StorageMgr    *storage.Manager
    Downloader    *downloader.Engine
}
```

All services receive dependencies via constructors, no global singletons.

## Testing Coverage

Test files present for:
- internal/config/ - config_test.go
- internal/downloader/ - resume_test.go
- internal/extractor/ - extractor_test.go
- internal/http/ - key_rotator_test.go, proxy_test.go, ratelimit_test.go
- internal/scanner/ - scanner_test.go, version_test.go
- internal/storage/ - manager_test.go
- internal/vuln/ - aggregator_test.go, cache_test.go

**Testing Approach:** Table-driven tests for multiple scenarios

## External Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| github.com/spf13/cobra | v1.10.2 | CLI framework |
| github.com/schollz/progressbar/v3 | v3.19.0 | Progress visualization |
| golang.org/x/time | v0.15.0 | Rate limiting (token bucket) |
| gopkg.in/yaml.v3 | v3.0.1 | YAML configuration parsing |

## Performance Characteristics

| Metric | Value | Notes |
|---|---|---|
| Download buffer | 32KB | Streaming, not in-memory |
| HTTP connection pool | 100 max idle | Per http.Transport |
| Concurrency | 5 (configurable) | Parallel downloads |
| Vulnerability cache | 24h TTL | Reduces API calls |
| Retry strategy | Exponential backoff | Max 3 attempts |

## Security Considerations

- API keys stored in `./config.yaml` (user responsible for file permissions)
- SHA256 verification of all downloads
- Zip-slip protection in archive extraction
- TLS for all external API communication
- No credentials logged (unless verbose mode)
- Proxy support for privacy-sensitive environments

## Entry Points

1. **CLI Entry:** cmd/lazywp/main.go → internal/cli.Execute()
2. **Commands:**
   - `lazywp download {plugin|theme} <slugs>...` - Batch download plugins/themes
   - `lazywp vuln check {plugin|theme} <slug>` - Check vulnerabilities for single item
   - `lazywp scan <dir> [-t plugin|theme] [--check-exploit]` - Scan local directory
   - `lazywp exploit [CVE-ID...] [--file scan.json] [--has-poc] [--has-nuclei]` - Lookup exploits
   - `lazywp convert <scan.json> [--vuln-only] [--min-cvss N] [--exploitable] [-f csv]` - Re-export scan results
   - `lazywp extract <path/to/file.zip> [-d <dest>]` - Extract plugin/theme archives
   - `lazywp report <scan.json> [-f html|markdown|json]` - Generate vulnerability reports
   - `lazywp cache {list|clear|cleanup}` - Manage cached data
   - `lazywp watch <dir> [--daemon]` - Monitor directory for WordPress changes
   - `lazywp list [plugin|theme]` - List downloaded items
   - `lazywp search {plugin|theme} <query>` - Search WordPress.org
   - `lazywp stats` - Display download statistics
   - `lazywp top {plugin|theme}` - Show popular extensions
   - `lazywp export {plugin|theme}` - Export metadata
   - `lazywp config {show|set <key> <value>}` - Manage configuration
   - `lazywp version` - Display CLI version

## Build & Deployment

**Binary:** `lazywp` (compiled from cmd/lazywp/main.go)
**Installation:** Via `go install github.com/hieuha/lazywp/cmd/lazywp@latest`

## Configuration Defaults

| Setting | Default | Range |
|---|---|---|
| Concurrency | 5 | 1-N |
| Cache TTL | 24h | Any duration |
| Retry max | 3 | 1-N |
| Retry base delay | 1s | Any duration |
| Output dir | ./downloads | Any path |
| Cache dir | ./cache | Any path |
| Output format | table | table/json/csv/sarif |
| Title max length | 100 | 1-N |

## Known Limitations

- Single-threaded CLI (each command runs once)
- Configuration requires manual file editing (except `config set` commands)
- No multi-user access control
- Watch mode requires manual restart on major changes
