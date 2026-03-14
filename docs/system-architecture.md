# System Architecture

## Package Structure

```
github.com/hieuha/lazywp/
├── cmd/lazywp/
│   └── main.go              # Entry point
├── internal/
│   ├── cli/                 # Command handlers (23 files)
│   ├── client/              # API clients for external services
│   ├── config/              # Configuration management
│   ├── downloader/          # Download orchestration
│   ├── exploit/             # vulnx/cvemap integration
│   ├── extractor/           # Zip extraction for SAST
│   ├── http/                # HTTP client with rate limiting
│   ├── scanner/             # Local directory scanning
│   ├── storage/             # File and metadata persistence
│   ├── vuln/                # Vulnerability aggregation
│   └── watch/               # Watch state management
```

## Component Descriptions

### cmd/lazywp
**Responsibility:** Application entry point.

**Files:**
- `main.go` - Initializes CLI and delegates to root command

### internal/cli
**Responsibility:** Command parsing, user input validation, output formatting.

**Key Files:**
- `root.go` - Root command with global flags (verbose, quiet, output format, config path)
- `download.go` - Download plugin/theme command
- `vuln.go` - Vulnerability check command
- `scan.go` - Scan local directory; supports `--check-exploit` to enrich with exploit data
- `scan_progress.go` - Progress bar helpers shared by scan and exploit commands
- `scan_exploit_enrichment.go` - Batch enrichment of scan results via vulnx
- `exploit.go` - Standalone exploit/PoC lookup (`lazywp exploit [CVE...] [--file] [--has-poc]`)
- `extract.go` - Extract downloaded zips for SAST analysis
- `cache_cmd.go` - Cache management (status, update, clear)
- `convert.go` - Re-read scan JSON, filter, re-export (`lazywp convert`)
- `report.go` - Generate HTML vulnerability report from scan JSON
- `report_template.go` - HTML template for report generation
- `sarif.go` - SARIF v2.1.0 output format for GitHub Code Scanning
- `watch.go` - Monitor plugins/themes for new versions and CVEs
- `list.go` - List downloaded items
- `search.go` - Search WordPress.org
- `stats.go` - Display download statistics
- `top.go` - Show popular extensions
- `export.go` - Export data in multiple formats
- `config_cmd.go` - Config management (set, show)
- `version.go` - Display CLI version
- `formatter.go` - Output formatting (table, JSON, CSV)
- `deps.go` - Dependency injection for services

### internal/exploit
**Responsibility:** Wrap ProjectDiscovery's vulnx/cvemap CLI for CVE exploit metadata.

**Key Files:**
- `cvemap.go` - Provides `CVEInfo` struct (CVEID, CVSS, Severity, HasPOC, POCCount, POCURLs, IsKEV, EPSS, HasNuclei, NucleiURL)
  - `CheckAvailable()` - verifies cvemap is installed
  - `LookupCVEs(ids, apiKey, onProgress)` - batched lookups (10 CVEs/batch, 3s inter-batch delay, rate-limit retry)

**Output Formats:**
- Table (human-readable)
- JSON (structured data)
- CSV (spreadsheet-friendly)

### internal/client
**Responsibility:** API client implementations for external services.

**Key Files:**
- `wordpress.go` - WordPress.org REST API client (plugins, themes, info)
- `wpscan.go` - WPScan vulnerability database client
- `nvd.go` - National Vulnerability Database client
- `wordfence.go` - Wordfence threat database client
- `types.go` - Shared type definitions and ItemType enum

### internal/config
**Responsibility:** Configuration file management and defaults.

**Key Files:**
- `config.go` - Config struct, load/save, default values

**Configuration Path:** `./config.yaml` (in current working directory)

**Default Configuration:**
```yaml
key_rotation: round-robin          # API key rotation strategy
proxy_strategy: round-robin        # Proxy rotation strategy
concurrency: 5                      # Concurrent downloads
output_dir: ./downloads            # Download destination
cache_dir: ./cache                 # Cache directory
rate_limits:                        # Per-domain request rates (req/sec)
  api.wordpress.org: 5
  wpscan.com: 1
  services.nvd.nist.gov: 0.16
  www.wordfence.com: 0.1
cache_ttl: 24h                      # Vulnerability cache duration
retry_max: 3                        # Maximum retry attempts
retry_base_delay: 1s               # Initial retry delay
title_max_len: 100                 # Max title length in display
```

### internal/downloader
**Responsibility:** Orchestrate concurrent downloads with resume support.

**Key Files:**
- `engine.go` - DownloadEngine, coordinates parallel downloads
- `progress.go` - Progress bar management for downloads
- `resume.go` - Download state persistence and resume logic

**Process:**
1. Validate plugin/theme exists via WordPress.org API
2. Create directory structure: `downloads/{type}/{slug}/{version}/`
3. Download file with progress tracking
4. Verify SHA256 checksum
5. Store metadata.json
6. Update index.json
7. On failure: record in errors.json, support resume

### internal/extractor
**Responsibility:** Safe zip extraction with protection against path traversal and zip bombs.

**Key Files:**
- `extractor.go` - Extract zips into destination directory
  - Validates against zip-slip path traversal attacks
  - Enforces 500MB safety limit per archive
  - Creates directory structure and preserves permissions

**Process:**
1. Open zip file for reading
2. Validate each file path (no parent directory references)
3. Check total extracted size against limit
4. Extract files to destination with proper permissions
5. Return error if safety checks fail

### internal/scanner
**Responsibility:** Detect WordPress plugins and themes from local directory structure.

**Key Files:**
- `scanner.go` - Scan directories and detect items
  - `ScanDirectory(dir, itemType)` - Walk directory tree, find plugins/themes
  - Version detection strategy:
    - **Plugin**: readme.txt "Stable tag" → PHP file "Version:" header
    - **Theme**: style.css "Version:" header → readme.txt "Stable tag"
- `version.go` - Version extraction helpers
  - Parse readme.txt for stable tag
  - Extract Version from PHP/CSS headers using regex patterns

**Output:**
- `ScannedPlugin` struct with: Slug, Version, Path

### internal/watch
**Responsibility:** Track plugin/theme versions and CVEs for continuous monitoring.

**Key Files:**
- `state.go` - Watch baseline state management
  - `WatchState` - Map of slug → version/CVE history
  - `SlugState` - Per-item tracking (Version, CVEs, LastCheck timestamp)
  - `Change` - Detected differences (new_version, new_cve)
  - Load/save state from JSON file for persistence

**Process:**
1. Load baseline state from watch file (if exists)
2. Check current versions and CVEs
3. Detect changes (version bump, new CVE)
4. Report changes to user
5. Update and persist state for next run

### internal/http
**Responsibility:** HTTP communication with rate limiting, key rotation, and proxy support.

**Key Files:**
- `client.go` - HTTP client wrapper with middleware
- `ratelimit.go` - Per-domain token bucket rate limiter
- `key_rotator.go` - API key rotation strategy (round-robin, random)
- `proxy.go` - Proxy selection and rotation

**Features:**
- Automatic retry with exponential backoff
- Per-domain rate limiting
- Multiple API key rotation strategies
- Proxy support with failover

### internal/storage
**Responsibility:** Persist downloads, metadata, and error tracking.

**Key Files:**
- `manager.go` - StorageManager for file operations
- `models.go` - Data structures (Metadata, Vulnerability, IndexEntry, ErrorEntry)
- `item_type.go` - ItemType enum (Plugin, Theme)

**Data Structures:**

**Metadata (per file):**
```json
{
  "slug": "akismet",
  "name": "Akismet Anti-spam",
  "type": "plugin",
  "version": "5.0.1",
  "sha256": "...",
  "file_size": 123456,
  "download_url": "https://downloads.wordpress.org/plugin/akismet.5.0.1.zip",
  "downloaded_at": "2024-01-01T10:00:00Z",
  "wp_metadata": {
    "active_installations": 3000000,
    "tested_up_to": "6.4",
    "requires_php": "5.2.4",
    "author": "Automattic",
    "last_updated": "2024-01-15"
  },
  "vulnerabilities": [...]
}
```

**Index (global):**
```json
[
  {
    "slug": "akismet",
    "type": "plugin",
    "version": "5.0.1",
    "downloaded_at": "2024-01-01T10:00:00Z",
    "has_vulns": true,
    "file_size": 123456
  }
]
```

**Error Log (global):**
```json
[
  {
    "slug": "broken-plugin",
    "version": "1.0",
    "type": "plugin",
    "error": "404 not found",
    "timestamp": "2024-01-01T10:05:00Z",
    "retries": 3
  }
]
```

### internal/vuln
**Responsibility:** Aggregate vulnerability data from multiple sources.

**Key Files:**
- `aggregator.go` - VulnAggregator queries all sources in parallel
- `cache.go` - Caches vulnerability data with configurable TTL

**Process:**
1. Query all vulnerability sources concurrently (WPScan, NVD, Wordfence)
2. Merge results, deduplicate by CVE ID
3. Sort by CVSS score (descending)
4. Cache results for configured TTL
5. Return merged list plus warnings for failed sources

## Data Flow

### Download Flow
```
User → CLI (download) → Validator (WordPress.org) → Downloader Engine
                                                     ↓
                                            HTTP Client (rate limited)
                                                     ↓
                                         WordPress CDN (file transfer)
                                                     ↓
                                            Storage Manager
                                                     ↓
                                         Disk (files + metadata)
```

### Vulnerability Lookup Flow
```
User → CLI (vuln check) → VulnAggregator
                              ↓
                         [Parallel queries]
                              ↓
                    ┌─────────┼─────────┐
                    ↓         ↓         ↓
                 WPScan     NVD    Wordfence
                    ↓         ↓         ↓
                    └─────────┼─────────┘
                              ↓
                         Cache Manager
                              ↓
                         Output Formatter → User
```

### List/Export Flow
```
User → CLI (list/export) → Storage Manager (read index.json)
                                ↓
                           Formatter (table/json/csv)
                                ↓
                              stdout
```

### Extract Flow
```
User → CLI (extract) → Extractor
                           ↓
                      Validate path safety (zip-slip)
                           ↓
                      Check size limits (500MB)
                           ↓
                      Extract files
                           ↓
                      Destination directory
```

### Report Flow
```
User → CLI (report) → Storage Manager (read scan results)
                           ↓
                      Report formatter
                           ↓
                      HTML template rendering
                           ↓
                      Output HTML report
```

### Watch Flow
```
User → CLI (watch) → Scanner (detect current versions)
                           ↓
                      VulnAggregator (fetch CVEs)
                           ↓
                      Compare with state file
                           ↓
                      Detect changes (new_version, new_cve)
                           ↓
                      Report changes + Update state
```

### Scan Flow (with optional exploit enrichment)
```
User → CLI (scan) → Scanner (detect local items)
                           ↓
                      Store results (JSON)
                           ↓
                      [Optional] Enrichment via vulnx
                           ↓
                      VulnAggregator (parallel sources)
                           ↓
                      Merge and cache
                           ↓
                      Output formatted results
```

## Rate Limiting Strategy

**Token Bucket Algorithm per domain:**
- Maintains separate rate limit for each API endpoint
- Configured defaults:
  - api.wordpress.org: 5 req/sec
  - wpscan.com: 1 req/sec
  - services.nvd.nist.gov: 0.16 req/sec
  - www.wordfence.com: 0.1 req/sec
- Blocks requests until tokens available
- Prevents API throttling and bans

## Concurrency Model

**Goroutine pools:**
- Download engine: up to N concurrent downloads (default 5)
- HTTP client: unlimited concurrent requests (rate limited via token bucket)
- Vulnerability aggregator: 1 goroutine per source (typically 3-4)

**Synchronization:**
- `sync.WaitGroup` for batch operations
- `sync.Mutex` for shared error collection
- Channel-based communication between goroutines

## Error Handling

**Strategy:**
- Non-fatal errors logged and recorded
- Failed downloads added to errors.json
- Resume state saved for retry attempts
- User receives error summary after batch operations
- Retry logic with exponential backoff

**Error Categories:**
1. Network errors → Retry with backoff
2. 404 errors → Log and skip
3. Rate limit (429) → Back off and retry
4. Invalid plugin/theme → Log and skip
5. Disk errors → Fatal, stop operation

## Configuration Lifecycle

**Load:**
1. Default config created
2. User-provided config path or default (./config.yaml) loaded
3. Merged with defaults
4. Validated before use

**Update:**
- CLI `config set` writes to config file
- Changes applied on next command execution

## Security Considerations

- API keys stored in plaintext in config file (user responsibility for file permissions)
- SHA256 verification of downloads
- TLS for all API communication
- No sensitive data logged by default (verbose flag adds detail)
- Proxy support for privacy-sensitive environments

## Performance Optimizations

- Parallel downloads limited by concurrency setting
- HTTP connection pooling via net/http
- Vulnerability data cached for 24 hours (configurable)
- Progress bar updates without blocking downloads
- Streaming file download with 32KB buffer
- Minimal memory footprint for large batches

## Extensibility Points

- **New CLI Commands:** Add handler in internal/cli/
- **New Vulnerability Sources:** Implement VulnSource interface
- **New Output Formats:** Extend Formatter in internal/cli/
- **New API Clients:** Add client in internal/client/
