# Project Changelog

All notable changes to lazywp are documented here.

## [0.8.0] - 2026-03-27

### Added
- Show affected versions (min/max) in `scan --detail` CVE output
- Extract min/max affected versions from Wordfence API response
- Show min/max affected version in all table/CSV output paths
- Progress bars for `top`, `download`, and `watch` commands
- `--download` now downloads all unique affected versions per CVE (deduplicated)

### Changed
- Detail output format now shows `(affected min: Y, max: Z, fixed: W)`
- Progress bar label width increased for full `slug@version` display

### Fixed
- `vuln --download` now downloads affected version instead of latest
- `minFromVersion` / `maxToVersion` return `*` instead of empty string for wildcard ranges
- Handle bool value in WordPress API `tested` field

## [0.7.6] - 2026-03-14

### Added
- Progress bars for `vuln --download`, `extract`, and `vuln --top` fetch operations (replaces verbose per-item print output)
- `--download` now downloads all unique max affected versions per CVE (deduplicated), not just the single highest
- Spinner animation during vulnerability data fetch
- `BatchProgressFunc` callback support in `DownloadBatch` for progress tracking

### Changed
- Detail output format: `(affected: X, min: Y, max: Z)` → `(affected min: Y, max: Z, fixed: W)`
- Progress bar label width increased from 20 to 40 chars for full `slug@version` display

### Fixed
- `minFromVersion` / `maxToVersion` now return `*` instead of empty string when all affected ranges use wildcard `from_version`

## [0.7.5] - 2026-03-14

### Fixed
- `scan` now detects versions in `lazywp extract` layout (`slug/version/slug/`), previously showed all as `@unknown`

### Added
- Typed JSON envelope (`{"type": "scan"|"vuln", "data": [...]}`) for reliable format auto-detection in `convert`

## [0.7.4] - 2026-03-14

### Added
- `vuln --output` (`-o`) flag — write results to file (matches `scan` and `exploit` commands)
- `vuln --detail` with `--format csv/json` now outputs one row per CVE with full info (slug, CVE, CVSS, type, title, affected versions, fixed in, source) instead of aggregated plugin summary
- `convert` auto-detects input format — now supports both `scan` and `vuln` JSON files
- `convert` vuln JSON supports `--slug`, `--min-cvss`, `--max-cvss`, `--cve` filters

## [0.7.3] - 2026-03-14

### Fixed
- `search` command required `--query` flag — now accepts positional arg (`lazywp search "security"`) with `--query` as fallback

### Changed
- Updated all docs: config format JSON → YAML, added missing packages (extractor, scanner, watch), fixed file references, removed outdated limitations

## [0.7.2] - 2026-03-14

### Fixed
- `.gitignore` pattern `lazywp` matched `cmd/lazywp/` directory, preventing it from being tracked — changed to `/lazywp`

## [0.7.1] - 2026-03-14

### Added
- `extract --slug slug:version` syntax for extracting specific versions
- `extract --source-dir` flag for custom downloads directory
- `extract --list` supports `slug:version` per line

### Fixed
- `download --force` flag was not passed to engine (always skipped existing)
- `download` now shows "Already exists: slug@version" instead of silent "Done"
- `download` shows resolved version in "Downloading..." and "Done" messages

## [0.7.0] - 2026-03-14

### Added
- `extract` command — extract downloaded plugin/theme zip files for SAST analysis
- Supports `--slug`, `--list`, `--output-dir`, `--clean` flags
- Zip-slip path traversal protection and zip bomb size limit (500MB)
- Flat output structure (`extracted/<slug>/<version>/`) for easy SAST tool integration

## [0.6.0] - 2026-03-14

### Added
- `watch` command — monitor plugins/themes for new versions and CVEs
- One-shot mode (default) with exit code 1 on changes — CI/cron friendly
- Daemon mode with configurable interval (`--daemon --interval 1h`)
- Webhook notification support (`--webhook <url>`)
- JSON report output (`-o changes.json`)
- State management with `--reset` to clear baseline

## [0.5.0] - 2026-03-14

### Added
- `report` command — generate self-contained HTML vulnerability report from scan JSON
- SARIF v2.1.0 output format (`-f sarif`) for scan and vuln commands — GitHub Code Scanning integration
- `vuln --list slugs.txt` — batch vulnerability check for multiple slugs from file
- Per-slug colored output with vulnerability count and summary

### Fixed
- Exploit lookup gracefully skips remaining CVEs when all PD API keys hit rate limit (instead of fatal error)
- Rotates through all configured PD keys before giving up

## [0.4.0] - 2026-03-14

### Added
- `exploit` command — look up PoC availability, KEV status, EPSS scores, Nuclei templates via vulnx
- `convert` command — re-read scan JSON, apply filters (`--vuln-only`, `--min-cvss`, `--max-cvss`, `--cve`, `--status`, `--exploitable`, `--safe-only`), re-export in table/JSON/CSV
- `scan --check-exploit` flag to enrich scan results with exploit data
- ProjectDiscovery API key support with key rotation
- Per-CVE exploit data caching in `cache/vulnx/`

## [0.3.0] - 2026-03-14

### Added
- `scan` command — detect versions and check vulnerabilities in local plugin/theme directories
- `--detail` flag with full CVE list and update suggestions
- `--output` file flag for CI/CD export
- Colored CVSS severity indicators
- Tabwriter-aligned output with VULNERABLE/SAFE sections

### Fixed
- Table headers and alignment for scan output
- Separated VULNERABLE/SAFE sections with summary at end

## [0.2.0] - 2026-03-13

### Added
- Multi-key rotation for WPScan API (round-robin, random, fallback)
- YAML config file support (`config.yaml`)
- `cache` command (status, update, clear)
- Improved vuln output formatting
- Case study documentation (EN/VI)

### Fixed
- Wordfence vuln query falls back to RSS when HTML scraping fails
- `active_installs` JSON tag to match WordPress API response

## [0.1.0] - 2026-03-13

### Added
- Initial CLI implementation with Cobra framework
- `download` command — bulk download plugins/themes with parallel workers
- `vuln` command — cross-reference against WPScan, NVD, Wordfence
- `search`, `top`, `list`, `stats`, `export`, `config`, `version` commands
- Resume support for interrupted downloads
- SHA256 checksum verification
- Per-domain rate limiting (token bucket)
- Proxy support (round-robin, failover, random)
- Table, JSON, CSV output formats
- File-based vulnerability caching with configurable TTL
- Dependency injection via AppDeps struct
