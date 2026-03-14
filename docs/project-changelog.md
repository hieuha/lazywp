# Project Changelog

All notable changes to lazywp are documented here.

## [Unreleased]

### Added
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
