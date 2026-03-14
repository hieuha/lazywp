# Development Roadmap

## Current Version: 0.6.0

## Phase 1 — Core CLI (COMPLETE)
- [x] Bulk download plugins/themes with resume support
- [x] Vulnerability scanning (WPScan, NVD, Wordfence)
- [x] Exploit lookup via vulnx (PoC, KEV, EPSS, Nuclei)
- [x] Scan local directories for vulnerable plugins/themes
- [x] Convert/filter scan results
- [x] Multi-key rotation, rate limiting, proxy support
- [x] Table/JSON/CSV output formats
- [x] Cache management

## Phase 2 — Feature Expansion (PLANNED)

### 2.1 Theme Support Parity
- Ensure all commands exercise theme paths equally (top, search, vuln, scan)
- Add theme-specific metadata fields (template, parent theme)
- Theme-specific test coverage

### 2.2 Batch Vuln Check (COMPLETE)
- [x] `lazywp vuln --list slugs.txt` — check vulnerabilities for multiple slugs from file
- [x] Mirrors existing `download --list` pattern
- [x] Per-slug colored output with summary
- [x] `--download` flag to download vulnerable plugins

### 2.3 Report Generation (COMPLETE)
- [x] `lazywp report <scan.json>` — generate formatted vulnerability reports
- [x] HTML output with severity charts and executive summary
- [x] Include exploit data, CVSS distribution, detailed findings
- [ ] Optional PDF export (via wkhtmltopdf or similar) — future enhancement

### 2.4 SARIF Output (COMPLETE)
- [x] `-f sarif` output format for scan and vuln commands
- [x] Integration with GitHub Code Scanning / CI tools
- [x] Map CVEs to SARIF rules, CVSS to severity levels
- [x] Upload via `gh api` for PR annotations

### 2.5 Auto-Update Monitoring (COMPLETE)
- [x] `lazywp watch --slug/--list` — monitor plugins for new versions/CVEs
- [x] One-shot mode (default) with exit code 1 on changes for CI/cron
- [x] Daemon mode with configurable interval (`--daemon --interval`)
- [x] Webhook notification support (`--webhook`)
- [x] JSON report output (`-o`)
- [x] State management with baseline tracking and `--reset`

## Phase 3 — Distribution & CI (PLANNED)

### 3.1 CI/CD Pipeline
- GitHub Actions for build, test, lint on PR
- Goreleaser for cross-platform binary releases
- Automated changelog generation

### 3.2 Distribution
- Homebrew formula for macOS
- Docker image for containerized usage
- Pre-built binaries on GitHub Releases

### 3.3 Quality
- Integration tests with real APIs (gated behind env flag)
- Fuzz testing for JSON parsers
- Increase unit test coverage to 80%+
