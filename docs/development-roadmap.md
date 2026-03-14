# Development Roadmap

## Current Version: 0.4.0

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

### 2.3 Report Generation
- `lazywp report <scan.json>` — generate formatted vulnerability reports
- HTML output with severity charts and executive summary
- Optional PDF export (via wkhtmltopdf or similar)
- Include exploit data, CVSS distribution, remediation suggestions

### 2.4 SARIF Output
- `-f sarif` output format for scan and vuln commands
- Integration with GitHub Code Scanning / CI tools
- Map CVEs to SARIF rules, CVSS to severity levels
- Upload via `gh api` for PR annotations

### 2.5 Auto-Update Monitoring
- `lazywp watch --list slugs.txt` — monitor plugins for new versions/CVEs
- Polling interval configurable (default: daily)
- Notification output (stdout, JSON webhook)
- Compare against previously downloaded versions

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
