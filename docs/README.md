# lazywp Documentation

Complete documentation for the lazywp Go CLI tool for bulk downloading WordPress plugins/themes with vulnerability scanning.

## Documentation Files

### Quick Start

Start here for an overview of the project and its capabilities.

- **[Project Overview & PDR](./project-overview-pdr.md)** — What lazywp does, features, requirements, and tech stack. Best for understanding project scope and making architectural decisions.

### For Developers

Learn how the codebase is organized and how to contribute.

- **[System Architecture](./system-architecture.md)** — Package structure, component responsibilities, data flow, concurrency patterns, and design decisions. Best for understanding how the system works.

- **[Code Standards](./code-standards.md)** — Go conventions, naming rules, error handling patterns, testing strategies, and code review checklist. Best for writing code that fits the project.

- **[Codebase Summary](./codebase-summary.md)** — Complete package-by-package breakdown with file names, LOC counts, key types, and data structures. Best for locating code and understanding implementation details.

## Navigation by Role

### Security Researcher (End User)

- Start with **Project Overview & PDR** to understand features
- See README.md in the project root for CLI command reference
- Use `lazywp --help` for command-line help

### New Developer

1. Read **Project Overview & PDR** (5 min) — understand the goal
2. Read **System Architecture** (10 min) — understand the design
3. Read **Code Standards** (10 min) — understand the conventions
4. Use **Codebase Summary** (reference) — locate code quickly

### Architect/Tech Lead

- **System Architecture** — data flow, concurrency, extensibility
- **Project Overview & PDR** — requirements, constraints, success metrics
- **Code Standards** — enforce consistency

### Maintenance/Bug Fix

- **Codebase Summary** — locate the relevant package
- **System Architecture** — understand interactions
- **Code Standards** — follow existing patterns

## Key Concepts

### Architecture Layers

```
CLI Layer (internal/cli/)
    ↓
Service Layer (downloader, vuln aggregator, storage)
    ↓
HTTP Client Layer (internal/http/) with rate limiting
    ↓
External APIs (WordPress.org, WPScan, NVD, Wordfence)
```

### Main Components

| Component | Purpose | Files |
|---|---|---|
| CLI | Command handling and output formatting | internal/cli/ (23 files) |
| Download Engine | Orchestrate parallel downloads | internal/downloader/ (3 files) |
| HTTP Client | Rate limiting + key rotation + proxies | internal/http/ (4 files) |
| Vulnerability Aggregator | Cross-reference CVE databases | internal/vuln/ (2 files) |
| Storage Manager | File and metadata persistence | internal/storage/ (3 files) |
| API Clients | External service integrations | internal/client/ (5 files) |
| Config Manager | Configuration file handling | internal/config/ (1 file) |
| Exploit Integration | Exploit database integration | internal/exploit/ |
| Extractor | Content extraction utilities | internal/extractor/ |
| Scanner | Scanning orchestration | internal/scanner/ |
| Watch Manager | File watching and monitoring | internal/watch/ |

### Storage Structure

```
downloads/
├── plugins/{slug}/{version}/
│   ├── {slug}.zip
│   └── metadata.json
├── themes/{slug}/{version}/
├── index.json
└── errors.json
```

### Configuration

Default location: `./config.yaml`

Format: YAML

Key settings:
- wpscan_keys: API keys for WPScan vulnerability database
- wordfence_keys: API keys for Wordfence threat intelligence
- nvd_keys: API keys for National Vulnerability Database
- projectdiscovery_api_keys: API keys for ProjectDiscovery services
- concurrency: Number of parallel downloads (default: 5)
- cache_ttl: Vulnerability data cache duration (default: 24h)
- rate_limits: Per-domain request throttling

## Performance Targets

- Download concurrency: 5 (configurable)
- Rate limiting: Per-domain token bucket
- Cache TTL: 24 hours (configurable)
- Retry strategy: Exponential backoff, max 3 attempts
- Buffer size: 32KB for streaming downloads

## Security

- API keys stored in config file (user responsible for permissions)
- SHA256 verification for all downloads
- TLS for all external API communication
- Proxy support for privacy-sensitive environments

## Common Tasks

### Adding a New CLI Command

1. Create file in internal/cli/newcommand.go
2. Define command struct with cobra.Command
3. Implement handler function
4. Register in root.go
5. Add output formatting via Formatter
6. Follow patterns in code-standards.md

### Adding a New Vulnerability Source

1. Implement VulnSource interface in internal/client/
2. Add to aggregator initialization in internal/cli/deps.go
3. Follow client patterns in code-standards.md
4. Add tests following table-driven test pattern

### Modifying Configuration

1. Update Config struct in internal/config/config.go
2. Add parsing logic if non-string type
3. Update DefaultConfig() with sensible default
4. Update documentation

## Dependencies

- **Cobra** v1.10.2 — CLI framework
- **progressbar** v3.19.0 — Progress visualization
- **golang.org/x/time** v0.15.0 — Rate limiting
- **yaml.v3** v3.0.1 — YAML parsing and serialization

## Testing

- Test files: `*_test.go` in same package
- Pattern: Table-driven tests
- Coverage target: 70% for business logic
- Run: `go test ./...`

## Code Quality

Before committing:
```bash
go fmt ./...
go vet ./...
go test ./...
```

## Build & Install

```bash
go install github.com/hieuha/lazywp/cmd/lazywp@latest
```

Or from source:
```bash
git clone https://github.com/hieuha/lazywp.git
cd lazywp
make build
make install
```

## External APIs

- **WordPress.org** — Plugin/theme info and downloads
- **WPScan** — Vulnerability database (API key required)
- **NVD (NIST)** — National Vulnerability Database (API key required)
- **Wordfence** — Threat intelligence (free tier available)

Rate limits enforced to prevent throttling.

## Questions?

Refer to the specific documentation file for your question:
- **What does this feature do?** → Project Overview & PDR
- **How does component X work?** → System Architecture
- **How do I write code that fits?** → Code Standards
- **Where is feature X implemented?** → Codebase Summary
- **How do I run tests?** → Code Standards → Testing Standards

---

**Last Updated:** 2026-03-27
**Version:** 1.0
**Go Version:** 1.25.0
