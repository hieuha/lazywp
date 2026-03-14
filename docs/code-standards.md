# Code Standards & Development Guidelines

## Go Conventions

### File Naming
- Use `snake_case` for Go source files
- Group related functionality by package, not by files
- Example: `download_engine.go`, `rate_limiter.go`, `key_rotator.go`

### Code Formatting
- Run `gofmt` before committing
- Use `go vet` to check for common mistakes
- Lines should be reasonable length (not exceeding 120 chars)
- Use `go mod tidy` to clean dependencies

### Naming Conventions

**Packages:** lowercase, single word preferred
```go
package downloader
package http  // internal/http to avoid builtin conflict
```

**Types/Interfaces:** PascalCase
```go
type Engine struct {}
type DownloadJob struct {}
type VulnSource interface {}
```

**Functions/Methods:** PascalCase for exported, camelCase for unexported
```go
func NewEngine() *Engine {}        // exported constructor
func (e *Engine) Download() {}     // exported method
func (e *Engine) validate() error  // unexported helper
```

**Variables:** camelCase for local, PascalCase for exported
```go
var GlobalConfig *Config      // exported
var httpClient *http.Client   // unexported (package-level)
```

**Constants:** UPPER_SNAKE_CASE for unexported, PascalCase for exported
```go
const DefaultRetryMax = 3
const downloadBufSize = 32 * 1024  // unexported
```

## Module Path

```
github.com/hieuha/lazywp
```

All imports reference this path:
```go
import "github.com/hieuha/lazywp/internal/cli"
```

## Project Structure

```
├── cmd/lazywp/
│   └── main.go              # thin entry point
├── internal/
│   ├── cli/                 # command handlers
│   ├── client/              # external service clients
│   ├── config/              # configuration
│   ├── downloader/          # download orchestration
│   ├── http/                # HTTP utilities
│   ├── storage/             # persistence
│   └── vuln/                # vulnerability aggregation
└── docs/                    # documentation
```

**Rule:** Unexported packages (internal/) contain implementation details. Public API exposed through cmd/.

## Error Handling

### Pattern 1: Wrap with Context
```go
if err != nil {
    return fmt.Errorf("download plugin: %w", err)
}
```

### Pattern 2: Silent Failure with Logging (non-critical)
```go
data, err := fetchVulnerabilities(ctx)
if err != nil {
    warnings = append(warnings, fmt.Sprintf("WPScan: %v", err))
    // continue with next source
}
```

### Pattern 3: Fatal Errors
```go
if err != nil {
    return fmt.Errorf("init config: %w", err)  // propagate to main
}
```

**Guidelines:**
- Always wrap errors with `%w` for error chain
- Include context about what operation failed
- Don't log and return (caller decides logging)
- Use panic only for unrecoverable initialization errors
- Return sentinel errors or custom error types for common cases

## Concurrency Patterns

### Worker Pool Pattern
```go
var wg sync.WaitGroup
for _, job := range jobs {
    wg.Add(1)
    go func(j DownloadJob) {
        defer wg.Done()
        if err := e.downloadOne(ctx, j); err != nil {
            mu.Lock()
            errs = append(errs, err)
            mu.Unlock()
        }
    }(job)
}
wg.Wait()
```

### Channel-based Fan-Out/Fan-In
```go
results := make(chan sourceResult, len(sources))
for _, src := range sources {
    go func(s VulnSource) {
        vulns, err := s.FetchBySlug(ctx, slug, itemType)
        results <- sourceResult{vulns: vulns, err: err}
    }(src)
}
```

**Guidelines:**
- Use `sync.WaitGroup` for bounded parallelism
- Use channels for producer-consumer patterns
- Always close channels from sender side
- Buffer channels appropriately to avoid deadlocks
- Use context.Context for cancellation across goroutines

## Testing Standards

### Test File Naming
- Test file: `filename_test.go` (same package)
- Table-driven tests for multiple scenarios
- Use `testify/assert` for cleaner assertions (if available)

### Test Structure
```go
func TestDownloadEngine_DownloadOne(t *testing.T) {
    tests := []struct {
        name    string
        job     DownloadJob
        wantErr bool
    }{
        {
            name: "successful download",
            job:  DownloadJob{Slug: "akismet", Version: "5.0.1"},
            wantErr: false,
        },
        {
            name: "plugin not found",
            job:  DownloadJob{Slug: "nonexistent", Version: "1.0"},
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // test logic
        })
    }
}
```

**Coverage Target:** 70%+ for business logic, 50%+ overall

## Configuration Management

**Config File:** `~/.lazywp/config.json`

**Structure:**
```go
type Config struct {
    WPScanKeys     []string           `json:"wpscan_keys"`
    NVDKey         string             `json:"nvd_key"`
    KeyRotation    string             `json:"key_rotation"`
    Proxies        []string           `json:"proxies"`
    ProxyStrategy  string             `json:"proxy_strategy"`
    Concurrency    int                `json:"concurrency"`
    OutputDir      string             `json:"output_dir"`
    RateLimits     map[string]float64 `json:"rate_limits"`
    CacheTTL       string             `json:"cache_ttl"`
    RetryMax       int                `json:"retry_max"`
    RetryBaseDelay string             `json:"retry_base_delay"`
}
```

**Loading:**
1. Apply defaults from `DefaultConfig()`
2. Load user config from file (if exists)
3. Validate required fields

## Logging & Debugging

**Verbose Flag:** Passed via CLI flag to control verbosity
```go
if verbose {
    fmt.Fprintf(os.Stderr, "DEBUG: %s\n", msg)
}
```

**Output Formatting:** Use Formatter for all user-facing output
```go
type Formatter struct {
    format string  // "table", "json", "csv"
    out    io.Writer
}

fmtr.PrintTable(headers, rows)
fmtr.PrintJSON(data)
fmtr.PrintCSV(records)
```

**Never log:**
- API keys or sensitive credentials
- Full file paths (unless debug mode)
- User data without explicit debug flag

## API Client Patterns

### Implementing a New Client
1. Define request/response types in `client/types.go`
2. Create client struct with HTTP client
3. Implement interface if part of aggregator
4. Handle rate limiting via http.Client middleware
5. Add unit tests with mocked responses

Example:
```go
type CustomClient struct {
    httpClient *http.Client
    apiKey     string
}

func NewCustomClient(httpClient *http.Client, apiKey string) *CustomClient {
    return &CustomClient{
        httpClient: httpClient,
        apiKey:     apiKey,
    }
}

func (c *CustomClient) FetchSomething(ctx context.Context) ([]Result, error) {
    // Implementation
}
```

## Dependency Injection

**Pattern:** AppDeps struct initialized once on CLI startup
```go
type AppDeps struct {
    Config    *config.Config
    HTTPClient *http.Client
    WPClient  *client.WordPressClient
    VulnAgg   *vuln.Aggregator
    StorageMgr *storage.Manager
    Downloader *downloader.Engine
}
```

**Rule:** Services receive dependencies via constructor, never global singletons

## Performance Considerations

### HTTP Connection Pooling
```go
&http.Client{
    Timeout: 30 * time.Second,
    Transport: &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     90 * time.Second,
    },
}
```

### Buffer Sizes
- Download buffer: 32KB
- Channel buffers: sized appropriately (usually len(sources) or len(jobs))

### Memory Management
- Stream large files instead of loading in memory
- Reuse buffers where possible
- Limit concurrent goroutines via concurrency config

## Documentation in Code

### Package-level comments
```go
// Package downloader orchestrates concurrent downloads with metadata persistence.
package downloader
```

### Function comments (exported only)
```go
// NewEngine creates a download engine with the given dependencies.
func NewEngine(cfg *config.Config) (*Engine, error) {
```

### Complex logic comments
```go
// Merge results, deduplicate by CVE ID, and sort by CVSS score.
// Sources are queried in parallel and non-fatal errors are accumulated.
func (a *Aggregator) FetchForSlug(ctx context.Context, slug string) ([]Vuln, []string) {
```

**Guidelines:**
- Document why, not what (code shows what)
- Explain non-obvious design decisions
- Reference external specifications if relevant
- Keep comments close to code

## Dependency Management

### Adding Dependencies
1. Use `go get github.com/owner/package@version`
2. Run `go mod tidy`
3. Commit go.mod and go.sum
4. Update CLAUDE.md if significant change

### Current Dependencies
- `github.com/spf13/cobra` v1.10.2 - CLI framework
- `github.com/schollz/progressbar/v3` v3.19.0 - Progress bars
- `golang.org/x/time` v0.15.0 - Rate limiting

**Constraint:** Minimize dependencies, prefer stdlib where reasonable

## Code Review Checklist

Before submitting:
- [ ] Run `go fmt ./...`
- [ ] Run `go vet ./...`
- [ ] Run `go test ./...` (all tests pass)
- [ ] Error messages are wrapped with context
- [ ] No magic numbers (use named constants)
- [ ] Exported functions have doc comments
- [ ] Tests cover happy path and error cases
- [ ] Concurrency safe (no race conditions)
- [ ] No unused variables or imports
- [ ] No hardcoded credentials or secrets
