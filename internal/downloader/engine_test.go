package downloader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hieuha/lazywp/internal/client"
	"github.com/hieuha/lazywp/internal/config"
	lazywphttp "github.com/hieuha/lazywp/internal/http"
	"github.com/hieuha/lazywp/internal/storage"
)

// buildTestEngine constructs an Engine backed by a minimal config.
// The testSrv parameter is accepted for signature consistency but HTTP calls
// go to whatever URL is passed (test code constructs those URLs from srv.URL).
// lazywphttp.Client uses NewClient with RetryMax=0 to avoid retry delays in tests.
func buildTestEngine(t *testing.T) (*Engine, *storage.Manager) {
	t.Helper()

	cfg := &config.Config{
		Concurrency:    2,
		RateLimits:     map[string]float64{},
		RetryMax:       0,
		RetryBaseDelay: "1ms",
	}

	httpClient, err := lazywphttp.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	wpClient := client.NewWordPressClient(httpClient, client.Plugin)

	stor := storage.NewManager(t.TempDir())
	if err := stor.EnsureStructure(); err != nil {
		t.Fatalf("storage.EnsureStructure: %v", err)
	}

	return NewEngine(httpClient, wpClient, stor, cfg), stor
}

// sha256hex is a test helper to compute expected SHA-256 of a byte slice.
func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// wpInfoJSON returns a minimal WordPress API plugin-info JSON response.
func wpInfoJSON(slug, version string) []byte {
	info := map[string]interface{}{
		"slug":            slug,
		"name":            slug + " Plugin",
		"version":         version,
		"author":          "Test Author",
		"active_installs": 1000,
		"tested":          "6.4",
		"requires_php":    "7.4",
		"last_updated":    "2024-01-01",
		"versions":        map[string]string{version: ""},
	}
	data, _ := json.Marshal(info)
	return data
}

// --- hashFile ---

func TestHashFile(t *testing.T) {
	content := []byte("hello world")
	path := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}
	if want := sha256hex(content); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestHashFile_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}
	if want := sha256hex([]byte{}); got != want {
		t.Errorf("empty hash got %s, want %s", got, want)
	}
}

func TestHashFile_NotExist(t *testing.T) {
	_, err := hashFile("/nonexistent/path/file.txt")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// --- checkDownloadURL ---

func TestCheckDownloadURL(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantOK     bool
		wantReason string // substring expected in reason when !wantOK
	}{
		// 200 → available
		{"200 OK", http.StatusOK, true, ""},
		// 404 → unavailable with version message
		{"404 Not Found", http.StatusNotFound, false, "version"},
		// Other non-200 codes become network errors via retry logic wrapping
		{"302 Redirect", http.StatusFound, false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			t.Cleanup(srv.Close)

			engine, _ := buildTestEngine(t)
			ok, reason := engine.checkDownloadURL(context.Background(), srv.URL+"/test.zip", "myplugin", "1.0")

			if ok != tc.wantOK {
				t.Errorf("available = %v, want %v (reason: %q)", ok, tc.wantOK, reason)
			}
			if tc.wantReason != "" && !strings.Contains(reason, tc.wantReason) {
				t.Errorf("reason = %q, want substring %q", reason, tc.wantReason)
			}
			if tc.wantOK && reason != "" {
				t.Errorf("expected empty reason on success, got %q", reason)
			}
		})
	}
}

func TestCheckDownloadURL_NetworkError(t *testing.T) {
	engine, _ := buildTestEngine(t)
	// Use an unreachable address to trigger a network error.
	ok, reason := engine.checkDownloadURL(context.Background(), "http://127.0.0.1:1/file.zip", "slug", "1.0")
	if ok {
		t.Error("expected ok=false for unreachable host")
	}
	if reason == "" {
		t.Error("expected non-empty reason for network error")
	}
}

// --- downloadFile ---

func TestDownloadFile_Success(t *testing.T) {
	content := []byte("fake-zip-content-for-testing")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(content) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	engine, _ := buildTestEngine(t)
	destPath := filepath.Join(t.TempDir(), "plugin.zip")

	n, hash, err := engine.downloadFile(context.Background(), srv.URL+"/plugin.zip", destPath, 0)
	if err != nil {
		t.Fatalf("downloadFile: %v", err)
	}
	if n != int64(len(content)) {
		t.Errorf("bytes written = %d, want %d", n, len(content))
	}
	if want := sha256hex(content); hash != want {
		t.Errorf("hash mismatch: got %s, want %s", hash, want)
	}

	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("file content = %q, want %q", data, content)
	}
}

func TestDownloadFile_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	engine, _ := buildTestEngine(t)
	destPath := filepath.Join(t.TempDir(), "plugin.zip")

	_, _, err := engine.downloadFile(context.Background(), srv.URL+"/plugin.zip", destPath, 0)
	if err == nil {
		t.Error("expected error for 403 response, got nil")
	}
}

func TestDownloadFile_PartialContent(t *testing.T) {
	// Simulate server returning 206 Partial Content (resume scenario).
	tailContent := []byte("second-half-of-file")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusPartialContent)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		w.Write(tailContent) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	engine, _ := buildTestEngine(t)
	dir := t.TempDir()
	destPath := filepath.Join(dir, "plugin.zip")
	tmpPath := destPath + ".tmp"

	// Create a .tmp file simulating partial prior download.
	firstHalf := []byte("first-half-")
	if err := os.WriteFile(tmpPath, firstHalf, 0644); err != nil {
		t.Fatalf("write tmp: %v", err)
	}

	resumeOffset := int64(len(firstHalf))
	n, _, err := engine.downloadFile(context.Background(), srv.URL+"/plugin.zip", destPath, resumeOffset)
	if err != nil {
		t.Fatalf("downloadFile with resume: %v", err)
	}
	// totalBytes = resumeOffset + new bytes written
	if n != int64(len(firstHalf))+int64(len(tailContent)) {
		t.Errorf("total bytes = %d, want %d", n, int64(len(firstHalf))+int64(len(tailContent)))
	}
}

func TestDownloadFile_ContextCancel(t *testing.T) {
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	engine, _ := buildTestEngine(t)
	destPath := filepath.Join(t.TempDir(), "plugin.zip")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := engine.downloadFile(ctx, srv.URL+"/plugin.zip", destPath, 0)
		done <- err
	}()

	<-started
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected error after context cancel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for downloadFile to return")
	}
}

// --- DownloadOne ---

func TestDownloadOne_AlreadyExists(t *testing.T) {
	const slug = "existing-plugin"
	const version = "2.0.0"

	engine, stor := buildTestEngine(t)

	// Pre-create metadata to simulate an already-downloaded item.
	meta := &storage.Metadata{
		Slug:         slug,
		Name:         slug,
		Type:         string(client.Plugin),
		Version:      version,
		DownloadedAt: time.Now(),
	}
	if err := stor.WriteMetadata(meta); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}

	result, err := engine.DownloadOne(context.Background(), slug, version, client.Plugin)
	if err == nil {
		t.Fatal("expected ErrAlreadyExists, got nil")
	}
	if result == nil {
		t.Fatal("expected non-nil result even when already exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, want ErrAlreadyExists", err)
	}
	if result.Slug != slug || result.Version != version {
		t.Errorf("result = {%s %s}, want {%s %s}", result.Slug, result.Version, slug, version)
	}
}

func TestDownloadOne_AlreadyExists_Force_BypassesCheck(t *testing.T) {
	// Verify that force=true skips the ErrAlreadyExists guard and proceeds
	// to call wpClient.GetInfo (which will fail due to hardcoded real URL,
	// but the failure must NOT be ErrAlreadyExists).
	const slug = "force-plugin"
	const version = "1.0.0"

	engine, stor := buildTestEngine(t)

	meta := &storage.Metadata{
		Slug:         slug,
		Name:         slug,
		Type:         string(client.Plugin),
		Version:      version,
		DownloadedAt: time.Now(),
	}
	if err := stor.WriteMetadata(meta); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := engine.DownloadOne(ctx, slug, version, client.Plugin, true)
	// Must fail (network/timeout) but NOT with ErrAlreadyExists.
	if err != nil && strings.Contains(err.Error(), "already exists") {
		t.Error("force=true should bypass ErrAlreadyExists guard")
	}
}

// --- DownloadBatch ---

func TestDownloadBatch_AllSkipped(t *testing.T) {
	const version = "1.0.0"
	slugs := []string{"plugin-a", "plugin-b", "plugin-c"}

	engine, stor := buildTestEngine(t)

	for _, slug := range slugs {
		meta := &storage.Metadata{
			Slug:         slug,
			Name:         slug,
			Type:         string(client.Plugin),
			Version:      version,
			DownloadedAt: time.Now(),
		}
		if err := stor.WriteMetadata(meta); err != nil {
			t.Fatalf("WriteMetadata %s: %v", slug, err)
		}
	}

	jobs := make([]DownloadJob, len(slugs))
	for i, s := range slugs {
		jobs[i] = DownloadJob{Slug: s, Version: version, ItemType: client.Plugin}
	}

	result := engine.DownloadBatch(context.Background(), jobs)

	if result.Total != len(slugs) {
		t.Errorf("Total = %d, want %d", result.Total, len(slugs))
	}
	if result.Skipped != len(slugs) {
		t.Errorf("Skipped = %d, want %d", result.Skipped, len(slugs))
	}
	if result.Failed != 0 {
		t.Errorf("Failed = %d, want 0", result.Failed)
	}
	if result.Succeeded != 0 {
		t.Errorf("Succeeded = %d, want 0", result.Succeeded)
	}
	if result.Duration <= 0 {
		t.Error("Duration should be positive")
	}
}

func TestDownloadBatch_ContextCancelledBeforeStart(t *testing.T) {
	engine, _ := buildTestEngine(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before batch starts

	jobs := make([]DownloadJob, 10)
	for i := range jobs {
		jobs[i] = DownloadJob{Slug: "p", Version: "1.0", ItemType: client.Plugin}
	}

	result := engine.DownloadBatch(ctx, jobs)
	if result.Total != len(jobs) {
		t.Errorf("Total = %d, want %d", result.Total, len(jobs))
	}
	// With cancelled context the first iteration exits immediately — remaining jobs counted as failed.
	total := result.Succeeded + result.Failed + result.Skipped
	if total > result.Total {
		t.Errorf("outcome sum %d > Total %d", total, result.Total)
	}
}

func TestDownloadBatch_ProgressCallback(t *testing.T) {
	const slug = "cb-plugin"
	const version = "3.0.0"

	engine, stor := buildTestEngine(t)

	meta := &storage.Metadata{
		Slug:         slug,
		Name:         slug,
		Type:         string(client.Plugin),
		Version:      version,
		DownloadedAt: time.Now(),
	}
	if err := stor.WriteMetadata(meta); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}

	var callCount int
	var gotSlug, gotVersion string
	jobs := []DownloadJob{{Slug: slug, Version: version, ItemType: client.Plugin}}

	engine.DownloadBatch(context.Background(), jobs, func(s, v string) {
		callCount++
		gotSlug, gotVersion = s, v
	})

	if callCount != 1 {
		t.Errorf("progress callback called %d times, want 1", callCount)
	}
	if gotSlug != slug {
		t.Errorf("callback slug = %q, want %q", gotSlug, slug)
	}
	if gotVersion != version {
		t.Errorf("callback version = %q, want %q", gotVersion, version)
	}
}

func TestDownloadBatch_EmptyJobs(t *testing.T) {
	engine, _ := buildTestEngine(t)

	result := engine.DownloadBatch(context.Background(), []DownloadJob{})
	if result.Total != 0 {
		t.Errorf("Total = %d, want 0", result.Total)
	}
	if result.Succeeded != 0 || result.Failed != 0 || result.Skipped != 0 {
		t.Error("all counts should be 0 for empty job list")
	}
}

// --- mockWPProvider for DownloadOne tests ---

type mockWPProvider struct {
	info        *client.ItemInfo
	infoErr     error
	downloadURL string
}

func (m *mockWPProvider) GetInfo(_ context.Context, _ string) (*client.ItemInfo, error) {
	return m.info, m.infoErr
}

func (m *mockWPProvider) DownloadURL(_, _ string) string {
	return m.downloadURL
}

// buildTestEngineWithMock constructs an Engine using a mock WPInfoProvider.
func buildTestEngineWithMock(t *testing.T, provider *mockWPProvider) (*Engine, *storage.Manager) {
	t.Helper()
	cfg := &config.Config{
		Concurrency:    2,
		RateLimits:     map[string]float64{},
		RetryMax:       0,
		RetryBaseDelay: "1ms",
	}
	httpClient, err := lazywphttp.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	stor := storage.NewManager(t.TempDir())
	if err := stor.EnsureStructure(); err != nil {
		t.Fatalf("storage.EnsureStructure: %v", err)
	}
	return NewEngine(httpClient, provider, stor, cfg), stor
}

// Ensure wpInfoJSON helper compiles (used in future integration tests).
var _ = wpInfoJSON
