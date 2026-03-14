package downloader

import (
	"context"
	"crypto/sha256"
	"errors"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hieuha/lazywp/internal/client"
	"github.com/hieuha/lazywp/internal/config"
	lazywphttp "github.com/hieuha/lazywp/internal/http"
	"github.com/hieuha/lazywp/internal/storage"
)

const downloadBufSize = 32 * 1024 // 32KB streaming buffer

// DownloadJob represents a single plugin/theme to download.
type DownloadJob struct {
	Slug     string
	Version  string
	ItemType client.ItemType
	Force    bool
}

// BatchResult summarizes a batch download operation.
type BatchResult struct {
	Total     int
	Succeeded int
	Failed    int
	Skipped   int
	Errors    []storage.ErrorEntry
	Duration  time.Duration
}

// Engine orchestrates concurrent downloads with metadata persistence.
type Engine struct {
	httpClient *lazywphttp.Client
	wpClient   *client.WordPressClient
	storage    *storage.Manager
	cfg        *config.Config
	mu         sync.Mutex // protects error collection
}

// NewEngine creates a download engine with the given dependencies.
func NewEngine(
	httpClient *lazywphttp.Client,
	wpClient *client.WordPressClient,
	stor *storage.Manager,
	cfg *config.Config,
) *Engine {
	return &Engine{
		httpClient: httpClient,
		wpClient:   wpClient,
		storage:    stor,
		cfg:        cfg,
	}
}

// ErrAlreadyExists is returned when a plugin/theme version is already downloaded.
var ErrAlreadyExists = fmt.Errorf("already exists")

// DownloadResult holds the outcome of a single download operation.
type DownloadResult struct {
	Slug    string
	Version string // resolved effective version
}

// DownloadOne downloads a single plugin/theme version.
// It skips if already present, fetches metadata, streams to disk, and writes metadata.json.
// Returns DownloadResult with the resolved version on success.
func (e *Engine) DownloadOne(ctx context.Context, slug, version string, itemType client.ItemType, force ...bool) (*DownloadResult, error) {
	isForce := len(force) > 0 && force[0]
	if !isForce && version != "" && e.storage.Exists(string(itemType), slug, version) {
		return &DownloadResult{Slug: slug, Version: version}, ErrAlreadyExists
	}

	// Fetch WordPress metadata for this item
	info, err := e.wpClient.GetInfo(ctx, slug)
	if err != nil {
		return nil, fmt.Errorf("get info for %s: %w", slug, err)
	}

	// Resolve effective version
	effectiveVersion := version
	if effectiveVersion == "" {
		effectiveVersion = info.Version
	}

	result := &DownloadResult{Slug: slug, Version: effectiveVersion}

	// Check exists after version resolution (covers empty --version case)
	if !isForce && version == "" && e.storage.Exists(string(itemType), slug, effectiveVersion) {
		return result, ErrAlreadyExists
	}

	downloadURL := e.wpClient.DownloadURL(slug, effectiveVersion)

	// Verify download URL is reachable before setting up directories
	if available, reason := e.checkDownloadURL(ctx, downloadURL, slug, effectiveVersion); !available {
		return nil, fmt.Errorf("skip %s@%s: %s", slug, effectiveVersion, reason)
	}

	destDir := e.storage.ItemDir(string(itemType), slug, effectiveVersion)

	if err = os.MkdirAll(destDir, 0755); err != nil {
		return nil, fmt.Errorf("create dest dir: %w", err)
	}

	// Check for existing resume state
	state, _ := LoadState(destDir) // nil if not found
	var resumeOffset int64
	if state != nil {
		resumeOffset = state.BytesDownloaded
	}

	// Save initial state before download
	if state == nil {
		state = &DownloadState{
			Slug:        slug,
			Version:     effectiveVersion,
			Type:        string(itemType),
			DownloadURL: downloadURL,
			StartedAt:   time.Now(),
		}
	}
	state.LastUpdated = time.Now()
	_ = SaveState(destDir, state)

	destPath := filepath.Join(destDir, slug+".zip")
	bytesWritten, sha256hex, err := e.downloadFile(ctx, downloadURL, destPath, resumeOffset)
	if err != nil {
		// Persist failure state for future resume
		state.LastUpdated = time.Now()
		_ = SaveState(destDir, state)
		return nil, fmt.Errorf("download %s@%s: %w", slug, effectiveVersion, err)
	}

	// Clear resume state on success
	_ = ClearState(destDir)

	// Build and write metadata
	meta := &storage.Metadata{
		Slug:        slug,
		Name:        info.Name,
		Type:        string(itemType),
		Version:     effectiveVersion,
		SHA256:      sha256hex,
		FileSize:    bytesWritten,
		DownloadURL: downloadURL,
		DownloadedAt: time.Now(),
		WPMetadata: storage.WPMetadata{
			ActiveInstallations: info.ActiveInstallations,
			TestedUpTo:          info.TestedUpTo,
			RequiresPHP:         string(info.RequiresPHP),
			Author:              info.Author,
			LastUpdated:         info.LastUpdated,
		},
	}

	if err := e.storage.WriteMetadata(meta); err != nil {
		return nil, fmt.Errorf("write metadata for %s: %w", slug, err)
	}

	if err := e.storage.UpdateIndex(storage.IndexEntry{
		Slug:         slug,
		Type:         string(itemType),
		Version:      effectiveVersion,
		DownloadedAt: meta.DownloadedAt,
		HasVulns:     len(meta.Vulnerabilities) > 0,
		FileSize:     bytesWritten,
	}); err != nil {
		return nil, fmt.Errorf("update index for %s: %w", slug, err)
	}

	return result, nil
}

// DownloadBatch concurrently downloads multiple items using a semaphore worker pool.
// Context cancellation triggers graceful shutdown — in-flight downloads complete first.
func (e *Engine) DownloadBatch(ctx context.Context, jobs []DownloadJob) *BatchResult {
	start := time.Now()
	result := &BatchResult{Total: len(jobs)}

	sem := make(chan struct{}, e.cfg.Concurrency)
	var wg sync.WaitGroup

	for _, job := range jobs {
		// Check cancellation before spawning each worker
		select {
		case <-ctx.Done():
			result.Failed += len(jobs) - result.Succeeded - result.Skipped - result.Failed
			result.Duration = time.Since(start)
			return result
		default:
		}

		sem <- struct{}{} // acquire slot
		wg.Add(1)

		go func(j DownloadJob) {
			defer wg.Done()
			defer func() { <-sem }() // release slot

			_, err := e.DownloadOne(ctx, j.Slug, j.Version, j.ItemType, j.Force)
			e.mu.Lock()
			defer e.mu.Unlock()

			if errors.Is(err, ErrAlreadyExists) {
				result.Skipped++
				return
			}
			if err != nil {
				result.Failed++
				errEntry := storage.ErrorEntry{
					Slug:    j.Slug,
					Version: j.Version,
					Type:    string(j.ItemType),
					Error:   err.Error(),
				}
				result.Errors = append(result.Errors, errEntry)
				_ = e.storage.LogError(errEntry)
			} else {
				result.Succeeded++
			}
		}(job)
	}

	wg.Wait()
	result.Duration = time.Since(start)
	return result
}

// checkDownloadURL does a HEAD request to verify the download URL exists.
// Returns (true, "") if available, or (false, reason) if not.
func (e *Engine) checkDownloadURL(ctx context.Context, url, slug, version string) (bool, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false, fmt.Sprintf("create request: %v", err)
	}
	resp, err := e.httpClient.Do(ctx, req)
	if err != nil {
		return false, fmt.Sprintf("network error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, ""
	}
	if resp.StatusCode == 404 {
		return false, fmt.Sprintf("version %s not available on wordpress.org (404)", version)
	}
	return false, fmt.Sprintf("unexpected status %d", resp.StatusCode)
}

// downloadFile streams a URL to destPath with optional resume via HTTP Range header.
// Returns bytes written and SHA256 hex string. Uses atomic temp file + rename.
func (e *Engine) downloadFile(ctx context.Context, url, destPath string, resumeOffset int64) (int64, string, error) {
	tmpPath := destPath + ".tmp"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", fmt.Errorf("create request: %w", err)
	}

	// Request partial content if resuming
	if resumeOffset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", resumeOffset))
	}

	resp, err := e.httpClient.Do(ctx, req)
	if err != nil {
		return 0, "", fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	// Accept 200 (full) or 206 (partial content)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return 0, "", fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	// If server doesn't support Range, restart from 0
	if resp.StatusCode == http.StatusOK && resumeOffset > 0 {
		resumeOffset = 0
	}

	// Open temp file — append if resuming, create otherwise
	var f *os.File
	if resumeOffset > 0 {
		f, err = os.OpenFile(tmpPath, os.O_WRONLY|os.O_APPEND, 0644)
	} else {
		f, err = os.Create(tmpPath)
	}
	if err != nil {
		return 0, "", fmt.Errorf("open temp file: %w", err)
	}

	// cleanup tracks whether f has been closed explicitly before the defer runs
	fileClosed := false
	defer func() {
		if !fileClosed {
			f.Close()
		}
		// Clean up temp file if final rename did not succeed
		if _, statErr := os.Stat(destPath); os.IsNotExist(statErr) {
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	// If resuming, we cannot reconstruct the hash of previous bytes without them,
	// so hash only the new bytes for now (metadata will hold final hash of full file).
	teeReader := io.TeeReader(resp.Body, hasher)

	buf := make([]byte, downloadBufSize)
	var written int64
	for {
		select {
		case <-ctx.Done():
			return 0, "", ctx.Err()
		default:
		}

		n, readErr := teeReader.Read(buf)
		if n > 0 {
			wn, writeErr := f.Write(buf[:n])
			if writeErr != nil {
				return 0, "", fmt.Errorf("write to temp file: %w", writeErr)
			}
			written += int64(wn)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return 0, "", fmt.Errorf("read response body: %w", readErr)
		}
	}

	fileClosed = true
	if err = f.Close(); err != nil {
		return 0, "", fmt.Errorf("close temp file: %w", err)
	}

	// If we resumed, re-hash the entire file to get the correct SHA256
	var sha256hex string
	if resumeOffset > 0 {
		sha256hex, err = hashFile(tmpPath)
		if err != nil {
			return 0, "", fmt.Errorf("hash resumed file: %w", err)
		}
	} else {
		sha256hex = hex.EncodeToString(hasher.Sum(nil))
	}

	// Atomic rename: temp → final
	if err = os.Rename(tmpPath, destPath); err != nil {
		return 0, "", fmt.Errorf("rename temp to dest: %w", err)
	}

	totalBytes := resumeOffset + written
	return totalBytes, sha256hex, nil
}

// hashFile computes SHA256 of a file by streaming it.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	buf := make([]byte, downloadBufSize)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
