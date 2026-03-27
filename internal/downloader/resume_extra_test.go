package downloader

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hieuha/lazywp/internal/client"
)

func TestLoadState_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, stateFileName)
	if err := os.WriteFile(path, []byte("not-json{{{"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadState(dir)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestSaveAndLoadState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	state := &DownloadState{
		Slug:            "round-trip-plugin",
		Version:         "1.0.0",
		Type:            "plugin",
		DownloadURL:     "https://example.com/plugin.zip",
		BytesDownloaded: 512,
		TotalBytes:      1024,
		StartedAt:       time.Now().Truncate(time.Second),
	}

	if err := SaveState(dir, state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	loaded, err := LoadState(dir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadState returned nil, want state")
	}
	if loaded.Slug != state.Slug {
		t.Errorf("Slug = %q, want %q", loaded.Slug, state.Slug)
	}
	if loaded.BytesDownloaded != state.BytesDownloaded {
		t.Errorf("BytesDownloaded = %d, want %d", loaded.BytesDownloaded, state.BytesDownloaded)
	}
}

func TestDownloadOne_ResumesExistingState(t *testing.T) {
	// Verifies that DownloadOne reads an existing .lazywp-state.json and proceeds.
	const slug = "resume-plugin"
	const version = "2.0.0"
	fullContent := []byte("PK full zip content for resume test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Return full content regardless of Range header (server ignores Range).
		w.WriteHeader(http.StatusOK)
		w.Write(fullContent) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	provider := &mockWPProvider{
		info:        &client.ItemInfo{Slug: slug, Name: "Resume Plugin", Version: version},
		downloadURL: srv.URL + "/plugin.zip",
	}

	engine, stor := buildTestEngineWithMock(t, provider)

	// Pre-create the dest dir and a state file simulating a partial prior download.
	destDir := stor.ItemDir(string(client.Plugin), slug, version)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	existingState := &DownloadState{
		Slug:            slug,
		Version:         version,
		Type:            "plugin",
		DownloadURL:     srv.URL + "/plugin.zip",
		BytesDownloaded: 5,
	}
	if err := SaveState(destDir, existingState); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	result, err := engine.DownloadOne(context.Background(), slug, version, client.Plugin)
	if err != nil {
		t.Fatalf("DownloadOne with resume state: %v", err)
	}
	if result.Version != version {
		t.Errorf("result.Version = %q, want %q", result.Version, version)
	}
}
