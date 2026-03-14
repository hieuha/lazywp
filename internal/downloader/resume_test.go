package downloader

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadState(t *testing.T) {
	tmpDir := t.TempDir()

	// Create state
	state := &DownloadState{
		Slug:            "akismet",
		Version:         "5.0.1",
		Type:            "plugin",
		DownloadURL:     "https://example.com/akismet.zip",
		BytesDownloaded: 500000,
		TotalBytes:      1000000,
		StartedAt:       time.Now().Add(-time.Minute),
	}

	// Save state
	if err := SaveState(tmpDir, state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Load state
	loaded, err := LoadState(tmpDir)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	if loaded == nil {
		t.Fatal("LoadState returned nil")
	}

	// Verify fields match
	if loaded.Slug != state.Slug {
		t.Errorf("Slug: got %q, want %q", loaded.Slug, state.Slug)
	}

	if loaded.Version != state.Version {
		t.Errorf("Version: got %q, want %q", loaded.Version, state.Version)
	}

	if loaded.Type != state.Type {
		t.Errorf("Type: got %q, want %q", loaded.Type, state.Type)
	}

	if loaded.BytesDownloaded != state.BytesDownloaded {
		t.Errorf("BytesDownloaded: got %d, want %d", loaded.BytesDownloaded, state.BytesDownloaded)
	}

	if loaded.TotalBytes != state.TotalBytes {
		t.Errorf("TotalBytes: got %d, want %d", loaded.TotalBytes, state.TotalBytes)
	}

	if loaded.DownloadURL != state.DownloadURL {
		t.Errorf("DownloadURL: got %q, want %q", loaded.DownloadURL, state.DownloadURL)
	}

	// LastUpdated should be set
	if loaded.LastUpdated.IsZero() {
		t.Error("LastUpdated should be set")
	}
}

func TestClearState(t *testing.T) {
	tmpDir := t.TempDir()

	// Save state
	state := &DownloadState{
		Slug:    "test",
		Version: "1.0",
		Type:    "plugin",
	}

	if err := SaveState(tmpDir, state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Verify file exists
	stateFile := filepath.Join(tmpDir, ".lazywp-state.json")
	if _, err := os.Stat(stateFile); err != nil {
		t.Fatalf("State file not created: %v", err)
	}

	// Clear state
	if err := ClearState(tmpDir); err != nil {
		t.Fatalf("ClearState failed: %v", err)
	}

	// Verify file is deleted
	if _, err := os.Stat(stateFile); err == nil {
		t.Error("State file should be deleted")
	}
}

func TestClearStateNotExist(t *testing.T) {
	tmpDir := t.TempDir()

	// Try to clear non-existent state file
	// Should return no error (idempotent)
	if err := ClearState(tmpDir); err != nil {
		t.Fatalf("ClearState should not error on non-existent file: %v", err)
	}
}

func TestLoadStateNotExist(t *testing.T) {
	tmpDir := t.TempDir()

	// Load from dir without state file
	loaded, err := LoadState(tmpDir)

	if err != nil {
		t.Fatalf("LoadState should not error on missing file: %v", err)
	}

	if loaded != nil {
		t.Error("LoadState should return nil when file does not exist")
	}
}

func TestLoadStateProgress(t *testing.T) {
	tmpDir := t.TempDir()

	// Save partially downloaded state
	state := &DownloadState{
		Slug:            "large-plugin",
		Version:         "2.0",
		Type:            "plugin",
		DownloadURL:     "https://example.com/large.zip",
		BytesDownloaded: 5000000,
		TotalBytes:      10000000,
	}

	if err := SaveState(tmpDir, state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Load and verify progress
	loaded, err := LoadState(tmpDir)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	if loaded.BytesDownloaded != 5000000 {
		t.Errorf("Progress: got %d bytes, want 5000000", loaded.BytesDownloaded)
	}

	progress := float64(loaded.BytesDownloaded) / float64(loaded.TotalBytes) * 100
	if progress < 49 || progress > 51 {
		t.Errorf("Progress percentage: got %.1f%%, want 50%%", progress)
	}
}

func TestStateLastUpdated(t *testing.T) {
	tmpDir := t.TempDir()

	state := &DownloadState{
		Slug:    "test",
		Version: "1.0",
		Type:    "plugin",
	}

	beforeSave := time.Now()
	if err := SaveState(tmpDir, state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}
	afterSave := time.Now()

	loaded, err := LoadState(tmpDir)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	// LastUpdated should be between beforeSave and afterSave
	if loaded.LastUpdated.Before(beforeSave) || loaded.LastUpdated.After(afterSave.Add(time.Second)) {
		t.Errorf("LastUpdated not in expected range: %v (expected between %v and %v)",
			loaded.LastUpdated, beforeSave, afterSave)
	}
}
