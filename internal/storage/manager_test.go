package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureStructure(t *testing.T) {
	baseDir := t.TempDir()
	mgr := NewManager(baseDir)

	if err := mgr.EnsureStructure(); err != nil {
		t.Fatalf("EnsureStructure failed: %v", err)
	}

	// Check plugins directory
	pluginDir := filepath.Join(baseDir, "plugins")
	if _, err := os.Stat(pluginDir); err != nil {
		t.Errorf("plugins dir not created: %v", err)
	}

	// Check themes directory
	themeDir := filepath.Join(baseDir, "themes")
	if _, err := os.Stat(themeDir); err != nil {
		t.Errorf("themes dir not created: %v", err)
	}

	// Check index.json created
	indexPath := filepath.Join(baseDir, "index.json")
	if _, err := os.Stat(indexPath); err != nil {
		t.Errorf("index.json not created: %v", err)
	}

	// Verify index.json is valid JSON array
	data, _ := os.ReadFile(indexPath)
	var entries []IndexEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Errorf("index.json invalid JSON: %v", err)
	}
}

func TestEnsureStructureIdempotent(t *testing.T) {
	baseDir := t.TempDir()
	mgr := NewManager(baseDir)

	if err := mgr.EnsureStructure(); err != nil {
		t.Fatalf("first EnsureStructure failed: %v", err)
	}

	if err := mgr.EnsureStructure(); err != nil {
		t.Fatalf("second EnsureStructure failed: %v", err)
	}

	// Verify structure still exists
	pluginDir := filepath.Join(baseDir, "plugins")
	if _, err := os.Stat(pluginDir); err != nil {
		t.Errorf("plugins dir missing after second call: %v", err)
	}
}

func TestWriteReadMetadata(t *testing.T) {
	baseDir := t.TempDir()
	mgr := NewManager(baseDir)
	mgr.EnsureStructure()

	// Create test metadata
	meta := &Metadata{
		Slug:        "akismet",
		Name:        "Akismet",
		Type:        "plugin",
		Version:     "5.0.1",
		SHA256:      "abc123def456",
		FileSize:    1024000,
		DownloadURL: "https://example.com/akismet.zip",
		DownloadedAt: time.Now(),
		WPMetadata: WPMetadata{
			ActiveInstallations: 5000000,
			TestedUpTo:          "6.4",
			RequiresPHP:         "5.6",
			Author:              "Automattic",
			LastUpdated:         "2024-01-01",
		},
		Vulnerabilities: []Vulnerability{
			{
				CVE:   "CVE-2024-1234",
				CVSS:  7.5,
				Title: "Test Vuln",
			},
		},
	}

	if err := mgr.WriteMetadata(meta); err != nil {
		t.Fatalf("WriteMetadata failed: %v", err)
	}

	// Read back
	loaded, err := mgr.ReadMetadata("plugin", "akismet", "5.0.1")
	if err != nil {
		t.Fatalf("ReadMetadata failed: %v", err)
	}

	// Verify fields match
	if loaded.Slug != meta.Slug {
		t.Errorf("Slug: got %q, want %q", loaded.Slug, meta.Slug)
	}

	if loaded.Name != meta.Name {
		t.Errorf("Name: got %q, want %q", loaded.Name, meta.Name)
	}

	if loaded.SHA256 != meta.SHA256 {
		t.Errorf("SHA256: got %q, want %q", loaded.SHA256, meta.SHA256)
	}

	if loaded.FileSize != meta.FileSize {
		t.Errorf("FileSize: got %d, want %d", loaded.FileSize, meta.FileSize)
	}

	if len(loaded.Vulnerabilities) != 1 {
		t.Errorf("Vulnerabilities count: got %d, want 1", len(loaded.Vulnerabilities))
	}

	if loaded.Vulnerabilities[0].CVE != "CVE-2024-1234" {
		t.Errorf("CVE: got %q, want CVE-2024-1234", loaded.Vulnerabilities[0].CVE)
	}
}

func TestExists(t *testing.T) {
	baseDir := t.TempDir()
	mgr := NewManager(baseDir)
	mgr.EnsureStructure()

	// Should not exist before write
	if mgr.Exists("plugin", "test", "1.0") {
		t.Error("Exists should return false before write")
	}

	// Write metadata
	meta := &Metadata{
		Slug:    "test",
		Type:    "plugin",
		Version: "1.0",
	}
	mgr.WriteMetadata(meta)

	// Should exist after write
	if !mgr.Exists("plugin", "test", "1.0") {
		t.Error("Exists should return true after write")
	}
}

func TestUpdateReadIndex(t *testing.T) {
	baseDir := t.TempDir()
	mgr := NewManager(baseDir)
	mgr.EnsureStructure()

	// Add first entry
	entry1 := IndexEntry{
		Slug:    "akismet",
		Type:    "plugin",
		Version: "5.0.1",
		FileSize: 1024000,
		HasVulns: false,
	}

	if err := mgr.UpdateIndex(entry1); err != nil {
		t.Fatalf("UpdateIndex entry1 failed: %v", err)
	}

	// Add second entry
	entry2 := IndexEntry{
		Slug:    "twenty-twenty",
		Type:    "theme",
		Version: "2.0",
		FileSize: 2048000,
		HasVulns: true,
	}

	if err := mgr.UpdateIndex(entry2); err != nil {
		t.Fatalf("UpdateIndex entry2 failed: %v", err)
	}

	// Read back
	entries, err := mgr.ReadIndex()
	if err != nil {
		t.Fatalf("ReadIndex failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Index entries: got %d, want 2", len(entries))
	}

	if entries[0].Slug != "akismet" {
		t.Errorf("First entry slug: got %q, want akismet", entries[0].Slug)
	}

	if entries[1].Slug != "twenty-twenty" {
		t.Errorf("Second entry slug: got %q, want twenty-twenty", entries[1].Slug)
	}

	if entries[0].HasVulns != false {
		t.Error("First entry HasVulns should be false")
	}

	if entries[1].HasVulns != true {
		t.Error("Second entry HasVulns should be true")
	}
}

func TestLogError(t *testing.T) {
	baseDir := t.TempDir()
	mgr := NewManager(baseDir)
	mgr.EnsureStructure()

	// Log first error
	err1 := ErrorEntry{
		Slug:    "akismet",
		Version: "5.0.1",
		Type:    "plugin",
		Error:   "download failed",
		Retries: 1,
	}

	if err := mgr.LogError(err1); err != nil {
		t.Fatalf("LogError err1 failed: %v", err)
	}

	// Log second error
	err2 := ErrorEntry{
		Slug:    "test-plugin",
		Version: "1.0",
		Type:    "plugin",
		Error:   "network timeout",
		Retries: 3,
	}

	if err := mgr.LogError(err2); err != nil {
		t.Fatalf("LogError err2 failed: %v", err)
	}

	// Read errors.json
	errorsPath := filepath.Join(baseDir, "errors.json")
	data, err := os.ReadFile(errorsPath)
	if err != nil {
		t.Fatalf("ReadFile errors.json failed: %v", err)
	}

	var entries []ErrorEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("Unmarshal errors.json failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Error entries: got %d, want 2", len(entries))
	}

	if entries[0].Error != "download failed" {
		t.Errorf("First error: got %q, want download failed", entries[0].Error)
	}

	if entries[1].Retries != 3 {
		t.Errorf("Second error retries: got %d, want 3", entries[1].Retries)
	}

	// Verify timestamp was set
	if entries[0].Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestBaseDir(t *testing.T) {
	baseDir := t.TempDir()
	mgr := NewManager(baseDir)

	if mgr.BaseDir() != baseDir {
		t.Errorf("BaseDir: got %q, want %q", mgr.BaseDir(), baseDir)
	}
}

func TestItemDir(t *testing.T) {
	baseDir := t.TempDir()
	mgr := NewManager(baseDir)

	itemDir := mgr.ItemDir("plugin", "akismet", "5.0.1")
	expected := filepath.Join(baseDir, "plugins", "akismet", "5.0.1")

	if itemDir != expected {
		t.Errorf("ItemDir: got %q, want %q", itemDir, expected)
	}
}

func TestReadMetadata_NotExist(t *testing.T) {
	mgr := NewManager(t.TempDir())
	_, err := mgr.ReadMetadata("plugin", "nonexistent", "1.0")
	if err == nil {
		t.Error("expected error for non-existent metadata")
	}
}

func TestReadIndex_NotExist(t *testing.T) {
	mgr := NewManager(t.TempDir())
	entries, err := mgr.ReadIndex()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil entries, got %v", entries)
	}
}

func TestWriteMetadata_CreatesDir(t *testing.T) {
	mgr := NewManager(t.TempDir())
	// Don't call EnsureStructure — WriteMetadata should create dirs itself
	meta := &Metadata{Slug: "test", Type: "plugin", Version: "1.0"}
	if err := mgr.WriteMetadata(meta); err != nil {
		t.Fatalf("WriteMetadata failed: %v", err)
	}
	// Verify file exists
	loaded, err := mgr.ReadMetadata("plugin", "test", "1.0")
	if err != nil {
		t.Fatalf("ReadMetadata failed: %v", err)
	}
	if loaded.Slug != "test" {
		t.Errorf("slug: got %q, want test", loaded.Slug)
	}
}
