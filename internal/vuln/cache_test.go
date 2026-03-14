package vuln

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSetGet(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	// Set data
	data := []byte(`{"cve": "CVE-2024-1234", "cvss": 7.5}`)
	if err := cache.Set("wpscan", "akismet", data); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Get data
	loaded, hit := cache.Get("wpscan", "akismet")
	if !hit {
		t.Error("Get should return hit=true for existing data")
	}

	if string(loaded) != string(data) {
		t.Errorf("Data mismatch: got %s, want %s", loaded, data)
	}
}

func TestExpired(t *testing.T) {
	baseDir := t.TempDir()
	// Use 10ms TTL for quick test
	cache := NewCache(baseDir, 10*time.Millisecond)

	// Set data
	data := []byte(`{"test": "data"}`)
	if err := cache.Set("nvd", "test-key", data); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Should hit immediately
	_, hit := cache.Get("nvd", "test-key")
	if !hit {
		t.Error("Get should hit immediately after Set")
	}

	// Wait for TTL to expire
	time.Sleep(20 * time.Millisecond)

	// Should miss
	_, hit = cache.Get("nvd", "test-key")
	if hit {
		t.Error("Get should return hit=false after TTL expires")
	}
}

func TestInvalidate(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	// Set data
	data := []byte(`{"test": "data"}`)
	if err := cache.Set("wpscan", "remove-me", data); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Verify it exists
	_, hit := cache.Get("wpscan", "remove-me")
	if !hit {
		t.Error("Data should exist after Set")
	}

	// Invalidate
	if err := cache.Invalidate("wpscan", "remove-me"); err != nil {
		t.Fatalf("Invalidate failed: %v", err)
	}

	// Should miss
	_, hit = cache.Get("wpscan", "remove-me")
	if hit {
		t.Error("Get should return hit=false after Invalidate")
	}
}

func TestInvalidateNonExistent(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	// Invalidate non-existent key (should not error)
	if err := cache.Invalidate("source", "nonexistent"); err != nil {
		t.Fatalf("Invalidate should not error on missing key: %v", err)
	}
}

func TestMiss(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	// Get non-existent key
	_, hit := cache.Get("wpscan", "nonexistent")
	if hit {
		t.Error("Get should return hit=false for non-existent key")
	}
}

func TestMultipleSources(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	data1 := []byte(`{"source": "wpscan"}`)
	data2 := []byte(`{"source": "nvd"}`)

	// Set same key in different sources
	if err := cache.Set("wpscan", "test", data1); err != nil {
		t.Fatalf("Set wpscan failed: %v", err)
	}

	if err := cache.Set("nvd", "test", data2); err != nil {
		t.Fatalf("Set nvd failed: %v", err)
	}

	// Get from each source
	loaded1, hit1 := cache.Get("wpscan", "test")
	loaded2, hit2 := cache.Get("nvd", "test")

	if !hit1 || !hit2 {
		t.Error("Both sources should have data")
	}

	if string(loaded1) != string(data1) {
		t.Errorf("wpscan data mismatch: got %s, want %s", loaded1, data1)
	}

	if string(loaded2) != string(data2) {
		t.Errorf("nvd data mismatch: got %s, want %s", loaded2, data2)
	}
}

func TestDirectoryStructure(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	// Set data
	data := []byte(`{"test": "data"}`)
	if err := cache.Set("wpscan", "plugin-slug", data); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Verify directory structure: baseDir/wpscan/<hash>.json
	sourceDir := filepath.Join(baseDir, "wpscan")
	if _, err := os.Stat(sourceDir); err != nil {
		t.Errorf("Source directory not created: %v", err)
	}

	// Should have at least one .json file
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	if len(entries) == 0 {
		t.Error("No cache files created")
	}

	found := false
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			found = true
			break
		}
	}

	if !found {
		t.Error("No .json files found in cache directory")
	}
}

func TestLargeData(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	// Create large data
	largeData := make([]byte, 1000000) // 1MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	if err := cache.Set("test", "large-key", largeData); err != nil {
		t.Fatalf("Set large data failed: %v", err)
	}

	loaded, hit := cache.Get("test", "large-key")
	if !hit {
		t.Error("Should hit for large data")
	}

	if len(loaded) != len(largeData) {
		t.Errorf("Data size mismatch: got %d, want %d", len(loaded), len(largeData))
	}

	// Verify data integrity
	for i := 0; i < len(largeData); i++ {
		if loaded[i] != largeData[i] {
			t.Errorf("Data corruption at byte %d: got %d, want %d", i, loaded[i], largeData[i])
			break
		}
	}
}
