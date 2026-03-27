package vuln

import (
	"testing"
	"time"
)

func TestClearSource(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	data := []byte(`{"test": "data"}`)
	if err := cache.Set("wpscan", "key1", data); err != nil {
		t.Fatalf("Set key1 failed: %v", err)
	}
	if err := cache.Set("wpscan", "key2", data); err != nil {
		t.Fatalf("Set key2 failed: %v", err)
	}

	n, err := cache.ClearSource("wpscan")
	if err != nil {
		t.Fatalf("ClearSource failed: %v", err)
	}
	if n != 2 {
		t.Errorf("want 2 files cleared, got %d", n)
	}

	if _, hit := cache.Get("wpscan", "key1"); hit {
		t.Error("key1 should be gone after ClearSource")
	}
	if _, hit := cache.Get("wpscan", "key2"); hit {
		t.Error("key2 should be gone after ClearSource")
	}
}

func TestClearSource_NonExistent(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	n, err := cache.ClearSource("nosuchsource")
	if err != nil {
		t.Fatalf("ClearSource on non-existent source should not error: %v", err)
	}
	if n != 0 {
		t.Errorf("want 0 files cleared, got %d", n)
	}
}

func TestClearAll(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	data := []byte(`{"test": "data"}`)
	sources := []string{"wpscan", "nvd", "patchstack"}
	for _, src := range sources {
		if err := cache.Set(src, "key", data); err != nil {
			t.Fatalf("Set %s failed: %v", src, err)
		}
	}

	n, err := cache.ClearAll()
	if err != nil {
		t.Fatalf("ClearAll failed: %v", err)
	}
	if n != len(sources) {
		t.Errorf("want %d files cleared, got %d", len(sources), n)
	}

	for _, src := range sources {
		if _, hit := cache.Get(src, "key"); hit {
			t.Errorf("source %s should be empty after ClearAll", src)
		}
	}
}

func TestSetDisabled(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	data := []byte(`{"test": "data"}`)
	if err := cache.Set("wpscan", "key", data); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	cache.SetDisabled(true)

	if _, hit := cache.Get("wpscan", "key"); hit {
		t.Error("disabled cache should always return miss")
	}

	// Re-enable: should hit again
	cache.SetDisabled(false)
	if _, hit := cache.Get("wpscan", "key"); !hit {
		t.Error("re-enabled cache should return hit for existing entry")
	}
}

func TestInfo_Exists(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	data := []byte(`{"test": "data"}`)
	if err := cache.Set("wpscan", "my-plugin", data); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	info := cache.Info("wpscan", "my-plugin")
	if info == nil {
		t.Fatal("Info should return non-nil for existing entry")
	}
	if info.Source != "wpscan" {
		t.Errorf("want source wpscan, got %s", info.Source)
	}
	if info.FileSize != int64(len(data)) {
		t.Errorf("want file size %d, got %d", len(data), info.FileSize)
	}
	if info.Expired {
		t.Error("entry should not be expired immediately after Set")
	}
	if info.Age < 0 {
		t.Error("age should be non-negative")
	}
}

func TestInfo_NotExists(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	if info := cache.Info("wpscan", "missing"); info != nil {
		t.Error("Info should return nil for missing entry")
	}
}

func TestSourceInfo(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	data := []byte(`{"test": "data"}`)
	if err := cache.Set("wpscan", "plugin-a", data); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	info := cache.SourceInfo("wpscan")
	if info == nil {
		t.Fatal("SourceInfo should return non-nil when files exist")
	}
	if info.Source != "wpscan" {
		t.Errorf("want source wpscan, got %s", info.Source)
	}
	if info.FileSize != int64(len(data)) {
		t.Errorf("want file size %d, got %d", len(data), info.FileSize)
	}
}

func TestSourceInfo_Empty(t *testing.T) {
	baseDir := t.TempDir()
	cache := NewCache(baseDir, 1*time.Hour)

	if info := cache.SourceInfo("nosuchsource"); info != nil {
		t.Error("SourceInfo should return nil for empty/missing source")
	}
}
