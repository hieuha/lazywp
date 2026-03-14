package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hieuha/lazywp/internal/storage"
)

func TestScanDirectory_Plugins(t *testing.T) {
	tmp := t.TempDir()

	// Plugin with readme.txt
	pluginA := filepath.Join(tmp, "akismet")
	os.MkdirAll(pluginA, 0o755)
	os.WriteFile(filepath.Join(pluginA, "readme.txt"), []byte(
		"=== Akismet ===\nStable tag: 5.3.1\nRequires PHP: 7.0\n",
	), 0o644)

	// Plugin with PHP header only
	pluginB := filepath.Join(tmp, "hello-dolly")
	os.MkdirAll(pluginB, 0o755)
	os.WriteFile(filepath.Join(pluginB, "hello.php"), []byte(
		"<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/\n",
	), 0o644)

	// Plugin with no version info
	pluginC := filepath.Join(tmp, "unknown-plugin")
	os.MkdirAll(pluginC, 0o755)
	os.WriteFile(filepath.Join(pluginC, "main.php"), []byte(
		"<?php\necho 'hello';\n",
	), 0o644)

	// Non-directory file (should be skipped)
	os.WriteFile(filepath.Join(tmp, "stray-file.txt"), []byte("ignore"), 0o644)

	results, err := ScanDirectory(tmp, storage.ItemTypePlugin)
	if err != nil {
		t.Fatalf("ScanDirectory() error: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 plugins, got %d", len(results))
	}

	bySlug := map[string]ScannedPlugin{}
	for _, p := range results {
		bySlug[p.Slug] = p
	}

	if p, ok := bySlug["akismet"]; !ok {
		t.Error("missing akismet")
	} else if p.Version != "5.3.1" {
		t.Errorf("akismet version = %q, want 5.3.1", p.Version)
	}

	if p, ok := bySlug["hello-dolly"]; !ok {
		t.Error("missing hello-dolly")
	} else if p.Version != "1.7.2" {
		t.Errorf("hello-dolly version = %q, want 1.7.2", p.Version)
	}

	if p, ok := bySlug["unknown-plugin"]; !ok {
		t.Error("missing unknown-plugin")
	} else if p.Version != "" {
		t.Errorf("unknown-plugin version = %q, want empty", p.Version)
	}
}

func TestScanDirectory_Themes(t *testing.T) {
	tmp := t.TempDir()

	// Theme with style.css
	themeA := filepath.Join(tmp, "flavor")
	os.MkdirAll(themeA, 0o755)
	os.WriteFile(filepath.Join(themeA, "style.css"), []byte(
		"/*\nTheme Name: Flavor\nVersion: 2.0.3\nAuthor: Someone\n*/\n",
	), 0o644)

	// Theme with only readme.txt (fallback)
	themeB := filepath.Join(tmp, "flavor-lite")
	os.MkdirAll(themeB, 0o755)
	os.WriteFile(filepath.Join(themeB, "readme.txt"), []byte(
		"=== Flavor Lite ===\nStable tag: 1.5.0\n",
	), 0o644)

	// Theme with no version info
	themeC := filepath.Join(tmp, "broken-theme")
	os.MkdirAll(themeC, 0o755)
	os.WriteFile(filepath.Join(themeC, "index.php"), []byte(
		"<?php\necho 'theme';\n",
	), 0o644)

	results, err := ScanDirectory(tmp, storage.ItemTypeTheme)
	if err != nil {
		t.Fatalf("ScanDirectory() error: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 themes, got %d", len(results))
	}

	bySlug := map[string]ScannedPlugin{}
	for _, p := range results {
		bySlug[p.Slug] = p
	}

	if p, ok := bySlug["flavor"]; !ok {
		t.Error("missing flavor")
	} else if p.Version != "2.0.3" {
		t.Errorf("flavor version = %q, want 2.0.3", p.Version)
	}

	if p, ok := bySlug["flavor-lite"]; !ok {
		t.Error("missing flavor-lite")
	} else if p.Version != "1.5.0" {
		t.Errorf("flavor-lite version = %q, want 1.5.0", p.Version)
	}

	if p, ok := bySlug["broken-theme"]; !ok {
		t.Error("missing broken-theme")
	} else if p.Version != "" {
		t.Errorf("broken-theme version = %q, want empty", p.Version)
	}
}

func TestScanDirectory_NotExists(t *testing.T) {
	_, err := ScanDirectory("/nonexistent/path", storage.ItemTypePlugin)
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestParseReadmeStableTag_TrunkTag(t *testing.T) {
	tmp := t.TempDir()
	readme := filepath.Join(tmp, "readme.txt")
	os.WriteFile(readme, []byte("Stable tag: trunk\n"), 0o644)

	v := parseReadmeStableTag(readme)
	if v != "" {
		t.Errorf("expected empty for trunk tag, got %q", v)
	}
}
