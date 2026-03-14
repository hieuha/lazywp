package extractor

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtract(t *testing.T) {
	// Create a temp zip file with sample content
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "test.zip")

	createTestZip(t, zipPath, map[string]string{
		"plugin/readme.txt":    "hello",
		"plugin/src/main.php":  "<?php echo 1;",
		"plugin/src/utils.php": "<?php function f(){}",
	})

	destDir := filepath.Join(tmpDir, "out")
	if err := Extract(zipPath, destDir); err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	// Verify files exist
	for _, name := range []string{"plugin/readme.txt", "plugin/src/main.php", "plugin/src/utils.php"} {
		p := filepath.Join(destDir, name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected file %s to exist: %v", name, err)
		}
	}
}

func TestExtractZipSlip(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "evil.zip")

	// Create zip with path traversal entry
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	_, err = w.Create("../../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	f.Close()

	destDir := filepath.Join(tmpDir, "out")
	err = Extract(zipPath, destDir)
	if err == nil {
		t.Fatal("expected error for zip-slip path, got nil")
	}
}

func createTestZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := zip.NewWriter(f)
	for name, content := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
