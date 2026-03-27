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

func TestExtractInvalidZip(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "bad.zip")
	os.WriteFile(zipPath, []byte("not a zip"), 0644)

	err := Extract(zipPath, filepath.Join(tmpDir, "out"))
	if err == nil {
		t.Fatal("expected error for invalid zip")
	}
}

func TestExtractWithDirectoryEntry(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "dirs.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	// Add a directory entry (trailing slash)
	_, err = w.Create("mydir/")
	if err != nil {
		t.Fatal(err)
	}
	fw, err := w.Create("mydir/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("content"))
	w.Close()
	f.Close()

	destDir := filepath.Join(tmpDir, "out")
	if err := Extract(zipPath, destDir); err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	// Verify directory was created
	info, err := os.Stat(filepath.Join(destDir, "mydir"))
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected mydir to be a directory")
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
