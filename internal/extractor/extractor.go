package extractor

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxExtractSize = 500 * 1024 * 1024 // 500MB safety limit per zip

// Extract unzips a zip file into destDir.
// It guards against path traversal (zip-slip) and oversized archives.
func Extract(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip %s: %w", zipPath, err)
	}
	defer r.Close()

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("create dest dir: %w", err)
	}

	var totalBytes int64
	for _, f := range r.File {
		if err := extractFile(f, destDir, &totalBytes); err != nil {
			return err
		}
	}
	return nil
}

// extractFile writes a single zip entry to disk with safety checks.
func extractFile(f *zip.File, destDir string, totalBytes *int64) error {
	// Guard against zip-slip path traversal
	target := filepath.Join(destDir, f.Name) //nolint:gosec
	if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)+string(os.PathSeparator)) {
		return fmt.Errorf("illegal path in zip: %s", f.Name)
	}

	if f.FileInfo().IsDir() {
		return os.MkdirAll(target, 0755)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return fmt.Errorf("create parent dir for %s: %w", f.Name, err)
	}

	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open entry %s: %w", f.Name, err)
	}
	defer rc.Close()

	out, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("create file %s: %w", target, err)
	}
	defer out.Close()

	// Limit total extracted bytes to prevent zip bombs
	written, err := io.Copy(out, io.LimitReader(rc, maxExtractSize-*totalBytes))
	if err != nil {
		return fmt.Errorf("write %s: %w", f.Name, err)
	}
	*totalBytes += written
	if *totalBytes >= maxExtractSize {
		return fmt.Errorf("archive exceeds %d byte safety limit", maxExtractSize)
	}

	return nil
}
