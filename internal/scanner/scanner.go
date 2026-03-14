package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hieuha/lazywp/internal/storage"
)

// ScannedPlugin holds detected plugin/theme info from a local directory.
type ScannedPlugin struct {
	Slug    string `json:"slug"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

// headerVersionRe matches "Version: X.Y.Z" in PHP/CSS file headers.
var headerVersionRe = regexp.MustCompile(`(?i)^\s*\*?\s*Version:\s*(.+)`)

// stableTagRe matches "Stable tag: X.Y.Z" in readme.txt.
var stableTagRe = regexp.MustCompile(`(?i)^Stable\s+tag:\s*(.+)`)

// ScanDirectory walks the given directory and detects WordPress plugins or themes.
// Detection strategy differs by item type:
//   - plugin: readme.txt "Stable tag" → .php header "Version:"
//   - theme:  style.css header "Version:" → readme.txt "Stable tag"
func ScanDirectory(dir string, itemType storage.ItemType) ([]ScannedPlugin, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var items []ScannedPlugin
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		slug := entry.Name()
		itemDir := filepath.Join(dir, slug)

		var version string
		if itemType == storage.ItemTypeTheme {
			version = detectThemeVersion(itemDir)
		} else {
			version = detectPluginVersion(itemDir)
		}

		items = append(items, ScannedPlugin{
			Slug:    slug,
			Version: version,
			Path:    itemDir,
		})
	}

	return items, nil
}

// detectPluginVersion tries readme.txt first, then falls back to PHP file headers.
func detectPluginVersion(dir string) string {
	if v := parseReadmeStableTag(filepath.Join(dir, "readme.txt")); v != "" {
		return v
	}

	// Fallback: scan PHP files for "Version:" in header comment
	phpFiles, _ := filepath.Glob(filepath.Join(dir, "*.php"))
	for _, f := range phpFiles {
		if v := parseHeaderVersion(f); v != "" {
			return v
		}
	}
	return ""
}

// detectThemeVersion reads style.css "Version:" header, falls back to readme.txt.
func detectThemeVersion(dir string) string {
	// Themes define version in style.css header comment
	if v := parseHeaderVersion(filepath.Join(dir, "style.css")); v != "" {
		return v
	}

	// Fallback: some themes also have readme.txt with Stable tag
	if v := parseReadmeStableTag(filepath.Join(dir, "readme.txt")); v != "" {
		return v
	}
	return ""
}

// parseReadmeStableTag extracts "Stable tag: X.Y.Z" from readme.txt.
func parseReadmeStableTag(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		if m := stableTagRe.FindStringSubmatch(s.Text()); len(m) == 2 {
			tag := strings.TrimSpace(m[1])
			if tag != "" && tag != "trunk" {
				return tag
			}
		}
	}
	return ""
}

// parseHeaderVersion extracts "Version: X.Y.Z" from a file's header comment
// (works for both PHP plugin headers and CSS theme headers).
func parseHeaderVersion(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	lineCount := 0
	for s.Scan() {
		lineCount++
		// Only check first 50 lines (header comment area)
		if lineCount > 50 {
			break
		}
		if m := headerVersionRe.FindStringSubmatch(s.Text()); len(m) == 2 {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}
