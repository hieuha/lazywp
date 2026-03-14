package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hieuha/lazywp/internal/extractor"
	"github.com/spf13/cobra"
)

var (
	extractSlug      string
	extractList      string
	extractOutputDir string
	extractSourceDir string
	extractClean     bool
)

var extractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract downloaded plugin/theme zip files for SAST analysis",
	Long: `Extract zip archives of downloaded plugins/themes into a flat directory
structure suitable for static analysis security testing (SAST).

Without flags, extracts all downloaded items of the current type.`,
	RunE: runExtract,
}

func init() {
	extractCmd.Flags().StringVar(&extractSlug, "slug", "", "Extract a specific plugin/theme by slug")
	extractCmd.Flags().StringVar(&extractList, "list", "", "Path to file with slugs to extract (one per line)")
	extractCmd.Flags().StringVar(&extractOutputDir, "output-dir", "", "Output directory (default: ./extracted)")
	extractCmd.Flags().StringVar(&extractSourceDir, "source-dir", "", "Source downloads directory (default: config output_dir)")
	extractCmd.Flags().BoolVar(&extractClean, "clean", false, "Remove existing extracted files before extracting")
	rootCmd.AddCommand(extractCmd)
}

func runExtract(cmd *cobra.Command, args []string) error {
	destDir := extractOutputDir
	if destDir == "" {
		destDir = "./extracted"
	}

	if extractClean {
		if !quiet {
			fmt.Printf("Cleaning %s...\n", destDir)
		}
		if err := os.RemoveAll(destDir); err != nil {
			return fmt.Errorf("clean output dir: %w", err)
		}
	}

	typeName := string(appDeps.ItemType) + "s" // "plugins" or "themes"

	// Resolve source base directory (downloads folder)
	sourceBase := appDeps.Storage.BaseDir()
	if extractSourceDir != "" {
		sourceBase = extractSourceDir
	}

	// Determine which slugs to extract
	slugs, err := resolveExtractSlugs(typeName, sourceBase)
	if err != nil {
		return err
	}
	if len(slugs) == 0 {
		fmt.Println("No items found to extract.")
		return nil
	}

	var succeeded, failed int
	for _, slug := range slugs {
		if err := extractSlugVersions(typeName, slug, destDir, sourceBase); err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %s\n", slug, err)
			failed++
		} else {
			succeeded++
		}
	}

	if !quiet {
		fmt.Printf("\nExtract complete: %d succeeded, %d failed (out of %d)\n", succeeded, failed, len(slugs))
		fmt.Printf("Output: %s\n", destDir)
	}
	return nil
}

// resolveExtractSlugs determines which slugs to extract based on flags.
func resolveExtractSlugs(typeName, sourceBase string) ([]string, error) {
	if extractSlug != "" {
		return []string{extractSlug}, nil
	}

	if extractList != "" {
		return readExtractList(extractList)
	}

	// Default: discover all downloaded slugs from disk
	return discoverDownloadedSlugs(typeName, sourceBase)
}

// readExtractList reads a file with one slug per line.
func readExtractList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open list file: %w", err)
	}
	defer f.Close()

	var slugs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip optional :version suffix — we extract all versions
		slug, _, _ := strings.Cut(line, ":")
		slugs = append(slugs, strings.TrimSpace(slug))
	}
	return slugs, scanner.Err()
}

// discoverDownloadedSlugs lists all slug directories under downloads/<type>.
func discoverDownloadedSlugs(typeName, sourceBase string) ([]string, error) {
	typeDir := filepath.Join(sourceBase, typeName)
	entries, err := os.ReadDir(typeDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s dir: %w", typeName, err)
	}

	var slugs []string
	for _, e := range entries {
		if e.IsDir() {
			slugs = append(slugs, e.Name())
		}
	}
	return slugs, nil
}

// extractSlugVersions finds and extracts all version zips for a given slug.
func extractSlugVersions(typeName, slug, destDir, sourceBase string) error {
	slugDir := filepath.Join(sourceBase, typeName, slug)
	versions, err := os.ReadDir(slugDir)
	if err != nil {
		return fmt.Errorf("read versions for %s: %w", slug, err)
	}

	extracted := 0
	for _, v := range versions {
		if !v.IsDir() {
			continue
		}
		zipPath := filepath.Join(slugDir, v.Name(), slug+".zip")
		if _, err := os.Stat(zipPath); err != nil {
			continue // no zip in this version dir
		}

		// Extract to: <destDir>/<slug>/<version>/
		extractDest := filepath.Join(destDir, slug, v.Name())
		if !quiet {
			fmt.Printf("  Extracting %s@%s...\n", slug, v.Name())
		}
		if err := extractor.Extract(zipPath, extractDest); err != nil {
			return fmt.Errorf("extract %s@%s: %w", slug, v.Name(), err)
		}
		extracted++
	}

	if extracted == 0 {
		return fmt.Errorf("no zip files found")
	}
	return nil
}
