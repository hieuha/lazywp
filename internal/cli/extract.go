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

// extractTarget holds a slug with an optional version filter.
type extractTarget struct {
	Slug    string
	Version string // empty = all versions
}

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

Examples:
  lazywp extract                                  # extract all downloaded plugins
  lazywp extract --slug akismet                   # extract all versions of akismet
  lazywp extract --slug akismet:5.0.1             # extract only akismet v5.0.1
  lazywp extract --list targets.txt               # extract from list (slug or slug:version)
  lazywp extract --source-dir /path/to/downloads  # custom downloads folder`,
	RunE: runExtract,
}

func init() {
	extractCmd.Flags().StringVar(&extractSlug, "slug", "", "Plugin/theme slug (use slug:version for specific version)")
	extractCmd.Flags().StringVar(&extractList, "list", "", "File with slugs to extract (one per line, slug:version supported)")
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

	// Determine which targets to extract
	targets, err := resolveExtractTargets(typeName, sourceBase)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("No items found to extract.")
		return nil
	}

	// Count total extractions for progress bar
	totalExtractions := countExtractions(typeName, targets, sourceBase)
	progress := newScanProgress(totalExtractions, "Extracting", quiet)

	var succeeded, failed int
	for _, t := range targets {
		if err := extractTarget_run(typeName, t, destDir, sourceBase, progress); err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR %s: %s\n", formatTarget(t), err)
			failed++
		} else {
			succeeded++
		}
	}
	progress.finish()

	if !quiet {
		fmt.Printf("\nExtract complete: %d succeeded, %d failed (out of %d)\n", succeeded, failed, len(targets))
		fmt.Printf("Output: %s\n", destDir)
	}
	return nil
}

// parseSlugVersion splits "slug:version" into slug and version parts.
func parseSlugVersion(s string) extractTarget {
	slug, version, _ := strings.Cut(s, ":")
	return extractTarget{
		Slug:    strings.TrimSpace(slug),
		Version: strings.TrimSpace(version),
	}
}

func formatTarget(t extractTarget) string {
	if t.Version != "" {
		return t.Slug + "@" + t.Version
	}
	return t.Slug
}

// resolveExtractTargets determines which slug+version pairs to extract.
func resolveExtractTargets(typeName, sourceBase string) ([]extractTarget, error) {
	if extractSlug != "" {
		return []extractTarget{parseSlugVersion(extractSlug)}, nil
	}

	if extractList != "" {
		return readExtractList(extractList)
	}

	// Default: discover all downloaded slugs (all versions)
	slugs, err := discoverDownloadedSlugs(typeName, sourceBase)
	if err != nil {
		return nil, err
	}
	targets := make([]extractTarget, len(slugs))
	for i, s := range slugs {
		targets[i] = extractTarget{Slug: s}
	}
	return targets, nil
}

// readExtractList reads a file with slug or slug:version per line.
func readExtractList(path string) ([]extractTarget, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open list file: %w", err)
	}
	defer f.Close()

	var targets []extractTarget
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, parseSlugVersion(line))
	}
	return targets, scanner.Err()
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

// countExtractions counts total zip files to extract for progress bar sizing.
func countExtractions(typeName string, targets []extractTarget, sourceBase string) int {
	total := 0
	for _, t := range targets {
		slugDir := filepath.Join(sourceBase, typeName, t.Slug)
		if t.Version != "" {
			zipPath := filepath.Join(slugDir, t.Version, t.Slug+".zip")
			if _, err := os.Stat(zipPath); err == nil {
				total++
			}
			continue
		}
		versions, err := os.ReadDir(slugDir)
		if err != nil {
			continue
		}
		for _, v := range versions {
			if !v.IsDir() {
				continue
			}
			zipPath := filepath.Join(slugDir, v.Name(), t.Slug+".zip")
			if _, err := os.Stat(zipPath); err == nil {
				total++
			}
		}
	}
	return total
}

// extractTarget_run extracts zip(s) for a single target.
func extractTarget_run(typeName string, t extractTarget, destDir, sourceBase string, progress *scanProgress) error {
	slugDir := filepath.Join(sourceBase, typeName, t.Slug)

	// Single version mode
	if t.Version != "" {
		zipPath := filepath.Join(slugDir, t.Version, t.Slug+".zip")
		if _, err := os.Stat(zipPath); err != nil {
			return fmt.Errorf("%s@%s not found", t.Slug, t.Version)
		}
		extractDest := filepath.Join(destDir, t.Slug, t.Version)
		progress.update(fmt.Sprintf("%s@%s", t.Slug, t.Version))
		return extractor.Extract(zipPath, extractDest)
	}

	// All versions mode
	versions, err := os.ReadDir(slugDir)
	if err != nil {
		return fmt.Errorf("read versions for %s: %w", t.Slug, err)
	}

	extracted := 0
	for _, v := range versions {
		if !v.IsDir() {
			continue
		}
		zipPath := filepath.Join(slugDir, v.Name(), t.Slug+".zip")
		if _, err := os.Stat(zipPath); err != nil {
			continue
		}

		extractDest := filepath.Join(destDir, t.Slug, v.Name())
		progress.update(fmt.Sprintf("%s@%s", t.Slug, v.Name()))
		if err := extractor.Extract(zipPath, extractDest); err != nil {
			return fmt.Errorf("extract %s@%s: %w", t.Slug, v.Name(), err)
		}
		extracted++
	}

	if extracted == 0 {
		return fmt.Errorf("no zip files found for %s", t.Slug)
	}
	return nil
}
