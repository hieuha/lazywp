package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hieuha/lazywp/internal/downloader"
	"github.com/spf13/cobra"
)

var (
	dlSlug      string
	dlVersion   string
	dlList      string
	dlOutputDir string
)

var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download WordPress plugins or themes",
	Long:  `Download one or more plugins/themes by slug or from a list file.`,
	RunE:  runDownload,
}

func init() {
	downloadCmd.Flags().StringVar(&dlSlug, "slug", "", "Slug of the plugin/theme to download")
	downloadCmd.Flags().StringVar(&dlVersion, "version", "", "Version to download (default: latest)")
	downloadCmd.Flags().StringVar(&dlList, "list", "", "Path to file with slugs (one per line, slug:version supported)")
	downloadCmd.Flags().StringVar(&dlOutputDir, "output-dir", "", "Override download output directory")
	rootCmd.AddCommand(downloadCmd)
}

func runDownload(cmd *cobra.Command, args []string) error {
	if dlSlug == "" && dlList == "" {
		return fmt.Errorf("must provide --slug or --list")
	}

	// Override output dir if requested.
	if dlOutputDir != "" {
		appDeps.Config.OutputDir = dlOutputDir
		// Re-init storage for new dir.
		appDeps.Storage.EnsureStructure() //nolint:errcheck
	}

	ctx := context.Background()

	if dlSlug != "" {
		return runDownloadSingle(ctx)
	}
	return runDownloadList(ctx)
}

func runDownloadSingle(ctx context.Context) error {
	if !quiet {
		fmt.Printf("Downloading %s %s...\n", appDeps.ItemType, dlSlug)
	}
	err := appDeps.Engine.DownloadOne(ctx, dlSlug, dlVersion, appDeps.ItemType)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	if !quiet {
		fmt.Printf("Done: %s\n", dlSlug)
	}
	return nil
}

func runDownloadList(ctx context.Context) error {
	jobs, err := readSlugList(dlList)
	if err != nil {
		return err
	}
	if len(jobs) == 0 {
		return fmt.Errorf("no slugs found in %s", dlList)
	}

	if !quiet {
		fmt.Printf("Downloading %d items...\n", len(jobs))
	}

	result := appDeps.Engine.DownloadBatch(ctx, jobs)
	printBatchResult(result)
	return nil
}

// readSlugList reads a file of slugs (one per line, optional :version suffix).
func readSlugList(path string) ([]downloader.DownloadJob, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open list file: %w", err)
	}
	defer f.Close()

	var jobs []downloader.DownloadJob
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		slug, version, _ := strings.Cut(line, ":")
		jobs = append(jobs, downloader.DownloadJob{
			Slug:     strings.TrimSpace(slug),
			Version:  strings.TrimSpace(version),
			ItemType: appDeps.ItemType,
			Force:    forceDown,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read list file: %w", err)
	}
	return jobs, nil
}

// printBatchResult prints a summary of a batch download operation.
func printBatchResult(r *downloader.BatchResult) {
	fmt.Printf("\nBatch complete in %s\n", r.Duration.Round(1e6))
	fmt.Printf("  Total:     %d\n", r.Total)
	fmt.Printf("  Succeeded: %d\n", r.Succeeded)
	fmt.Printf("  Existed:   %d\n", r.Skipped)
	fmt.Printf("  Failed:    %d\n", r.Failed)
	for _, e := range r.Errors {
		fmt.Fprintf(os.Stderr, "  ERROR %s@%s: %s\n", e.Slug, e.Version, e.Error)
	}
}
