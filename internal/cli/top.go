package cli

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hieuha/lazywp/internal/downloader"
	"github.com/spf13/cobra"
)

var (
	topCount    int
	topDownload bool
	topBrowse   string
)

var topCmd = &cobra.Command{
	Use:   "top",
	Short: "Browse top WordPress plugins or themes",
	Long:  `Fetch top plugins/themes from the WordPress directory by category.`,
	RunE:  runTop,
}

func init() {
	topCmd.Flags().IntVar(&topCount, "count", 10, "Number of items to fetch")
	topCmd.Flags().BoolVar(&topDownload, "download", false, "Download the listed items after browsing")
	topCmd.Flags().StringVar(&topBrowse, "browse", "popular", "Browse category: popular|new|trending|featured")
	rootCmd.AddCommand(topCmd)
}

func runTop(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	items, err := appDeps.WPClient.Browse(ctx, topBrowse, topCount)
	if err != nil {
		return fmt.Errorf("browse %s: %w", topBrowse, err)
	}

	headers := []string{"#", "Slug", "Version", "Name", "Active Installs"}
	rows := make([][]string, len(items))
	for i, item := range items {
		rows[i] = []string{
			strconv.Itoa(i + 1),
			item.Slug,
			item.Version,
			item.Name,
			formatNumber(item.ActiveInstallations),
		}
	}
	fmtr.Print(headers, rows, items)

	if topDownload {
		jobs := make([]downloader.DownloadJob, len(items))
		for i, item := range items {
			jobs[i] = downloader.DownloadJob{
				Slug:     item.Slug,
				Version:  item.Version,
				ItemType: appDeps.ItemType,
				Force:    forceDown,
			}
		}
		if !quiet {
			fmt.Printf("\nDownloading %d items...\n", len(jobs))
		}
		result := appDeps.Engine.DownloadBatch(ctx, jobs)
		printBatchResult(result)
	}

	return nil
}
