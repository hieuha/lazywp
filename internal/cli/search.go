package cli

import (
	"context"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

var (
	searchQuery string
	searchCount int
)

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search WordPress plugins or themes by keyword",
	RunE:  runSearch,
}

func init() {
	searchCmd.Flags().StringVar(&searchQuery, "query", "", "Search query (required)")
	searchCmd.Flags().IntVar(&searchCount, "count", 20, "Maximum results to return")
	_ = searchCmd.MarkFlagRequired("query")
	rootCmd.AddCommand(searchCmd)
}

func runSearch(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	items, err := appDeps.WPClient.Search(ctx, searchQuery, searchCount)
	if err != nil {
		return fmt.Errorf("search: %w", err)
	}
	if len(items) == 0 {
		fmt.Println("No results found.")
		return nil
	}

	headers := []string{"#", "Slug", "Name", "Version", "Active Installs", "Rating"}
	rows := make([][]string, len(items))
	for i, item := range items {
		rows[i] = []string{
			strconv.Itoa(i + 1),
			item.Slug,
			item.Name,
			item.Version,
			strconv.Itoa(item.ActiveInstallations),
			strconv.FormatFloat(item.Rating, 'f', 1, 64),
		}
	}
	fmtr.Print(headers, rows, items)
	return nil
}
