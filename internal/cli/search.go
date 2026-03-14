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
	Use:   "search <query>",
	Short: "Search WordPress plugins or themes by keyword",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runSearch,
}

func init() {
	searchCmd.Flags().StringVar(&searchQuery, "query", "", "Search query (alternative to positional arg)")
	searchCmd.Flags().IntVar(&searchCount, "count", 20, "Maximum results to return")
	rootCmd.AddCommand(searchCmd)
}

func runSearch(cmd *cobra.Command, args []string) error {
	query := searchQuery
	if len(args) > 0 {
		query = args[0]
	}
	if query == "" {
		return fmt.Errorf("search query required: provide as argument or use --query")
	}

	ctx := context.Background()

	items, err := appDeps.WPClient.Search(ctx, query, searchCount)
	if err != nil {
		return fmt.Errorf("search: %w", err)
	}
	if len(items) == 0 {
		fmt.Println("No results found.")
		return nil
	}

	headers := []string{"#", "Slug", "Version", "Name", "Active Installs", "Rating"}
	rows := make([][]string, len(items))
	for i, item := range items {
		rows[i] = []string{
			strconv.Itoa(i + 1),
			item.Slug,
			item.Version,
			item.Name,
			formatNumber(item.ActiveInstallations),
			strconv.FormatFloat(item.Rating, 'f', 1, 64),
		}
	}
	fmtr.Print(headers, rows, items)
	return nil
}
