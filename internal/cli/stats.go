package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show statistics about locally downloaded items",
	RunE:  runStats,
}

func init() {
	rootCmd.AddCommand(statsCmd)
}

func runStats(cmd *cobra.Command, args []string) error {
	entries, err := appDeps.Storage.ReadIndex()
	if err != nil {
		return fmt.Errorf("read index: %w", err)
	}

	var totalSize int64
	vulnCount := 0
	typeCount := map[string]int{}

	for _, e := range entries {
		totalSize += e.FileSize
		typeCount[e.Type]++
		if e.HasVulns {
			vulnCount++
		}
	}

	fmt.Printf("Storage dir:       %s\n", appDeps.Storage.BaseDir())
	fmt.Printf("Total downloaded:  %d\n", len(entries))
	fmt.Printf("  Plugins:         %d\n", typeCount["plugin"])
	fmt.Printf("  Themes:          %d\n", typeCount["theme"])
	fmt.Printf("With vulns:        %d\n", vulnCount)
	fmt.Printf("Total disk usage:  %s\n", formatBytes(totalSize))

	return nil
}
