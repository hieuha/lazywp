package cli

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/hieuha/lazywp/internal/storage"
	"github.com/spf13/cobra"
)

var (
	listSort    string
	listHasVuln bool
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List locally downloaded plugins or themes",
	RunE:  runList,
}

func init() {
	listCmd.Flags().StringVar(&listSort, "sort", "name", "Sort by: name|date|size")
	listCmd.Flags().BoolVar(&listHasVuln, "has-vuln", false, "Show only items with known vulnerabilities")
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	entries, err := appDeps.Storage.ReadIndex()
	if err != nil {
		return fmt.Errorf("read index: %w", err)
	}

	// Filter
	if listHasVuln {
		filtered := entries[:0]
		for _, e := range entries {
			if e.HasVulns {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	if len(entries) == 0 {
		fmt.Println("No items found.")
		return nil
	}

	sortEntries(entries, listSort)

	headers := []string{"Slug", "Type", "Version", "Downloaded At", "Has Vulns", "Size"}
	rows := make([][]string, len(entries))
	for i, e := range entries {
		rows[i] = []string{
			e.Slug,
			e.Type,
			e.Version,
			e.DownloadedAt.Format(time.RFC3339),
			boolStr(e.HasVulns),
			formatBytes(e.FileSize),
		}
	}
	fmtr.Print(headers, rows, entries)
	return nil
}

func sortEntries(entries []storage.IndexEntry, by string) {
	switch by {
	case "date":
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].DownloadedAt.After(entries[j].DownloadedAt)
		})
	case "size":
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].FileSize > entries[j].FileSize
		})
	default: // name
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Slug < entries[j].Slug
		})
	}
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// formatNumber formats an integer with human-readable suffixes (e.g. 10M, 500K).
func formatNumber(n int) string {
	switch {
	case n >= 1_000_000:
		if n%1_000_000 == 0 {
			return fmt.Sprintf("%dM", n/1_000_000)
		}
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		if n%1_000 == 0 {
			return fmt.Sprintf("%dK", n/1_000)
		}
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return strconv.Itoa(n)
	}
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	suffixes := []string{"KB", "MB", "GB"}
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), suffixes[exp])
}
