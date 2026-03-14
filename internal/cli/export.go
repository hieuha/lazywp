package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/hieuha/lazywp/internal/storage"
	"github.com/spf13/cobra"
)

var (
	exportFormat string
	exportFile   string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export download index to CSV or JSON",
	RunE:  runExport,
}

func init() {
	exportCmd.Flags().StringVar(&exportFormat, "format", "json", "Output format: json|csv")
	exportCmd.Flags().StringVar(&exportFile, "file", "", "Output file path (default: stdout)")
	rootCmd.AddCommand(exportCmd)
}

func runExport(cmd *cobra.Command, args []string) error {
	entries, err := appDeps.Storage.ReadIndex()
	if err != nil {
		return fmt.Errorf("read index: %w", err)
	}

	var w io.Writer = os.Stdout
	if exportFile != "" {
		f, err := os.Create(exportFile)
		if err != nil {
			return fmt.Errorf("create export file: %w", err)
		}
		defer f.Close()
		w = f
	}

	out := NewFormatter(exportFormat, w)

	if exportFormat == "json" {
		out.JSON(entries)
		return nil
	}

	// CSV: flatten index entries
	headers, rows := flattenEntries(entries)
	out.CSV(headers, rows)
	return nil
}

// flattenEntries converts index entries to CSV-friendly rows.
func flattenEntries(entries []storage.IndexEntry) ([]string, [][]string) {
	headers := []string{"slug", "type", "version", "downloaded_at", "has_vulns", "file_size"}
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
	return headers, rows
}
