package cli

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hieuha/lazywp/internal/client"
	"github.com/hieuha/lazywp/internal/downloader"
	"github.com/spf13/cobra"
)

var (
	vulnSlug     string
	vulnTop      int
	vulnDownload bool
	vulnSource   string
	vulnCWE      string
	vulnSeverity string
	vulnMonth    int
	vulnYear     int
)

var vulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "Query vulnerability data for plugins or themes",
	Long:  `Fetch known vulnerabilities from WPScan, NVD, or Wordfence.`,
	RunE:  runVuln,
}

func init() {
	vulnCmd.Flags().StringVar(&vulnSlug, "slug", "", "Slug to look up vulnerabilities for")
	vulnCmd.Flags().IntVar(&vulnTop, "top", 0, "Show top N most vulnerable items (Wordfence)")
	vulnCmd.Flags().BoolVar(&vulnDownload, "download", false, "Download items listed in results")
	vulnCmd.Flags().StringVar(&vulnSource, "source", "all", "Vulnerability source: wpscan|nvd|wordfence|all")
	vulnCmd.Flags().StringVar(&vulnCWE, "cwe-type", "", "Wordfence CWE filter (e.g. sqli, xss, rce)")
	vulnCmd.Flags().StringVar(&vulnSeverity, "severity", "", "Wordfence CVSS severity: critical|high|medium|low")
	vulnCmd.Flags().IntVar(&vulnMonth, "month", 0, "Wordfence month filter (1-12)")
	vulnCmd.Flags().IntVar(&vulnYear, "year", 0, "Wordfence year filter (e.g. 2024)")
	rootCmd.AddCommand(vulnCmd)
}

func runVuln(cmd *cobra.Command, args []string) error {
	if vulnSlug == "" && vulnTop == 0 {
		return fmt.Errorf("must provide --slug or --top")
	}

	ctx := context.Background()

	if vulnSlug != "" {
		return runVulnBySlug(ctx)
	}
	return runVulnTop(ctx)
}

func runVulnBySlug(ctx context.Context) error {
	vulns, warnings := appDeps.VulnAgg.FetchForSlug(ctx, vulnSlug, appDeps.ItemType)
	for _, w := range warnings {
		fmt.Printf("warning: %s\n", w)
	}

	if len(vulns) == 0 {
		fmt.Printf("No vulnerabilities found for %s\n", vulnSlug)
		return nil
	}

	headers := []string{"CVE", "CVSS", "Type", "Title", "Source", "Fixed In"}
	rows := make([][]string, len(vulns))
	for i, v := range vulns {
		rows[i] = []string{
			v.CVE,
			strconv.FormatFloat(v.CVSS, 'f', 1, 64),
			v.Type,
			truncate(v.Title, 60),
			v.Source,
			v.FixedIn,
		}
	}
	fmtr.Print(headers, rows, vulns)

	if vulnDownload {
		ctx2 := context.Background()
		jobs := []downloader.DownloadJob{{Slug: vulnSlug, ItemType: appDeps.ItemType}}
		result := appDeps.Engine.DownloadBatch(ctx2, jobs)
		printBatchResult(result)
	}
	return nil
}

func runVulnTop(ctx context.Context) error {
	filters := client.WordfenceFilters{
		CWEType:    vulnCWE,
		CVSSRating: vulnSeverity,
		Month:      vulnMonth,
		Year:       vulnYear,
	}

	items, err := appDeps.WFClient.FetchVulnPlugins(ctx, filters, vulnTop)
	if err != nil {
		return fmt.Errorf("fetch vuln plugins: %w", err)
	}
	if len(items) == 0 {
		fmt.Println("No vulnerable items found.")
		return nil
	}

	headers := []string{"#", "Slug", "Vuln Count", "Max CVSS"}
	rows := make([][]string, len(items))
	for i, it := range items {
		rows[i] = []string{
			strconv.Itoa(i + 1),
			it.Slug,
			strconv.Itoa(it.VulnCount),
			strconv.FormatFloat(it.MaxCVSS, 'f', 1, 64),
		}
	}
	fmtr.Print(headers, rows, items)

	if vulnDownload {
		jobs := make([]downloader.DownloadJob, len(items))
		for i, it := range items {
			jobs[i] = downloader.DownloadJob{Slug: it.Slug, ItemType: appDeps.ItemType}
		}
		result := appDeps.Engine.DownloadBatch(ctx, jobs)
		printBatchResult(result)
	}
	return nil
}

// truncate shortens a string to max n runes, appending "..." if trimmed.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-3]) + "..."
}
