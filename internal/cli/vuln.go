package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"

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
	vulnDetail bool
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
	vulnCmd.Flags().BoolVar(&vulnDetail, "detail", false, "Show detailed CVEs for each plugin in top results")
	rootCmd.AddCommand(vulnCmd)
}

// printQueryInfo prints a summary of the current query parameters.
func printQueryInfo() {
	if quiet || outputFmt != "table" {
		return
	}
	parts := []string{}
	if vulnSlug != "" {
		parts = append(parts, fmt.Sprintf("slug=%s", vulnSlug))
	}
	if vulnTop > 0 {
		parts = append(parts, fmt.Sprintf("top=%d", vulnTop))
	}
	parts = append(parts, fmt.Sprintf("source=%s", vulnSource))
	if vulnCWE != "" {
		parts = append(parts, fmt.Sprintf("cwe=%s", vulnCWE))
	}
	if vulnSeverity != "" {
		parts = append(parts, fmt.Sprintf("severity=%s", vulnSeverity))
	}
	if vulnMonth > 0 {
		parts = append(parts, fmt.Sprintf("month=%d", vulnMonth))
	}
	if vulnYear > 0 {
		parts = append(parts, fmt.Sprintf("year=%d", vulnYear))
	}
	fmt.Printf("Query: %s\n\n", strings.Join(parts, ", "))
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
	printQueryInfo()
	printCacheSummary("wordfence", "wpscan", "nvd")

	vulns, warnings := appDeps.VulnAgg.FetchForSlug(ctx, vulnSlug, appDeps.ItemType)
	if outputFmt == "table" {
		for _, w := range warnings {
			fmt.Printf("warning: %s\n", w)
		}
	}

	if len(vulns) == 0 {
		if outputFmt == "table" {
			fmt.Printf("No vulnerabilities found for %s\n", vulnSlug)
		} else {
			fmtr.Print(nil, nil, vulns)
		}
		return nil
	}

	headers := []string{"CVE", "CVSS", "Type", "Title", "Affected", "Source", "Fixed In"}
	rows := make([][]string, len(vulns))
	for i, v := range vulns {
		rows[i] = []string{
			v.CVE,
			strconv.FormatFloat(v.CVSS, 'f', 1, 64),
			v.Type,
			vulnTitle(v.Title),
			v.AffectedVersions,
			v.Source,
			v.FixedIn,
		}
	}
	fmtr.Print(headers, rows, vulns)

	if vulnDownload {
		ctx2 := context.Background()
		jobs := []downloader.DownloadJob{{Slug: vulnSlug, ItemType: appDeps.ItemType, Force: forceDown}}
		result := appDeps.Engine.DownloadBatch(ctx2, jobs)
		printBatchResult(result)
	}
	return nil
}

func runVulnTop(ctx context.Context) error {
	printQueryInfo()
	printCacheSummary("wordfence")

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
		if outputFmt == "table" {
			fmt.Println("No vulnerable items found.")
		} else {
			fmtr.Print(nil, nil, items)
		}
		return nil
	}

	// Strip Vulns from JSON/CSV output when --detail is not requested.
	if !vulnDetail {
		for i := range items {
			items[i].Vulns = nil
		}
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

	if vulnDetail && outputFmt == "table" {
		fmt.Println()
		for _, it := range items {
			fmt.Printf("--- %s (%d vulns, max CVSS %.1f) ---\n", it.Slug, it.VulnCount, it.MaxCVSS)
			for _, v := range it.Vulns {
				cve := v.CVE
				if cve == "" {
					cve = "N/A"
				}
				fixed := v.FixedIn
				if fixed == "" {
					fixed = "unfixed"
				}
				fmt.Printf("  %-18s  CVSS:%-4s  %-8s  %s  (affected: %s, fixed: %s)\n",
					cve,
					strconv.FormatFloat(v.CVSS, 'f', 1, 64),
					v.Type,
					vulnTitle(v.Title),
					v.AffectedVersions,
					fixed,
				)
			}
			fmt.Println()
		}
	}

	if vulnDownload {
		jobs := make([]downloader.DownloadJob, len(items))
		for i, it := range items {
			jobs[i] = downloader.DownloadJob{Slug: it.Slug, ItemType: appDeps.ItemType, Force: forceDown}
		}
		result := appDeps.Engine.DownloadBatch(ctx, jobs)
		printBatchResult(result)
	}
	return nil
}

// vulnTitle returns the title, truncated per config title_max_len (0 = no truncation).
func vulnTitle(s string) string {
	if appDeps == nil || appDeps.Config.TitleMaxLen <= 0 {
		return s
	}
	return truncate(s, appDeps.Config.TitleMaxLen)
}

// truncate shortens a string to max n runes, appending "..." if trimmed.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-3]) + "..."
}

// printCacheSummary prints cache info lines for the given sources (table format only).
func printCacheSummary(sources ...string) {
	if quiet || outputFmt != "table" {
		return
	}
	for _, src := range sources {
		PrintCacheInfo(src)
	}
	fmt.Println()
}

