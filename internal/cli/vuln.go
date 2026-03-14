package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/hieuha/lazywp/internal/client"
	"github.com/hieuha/lazywp/internal/downloader"
	"github.com/hieuha/lazywp/internal/storage"
	"github.com/spf13/cobra"
)

var (
	vulnSlug     string
	vulnList     string
	vulnTop      int
	vulnDownload bool
	vulnSource   string
	vulnCWE      string
	vulnSeverity string
	vulnMonth    int
	vulnYear     int
	vulnDetail   bool
	vulnOutput   string
)

var vulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "Query vulnerability data for plugins or themes",
	Long:  `Fetch known vulnerabilities from WPScan, NVD, or Wordfence.`,
	RunE:  runVuln,
}

func init() {
	vulnCmd.Flags().StringVar(&vulnSlug, "slug", "", "Slug to look up vulnerabilities for")
	vulnCmd.Flags().StringVar(&vulnList, "list", "", "Path to file with slugs (one per line)")
	vulnCmd.Flags().IntVar(&vulnTop, "top", 0, "Show top N most vulnerable items (Wordfence)")
	vulnCmd.Flags().BoolVar(&vulnDownload, "download", false, "Download items listed in results")
	vulnCmd.Flags().StringVar(&vulnSource, "source", "all", "Vulnerability source: wpscan|nvd|wordfence|all")
	vulnCmd.Flags().StringVar(&vulnCWE, "cwe-type", "", "Wordfence CWE filter (e.g. sqli, xss, rce)")
	vulnCmd.Flags().StringVar(&vulnSeverity, "severity", "", "Wordfence CVSS severity: critical|high|medium|low")
	vulnCmd.Flags().IntVar(&vulnMonth, "month", 0, "Wordfence month filter (1-12)")
	vulnCmd.Flags().IntVar(&vulnYear, "year", 0, "Wordfence year filter (e.g. 2024)")
	vulnCmd.Flags().BoolVar(&vulnDetail, "detail", false, "Show detailed CVEs for each plugin in top results")
	vulnCmd.Flags().StringVarP(&vulnOutput, "output", "o", "", "Write results to file (default: stdout)")
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

// vulnFormatter returns a Formatter targeting a file (when --output is set) or
// the default stdout formatter. The caller must call the returned closer.
func vulnFormatter() (outFmtr *Formatter, closer func(), err error) {
	if vulnOutput == "" {
		return fmtr, func() {}, nil
	}
	f, err := os.Create(vulnOutput)
	if err != nil {
		return nil, nil, fmt.Errorf("create output file: %w", err)
	}
	return NewFormatter(outputFmt, f), func() { f.Close() }, nil
}

func runVuln(cmd *cobra.Command, args []string) error {
	if vulnSlug == "" && vulnList == "" && vulnTop == 0 {
		return fmt.Errorf("must provide --slug, --list, or --top")
	}

	ctx := context.Background()

	if vulnList != "" {
		return runVulnBatch(ctx)
	}
	if vulnSlug != "" {
		return runVulnBySlug(ctx)
	}
	return runVulnTop(ctx)
}

func runVulnBySlug(ctx context.Context) error {
	printQueryInfo()
	printCacheSummary("wordfence", "wpscan", "nvd")

	outFmtr, closer, err := vulnFormatter()
	if err != nil {
		return err
	}
	defer closer()

	stop := startSpinner("Fetching vulnerabilities...", outputFmt != "table")
	vulns, warnings := appDeps.VulnAgg.FetchForSlug(ctx, vulnSlug, appDeps.ItemType)
	stop()
	if outputFmt == "table" {
		for _, w := range warnings {
			fmt.Printf("warning: %s\n", w)
		}
	}

	if len(vulns) == 0 {
		if outputFmt == "table" {
			fmt.Printf("No vulnerabilities found for %s\n", vulnSlug)
		} else {
			outFmtr.PrintTyped("vuln", nil, nil, vulns)
		}
		return nil
	}

	if outputFmt == "sarif" {
		var w io.Writer = os.Stdout
		if vulnOutput != "" {
			w = outFmtr.writer
		}
		return writeVulnSARIF(w, vulnSlug, vulns)
	}

	headers := []string{"CVE", "CVSS", "Type", "Title", "Affected", "Min Affected", "Max Affected", "Source", "Fixed In"}
	rows := make([][]string, len(vulns))
	for i, v := range vulns {
		rows[i] = []string{
			v.CVE,
			strconv.FormatFloat(v.CVSS, 'f', 1, 64),
			v.Type,
			vulnTitle(v.Title),
			v.AffectedVersions,
			v.MinAffectedVersion,
			v.MaxAffectedVersion,
			v.Source,
			v.FixedIn,
		}
	}
	outFmtr.PrintTyped("vuln", headers, rows, vulns)

	if vulnDownload {
		ctx2 := context.Background()
		versions := uniqueMaxAffectedVersions(vulns)
		if len(versions) == 0 {
			fmt.Println("\nNo affected versions to download.")
		} else {
			jobs := make([]downloader.DownloadJob, len(versions))
			for i, ver := range versions {
				jobs[i] = downloader.DownloadJob{Slug: vulnSlug, Version: ver, ItemType: appDeps.ItemType, Force: forceDown}
			}
			result := downloadWithProgress(ctx2, jobs)
			printBatchResult(result)
		}
	}
	return nil
}

func runVulnTop(ctx context.Context) error {
	printQueryInfo()
	printCacheSummary("wordfence")

	outFmtr, closer, err := vulnFormatter()
	if err != nil {
		return err
	}
	defer closer()

	filters := client.WordfenceFilters{
		CWEType:    vulnCWE,
		CVSSRating: vulnSeverity,
		Month:      vulnMonth,
		Year:       vulnYear,
	}

	stop := startSpinner("Fetching vulnerabilities...", outputFmt != "table")
	items, err := appDeps.WFClient.FetchVulnPlugins(ctx, filters, vulnTop)
	stop()
	if err != nil {
		return fmt.Errorf("fetch vuln plugins: %w", err)
	}
	if len(items) == 0 {
		if outputFmt == "table" {
			fmt.Println("No vulnerable items found.")
		} else {
			outFmtr.PrintTyped("vuln", nil, nil, items)
		}
		return nil
	}

	// When --detail is used with structured formats, flatten to one row per CVE.
	if vulnDetail && outputFmt != "table" {
		flat := flattenVulnItems(items)
		if outputFmt == "json" {
			outFmtr.TypedJSON("vuln", flat)
		} else {
			headers, rows := flattenVulnRows(flat)
			outFmtr.CSV(headers, rows)
		}
	} else {
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
		outFmtr.PrintTyped("vuln", headers, rows, items)

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
					fmt.Printf("  %-18s  CVSS:%-4s  %-8s  %s  (affected min: %s, max: %s, fixed: %s)\n",
						cve,
						strconv.FormatFloat(v.CVSS, 'f', 1, 64),
						v.Type,
						vulnTitle(v.Title),
						v.MinAffectedVersion,
						v.MaxAffectedVersion,
						fixed,
					)
				}
				fmt.Println()
			}
		}
	}

	if vulnDownload {
		var jobs []downloader.DownloadJob
		for _, it := range items {
			for _, ver := range uniqueMaxAffectedVersions(it.Vulns) {
				jobs = append(jobs, downloader.DownloadJob{Slug: it.Slug, Version: ver, ItemType: appDeps.ItemType, Force: forceDown})
			}
		}
		if len(jobs) == 0 {
			fmt.Println("\nNo affected versions to download.")
		} else {
			result := downloadWithProgress(ctx, jobs)
			printBatchResult(result)
		}
	}
	return nil
}

// runVulnBatch checks vulnerabilities for multiple slugs from a file.
func runVulnBatch(ctx context.Context) error {
	slugs, err := readSlugListFile(vulnList)
	if err != nil {
		return err
	}
	if len(slugs) == 0 {
		return fmt.Errorf("no slugs found in %s", vulnList)
	}

	outFmtr, closer, err := vulnFormatter()
	if err != nil {
		return err
	}
	defer closer()

	if !quiet && outputFmt == "table" {
		fmt.Printf("Checking vulnerabilities for %d slugs...\n\n", len(slugs))
	}
	printCacheSummary("wordfence", "wpscan", "nvd")

	type slugResult struct {
		Slug  string              `json:"slug"`
		Vulns []storage.Vulnerability `json:"vulns"`
	}
	var allResults []slugResult
	var downloadSlugs []string

	for _, slug := range slugs {
		vulns, warnings := appDeps.VulnAgg.FetchForSlug(ctx, slug, appDeps.ItemType)
		if outputFmt == "table" {
			for _, w := range warnings {
				fmt.Printf("warning [%s]: %s\n", slug, w)
			}
		}

		allResults = append(allResults, slugResult{Slug: slug, Vulns: vulns})

		if outputFmt == "table" {
			if len(vulns) == 0 {
				fmt.Printf("%s%s%s: no vulnerabilities found\n", ansiBoldGreen, slug, ansiReset)
			} else {
				fmt.Printf("%s%s%s: %d vulnerabilities\n", ansiBoldRed, slug, ansiReset, len(vulns))
				for j, v := range vulns {
					cve := v.CVE
					if cve == "" {
						cve = "N/A"
					}
					fixed := v.FixedIn
					if fixed == "" {
						fixed = "unfixed"
					}
					fmt.Printf("  %d. %-18s  CVSS:%s  %s  (affected min: %s, max: %s, fixed: %s)\n",
						j+1, cve, colorCVSS(v.CVSS), vulnTitle(v.Title), v.MinAffectedVersion, v.MaxAffectedVersion, fixed)
				}
			}
			fmt.Println()
		}

		if vulnDownload && len(vulns) > 0 {
			downloadSlugs = append(downloadSlugs, slug)
		}
	}

	// JSON/CSV output
	if outputFmt != "table" {
		outFmtr.TypedJSON("vuln", allResults)
	}

	// Summary
	vulnCount := 0
	affectedCount := 0
	for _, r := range allResults {
		if len(r.Vulns) > 0 {
			affectedCount++
			vulnCount += len(r.Vulns)
		}
	}
	if outputFmt == "table" {
		fmt.Printf("Summary: %d/%d slugs vulnerable, %d total CVEs\n",
			affectedCount, len(slugs), vulnCount)
	}

	if vulnDownload && len(downloadSlugs) > 0 {
		// Build slug→vulns map for affected version lookup
		vulnMap := make(map[string][]storage.Vulnerability)
		for _, r := range allResults {
			if len(r.Vulns) > 0 {
				vulnMap[r.Slug] = r.Vulns
			}
		}
		var jobs []downloader.DownloadJob
		for _, s := range downloadSlugs {
			for _, ver := range uniqueMaxAffectedVersions(vulnMap[s]) {
				jobs = append(jobs, downloader.DownloadJob{Slug: s, Version: ver, ItemType: appDeps.ItemType, Force: forceDown})
			}
		}
		result := downloadWithProgress(ctx, jobs)
		printBatchResult(result)
	}
	return nil
}

// flatVuln is a single CVE row with the parent plugin slug attached.
type flatVuln struct {
	Slug               string  `json:"slug"`
	CVE                string  `json:"cve"`
	CVSS               float64 `json:"cvss"`
	Type               string  `json:"type"`
	Title              string  `json:"title"`
	AffectedVersions   string  `json:"affected_versions"`
	MinAffectedVersion string  `json:"min_affected_version,omitempty"`
	MaxAffectedVersion string  `json:"max_affected_version,omitempty"`
	FixedIn            string  `json:"fixed_in"`
	Source             string  `json:"source"`
}

// flattenVulnItems expands VulnerableItems into one flatVuln per CVE.
func flattenVulnItems(items []client.VulnerableItem) []flatVuln {
	var out []flatVuln
	for _, it := range items {
		for _, v := range it.Vulns {
			title := v.Title
			if outputFmt == "table" {
				title = vulnTitle(v.Title)
			}
			out = append(out, flatVuln{
				Slug:               it.Slug,
				CVE:                v.CVE,
				CVSS:               v.CVSS,
				Type:               v.Type,
				Title:              title,
				AffectedVersions:   v.AffectedVersions,
				MinAffectedVersion: v.MinAffectedVersion,
				MaxAffectedVersion: v.MaxAffectedVersion,
				FixedIn:            v.FixedIn,
				Source:             v.Source,
			})
		}
	}
	return out
}

// flattenVulnRows converts flatVuln slice into CSV headers and rows.
func flattenVulnRows(flat []flatVuln) ([]string, [][]string) {
	headers := []string{"Slug", "CVE", "CVSS", "Type", "Title", "Affected Versions", "Min Affected", "Max Affected", "Fixed In", "Source"}
	rows := make([][]string, len(flat))
	for i, f := range flat {
		rows[i] = []string{
			f.Slug,
			f.CVE,
			strconv.FormatFloat(f.CVSS, 'f', 1, 64),
			f.Type,
			f.Title,
			f.AffectedVersions,
			f.MinAffectedVersion,
			f.MaxAffectedVersion,
			f.FixedIn,
			f.Source,
		}
	}
	return headers, rows
}

// uniqueMaxAffectedVersions returns deduplicated max affected versions across all vulns,
// skipping empty and wildcard values.
func uniqueMaxAffectedVersions(vulns []storage.Vulnerability) []string {
	seen := make(map[string]struct{})
	var versions []string
	for _, v := range vulns {
		ver := v.MaxAffectedVersion
		if ver == "" || ver == "*" {
			continue
		}
		if _, ok := seen[ver]; !ok {
			seen[ver] = struct{}{}
			versions = append(versions, ver)
		}
	}
	return versions
}

// downloadWithProgress downloads jobs with a progress bar showing current item.
func downloadWithProgress(ctx context.Context, jobs []downloader.DownloadJob) *downloader.BatchResult {
	fmt.Println()
	progress := newScanProgress(len(jobs), "Downloading", outputFmt != "table")
	onDone := func(slug, version string) {
		progress.update(fmt.Sprintf("%s@%s", slug, version))
	}
	result := appDeps.Engine.DownloadBatch(ctx, jobs, onDone)
	progress.finish()
	return result
}

// readSlugListFile reads a file of slugs (one per line, # comments allowed).
func readSlugListFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open list file: %w", err)
	}
	defer f.Close()

	seen := map[string]bool{}
	var slugs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !seen[line] {
			seen[line] = true
			slugs = append(slugs, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read list file: %w", err)
	}
	return slugs, nil
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

