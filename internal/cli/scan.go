package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/hieuha/lazywp/internal/scanner"
	"github.com/hieuha/lazywp/internal/storage"
	"github.com/spf13/cobra"
)

var (
	scanSource  string
	scanNoCache bool
	scanDetail  bool
	scanOutput  string
)

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Scan local plugins/themes directory for vulnerabilities",
	Long: `Scan a local WordPress plugins or themes directory, detect slug and version,
then cross-reference against vulnerability databases.

Use --type (-t) to specify whether scanning plugins or themes (required because
detection strategies differ: plugins use readme.txt/PHP headers, themes use style.css).

Examples:
  lazywp scan /path/to/wp-content/plugins --type plugin
  lazywp scan /path/to/wp-content/themes --type theme
  lazywp scan ./plugins -t plugin --source wordfence -f json`,
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanSource, "source", "all", "Vulnerability source: wpscan|nvd|wordfence|all")
	scanCmd.Flags().BoolVar(&scanNoCache, "no-cache", false, "Skip cache, force fresh API lookups (results still cached)")
	scanCmd.Flags().BoolVar(&scanDetail, "detail", false, "Show detailed CVE list for vulnerable items")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Write results to file (default: stdout)")
	rootCmd.AddCommand(scanCmd)
}

// ScanResult holds vulnerability lookup results for a scanned plugin.
type ScanResult struct {
	Plugin       scanner.ScannedPlugin  `json:"plugin"`
	Vulns        []storage.Vulnerability `json:"vulns,omitempty"`
	ActiveVulns  int                     `json:"active_vulns"`
	MaxCVSS      float64                 `json:"max_cvss"`
	MaxFixedIn   string                  `json:"max_fixed_in,omitempty"`
	IsVulnerable bool                    `json:"is_vulnerable"`
}

func runScan(cmd *cobra.Command, args []string) error {
	dir := args[0]
	ctx := context.Background()

	if scanNoCache {
		appDeps.VulnCache.SetDisabled(true)
		defer appDeps.VulnCache.SetDisabled(false)
	}

	plugins, err := scanner.ScanDirectory(dir, appDeps.ItemType)
	if err != nil {
		return fmt.Errorf("scan directory: %w", err)
	}

	if len(plugins) == 0 {
		if outputFmt == "table" {
			fmt.Printf("No %ss found in %s\n", itemType, dir)
		} else {
			fmtr.Print(nil, nil, []ScanResult{})
		}
		return nil
	}

	if !quiet && outputFmt == "table" {
		fmt.Printf("Scanning: %s (%d %ss found)\n\n", dir, len(plugins), itemType)
	}

	// Sort plugins: cached first (faster), uncached after
	cached, uncached := partitionByCacheStatus(plugins)
	ordered := append(cached, uncached...)
	if !quiet && outputFmt == "table" {
		fmt.Printf("  %d %ss found in cache, %d need API lookup\n\n", len(cached), itemType, len(uncached))
	}

	results, disabledSources := lookupVulnerabilities(ctx, ordered)

	// Print disabled sources after progress bar completes
	if !quiet && outputFmt == "table" {
		for src := range disabledSources {
			fmt.Printf("[!] %s disabled: API key error\n", src)
		}
	}

	// Partition into vulnerable and safe
	var vulnerable, safe []ScanResult
	for _, r := range results {
		if r.IsVulnerable {
			vulnerable = append(vulnerable, r)
		} else {
			safe = append(safe, r)
		}
	}

	// Sort vulnerable by max CVSS descending
	sort.Slice(vulnerable, func(i, j int) bool {
		return vulnerable[i].MaxCVSS > vulnerable[j].MaxCVSS
	})

	// Build output formatter (file or stdout)
	outFmtr := fmtr
	if scanOutput != "" {
		f, err := os.Create(scanOutput)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		outFmtr = NewFormatter(outputFmt, f)
	}

	if outputFmt == "csv" {
		headers, rows := flattenScanResults(append(vulnerable, safe...))
		outFmtr.CSV(headers, rows)
		return nil
	}

	if outputFmt == "json" {
		outFmtr.JSON(results)
		return nil
	}

	// Table format (always to stdout)
	printScanTable(vulnerable, safe)
	printScanSummary(len(plugins), len(vulnerable), len(safe))

	return nil
}

// lookupVulnerabilities queries vuln databases for each scanned plugin.
// Auto-disables sources that return API key / auth errors to avoid repeated failures.
func lookupVulnerabilities(ctx context.Context, plugins []scanner.ScannedPlugin) ([]ScanResult, map[string]bool) {
	results := make([]ScanResult, 0, len(plugins))
	disabledSources := map[string]bool{}

	progress := newScanProgress(len(plugins), "Checking vulnerabilities", quiet || outputFmt != "table")
	defer progress.finish()

	for _, p := range plugins {
		progress.update(p.Slug)
		r := ScanResult{Plugin: p}

		if p.Version == "" {
			results = append(results, r)
			continue
		}

		vulns, warnings := appDeps.VulnAgg.FetchForSlugExcluding(ctx, p.Slug, appDeps.ItemType, disabledSources)

		// Check warnings for API key errors and auto-disable those sources
		for _, w := range warnings {
			sourceName := extractSourceName(w)
			if sourceName != "" && isAPIKeyError(w) {
				if !disabledSources[sourceName] {
					disabledSources[sourceName] = true
				}
			}
		}

		// Filter vulns that affect the current version
		for _, v := range vulns {
			if scanner.IsVulnerable(p.Version, v.FixedIn) {
				r.Vulns = append(r.Vulns, v)
				r.ActiveVulns++
				if v.CVSS > r.MaxCVSS {
					r.MaxCVSS = v.CVSS
				}
				if scanner.CompareVersions(v.FixedIn, r.MaxFixedIn) > 0 {
					r.MaxFixedIn = v.FixedIn
				}
			}
		}

		r.IsVulnerable = r.ActiveVulns > 0
		results = append(results, r)
	}

	return results, disabledSources
}

// partitionByCacheStatus splits plugins into cached (have data in any vuln cache) and uncached.
func partitionByCacheStatus(plugins []scanner.ScannedPlugin) (cached, uncached []scanner.ScannedPlugin) {
	// Cache key patterns per source (must match client implementations)
	sources := map[string]func(slug string) string{
		"wpscan":    func(slug string) string { return slug + ":" + itemType },
		"nvd":       func(slug string) string { return slug + ":" + itemType },
		"wordfence": func(slug string) string { return "slug:" + slug + ":" + itemType },
	}

	for _, p := range plugins {
		hit := false
		for src, keyFn := range sources {
			if info := appDeps.VulnCache.Info(src, keyFn(p.Slug)); info != nil && !info.Expired {
				hit = true
				break
			}
		}
		if hit {
			cached = append(cached, p)
		} else {
			uncached = append(uncached, p)
		}
	}
	return
}

// extractSourceName gets the source name from a warning string like "wpscan: some error".
func extractSourceName(warning string) string {
	if idx := strings.Index(warning, ":"); idx > 0 {
		return warning[:idx]
	}
	return ""
}

// isAPIKeyError checks if a warning indicates an API key / auth problem.
func isAPIKeyError(warning string) bool {
	lower := strings.ToLower(warning)
	return strings.Contains(lower, "no api key") ||
		strings.Contains(lower, "no api keys configured") ||
		strings.Contains(lower, "http 401") ||
		strings.Contains(lower, "http 403")
}

// printScanTable renders the vulnerable/safe sections in table format.
func printScanTable(vulnerable, safe []ScanResult) {
	if len(vulnerable) > 0 {
		fmt.Printf("VULNERABLE (%d):\n", len(vulnerable))
		for _, r := range vulnerable {
			cveLabel := "CVEs"
			if r.ActiveVulns == 1 {
				cveLabel = "CVE"
			}
			updateHint := ""
			if r.MaxFixedIn != "" {
				updateHint = fmt.Sprintf(" → update to %s", r.MaxFixedIn)
			} else {
				updateHint = " → no fix available"
			}
			fmt.Printf("  %-30s  %d %s (max CVSS %.1f)%s\n",
				r.Plugin.Slug+"@"+r.Plugin.Version,
				r.ActiveVulns, cveLabel,
				r.MaxCVSS, updateHint,
			)

			// Show detailed CVE list when --detail is used
			if scanDetail {
				for _, v := range r.Vulns {
					cve := v.CVE
					if cve == "" {
						cve = "N/A"
					}
					fixed := v.FixedIn
					if fixed == "" {
						fixed = "unfixed"
					}
					fmt.Printf("    %-18s  CVSS:%-4s  %-8s  %s (fixed: %s)\n",
						cve,
						strconv.FormatFloat(v.CVSS, 'f', 1, 64),
						v.Type,
						vulnTitle(v.Title),
						fixed,
					)
				}
				fmt.Println()
			}
		}
		if !scanDetail {
			fmt.Println()
		}
	}

	if len(safe) > 0 {
		fmt.Printf("SAFE (%d):\n", len(safe))
		for _, r := range safe {
			ver := r.Plugin.Version
			if ver == "" {
				ver = "unknown"
			}
			fmt.Printf("  %-30s  0 CVEs\n", r.Plugin.Slug+"@"+ver)
		}
		fmt.Println()
	}
}

// printScanSummary prints the final summary line.
func printScanSummary(total, vulnCount, safeCount int) {
	if quiet {
		return
	}
	fmt.Printf("Summary: %s scanned, %s vulnerable, %s safe\n",
		strconv.Itoa(total),
		strconv.Itoa(vulnCount),
		strconv.Itoa(safeCount),
	)
}

// flattenScanResults converts scan results to CSV-friendly rows.
// One row per CVE (vulnerable plugins expand to multiple rows).
func flattenScanResults(results []ScanResult) ([]string, [][]string) {
	headers := []string{"slug", "version", "status", "cve_count", "max_cvss", "update_to", "cve", "cvss", "type", "title", "fixed_in"}
	var rows [][]string

	for _, r := range results {
		if len(r.Vulns) == 0 {
			ver := r.Plugin.Version
			if ver == "" {
				ver = "unknown"
			}
			rows = append(rows, []string{
				r.Plugin.Slug, ver, "safe",
				"0", "0.0", "", "", "", "", "", "",
			})
			continue
		}

		for _, v := range r.Vulns {
			fixed := v.FixedIn
			if fixed == "" {
				fixed = "unfixed"
			}
			rows = append(rows, []string{
				r.Plugin.Slug,
				r.Plugin.Version,
				"vulnerable",
				strconv.Itoa(r.ActiveVulns),
				strconv.FormatFloat(r.MaxCVSS, 'f', 1, 64),
				r.MaxFixedIn,
				v.CVE,
				strconv.FormatFloat(v.CVSS, 'f', 1, 64),
				v.Type,
				v.Title,
				fixed,
			})
		}
	}

	return headers, rows
}
