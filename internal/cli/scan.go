package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/hieuha/lazywp/internal/exploit"
	"github.com/hieuha/lazywp/internal/scanner"
	"github.com/hieuha/lazywp/internal/storage"
	"github.com/spf13/cobra"
)

var (
	scanSource       string
	scanNoCache      bool
	scanDetail       bool
	scanOutput       string
	scanCheckExploit bool
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
  lazywp scan ./plugins -t plugin --source wordfence -f json
  lazywp scan ./plugins -t plugin --check-exploit`,
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanSource, "source", "all", "Vulnerability source: wpscan|nvd|wordfence|all")
	scanCmd.Flags().BoolVar(&scanNoCache, "no-cache", false, "Skip cache, force fresh API lookups (results still cached)")
	scanCmd.Flags().BoolVar(&scanDetail, "detail", false, "Show detailed CVE list for vulnerable items")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Write results to file (default: stdout)")
	scanCmd.Flags().BoolVar(&scanCheckExploit, "check-exploit", false, "Check exploit/PoC availability via vulnx")
	rootCmd.AddCommand(scanCmd)
}

// ScanResult holds vulnerability lookup results for a scanned plugin.
type ScanResult struct {
	Plugin       scanner.ScannedPlugin      `json:"plugin"`
	Vulns        []storage.Vulnerability    `json:"vulns,omitempty"`
	ActiveVulns  int                        `json:"active_vulns"`
	MaxCVSS      float64                    `json:"max_cvss"`
	MaxFixedIn   string                     `json:"max_fixed_in,omitempty"`
	IsVulnerable bool                       `json:"is_vulnerable"`
	ExploitData  map[string]exploit.CVEInfo `json:"exploit_data,omitempty"`
}

func runScan(cmd *cobra.Command, args []string) error {
	dir := args[0]
	ctx := context.Background()

	if scanNoCache {
		appDeps.VulnCache.SetDisabled(true)
		defer appDeps.VulnCache.SetDisabled(false)
	}

	// Verify vulnx is installed before scanning if exploit check requested
	if scanCheckExploit {
		if err := exploit.CheckAvailable(); err != nil {
			return err
		}
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

	// Sort plugins: cached first (faster), uncached after
	cached, uncached := partitionByCacheStatus(plugins)
	ordered := append(cached, uncached...)

	results, disabledSources := lookupVulnerabilities(ctx, ordered)

	// Exploit enrichment via vulnx
	var exploitWarning string
	if scanCheckExploit {
		exploitWarning = enrichScanWithExploitData(results)
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

	if outputFmt == "sarif" {
		var w io.Writer = os.Stdout
		if scanOutput != "" {
			w = outFmtr.writer
		}
		return writeScanSARIF(w, results)
	}

	if outputFmt == "csv" {
		headers, rows := flattenScanResults(append(vulnerable, safe...))
		outFmtr.CSV(headers, rows)
		return nil
	}

	if outputFmt == "json" {
		outFmtr.TypedJSON("scan", results)
		return nil
	}

	// Table format (always to stdout)
	printScanTable(vulnerable, safe)
	printScanSummary(dir, len(plugins), len(cached), len(uncached), len(vulnerable), len(safe), disabledSources)

	if scanCheckExploit {
		if exploitWarning != "" {
			fmt.Println(exploitWarning)
		}
		printExploitScanSummary(results)
	}

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

// ANSI color/style codes for terminal output.
const (
	ansiReset     = "\033[0m"
	ansiBold      = "\033[1m"
	ansiRed       = "\033[31m"
	ansiYellow    = "\033[33m"
	ansiGreen     = "\033[32m"
	ansiCyan      = "\033[36m"
	ansiBoldRed   = "\033[1;31m"
	ansiBoldGreen = "\033[1;32m"
)

// colorCVSS returns CVSS score string colored by severity level.
func colorCVSS(score float64) string {
	s := strconv.FormatFloat(score, 'f', 1, 64)
	switch {
	case score >= 9.0:
		return ansiBoldRed + s + ansiReset // critical: bold red
	case score >= 7.0:
		return ansiRed + s + ansiReset // high: red
	case score >= 4.0:
		return ansiYellow + s + ansiReset // medium: yellow
	default:
		return ansiGreen + s + ansiReset // low: green
	}
}

// printScanTable renders vulnerable/safe sections with colors, then detail and summary.
func printScanTable(vulnerable, safe []ScanResult) {
	// Vulnerable section
	if len(vulnerable) > 0 {
		fmt.Printf("%sVULNERABLE (%d):%s\n", ansiBoldRed, len(vulnerable), ansiReset)
		for _, r := range vulnerable {
			cveLabel := "CVEs"
			if r.ActiveVulns == 1 {
				cveLabel = "CVE"
			}
			updateHint := ansiRed + "no fix" + ansiReset
			if r.MaxFixedIn != "" {
				updateHint = "update to " + ansiCyan + r.MaxFixedIn + ansiReset
			}
			fmt.Printf("  %s%s%s@%s%s%s  %s%d%s %s (CVSS %s)%s → %s\n",
				ansiBold, r.Plugin.Slug, ansiReset,
				ansiBold, r.Plugin.Version, ansiReset,
				ansiBold, r.ActiveVulns, ansiReset,
				cveLabel,
				colorCVSS(r.MaxCVSS),
				exploitSummary(r),
				updateHint,
			)
		}
		fmt.Println()
	}

	// Safe section
	if len(safe) > 0 {
		fmt.Printf("%sSAFE (%d):%s\n", ansiBoldGreen, len(safe), ansiReset)
		for _, r := range safe {
			ver := r.Plugin.Version
			if ver == "" {
				ver = "unknown"
			}
			fmt.Printf("  %s@%s  %s0 CVEs%s\n",
				r.Plugin.Slug, ver,
				ansiBoldGreen, ansiReset,
			)
		}
		fmt.Println()
	}

	// Detail: numbered CVE list per vulnerable plugin
	if scanDetail && len(vulnerable) > 0 {
		for _, r := range vulnerable {
			fmt.Printf("--- %s%s%s@%s%s%s (%d CVEs, max CVSS %s) ---\n",
				ansiBold, r.Plugin.Slug, ansiReset,
				ansiBold, r.Plugin.Version, ansiReset,
				r.ActiveVulns, colorCVSS(r.MaxCVSS))
			for i, v := range r.Vulns {
				cve := v.CVE
				if cve == "" {
					cve = "N/A"
				}
				fixed := v.FixedIn
				if fixed == "" {
					fixed = "unfixed"
				}
				affected := v.AffectedVersions
				if affected == "" {
					affected = "all"
				}
				fmt.Printf("  #%-3d %-18s  CVSS:%s  %-8s  %s (affected: %s, min: %s, max: %s, fixed: %s)%s\n",
					i+1,
					cve,
					colorCVSS(v.CVSS),
					v.Type,
					vulnTitle(v.Title),
					affected,
					v.MinAffectedVersion,
					v.MaxAffectedVersion,
					fixed,
					exploitCVELabel(r, v.CVE),
				)
			}
			fmt.Println()
		}
	}
}

// printScanSummary prints scan metadata and summary at the bottom.
func printScanSummary(dir string, total, cached, uncached, vulnCount, safeCount int, disabled map[string]bool) {
	if quiet {
		return
	}
	fmt.Printf("Scanned: %s (%d %ss, %d cached, %d API lookup)\n", dir, total, itemType, cached, uncached)
	for src := range disabled {
		fmt.Printf("[!] %s disabled: API key error\n", src)
	}
	fmt.Printf("Summary: %d scanned, %s%d vulnerable%s, %s%d safe%s\n",
		total,
		ansiBoldRed, vulnCount, ansiReset,
		ansiBoldGreen, safeCount, ansiReset,
	)
}

// flattenScanResults converts scan results to CSV-friendly rows.
// One row per CVE (vulnerable plugins expand to multiple rows).
func flattenScanResults(results []ScanResult) ([]string, [][]string) {
	headers := []string{"slug", "version", "status", "cve_count", "max_cvss", "update_to",
		"cve", "cvss", "type", "title", "min_affected_version", "max_affected_version", "fixed_in", "has_poc", "is_kev", "epss", "has_nuclei"}
	var rows [][]string

	for _, r := range results {
		if len(r.Vulns) == 0 {
			ver := r.Plugin.Version
			if ver == "" {
				ver = "unknown"
			}
			rows = append(rows, []string{
				r.Plugin.Slug, ver, "safe",
				"0", "0.0", "", "", "", "", "", "", "", "",
				"", "", "", "",
			})
			continue
		}

		for _, v := range r.Vulns {
			fixed := v.FixedIn
			if fixed == "" {
				fixed = "unfixed"
			
			}
			hasPOC, isKEV, epss, hasNuclei := "", "", "", ""
			if info, ok := r.ExploitData[v.CVE]; ok {
				hasPOC = strconv.FormatBool(info.HasPOC)
				isKEV = strconv.FormatBool(info.IsKEV)
				epss = strconv.FormatFloat(info.EPSS, 'f', 4, 64)
				hasNuclei = strconv.FormatBool(info.HasNuclei)
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
				v.MinAffectedVersion,
				v.MaxAffectedVersion,
				fixed,
				hasPOC, isKEV, epss, hasNuclei,
			})
		}
	}

	return headers, rows
}
