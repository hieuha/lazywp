package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	convertSlug       string
	convertMinCVSS    float64
	convertMaxCVSS    float64
	convertCVE        string
	convertStatus     string
	convertOutput     string
	convertVulnOnly    bool
	convertSafeOnly    bool
	convertExploitable bool
)

var convertCmd = &cobra.Command{
	Use:   "convert <json-file>",
	Short: "Convert scan/vuln JSON to other formats with filtering",
	Long: `Read a JSON file from lazywp scan or lazywp vuln and convert it
to table, CSV, or JSON with optional filters.

Auto-detects the input format (scan results, vuln flat CVEs, or vuln top items).

Examples:
  lazywp convert scan.json -f csv -o report.csv
  lazywp convert scan.json --slug elementor --detail
  lazywp convert scan.json --vuln-only --min-cvss 7.0
  lazywp convert vuln.json -f csv --slug contact-form
  lazywp convert vuln.json --min-cvss 9.0 -f csv -o critical.csv`,
	Args: cobra.ExactArgs(1),
	RunE: runConvert,
}

func init() {
	convertCmd.Flags().StringVar(&convertSlug, "slug", "", "Filter by plugin slug (substring match)")
	convertCmd.Flags().Float64Var(&convertMinCVSS, "min-cvss", 0, "Filter by minimum CVSS score")
	convertCmd.Flags().Float64Var(&convertMaxCVSS, "max-cvss", 0, "Filter by maximum CVSS score")
	convertCmd.Flags().StringVar(&convertCVE, "cve", "", "Filter by CVE ID (substring match)")
	convertCmd.Flags().StringVar(&convertStatus, "status", "", "Filter by status: vulnerable|safe")
	convertCmd.Flags().BoolVar(&convertVulnOnly, "vuln-only", false, "Show only vulnerable plugins")
	convertCmd.Flags().BoolVar(&convertSafeOnly, "safe-only", false, "Show only safe plugins")
	convertCmd.Flags().BoolVar(&convertExploitable, "exploitable", false, "Show only plugins with exploitable CVEs (has PoC/KEV/Nuclei)")
	convertCmd.Flags().StringVarP(&convertOutput, "output", "o", "", "Write output to file (default: stdout)")
	convertCmd.Flags().BoolVar(&scanDetail, "detail", false, "Show detailed CVE list (table format)")
	rootCmd.AddCommand(convertCmd)
}

// skipDeps: convert doesn't need API keys or network
func init() {
	skipDepsCommands["convert"] = true
}

func runConvert(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	// Build output formatter
	outFmtr := fmtr
	if convertOutput != "" {
		f, err := os.Create(convertOutput)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		outFmtr = NewFormatter(outputFmt, f)
	}

	// Auto-detect format: try scan results first, then vuln flat CVEs.
	var scanResults []ScanResult
	if err := json.Unmarshal(data, &scanResults); err == nil && len(scanResults) > 0 && scanResults[0].Plugin.Slug != "" {
		return convertScanJSON(outFmtr, scanResults)
	}

	var vulnResults []flatVuln
	if err := json.Unmarshal(data, &vulnResults); err == nil && len(vulnResults) > 0 && vulnResults[0].CVE != "" {
		return convertVulnJSON(outFmtr, vulnResults)
	}

	return fmt.Errorf("unrecognized JSON format (expected scan or vuln output)")
}

// convertScanJSON handles JSON from `lazywp scan`.
func convertScanJSON(outFmtr *Formatter, results []ScanResult) error {
	filtered := filterScanResults(results)

	if len(filtered) == 0 {
		if outputFmt == "table" {
			fmt.Println("No results match the given filters.")
		} else {
			outFmtr.Print(nil, nil, []ScanResult{})
		}
		return nil
	}

	var vulnerable, safe []ScanResult
	for _, r := range filtered {
		if r.IsVulnerable {
			vulnerable = append(vulnerable, r)
		} else {
			safe = append(safe, r)
		}
	}

	switch outputFmt {
	case "json":
		outFmtr.JSON(filtered)
	case "csv":
		headers, rows := flattenScanResults(append(vulnerable, safe...))
		outFmtr.CSV(headers, rows)
	default:
		printScanTable(vulnerable, safe)
		fmt.Printf("Summary: %d scanned, %d vulnerable, %d safe\n", len(filtered), len(vulnerable), len(safe))
	}
	return nil
}

// convertVulnJSON handles JSON from `lazywp vuln --detail`.
func convertVulnJSON(outFmtr *Formatter, results []flatVuln) error {
	filtered := filterVulnResults(results)

	if len(filtered) == 0 {
		if outputFmt == "table" {
			fmt.Println("No results match the given filters.")
		} else {
			outFmtr.JSON([]flatVuln{})
		}
		return nil
	}

	switch outputFmt {
	case "json":
		outFmtr.JSON(filtered)
	case "csv":
		headers, rows := flattenVulnRows(filtered)
		outFmtr.CSV(headers, rows)
	default:
		headers, rows := flattenVulnRows(filtered)
		outFmtr.Table(headers, rows)
		fmt.Printf("\nSummary: %d CVEs across %d plugins\n", len(filtered), countUniqueVulnSlugs(filtered))
	}
	return nil
}

// filterScanResults applies all active filters to scan results.
func filterScanResults(results []ScanResult) []ScanResult {
	filtered := make([]ScanResult, 0, len(results))

	for _, r := range results {
		// Filter by slug (substring)
		if convertSlug != "" && !strings.Contains(strings.ToLower(r.Plugin.Slug), strings.ToLower(convertSlug)) {
			continue
		}

		// Filter by status
		if convertVulnOnly || convertStatus == "vulnerable" {
			if !r.IsVulnerable {
				continue
			}
		}
		if convertSafeOnly || convertStatus == "safe" {
			if r.IsVulnerable {
				continue
			}
		}

		// Filter by min CVSS
		if convertMinCVSS > 0 && r.MaxCVSS < convertMinCVSS {
			continue
		}

		// Filter by max CVSS
		if convertMaxCVSS > 0 && r.MaxCVSS > convertMaxCVSS {
			continue
		}

		// Filter by exploitable (has PoC, KEV, or Nuclei template)
		if convertExploitable {
			hasExploit := false
			for _, info := range r.ExploitData {
				if info.HasPOC || info.IsKEV || info.HasNuclei {
					hasExploit = true
					break
				}
			}
			if !hasExploit {
				continue
			}
		}

		// Filter by CVE ID (substring match in any vuln)
		if convertCVE != "" {
			found := false
			for _, v := range r.Vulns {
				if strings.Contains(strings.ToUpper(v.CVE), strings.ToUpper(convertCVE)) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		filtered = append(filtered, r)
	}

	return filtered
}

// filterVulnResults applies slug/CVSS/CVE filters to flat vuln results.
func filterVulnResults(results []flatVuln) []flatVuln {
	filtered := make([]flatVuln, 0, len(results))
	for _, r := range results {
		if convertSlug != "" && !strings.Contains(strings.ToLower(r.Slug), strings.ToLower(convertSlug)) {
			continue
		}
		if convertMinCVSS > 0 && r.CVSS < convertMinCVSS {
			continue
		}
		if convertMaxCVSS > 0 && r.CVSS > convertMaxCVSS {
			continue
		}
		if convertCVE != "" && !strings.Contains(strings.ToUpper(r.CVE), strings.ToUpper(convertCVE)) {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}

// countUniqueVulnSlugs returns the number of distinct slugs in flat vuln results.
func countUniqueVulnSlugs(results []flatVuln) int {
	seen := make(map[string]bool)
	for _, r := range results {
		seen[r.Slug] = true
	}
	return len(seen)
}
