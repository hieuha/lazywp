package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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
	Short: "Convert scan JSON to other formats with filtering",
	Long: `Read a scan result JSON file (from lazywp scan -f json) and convert it
to table, CSV, or JSON with optional filters.

Examples:
  lazywp convert scan.json -f table --detail
  lazywp convert scan.json -f csv -o report.csv
  lazywp convert scan.json --slug elementor --detail
  lazywp convert scan.json --vuln-only --min-cvss 7.0
  lazywp convert scan.json --cve CVE-2024-1234
  lazywp convert scan.json --status vulnerable -f csv -o critical.csv`,
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

	var results []ScanResult
	if err := json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}

	// Apply filters
	filtered := filterScanResults(results)

	if len(filtered) == 0 {
		if outputFmt == "table" {
			fmt.Println("No results match the given filters.")
		} else {
			fmtr.Print(nil, nil, []ScanResult{})
		}
		return nil
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

	// Partition for table display
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

// init registers ScanResult's ScannedPlugin type for JSON unmarshalling.
// flattenScanResults is reused from scan.go.
// colorCVSS, printScanTable, printScanSummary are reused from scan.go.

// convertSummary prints a summary line for convert results.
func convertSummary(total, vulnCount int) string {
	return fmt.Sprintf("%s results: %s vulnerable, %s safe",
		strconv.Itoa(total),
		strconv.Itoa(vulnCount),
		strconv.Itoa(total-vulnCount),
	)
}
