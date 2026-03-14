package cli

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
)

var reportOutput string

var reportCmd = &cobra.Command{
	Use:   "report <scan.json>",
	Short: "Generate HTML vulnerability report from scan results",
	Long: `Read a scan result JSON file and generate a self-contained HTML report
with severity charts, executive summary, and detailed findings.

Examples:
  lazywp report scan.json
  lazywp report scan.json -o report.html`,
	Args: cobra.ExactArgs(1),
	RunE: runReport,
}

func init() {
	reportCmd.Flags().StringVarP(&reportOutput, "output", "o", "", "Output file (default: report-<timestamp>.html)")
	rootCmd.AddCommand(reportCmd)
}

func init() {
	skipDepsCommands["report"] = true
}

// reportData holds processed data for the HTML template.
type reportData struct {
	Version     string
	Generated   string
	SourceFile  string
	Total       int
	VulnCount   int
	SafeCount   int
	TotalCVEs   int
	Critical    int
	High        int
	Medium      int
	Low         int
	HasExploit  bool
	POCCount    int
	KEVCount    int
	NucleiCount int
	Results     []ScanResult
}

func runReport(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var results []ScanResult
	if err := json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}

	// Sort: vulnerable first (by max CVSS desc), then safe
	sort.Slice(results, func(i, j int) bool {
		if results[i].IsVulnerable != results[j].IsVulnerable {
			return results[i].IsVulnerable
		}
		return results[i].MaxCVSS > results[j].MaxCVSS
	})

	rd := buildReportData(args[0], results)

	outPath := reportOutput
	if outPath == "" {
		outPath = fmt.Sprintf("report-%s.html", time.Now().Format("20060102-150405"))
	}

	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer f.Close()

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityClass": severityClass,
		"fixedLabel":    fixedLabel,
		"pct":           func(n, total int) int { if total == 0 { return 0 }; return n * 100 / total },
	}).Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	if err := tmpl.Execute(f, rd); err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	fmt.Printf("Report generated: %s\n", outPath)
	return nil
}

func buildReportData(source string, results []ScanResult) reportData {
	rd := reportData{
		Version:    Version,
		Generated:  time.Now().Format("2006-01-02 15:04:05"),
		SourceFile: source,
		Total:      len(results),
		Results:    results,
	}

	for _, r := range results {
		if r.IsVulnerable {
			rd.VulnCount++
		} else {
			rd.SafeCount++
		}
		for _, v := range r.Vulns {
			rd.TotalCVEs++
			switch {
			case v.CVSS >= 9.0:
				rd.Critical++
			case v.CVSS >= 7.0:
				rd.High++
			case v.CVSS >= 4.0:
				rd.Medium++
			default:
				rd.Low++
			}
		}
		for _, info := range r.ExploitData {
			if info.HasPOC {
				rd.POCCount++
			}
			if info.IsKEV {
				rd.KEVCount++
			}
			if info.HasNuclei {
				rd.NucleiCount++
			}
		}
	}
	rd.HasExploit = rd.POCCount > 0 || rd.KEVCount > 0 || rd.NucleiCount > 0
	return rd
}

func severityClass(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "critical"
	case cvss >= 7.0:
		return "high"
	case cvss >= 4.0:
		return "medium"
	default:
		return "low"
	}
}
