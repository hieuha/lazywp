package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hieuha/lazywp/internal/scanner"
	"github.com/hieuha/lazywp/internal/storage"
)

// SARIF v2.1.0 minimal types for GitHub Code Scanning integration.
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// cvssToSARIFLevel maps CVSS score to SARIF level.
func cvssToSARIFLevel(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "error"
	case cvss >= 7.0:
		return "error"
	case cvss >= 4.0:
		return "warning"
	default:
		return "note"
	}
}

// writeScanSARIF writes scan results in SARIF v2.1.0 format.
func writeScanSARIF(w io.Writer, results []ScanResult) error {
	ruleMap := map[string]sarifRule{}
	var sarifResults []sarifResult

	for _, r := range results {
		for _, v := range r.Vulns {
			ruleID := v.CVE
			if ruleID == "" {
				continue
			}

			// Add rule if not seen
			if _, exists := ruleMap[ruleID]; !exists {
				ruleMap[ruleID] = sarifRule{
					ID:               ruleID,
					ShortDescription: sarifMessage{Text: v.Title},
					Properties: sarifRuleProperties{
						SecuritySeverity: fmt.Sprintf("%.1f", v.CVSS),
						Tags:             []string{"security", "wordpress", v.Source},
					},
				}
			}

			msg := fmt.Sprintf("%s in %s (version %s). CVSS: %.1f. Fixed in: %s",
				v.Title, r.Plugin.Slug, r.Plugin.Version, v.CVSS, fixedLabel(v.FixedIn))

			sr := sarifResult{
				RuleID:  ruleID,
				Level:   cvssToSARIFLevel(v.CVSS),
				Message: sarifMessage{Text: msg},
			}
			if r.Plugin.Path != "" {
				sr.Locations = []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: r.Plugin.Path},
					},
				}}
			}
			sarifResults = append(sarifResults, sr)
		}
	}

	rules := make([]sarifRule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		rules = append(rules, rule)
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:    "lazywp",
					Version: Version,
					Rules:   rules,
				},
			},
			Results: sarifResults,
		}},
	}

	out, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", out)
	return err
}

// writeVulnSARIF writes vulnerability results for a single slug in SARIF format.
func writeVulnSARIF(w io.Writer, slug string, vulns []storage.Vulnerability) error {
	results := []ScanResult{{
		Plugin: scanner.ScannedPlugin{Slug: slug},
		Vulns:  vulns,
	}}
	return writeScanSARIF(w, results)
}

func fixedLabel(s string) string {
	if s == "" {
		return "unfixed"
	}
	return s
}
