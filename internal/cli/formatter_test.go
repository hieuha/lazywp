package cli

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
)

func TestTableOutput(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("table", &buf)

	headers := []string{"Name", "Version", "Status"}
	rows := [][]string{
		{"akismet", "5.0.1", "active"},
		{"hello-dolly", "1.7.2", "inactive"},
	}

	formatter.Table(headers, rows)

	output := buf.String()

	// Verify headers present
	if !strings.Contains(output, "Name") {
		t.Error("Table should contain 'Name' header")
	}

	if !strings.Contains(output, "Version") {
		t.Error("Table should contain 'Version' header")
	}

	if !strings.Contains(output, "Status") {
		t.Error("Table should contain 'Status' header")
	}

	// Verify data present
	if !strings.Contains(output, "akismet") {
		t.Error("Table should contain 'akismet' data")
	}

	if !strings.Contains(output, "5.0.1") {
		t.Error("Table should contain '5.0.1' data")
	}

	// Verify separator present (dashes)
	if !strings.Contains(output, "----") {
		t.Error("Table should contain separator")
	}
}

func TestTableOutputEmpty(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("table", &buf)

	headers := []string{"Name", "Version"}
	rows := [][]string{}

	formatter.Table(headers, rows)

	output := buf.String()

	// Should still have headers
	if !strings.Contains(output, "Name") {
		t.Error("Table should contain headers even with no rows")
	}
}

func TestJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("json", &buf)

	data := map[string]interface{}{
		"name":    "akismet",
		"version": "5.0.1",
		"vulns":   3,
	}

	formatter.JSON(data)

	output := buf.String()

	// Should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Verify fields
	if parsed["name"] != "akismet" {
		t.Errorf("JSON name: got %v, want akismet", parsed["name"])
	}

	if parsed["version"] != "5.0.1" {
		t.Errorf("JSON version: got %v, want 5.0.1", parsed["version"])
	}

	if parsed["vulns"] != float64(3) {
		t.Errorf("JSON vulns: got %v, want 3", parsed["vulns"])
	}
}

func TestJSONOutputArray(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("json", &buf)

	data := []map[string]interface{}{
		{"id": "1", "name": "item1"},
		{"id": "2", "name": "item2"},
	}

	formatter.JSON(data)

	output := buf.String()

	// Should be valid JSON array
	var parsed []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if len(parsed) != 2 {
		t.Errorf("JSON array length: got %d, want 2", len(parsed))
	}
}

func TestJSONOutputError(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("json", &buf)

	// Use a channel which is not JSON serializable
	data := make(chan struct{})

	formatter.JSON(data)

	output := buf.String()

	// Should have error in JSON response
	if !strings.Contains(output, "error") {
		t.Error("JSON should contain error field for unmarshalable data")
	}
}

func TestCSVOutput(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("csv", &buf)

	headers := []string{"Name", "Version", "Status"}
	rows := [][]string{
		{"akismet", "5.0.1", "active"},
		{"hello-dolly", "1.7.2", "inactive"},
	}

	formatter.CSV(headers, rows)

	output := buf.String()

	// Parse CSV to verify format
	reader := csv.NewReader(strings.NewReader(output))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV output: %v", err)
	}

	if len(records) != 3 {
		t.Errorf("CSV should have 3 rows (header + 2 data), got %d", len(records))
	}

	// Verify header row
	if records[0][0] != "Name" {
		t.Errorf("First header: got %q, want Name", records[0][0])
	}

	// Verify first data row
	if records[1][0] != "akismet" {
		t.Errorf("First row name: got %q, want akismet", records[1][0])
	}

	if records[1][1] != "5.0.1" {
		t.Errorf("First row version: got %q, want 5.0.1", records[1][1])
	}
}

func TestCSVOutputEmpty(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("csv", &buf)

	headers := []string{"Name", "Version"}
	rows := [][]string{}

	formatter.CSV(headers, rows)

	output := buf.String()

	reader := csv.NewReader(strings.NewReader(output))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	// Should have header row only
	if len(records) != 1 {
		t.Errorf("CSV with no rows should have 1 row (header), got %d", len(records))
	}
}

func TestCSVOutputSpecialChars(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("csv", &buf)

	headers := []string{"Name", "Description"}
	rows := [][]string{
		{"plugin,name", "has,commas"},
		{"plugin\"quote", "has\"quotes"},
		{"plugin\nline", "has\nnewline"},
	}

	formatter.CSV(headers, rows)

	output := buf.String()

	reader := csv.NewReader(strings.NewReader(output))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	if len(records) != 4 {
		t.Errorf("Expected 4 records (header + 3 rows), got %d", len(records))
	}

	// Verify special characters preserved
	if records[1][0] != "plugin,name" {
		t.Errorf("Comma in field: got %q, want plugin,name", records[1][0])
	}
}

func TestPrintDispatchTable(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("table", &buf)

	headers := []string{"Col1", "Col2"}
	rows := [][]string{{"val1", "val2"}}
	data := map[string]string{"test": "data"}

	formatter.Print(headers, rows, data)

	output := buf.String()

	// Should have table output, not JSON
	if strings.Contains(output, "{") && strings.Contains(output, "}") {
		t.Error("Table format should not have JSON braces")
	}

	if !strings.Contains(output, "Col1") {
		t.Error("Table format should have headers")
	}
}

func TestPrintDispatchJSON(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("json", &buf)

	headers := []string{"Col1", "Col2"}
	rows := [][]string{{"val1", "val2"}}
	data := map[string]string{"test": "data"}

	formatter.Print(headers, rows, data)

	output := buf.String()

	// Should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}
}

func TestPrintDispatchCSV(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("csv", &buf)

	headers := []string{"Name", "Value"}
	rows := [][]string{{"test", "123"}}
	data := map[string]string{"unused": "ignored"}

	formatter.Print(headers, rows, data)

	output := buf.String()

	reader := csv.NewReader(strings.NewReader(output))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	if len(records) != 2 {
		t.Errorf("Expected 2 records (header + data), got %d", len(records))
	}
}

func TestNewFormatter(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("json", &buf)

	if formatter == nil {
		t.Fatal("NewFormatter should not return nil")
	}
}

func TestTableWithManyColumns(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewFormatter("table", &buf)

	headers := []string{"A", "B", "C", "D", "E"}
	rows := [][]string{
		{"a1", "b1", "c1", "d1", "e1"},
		{"a2", "b2", "c2", "d2", "e2"},
	}

	formatter.Table(headers, rows)

	output := buf.String()

	// Verify all headers and data present
	for _, h := range headers {
		if !strings.Contains(output, h) {
			t.Errorf("Missing header: %s", h)
		}
	}

	if !strings.Contains(output, "a1") || !strings.Contains(output, "e2") {
		t.Error("Missing data in table")
	}
}
