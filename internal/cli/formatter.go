package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Formatter renders output in table, JSON, or CSV formats.
type Formatter struct {
	format string
	writer io.Writer
}

// NewFormatter creates a Formatter with the given output format and writer.
func NewFormatter(format string, w io.Writer) *Formatter {
	return &Formatter{format: format, writer: w}
}

// Print dispatches to the correct output method based on format.
func (f *Formatter) Print(headers []string, rows [][]string, data any) {
	switch f.format {
	case "json":
		f.JSON(data)
	case "csv":
		f.CSV(headers, rows)
	default:
		f.Table(headers, rows)
	}
}

// PrintTyped is like Print but wraps JSON output in a typed envelope.
func (f *Formatter) PrintTyped(typeName string, headers []string, rows [][]string, data any) {
	switch f.format {
	case "json":
		f.TypedJSON(typeName, data)
	case "csv":
		f.CSV(headers, rows)
	default:
		f.Table(headers, rows)
	}
}

// Table renders aligned columns using tabwriter with bold headers.
func (f *Formatter) Table(headers []string, rows [][]string) {
	tw := tabwriter.NewWriter(f.writer, 0, 0, 2, ' ', 0)
	// Bold headers via ANSI escape (safe on most terminals)
	headerLine := "\033[1m" + strings.Join(headers, "\t") + "\033[0m"
	fmt.Fprintln(tw, headerLine)
	// Separator
	seps := make([]string, len(headers))
	for i, h := range headers {
		seps[i] = strings.Repeat("-", len(h))
	}
	fmt.Fprintln(tw, strings.Join(seps, "\t"))
	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	tw.Flush()
}

// jsonEnvelope wraps JSON output with a type discriminator for auto-detection.
type jsonEnvelope struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// JSON marshals data as indented JSON and writes to the writer.
func (f *Formatter) JSON(data any) {
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Fprintf(f.writer, `{"error": %q}`+"\n", err.Error())
		return
	}
	fmt.Fprintf(f.writer, "%s\n", out)
}

// TypedJSON wraps data in a {"type": ..., "data": ...} envelope for auto-detection.
func (f *Formatter) TypedJSON(typeName string, data any) {
	f.JSON(jsonEnvelope{Type: typeName, Data: data})
}

// CSV writes headers and rows as RFC 4180 CSV.
func (f *Formatter) CSV(headers []string, rows [][]string) {
	w := csv.NewWriter(f.writer)
	_ = w.Write(headers)
	for _, row := range rows {
		_ = w.Write(row)
	}
	w.Flush()
}
