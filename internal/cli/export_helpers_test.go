package cli

import (
	"testing"
	"time"

	"github.com/hieuha/lazywp/internal/storage"
)

func TestFlattenEntries_Headers(t *testing.T) {
	headers, _ := flattenEntries(nil)
	want := []string{"slug", "type", "version", "downloaded_at", "has_vulns", "file_size"}
	if len(headers) != len(want) {
		t.Fatalf("header count: got %d, want %d", len(headers), len(want))
	}
	for i, h := range want {
		if headers[i] != h {
			t.Errorf("header[%d]: got %q, want %q", i, headers[i], h)
		}
	}
}

func TestFlattenEntries_Empty(t *testing.T) {
	_, rows := flattenEntries(nil)
	if len(rows) != 0 {
		t.Errorf("empty input: expected 0 rows, got %d", len(rows))
	}
}

func TestFlattenEntries_SingleEntry(t *testing.T) {
	ts := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	entries := []storage.IndexEntry{
		{
			Slug:         "akismet",
			Type:         "plugin",
			Version:      "5.3.1",
			DownloadedAt: ts,
			HasVulns:     false,
			FileSize:     2048,
		},
	}
	_, rows := flattenEntries(entries)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row[0] != "akismet" {
		t.Errorf("slug: got %q, want akismet", row[0])
	}
	if row[1] != "plugin" {
		t.Errorf("type: got %q, want plugin", row[1])
	}
	if row[2] != "5.3.1" {
		t.Errorf("version: got %q, want 5.3.1", row[2])
	}
	if row[3] != ts.Format(time.RFC3339) {
		t.Errorf("downloaded_at: got %q, want %q", row[3], ts.Format(time.RFC3339))
	}
	if row[4] != "no" {
		t.Errorf("has_vulns: got %q, want no", row[4])
	}
	if row[5] != "2.0 KB" {
		t.Errorf("file_size: got %q, want 2.0 KB", row[5])
	}
}

func TestFlattenEntries_HasVulnsTrue(t *testing.T) {
	entries := []storage.IndexEntry{
		{Slug: "bad-plugin", HasVulns: true, DownloadedAt: time.Now()},
	}
	_, rows := flattenEntries(entries)
	if rows[0][4] != "yes" {
		t.Errorf("has_vulns=true: got %q, want yes", rows[0][4])
	}
}

func TestFlattenEntries_MultipleEntries(t *testing.T) {
	entries := []storage.IndexEntry{
		{Slug: "plugin-a", Type: "plugin", DownloadedAt: time.Now()},
		{Slug: "theme-b", Type: "theme", DownloadedAt: time.Now()},
		{Slug: "plugin-c", Type: "plugin", DownloadedAt: time.Now()},
	}
	_, rows := flattenEntries(entries)
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	if rows[0][0] != "plugin-a" || rows[1][0] != "theme-b" || rows[2][0] != "plugin-c" {
		t.Error("row order not preserved")
	}
}
