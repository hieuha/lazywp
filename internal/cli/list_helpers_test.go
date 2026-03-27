package cli

import (
	"testing"
	"time"

	"github.com/hieuha/lazywp/internal/storage"
)

func TestBoolStr(t *testing.T) {
	tests := []struct {
		name string
		b    bool
		want string
	}{
		{"true returns yes", true, "yes"},
		{"false returns no", false, "no"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := boolStr(tc.b); got != tc.want {
				t.Errorf("boolStr(%v) = %q, want %q", tc.b, got, tc.want)
			}
		})
	}
}

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1K"},
		{1500, "1.5K"},
		{10000, "10K"},
		{1_000_000, "1M"},
		{1_500_000, "1.5M"},
		{5_000_000, "5M"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := formatNumber(tc.n); got != tc.want {
				t.Errorf("formatNumber(%d) = %q, want %q", tc.n, got, tc.want)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := formatBytes(tc.n); got != tc.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tc.n, got, tc.want)
			}
		})
	}
}

func TestSortEntriesByName(t *testing.T) {
	entries := []storage.IndexEntry{
		{Slug: "zebra"},
		{Slug: "apple"},
		{Slug: "mango"},
	}
	sortEntries(entries, "name")
	if entries[0].Slug != "apple" || entries[1].Slug != "mango" || entries[2].Slug != "zebra" {
		t.Errorf("name sort failed: got %v", []string{entries[0].Slug, entries[1].Slug, entries[2].Slug})
	}
}

func TestSortEntriesByDate(t *testing.T) {
	now := time.Now()
	entries := []storage.IndexEntry{
		{Slug: "old", DownloadedAt: now.Add(-2 * time.Hour)},
		{Slug: "newest", DownloadedAt: now},
		{Slug: "middle", DownloadedAt: now.Add(-1 * time.Hour)},
	}
	sortEntries(entries, "date")
	if entries[0].Slug != "newest" {
		t.Errorf("date sort: first entry should be newest, got %q", entries[0].Slug)
	}
	if entries[2].Slug != "old" {
		t.Errorf("date sort: last entry should be old, got %q", entries[2].Slug)
	}
}

func TestSortEntriesBySize(t *testing.T) {
	entries := []storage.IndexEntry{
		{Slug: "small", FileSize: 100},
		{Slug: "large", FileSize: 9000},
		{Slug: "medium", FileSize: 500},
	}
	sortEntries(entries, "size")
	if entries[0].Slug != "large" {
		t.Errorf("size sort: first entry should be large, got %q", entries[0].Slug)
	}
	if entries[2].Slug != "small" {
		t.Errorf("size sort: last entry should be small, got %q", entries[2].Slug)
	}
}

func TestSortEntriesDefaultIsName(t *testing.T) {
	entries := []storage.IndexEntry{
		{Slug: "z-plugin"},
		{Slug: "a-plugin"},
	}
	sortEntries(entries, "unknown-value")
	if entries[0].Slug != "a-plugin" {
		t.Errorf("default sort should be by name, got %q first", entries[0].Slug)
	}
}
