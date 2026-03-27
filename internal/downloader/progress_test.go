package downloader

import (
	"bytes"
	"strings"
	"testing"
)

// All tests use quiet=true to avoid progressbar terminal rendering in CI.

func TestProgressTracker_QuietMode_Counts(t *testing.T) {
	tr := NewTracker(3, true)

	tr.OnFileStart("plugin-a", 1024)
	tr.OnFileStart("plugin-b", 2048)

	tr.OnFileComplete("plugin-a")
	tr.OnFileComplete("plugin-b")
	tr.OnFileError("plugin-c", nil)

	summary := tr.Summary()
	if !strings.Contains(summary, "3 total") {
		t.Errorf("summary missing total: %q", summary)
	}
	if !strings.Contains(summary, "1 failed") {
		t.Errorf("summary missing failed count: %q", summary)
	}
}

func TestProgressTracker_QuietMode_OnFileProgress(t *testing.T) {
	// In quiet mode OnFileProgress is a no-op — should not panic.
	tr := NewTracker(1, true)
	tr.OnFileStart("slug", 100)
	tr.OnFileProgress("slug", 50)
	tr.OnFileProgress("nonexistent", 10)
}

func TestProgressTracker_QuietMode_Summary_AllSucceeded(t *testing.T) {
	tr := NewTracker(2, true)
	tr.OnFileComplete("a")
	tr.OnFileComplete("b")

	summary := tr.Summary()
	if !strings.Contains(summary, "2 succeeded") {
		t.Errorf("want 2 succeeded in summary, got %q", summary)
	}
	if !strings.Contains(summary, "0 failed") {
		t.Errorf("want 0 failed in summary, got %q", summary)
	}
}

func TestProgressTracker_QuietMode_Summary_Empty(t *testing.T) {
	tr := NewTracker(0, true)
	summary := tr.Summary()
	if summary == "" {
		t.Error("Summary should return non-empty string")
	}
}

func TestNewTracker_NonQuiet_ZeroFiles(t *testing.T) {
	// totalFiles=0 with quiet=false should not create overall bar (no panic).
	tr := NewTracker(0, false)
	if tr == nil {
		t.Fatal("NewTracker returned nil")
	}
	summary := tr.Summary()
	if !strings.Contains(summary, "0 total") {
		t.Errorf("unexpected summary: %q", summary)
	}
}

func TestProgressWriter_Write(t *testing.T) {
	tr := NewTracker(1, true)
	tr.OnFileStart("test-plugin", 100)

	var buf bytes.Buffer
	pw := NewProgressWriter("test-plugin", tr, &buf)

	data := []byte("hello world")
	n, err := pw.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("wrote %d bytes, want %d", n, len(data))
	}
	if buf.String() != "hello world" {
		t.Errorf("inner writer got %q, want %q", buf.String(), "hello world")
	}
}

func TestProgressWriter_Write_Empty(t *testing.T) {
	tr := NewTracker(1, true)
	var buf bytes.Buffer
	pw := NewProgressWriter("slug", tr, &buf)

	n, err := pw.Write([]byte{})
	if err != nil {
		t.Fatalf("Write empty: %v", err)
	}
	if n != 0 {
		t.Errorf("want 0 bytes written, got %d", n)
	}
}

// --- non-quiet mode: exercises progressbar creation paths ---
// progressbar writes to stdout; these tests verify no panics occur.

func TestProgressTracker_NonQuiet_LifeCycle(t *testing.T) {
	tr := NewTracker(2, false)

	tr.OnFileStart("plugin-a", 1024)
	tr.OnFileStart("plugin-b", 2048)

	tr.OnFileProgress("plugin-a", 256)
	tr.OnFileProgress("plugin-a", 256)
	tr.OnFileProgress("nonexistent-slug", 100) // no bar registered — should not panic

	tr.OnFileComplete("plugin-a")
	tr.OnFileError("plugin-b", nil)

	summary := tr.Summary()
	if !strings.Contains(summary, "2 total") {
		t.Errorf("unexpected summary: %q", summary)
	}
}

func TestProgressTracker_NonQuiet_ZeroFiles(t *testing.T) {
	// No overall bar created when totalFiles=0.
	tr := NewTracker(0, false)
	tr.OnFileStart("slug", 512)
	tr.OnFileProgress("slug", 100)
	tr.OnFileComplete("slug")
}

func TestProgressTracker_NonQuiet_OnFileError_NoBar(t *testing.T) {
	// OnFileError for an unknown slug should not panic.
	tr := NewTracker(1, false)
	tr.OnFileError("ghost-slug", nil)
}
