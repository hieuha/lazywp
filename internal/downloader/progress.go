package downloader

import (
	"fmt"
	"io"
	"sync"

	"github.com/schollz/progressbar/v3"
)

// ProgressTracker manages per-file and overall progress display during batch downloads.
type ProgressTracker struct {
	quiet      bool
	totalFiles int
	completed  int
	failed     int
	mu         sync.Mutex
	bars       map[string]*progressbar.ProgressBar
	overall    *progressbar.ProgressBar
}

// NewTracker creates a ProgressTracker for totalFiles downloads.
// In quiet mode no bars are rendered; only the final summary counts are tracked.
func NewTracker(totalFiles int, quiet bool) *ProgressTracker {
	t := &ProgressTracker{
		quiet:      quiet,
		totalFiles: totalFiles,
		bars:       make(map[string]*progressbar.ProgressBar),
	}
	if !quiet && totalFiles > 0 {
		t.overall = progressbar.NewOptions(totalFiles,
			progressbar.OptionSetDescription("overall"),
			progressbar.OptionSetWidth(30),
			progressbar.OptionShowCount(),
			progressbar.OptionClearOnFinish(),
		)
	}
	return t
}

// OnFileStart registers a new file download and creates a per-file progress bar.
func (t *ProgressTracker) OnFileStart(slug string, totalBytes int64) {
	if t.quiet {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	bar := progressbar.NewOptions64(totalBytes,
		progressbar.OptionSetDescription(fmt.Sprintf("%-30s", slug)),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowBytes(true),
		progressbar.OptionClearOnFinish(),
	)
	t.bars[slug] = bar
}

// OnFileProgress advances the per-file bar by bytesWritten.
func (t *ProgressTracker) OnFileProgress(slug string, bytesWritten int64) {
	if t.quiet {
		return
	}
	t.mu.Lock()
	bar, ok := t.bars[slug]
	t.mu.Unlock()
	if ok {
		_ = bar.Add64(bytesWritten)
	}
}

// OnFileComplete marks the per-file bar as done and increments the overall counter.
func (t *ProgressTracker) OnFileComplete(slug string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.completed++
	if t.quiet {
		return
	}
	if bar, ok := t.bars[slug]; ok {
		_ = bar.Finish()
		delete(t.bars, slug)
	}
	if t.overall != nil {
		_ = t.overall.Add(1)
	}
}

// OnFileError marks a failed download and increments the failure and overall counters.
func (t *ProgressTracker) OnFileError(slug string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failed++
	if t.quiet {
		return
	}
	if bar, ok := t.bars[slug]; ok {
		_ = bar.Exit() // stop without clearing
		delete(t.bars, slug)
	}
	if t.overall != nil {
		_ = t.overall.Add(1)
	}
}

// Summary returns a human-readable final summary string.
func (t *ProgressTracker) Summary() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return fmt.Sprintf("done: %d succeeded, %d failed, %d total",
		t.completed-t.failed, t.failed, t.totalFiles)
}

// progressWriter wraps an io.Writer and reports each Write call to the ProgressTracker.
type progressWriter struct {
	slug    string
	tracker *ProgressTracker
	inner   io.Writer
}

// NewProgressWriter returns an io.Writer that forwards writes to inner while
// reporting progress for slug to the given ProgressTracker.
func NewProgressWriter(slug string, tracker *ProgressTracker, inner io.Writer) io.Writer {
	return &progressWriter{slug: slug, tracker: tracker, inner: inner}
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.inner.Write(p)
	if n > 0 {
		pw.tracker.OnFileProgress(pw.slug, int64(n))
	}
	return n, err
}
