package cli

import (
	"fmt"
	"sync"

	"github.com/schollz/progressbar/v3"
)

// scanProgress tracks scan progress with a progress bar.
type scanProgress struct {
	bar   *progressbar.ProgressBar
	mu    sync.Mutex
	quiet bool
}

// newScanProgress creates a progress bar for scanning N items.
func newScanProgress(total int, description string, isQuiet bool) *scanProgress {
	sp := &scanProgress{quiet: isQuiet}
	if isQuiet || total == 0 {
		return sp
	}
	sp.bar = progressbar.NewOptions(total,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetPredictTime(true),
	)
	return sp
}

// update advances the progress bar by 1 and shows current item being processed.
func (sp *scanProgress) update(currentItem string) {
	if sp.quiet || sp.bar == nil {
		return
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.bar.Describe(fmt.Sprintf("%-30s", truncateSlug(currentItem, 30)))
	_ = sp.bar.Add(1)
}

// finish completes the progress bar.
func (sp *scanProgress) finish() {
	if sp.quiet || sp.bar == nil {
		return
	}
	_ = sp.bar.Finish()
	fmt.Println()
}

// truncateSlug shortens a slug for display in the progress bar.
func truncateSlug(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
