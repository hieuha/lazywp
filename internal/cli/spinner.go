package cli

import (
	"fmt"
	"os"
	"time"
)

// startSpinner displays an animated spinner on stderr. Returns a stop function
// that clears the spinner line. If quiet is true, the spinner is suppressed.
func startSpinner(message string, quiet bool) func() {
	if quiet {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		for {
			select {
			case <-done:
				return
			default:
				fmt.Fprintf(os.Stderr, "\r%s %s", frames[i%len(frames)], message)
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
	return func() {
		close(done)
		fmt.Fprintf(os.Stderr, "\r\033[K") // clear line
	}
}
