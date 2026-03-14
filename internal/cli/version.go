package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Build-time variables set via ldflags.
var (
	Version = "0.7.0"
	Commit  = "none"
	Date    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print lazywp version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("lazywp %s\n  commit: %s\n  built:  %s\n", Version, Commit, Date)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
