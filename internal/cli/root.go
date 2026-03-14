package cli

import (
	"fmt"
	"os"

	"github.com/hieuha/lazywp/internal/config"
	"github.com/spf13/cobra"
)

var (
	verbose    bool
	quiet      bool
	outputFmt  string
	configPath string
	itemType   string
	forceDown  bool
)

// package-level singletons set in PersistentPreRunE.
var appDeps *AppDeps
var fmtr *Formatter

// skipDepsCommands are commands that don't need service dependencies.
var skipDepsCommands = map[string]bool{
	"version":    true,
	"help":       true,
	"completion": true,
	"config":     true,
}

var rootCmd = &cobra.Command{
	Use:   "lazywp",
	Short: "Bulk download WordPress plugins/themes with vulnerability research",
	Long: `lazywp is a CLI tool for security researchers to bulk-download
WordPress plugins and themes, cross-referencing them against
CVE databases (WPScan, NVD, Wordfence) for vulnerability analysis.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Always build the formatter.
		fmtr = NewFormatter(outputFmt, os.Stdout)

		// Skip heavy dep-building for lightweight commands.
		if skipDepsCommands[cmd.Name()] {
			return nil
		}

		// Resolve config path.
		cfgPath := configPath
		if cfgPath == "" {
			var err error
			cfgPath, err = config.DefaultConfigPath()
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}
		}

		cfg, err := config.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		deps, err := BuildDeps(cfg, itemType)
		if err != nil {
			return fmt.Errorf("init dependencies: %w", err)
		}
		appDeps = deps
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress non-essential output")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "format", "f", "table", "Output format: table|json|csv|sarif")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Config file path (default: ./config.yaml)")
	rootCmd.PersistentFlags().StringVarP(&itemType, "type", "t", "plugin", "Resource type: plugin|theme")
	rootCmd.PersistentFlags().BoolVar(&forceDown, "force", false, "Force re-download even if already exists")
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}
