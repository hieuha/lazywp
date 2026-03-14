package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var cacheSource string

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage vulnerability data cache",
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear cached vulnerability data",
	RunE:  runCacheClear,
}

var cacheUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Force refresh vulnerability feed (clears cache then re-fetches)",
	RunE:  runCacheUpdate,
}

var cacheStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show cache status for all sources",
	RunE:  runCacheStatus,
}

func init() {
	cacheClearCmd.Flags().StringVar(&cacheSource, "source", "", "Clear specific source (wordfence|wpscan|nvd)")
	cacheCmd.AddCommand(cacheClearCmd, cacheUpdateCmd, cacheStatusCmd)
	rootCmd.AddCommand(cacheCmd)
}

func runCacheClear(cmd *cobra.Command, args []string) error {
	var count int
	var err error

	if cacheSource != "" {
		count, err = appDeps.VulnCache.ClearSource(cacheSource)
	} else {
		count, err = appDeps.VulnCache.ClearAll()
	}
	if err != nil {
		return fmt.Errorf("clear cache: %w", err)
	}

	if cacheSource != "" {
		fmt.Printf("Cleared %d cached entries for %s\n", count, cacheSource)
	} else {
		fmt.Printf("Cleared %d cached entries\n", count)
	}
	return nil
}

func runCacheUpdate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	n, _ := appDeps.VulnCache.ClearAll()
	fmt.Printf("Cleared %d old cache entries\n", n)

	fmt.Println("Fetching Wordfence feed...")
	vulns, err := appDeps.WFClient.FetchRecent(ctx, 0)
	if err != nil {
		fmt.Printf("  Wordfence error: %v\n", err)
	} else {
		fmt.Printf("  Cached %d Wordfence vulnerabilities\n", len(vulns))
	}

	fmt.Println("NVD/WPScan caches will refresh on next query.")
	printCacheStatus()
	return nil
}

func runCacheStatus(cmd *cobra.Command, args []string) error {
	printCacheStatus()
	return nil
}

// printCacheStatus prints cache info for all sources.
func printCacheStatus() {
	fmt.Printf("\nCache directory: %s\n", appDeps.VulnCache.BaseDir())
	fmt.Printf("Cache TTL: %s\n\n", appDeps.Config.CacheTTL)

	sources := []string{"wordfence", "wpscan", "nvd"}
	for _, src := range sources {
		info := appDeps.VulnCache.SourceInfo(src)
		if info == nil {
			fmt.Printf("  %-12s  no cache\n", src)
			continue
		}
		status := "valid"
		if info.Expired {
			status = "expired"
		}
		fmt.Printf("  %-12s  cached at %s  (age: %s, size: %s, status: %s)\n",
			src,
			info.CachedAt.Format("2006-01-02 15:04:05"),
			formatDuration(info.Age),
			formatCacheBytes(info.FileSize),
			status,
		)
	}
}

// PrintCacheInfo prints a one-line cache summary for use in command output.
func PrintCacheInfo(source string) {
	if appDeps == nil || appDeps.VulnCache == nil {
		return
	}
	info := appDeps.VulnCache.SourceInfo(source)
	if info == nil {
		return
	}
	status := "valid"
	if info.Expired {
		status = "expired"
	}
	fmt.Printf("[cache: %s | cached at %s | age: %s | %s]\n",
		source,
		info.CachedAt.Format("2006-01-02 15:04:05"),
		formatDuration(info.Age),
		status,
	)
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

// formatCacheBytes formats file size for cache display.
func formatCacheBytes(b int64) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%.1fMB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	default:
		return fmt.Sprintf("%dB", b)
	}
}
