package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hieuha/lazywp/internal/watch"
	"github.com/spf13/cobra"
)

// errChangesDetected is returned when one-shot mode finds changes (exit code 1).
var errChangesDetected = fmt.Errorf("changes detected")

var (
	watchSlug     string
	watchList     string
	watchDaemon   bool
	watchInterval string
	watchWebhook  string
	watchOutput   string
	watchReset    bool
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Monitor plugins/themes for new versions and CVEs",
	Long: `Monitor WordPress plugins/themes for version updates and new CVEs.
One-shot mode (default) checks once and exits — ideal for cron/CI.
Daemon mode loops on an interval until interrupted.`,
	RunE: runWatch,
}

func init() {
	watchCmd.Flags().StringVar(&watchSlug, "slug", "", "Slug to monitor")
	watchCmd.Flags().StringVar(&watchList, "list", "", "Path to file with slugs (one per line)")
	watchCmd.Flags().BoolVar(&watchDaemon, "daemon", false, "Run continuously on an interval")
	watchCmd.Flags().StringVar(&watchInterval, "interval", "24h", "Check interval for daemon mode")
	watchCmd.Flags().StringVar(&watchWebhook, "webhook", "", "Webhook URL to POST changes to")
	watchCmd.Flags().StringVarP(&watchOutput, "output", "o", "", "Write JSON report to file")
	watchCmd.Flags().BoolVar(&watchReset, "reset", false, "Delete state file and exit")
	rootCmd.AddCommand(watchCmd)
}

// watchReport is the JSON payload for file output and webhook.
type watchReport struct {
	Timestamp string         `json:"timestamp"`
	Changes   []watch.Change `json:"changes"`
}

func runWatch(cmd *cobra.Command, args []string) error {
	statePath := filepath.Join(appDeps.Config.CacheDir, "watch-state.json")

	if watchReset {
		if err := watch.Reset(statePath); err != nil {
			return err
		}
		if !quiet {
			fmt.Println("Watch state reset.")
		}
		return nil
	}

	if watchSlug == "" && watchList == "" {
		return fmt.Errorf("must provide --slug or --list")
	}

	// Validate webhook URL if provided.
	if watchWebhook != "" {
		if err := validateWebhookURL(watchWebhook); err != nil {
			return err
		}
	}

	// Resolve slug list.
	slugs, err := resolveWatchSlugs()
	if err != nil {
		return err
	}
	if len(slugs) == 0 {
		return fmt.Errorf("no slugs found")
	}

	if !watchDaemon {
		changes, err := runWatchOnce(slugs, statePath)
		if err != nil {
			return err
		}
		if err := outputChanges(changes); err != nil {
			return err
		}
		if len(changes) > 0 {
			return errChangesDetected
		}
		return nil
	}

	// Daemon mode with signal handling.
	interval, err := time.ParseDuration(watchInterval)
	if err != nil {
		return fmt.Errorf("invalid interval: %w", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	if !quiet {
		fmt.Printf("lazywp watch daemon — checking %d slugs every %s (Ctrl+C to stop)\n\n", len(slugs), interval)
	}

	timer := time.NewTimer(0) // fire immediately for first run
	for {
		select {
		case <-sigCh:
			timer.Stop()
			if !quiet {
				fmt.Println("\nWatch stopped.")
			}
			return nil
		case <-timer.C:
			changes, err := runWatchOnce(slugs, statePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "watch error: %v\n", err)
			} else if err := outputChanges(changes); err != nil {
				fmt.Fprintf(os.Stderr, "output error: %v\n", err)
			}
			timer.Reset(interval)
		}
	}
}

// resolveWatchSlugs builds the slug list from --slug or --list flags.
func resolveWatchSlugs() ([]string, error) {
	if watchList != "" {
		return readSlugListFile(watchList)
	}
	return []string{watchSlug}, nil
}

// runWatchOnce loads state, checks each slug, diffs, saves state, returns changes.
func runWatchOnce(slugs []string, statePath string) ([]watch.Change, error) {
	ctx := context.Background()

	state, err := watch.LoadState(statePath)
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}

	var allChanges []watch.Change
	progress := newScanProgress(len(slugs), "Checking", quiet)

	for _, slug := range slugs {
		progress.update(slug)

		// Fetch current version from WordPress.org.
		info, err := appDeps.WPClient.GetInfo(ctx, slug)
		if err != nil {
			if !quiet {
				fmt.Fprintf(os.Stderr, "warning: %s: %v\n", slug, err)
			}
			continue
		}

		// Fetch current CVEs from all sources.
		vulns, warnings := appDeps.VulnAgg.FetchForSlug(ctx, slug, appDeps.ItemType)
		if !quiet {
			for _, w := range warnings {
				fmt.Fprintf(os.Stderr, "warning [%s]: %s\n", slug, w)
			}
		}

		// Diff against previous state.
		old := state[slug]
		changes := watch.DiffSlug(slug, old, info.Version, vulns)
		allChanges = append(allChanges, changes...)

		// Update state with current data.
		cves := make([]string, 0, len(vulns))
		for _, v := range vulns {
			if v.CVE != "" {
				cves = append(cves, v.CVE)
			}
		}
		state[slug] = watch.SlugState{
			Version:   info.Version,
			CVEs:      cves,
			LastCheck: time.Now(),
		}
	}

	progress.finish()

	if err := watch.SaveState(statePath, state); err != nil {
		return allChanges, fmt.Errorf("save state: %w", err)
	}

	return allChanges, nil
}

// outputChanges prints changes to stdout and optionally writes JSON file / sends webhook.
func outputChanges(changes []watch.Change) error {
	// Stdout summary.
	if !quiet {
		if len(changes) == 0 {
			fmt.Println("lazywp watch — no changes detected")
		} else {
			fmt.Printf("lazywp watch — %d change(s) detected\n\n", len(changes))
			for _, c := range changes {
				switch c.Type {
				case "new_version":
					fmt.Printf("  %sNEW VERSION%s  %s  %s → %s\n",
						ansiBoldGreen, ansiReset, c.Slug, c.OldVersion, c.NewVersion)
				case "new_cve":
					cvss := fmt.Sprintf("CVSS:%.1f", c.CVSS)
					fmt.Printf("  %sNEW CVE%s      %s  %s  %s  %s\n",
						ansiBoldRed, ansiReset, c.Slug, c.CVE, cvss, truncate(c.Title, 60))
				}
			}
			fmt.Println()
		}
	}

	report := watchReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Changes:   changes,
	}

	// JSON file output.
	if watchOutput != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal report: %w", err)
		}
		if err := os.WriteFile(watchOutput, data, 0o644); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		if !quiet {
			fmt.Printf("Report written to %s\n", watchOutput)
		}
	}

	// Webhook POST.
	if watchWebhook != "" && len(changes) > 0 {
		if err := sendWebhook(watchWebhook, report); err != nil {
			fmt.Fprintf(os.Stderr, "webhook error: %v\n", err)
		}
	}

	return nil
}

// validateWebhookURL checks that the webhook URL has an http or https scheme.
func validateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("webhook URL must use http or https scheme, got %q", u.Scheme)
	}
	return nil
}

// sendWebhook POSTs the report JSON to the given URL with a 10s timeout.
func sendWebhook(webhookURL string, report watchReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("POST webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	if !quiet {
		fmt.Printf("Webhook sent: %s (status %d)\n", webhookURL, resp.StatusCode)
	}
	return nil
}
