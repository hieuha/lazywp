package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/hieuha/lazywp/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage lazywp configuration",
}

var configSetCmd = &cobra.Command{
	Use:   "set KEY VALUE",
	Short: "Set a config value by flat JSON key",
	Args:  cobra.ExactArgs(2),
	RunE:  runConfigSet,
}

var configGetCmd = &cobra.Command{
	Use:   "get KEY",
	Short: "Get a config value by flat JSON key",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigGet,
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all config values (API keys redacted)",
	RunE:  runConfigList,
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create default config file at ~/.lazywp/config.json",
	RunE:  runConfigInit,
}

func init() {
	configCmd.AddCommand(configSetCmd, configGetCmd, configListCmd, configInitCmd)
	rootCmd.AddCommand(configCmd)
}

func resolveConfigPath() (string, error) {
	if configPath != "" {
		return configPath, nil
	}
	return config.DefaultConfigPath()
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	key, value := args[0], args[1]

	cfgPath, err := resolveConfigPath()
	if err != nil {
		return err
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := setConfigField(cfg, key, value); err != nil {
		return err
	}

	if err := cfg.Save(cfgPath); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	fmt.Printf("Set %s = %s\n", key, value)
	return nil
}

func runConfigGet(cmd *cobra.Command, args []string) error {
	key := args[0]

	cfgPath, err := resolveConfigPath()
	if err != nil {
		return err
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	val, err := getConfigField(cfg, key)
	if err != nil {
		return err
	}
	fmt.Println(val)
	return nil
}

func runConfigList(cmd *cobra.Command, args []string) error {
	cfgPath, err := resolveConfigPath()
	if err != nil {
		return err
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Redact API keys before display.
	display := *cfg
	if len(display.WPScanKeys) > 0 {
		redacted := make([]string, len(display.WPScanKeys))
		for i := range display.WPScanKeys {
			redacted[i] = "[redacted]"
		}
		display.WPScanKeys = redacted
	}
	if display.NVDKey != "" {
		display.NVDKey = "[redacted]"
	}

	out, err := json.MarshalIndent(display, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	cfgPath, err := resolveConfigPath()
	if err != nil {
		return err
	}

	if _, statErr := os.Stat(cfgPath); statErr == nil {
		fmt.Printf("Config already exists at %s\n", cfgPath)
		return nil
	}

	cfg := config.DefaultConfig()
	if err := cfg.Save(cfgPath); err != nil {
		return fmt.Errorf("write default config: %w", err)
	}
	fmt.Printf("Created default config at %s\n", cfgPath)
	return nil
}

// setConfigField sets a flat JSON key on the config struct via marshal/unmarshal.
func setConfigField(cfg *config.Config, key, value string) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}

	// Try to parse value as JSON; fall back to quoted string.
	var jsonVal json.RawMessage
	if json.Unmarshal([]byte(value), &jsonVal) == nil {
		m[key] = jsonVal
	} else {
		m[key] = json.RawMessage(`"` + strings.ReplaceAll(value, `"`, `\"`) + `"`)
	}

	merged, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(merged, cfg); err != nil {
		return fmt.Errorf("invalid value for key %q: %w", key, err)
	}
	return nil
}

// getConfigField retrieves a flat JSON key from the config struct.
func getConfigField(cfg *config.Config, key string) (string, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", err
	}
	val, ok := m[key]
	if !ok {
		return "", fmt.Errorf("unknown config key: %s", key)
	}
	// Strip outer quotes for plain strings.
	s := string(val)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return s, nil
}
