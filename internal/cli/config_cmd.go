package cli

import (
	"fmt"
	"os"

	"github.com/hieuha/lazywp/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage lazywp configuration",
}

var configSetCmd = &cobra.Command{
	Use:   "set KEY VALUE",
	Short: "Set a config value by flat YAML key",
	Args:  cobra.ExactArgs(2),
	RunE:  runConfigSet,
}

var configGetCmd = &cobra.Command{
	Use:   "get KEY",
	Short: "Get a config value by flat YAML key",
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
	Short: "Create default config file at ./config.yaml",
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
	display.WPScanKeys = redactKeys(display.WPScanKeys)
	display.WordfenceKeys = redactKeys(display.WordfenceKeys)
	display.NVDKeys = redactKeys(display.NVDKeys)

	out, err := yaml.Marshal(display)
	if err != nil {
		return err
	}
	fmt.Print(string(out))
	return nil
}

func redactKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	redacted := make([]string, len(keys))
	for i := range keys {
		redacted[i] = "[redacted]"
	}
	return redacted
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

// setConfigField sets a field on the config via YAML marshal/unmarshal round-trip.
func setConfigField(cfg *config.Config, key, value string) error {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	var m map[string]interface{}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return err
	}

	// Try to parse value as YAML (handles arrays, numbers, booleans).
	var parsed interface{}
	if err := yaml.Unmarshal([]byte(value), &parsed); err == nil {
		m[key] = parsed
	} else {
		m[key] = value
	}

	merged, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(merged, cfg); err != nil {
		return fmt.Errorf("invalid value for key %q: %w", key, err)
	}
	return nil
}

// getConfigField retrieves a field from the config via YAML marshal/unmarshal.
func getConfigField(cfg *config.Config, key string) (string, error) {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	var m map[string]interface{}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return "", err
	}
	val, ok := m[key]
	if !ok {
		return "", fmt.Errorf("unknown config key: %s", key)
	}
	return fmt.Sprintf("%v", val), nil
}
