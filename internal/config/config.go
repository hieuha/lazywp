package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config holds all lazywp configuration.
type Config struct {
	WPScanKeys     []string           `json:"wpscan_keys"`
	NVDKey         string             `json:"nvd_key"`
	KeyRotation    string             `json:"key_rotation"`
	Proxies        []string           `json:"proxies"`
	ProxyStrategy  string             `json:"proxy_strategy"`
	Concurrency    int                `json:"concurrency"`
	OutputDir      string             `json:"output_dir"`
	RateLimits     map[string]float64 `json:"rate_limits"`
	CacheTTL       string             `json:"cache_ttl"`
	RetryMax       int                `json:"retry_max"`
	RetryBaseDelay string             `json:"retry_base_delay"`
}

// DefaultConfig returns config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		KeyRotation:    "round-robin",
		ProxyStrategy:  "round-robin",
		Concurrency:    5,
		OutputDir:      "./downloads",
		RateLimits:     map[string]float64{"api.wordpress.org": 5, "wpscan.com": 1, "services.nvd.nist.gov": 0.16},
		CacheTTL:       "24h",
		RetryMax:       3,
		RetryBaseDelay: "1s",
	}
}

// CacheTTLDuration parses CacheTTL as time.Duration.
func (c *Config) CacheTTLDuration() time.Duration {
	d, err := time.ParseDuration(c.CacheTTL)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

// RetryBaseDelayDuration parses RetryBaseDelay as time.Duration.
func (c *Config) RetryBaseDelayDuration() time.Duration {
	d, err := time.ParseDuration(c.RetryBaseDelay)
	if err != nil {
		return time.Second
	}
	return d
}

// ConfigDir returns the lazywp config directory path.
func ConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	return filepath.Join(home, ".lazywp"), nil
}

// DefaultConfigPath returns the default config file path.
func DefaultConfigPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// EnsureConfigDir creates the config directory if it doesn't exist.
func EnsureConfigDir() error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	return os.MkdirAll(dir, 0700)
}

// Load reads config from path, merging with defaults for missing fields.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// Save writes config to path with secure permissions.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// Validate checks config for obvious errors.
func (c *Config) Validate() error {
	if c.Concurrency < 1 {
		return fmt.Errorf("concurrency must be >= 1, got %d", c.Concurrency)
	}
	if c.RetryMax < 0 {
		return fmt.Errorf("retry_max must be >= 0, got %d", c.RetryMax)
	}
	return nil
}
