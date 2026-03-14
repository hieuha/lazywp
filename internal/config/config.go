package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all lazywp configuration.
type Config struct {
	WPScanKeys     []string           `yaml:"wpscan_keys,omitempty"`
	WordfenceKeys  []string           `yaml:"wordfence_keys,omitempty"`
	NVDKeys        []string           `yaml:"nvd_keys,omitempty"`
	KeyRotation    string             `yaml:"key_rotation"`
	Proxies        []string           `yaml:"proxies,omitempty"`
	ProxyStrategy  string             `yaml:"proxy_strategy"`
	Concurrency    int                `yaml:"concurrency"`
	OutputDir      string             `yaml:"output_dir"`
	CacheDir       string             `yaml:"cache_dir"`
	RateLimits     map[string]float64 `yaml:"rate_limits"`
	CacheTTL       string             `yaml:"cache_ttl"`
	RetryMax       int                `yaml:"retry_max"`
	RetryBaseDelay string             `yaml:"retry_base_delay"`
	TitleMaxLen    int                `yaml:"title_max_len"`
}

// DefaultConfig returns config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		KeyRotation:    "round-robin",
		ProxyStrategy:  "round-robin",
		Concurrency:    5,
		OutputDir:      "./downloads",
		CacheDir:       "./cache",
		RateLimits:     map[string]float64{"api.wordpress.org": 5, "wpscan.com": 1, "services.nvd.nist.gov": 0.16, "www.wordfence.com": 0.1},
		CacheTTL:       "24h",
		RetryMax:       3,
		RetryBaseDelay: "1s",
		TitleMaxLen:    100,
	}
}

// EffectiveNVDKeys returns NVDKeys if configured.
func (c *Config) EffectiveNVDKeys() []string {
	if len(c.NVDKeys) > 0 {
		return c.NVDKeys
	}
	return nil
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

// DefaultConfigPath returns "./config.yaml" in the current working directory.
func DefaultConfigPath() (string, error) {
	return "config.yaml", nil
}

// Load reads config from a YAML file, merging with defaults for missing fields.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// Save writes config to path as YAML with secure permissions.
func (c *Config) Save(path string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}
	data, err := yaml.Marshal(c)
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
