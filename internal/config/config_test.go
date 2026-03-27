package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	if cfg.KeyRotation != "round-robin" {
		t.Errorf("KeyRotation: got %q, want %q", cfg.KeyRotation, "round-robin")
	}

	if cfg.ProxyStrategy != "round-robin" {
		t.Errorf("ProxyStrategy: got %q, want %q", cfg.ProxyStrategy, "round-robin")
	}

	if cfg.Concurrency != 5 {
		t.Errorf("Concurrency: got %d, want %d", cfg.Concurrency, 5)
	}

	if cfg.RetryMax != 3 {
		t.Errorf("RetryMax: got %d, want %d", cfg.RetryMax, 3)
	}

	if cfg.OutputDir != "./downloads" {
		t.Errorf("OutputDir: got %q, want %q", cfg.OutputDir, "./downloads")
	}
}

func TestLoadSave(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create and save config
	original := DefaultConfig()
	original.WPScanKeys = []string{"key1", "key2"}
	original.NVDKeys = []string{"nvd-test-key"}
	original.Concurrency = 10
	original.RetryMax = 5

	if err := original.Save(configPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load and verify
	loaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(loaded.WPScanKeys) != 2 || loaded.WPScanKeys[0] != "key1" {
		t.Errorf("WPScanKeys mismatch: got %v, want [key1 key2]", loaded.WPScanKeys)
	}

	if len(loaded.NVDKeys) != 1 || loaded.NVDKeys[0] != "nvd-test-key" {
		t.Errorf("NVDKeys: got %v, want [nvd-test-key]", loaded.NVDKeys)
	}

	if loaded.Concurrency != 10 {
		t.Errorf("Concurrency: got %d, want %d", loaded.Concurrency, 10)
	}

	if loaded.RetryMax != 5 {
		t.Errorf("RetryMax: got %d, want %d", loaded.RetryMax, 5)
	}
}

func TestLoadMissing(t *testing.T) {
	// Load from non-existent path should return defaults
	loaded, err := Load("/tmp/nonexistent/config.yaml")

	if err != nil {
		t.Fatalf("Load should not error on missing file: %v", err)
	}

	if loaded == nil {
		t.Fatal("expected non-nil config")
	}

	// Should have defaults
	if loaded.Concurrency != 5 {
		t.Errorf("Concurrency: got %d, want %d", loaded.Concurrency, 5)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name:    "valid config",
			cfg:     DefaultConfig(),
			wantErr: false,
		},
		{
			name: "invalid concurrency zero",
			cfg: &Config{
				Concurrency: 0,
				RetryMax:    3,
			},
			wantErr: true,
		},
		{
			name: "invalid concurrency negative",
			cfg: &Config{
				Concurrency: -1,
				RetryMax:    3,
			},
			wantErr: true,
		},
		{
			name: "invalid retry negative",
			cfg: &Config{
				Concurrency: 5,
				RetryMax:    -1,
			},
			wantErr: true,
		},
		{
			name: "valid retry zero",
			cfg: &Config{
				Concurrency: 5,
				RetryMax:    0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate: got err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestCacheTTLDuration(t *testing.T) {
	tests := []struct {
		name     string
		ttlStr   string
		expected time.Duration
	}{
		{"24h", "24h", 24 * time.Hour},
		{"1h", "1h", time.Hour},
		{"30m", "30m", 30 * time.Minute},
		{"invalid", "invalid", 24 * time.Hour}, // fallback to default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{CacheTTL: tt.ttlStr}
			d := cfg.CacheTTLDuration()
			if d != tt.expected {
				t.Errorf("CacheTTLDuration: got %v, want %v", d, tt.expected)
			}
		})
	}
}

func TestRetryBaseDelayDuration(t *testing.T) {
	tests := []struct {
		name     string
		delayStr string
		expected time.Duration
	}{
		{"1s", "1s", time.Second},
		{"100ms", "100ms", 100 * time.Millisecond},
		{"2s", "2s", 2 * time.Second},
		{"invalid", "invalid", time.Second}, // fallback to default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{RetryBaseDelay: tt.delayStr}
			d := cfg.RetryBaseDelayDuration()
			if d != tt.expected {
				t.Errorf("RetryBaseDelayDuration: got %v, want %v", d, tt.expected)
			}
		})
	}
}

func TestEffectiveNVDKeys(t *testing.T) {
	cfg := &Config{NVDKeys: []string{"key1"}}
	if got := cfg.EffectiveNVDKeys(); len(got) != 1 || got[0] != "key1" {
		t.Errorf("expected [key1], got %v", got)
	}

	cfg2 := &Config{}
	if got := cfg2.EffectiveNVDKeys(); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestEffectivePDAPIKeys(t *testing.T) {
	// Array takes priority
	cfg := &Config{PDAPIKeys: []string{"arr1"}, PDAPIKey: "single"}
	if got := cfg.EffectivePDAPIKeys(); len(got) != 1 || got[0] != "arr1" {
		t.Errorf("array should take priority, got %v", got)
	}

	// Falls back to single key
	cfg2 := &Config{PDAPIKey: "single"}
	if got := cfg2.EffectivePDAPIKeys(); len(got) != 1 || got[0] != "single" {
		t.Errorf("expected [single], got %v", got)
	}

	// Both empty
	cfg3 := &Config{}
	if got := cfg3.EffectivePDAPIKeys(); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestDefaultConfigPath(t *testing.T) {
	path, err := DefaultConfigPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "config.yaml" {
		t.Errorf("expected config.yaml, got %q", path)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("{{invalid yaml"), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestSaveCreatesNestedDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	path := filepath.Join(dir, "config.yaml")

	cfg := DefaultConfig()
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save to nested dir failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestConfigDirPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_config.yaml")

	cfg := DefaultConfig()
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Check file permissions (0600 = rw-------)
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	mode := info.Mode()
	if mode&0600 != 0600 {
		t.Errorf("Config file permissions: got %o, want at least 0600", mode.Perm())
	}
}
