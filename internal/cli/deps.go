package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hieuha/lazywp/internal/client"
	"github.com/hieuha/lazywp/internal/config"
	"github.com/hieuha/lazywp/internal/downloader"
	lazywphttp "github.com/hieuha/lazywp/internal/http"
	"github.com/hieuha/lazywp/internal/storage"
	"github.com/hieuha/lazywp/internal/vuln"
)

// AppDeps holds all lazywp runtime dependencies.
type AppDeps struct {
	Config     *config.Config
	HTTPClient *lazywphttp.Client
	WPClient   *client.WordPressClient
	Storage    *storage.Manager
	KeyRotator *lazywphttp.KeyRotator
	VulnAgg    *vuln.Aggregator
	Engine     *downloader.Engine
	WFClient   *client.WordfenceClient // exposed for vuln command wordfence filters
	ItemType   client.ItemType
}

// BuildDeps constructs all application services from the given config and item type string.
func BuildDeps(cfg *config.Config, itemTypeStr string) (*AppDeps, error) {
	it, err := client.ItemTypeFromString(itemTypeStr)
	if err != nil {
		return nil, err
	}

	httpClient, err := lazywphttp.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("build http client: %w", err)
	}

	// Vuln cache stored under ~/.lazywp/cache/
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}
	cacheDir := filepath.Join(home, ".lazywp", "cache")
	vulnCache := vuln.NewCache(cacheDir, cfg.CacheTTLDuration())

	keyRotator := lazywphttp.NewKeyRotator(cfg.WPScanKeys)

	wpClient := client.NewWordPressClient(httpClient, it)
	wpscanClient := client.NewWPScanClient(httpClient, keyRotator, vulnCache)
	nvdClient := client.NewNVDClient(httpClient, cfg.NVDKey, vulnCache)
	wfClient := client.NewWordfenceClient(httpClient, vulnCache)

	aggregator := vuln.NewAggregator([]vuln.VulnSource{wpscanClient, nvdClient, wfClient})

	stor := storage.NewManager(cfg.OutputDir)
	if err := stor.EnsureStructure(); err != nil {
		return nil, fmt.Errorf("ensure storage structure: %w", err)
	}

	engine := downloader.NewEngine(httpClient, wpClient, stor, cfg)

	return &AppDeps{
		Config:     cfg,
		HTTPClient: httpClient,
		WPClient:   wpClient,
		Storage:    stor,
		KeyRotator: keyRotator,
		VulnAgg:    aggregator,
		Engine:     engine,
		WFClient:   wfClient,
		ItemType:   it,
	}, nil
}
