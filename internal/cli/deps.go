package cli

import (
	"fmt"

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
	VulnCache  *vuln.Cache
	VulnAgg    *vuln.Aggregator
	Engine     *downloader.Engine
	WFClient   *client.WordfenceClient // exposed for vuln command wordfence filters
	PDRotator  *lazywphttp.KeyRotator // ProjectDiscovery API key rotator
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

	cacheDir := cfg.CacheDir
	vulnCache := vuln.NewCache(cacheDir, cfg.CacheTTLDuration())

	wpscanRotator := lazywphttp.NewKeyRotator(cfg.WPScanKeys)
	wfRotator := lazywphttp.NewKeyRotator(cfg.WordfenceKeys)
	nvdRotator := lazywphttp.NewKeyRotator(cfg.EffectiveNVDKeys())

	wpClient := client.NewWordPressClient(httpClient, it)
	wpscanClient := client.NewWPScanClient(httpClient, wpscanRotator, vulnCache)
	nvdClient := client.NewNVDClient(httpClient, nvdRotator, vulnCache)
	wfClient := client.NewWordfenceClient(httpClient, wfRotator, vulnCache)

	pdRotator := lazywphttp.NewKeyRotator(cfg.EffectivePDAPIKeys())

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
		VulnCache:  vulnCache,
		VulnAgg:    aggregator,
		Engine:     engine,
		WFClient:   wfClient,
		PDRotator:  pdRotator,
		ItemType:   it,
	}, nil
}
