package downloader

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hieuha/lazywp/internal/client"
	"github.com/hieuha/lazywp/internal/storage"
)

func TestDownloadOne_Success(t *testing.T) {
	const slug = "my-plugin"
	const version = "1.2.3"
	zipContent := []byte("PK fake zip content")

	// Serve both HEAD (URL check) and GET (file download).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(zipContent) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	provider := &mockWPProvider{
		info: &client.ItemInfo{
			Slug:    slug,
			Name:    "My Plugin",
			Version: version,
			Author:  "Test Author",
		},
		downloadURL: srv.URL + "/" + slug + "." + version + ".zip",
	}

	engine, stor := buildTestEngineWithMock(t, provider)

	result, err := engine.DownloadOne(context.Background(), slug, version, client.Plugin)
	if err != nil {
		t.Fatalf("DownloadOne: %v", err)
	}
	if result.Slug != slug {
		t.Errorf("result.Slug = %q, want %q", result.Slug, slug)
	}
	if result.Version != version {
		t.Errorf("result.Version = %q, want %q", result.Version, version)
	}

	// Verify metadata was written.
	if !stor.Exists(string(client.Plugin), slug, version) {
		t.Error("storage.Exists returned false after successful download")
	}
}

func TestDownloadOne_GetInfoError(t *testing.T) {
	provider := &mockWPProvider{
		infoErr: errors.New("API unavailable"),
	}
	engine, _ := buildTestEngineWithMock(t, provider)

	_, err := engine.DownloadOne(context.Background(), "broken-plugin", "1.0.0", client.Plugin)
	if err == nil {
		t.Fatal("expected error from GetInfo failure, got nil")
	}
	if !strings.Contains(err.Error(), "get info") {
		t.Errorf("error = %q, want 'get info' prefix", err)
	}
}

func TestDownloadOne_VersionResolution(t *testing.T) {
	const slug = "ver-plugin"
	const latestVersion = "3.0.0"
	zipContent := []byte("fake zip")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			w.Write(zipContent) //nolint:errcheck
		}
	}))
	t.Cleanup(srv.Close)

	provider := &mockWPProvider{
		info: &client.ItemInfo{
			Slug:    slug,
			Name:    "Ver Plugin",
			Version: latestVersion,
		},
		downloadURL: srv.URL + "/test.zip",
	}
	engine, _ := buildTestEngineWithMock(t, provider)

	// Pass empty version → should resolve to info.Version.
	result, err := engine.DownloadOne(context.Background(), slug, "", client.Plugin)
	if err != nil {
		t.Fatalf("DownloadOne: %v", err)
	}
	if result.Version != latestVersion {
		t.Errorf("resolved version = %q, want %q", result.Version, latestVersion)
	}
}

func TestDownloadOne_AlreadyExists_AfterVersionResolution(t *testing.T) {
	const slug = "resolved-plugin"
	const version = "2.5.0"

	provider := &mockWPProvider{
		info: &client.ItemInfo{Slug: slug, Name: slug, Version: version},
	}
	engine, stor := buildTestEngineWithMock(t, provider)

	// Pre-create metadata for the resolved version.
	meta := &storage.Metadata{
		Slug:         slug,
		Name:         slug,
		Type:         string(client.Plugin),
		Version:      version,
		DownloadedAt: time.Now(),
	}
	if err := stor.WriteMetadata(meta); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}

	// Empty version → resolves to version → hits already-exists guard.
	result, err := engine.DownloadOne(context.Background(), slug, "", client.Plugin)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
	if result == nil || result.Version != version {
		t.Errorf("result = %v, want version=%q", result, version)
	}
}

func TestDownloadOne_Force(t *testing.T) {
	const slug = "force-plugin"
	const version = "1.0.0"
	zipContent := []byte("fresh zip")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			w.Write(zipContent) //nolint:errcheck
		}
	}))
	t.Cleanup(srv.Close)

	provider := &mockWPProvider{
		info:        &client.ItemInfo{Slug: slug, Name: "Force Plugin", Version: version},
		downloadURL: srv.URL + "/test.zip",
	}
	engine, stor := buildTestEngineWithMock(t, provider)

	// Pre-create metadata to simulate existing download.
	meta := &storage.Metadata{
		Slug:         slug,
		Name:         slug,
		Type:         string(client.Plugin),
		Version:      version,
		DownloadedAt: time.Now(),
	}
	if err := stor.WriteMetadata(meta); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}

	// force=true should bypass ErrAlreadyExists and re-download.
	result, err := engine.DownloadOne(context.Background(), slug, version, client.Plugin, true)
	if err != nil {
		t.Fatalf("DownloadOne with force: %v", err)
	}
	if result.Version != version {
		t.Errorf("result.Version = %q, want %q", result.Version, version)
	}
}
