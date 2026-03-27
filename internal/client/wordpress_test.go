package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	lazywphttp "github.com/hieuha/lazywp/internal/http"
)

// redirectTransport rewrites all outbound request URLs to the given test server URL,
// preserving path and query so handlers can inspect them. This allows clients that
// hardcode API base URLs (e.g. wpAPIBase) to be tested against httptest.Server.
type redirectTransport struct {
	base      *url.URL
	transport http.RoundTripper
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = rt.base.Scheme
	clone.URL.Host = rt.base.Host
	return rt.transport.RoundTrip(clone)
}

// newTestHTTPClient returns a lazywphttp.Client that redirects all requests to srv.
func newTestHTTPClient(srv *httptest.Server) *lazywphttp.Client {
	base, _ := url.Parse(srv.URL)
	inner := &http.Client{
		Transport: &redirectTransport{
			base:      base,
			transport: srv.Client().Transport,
		},
	}
	return lazywphttp.NewClientWithInner(inner)
}

func TestWordPressClient_GetInfo_Plugin(t *testing.T) {
	payload := ItemInfo{
		Slug:    "akismet",
		Name:    "Akismet Anti-Spam",
		Version: "5.3",
		Author:  "Automattic &amp; Friends",
	}
	body, _ := json.Marshal(payload)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	wc := &WordPressClient{
		http:     newTestHTTPClient(srv),
		itemType: Plugin,
	}
	// Override the URL by monkey-patching via a wrapper server that proxies to our srv.
	// Instead, we replace the URL construction — since infoURL is unexported, we use a
	// server that always returns the payload regardless of path.
	info, err := wc.GetInfo(context.Background(), "akismet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Slug != "akismet" {
		t.Errorf("want slug=akismet, got %q", info.Slug)
	}
	// DecodeNames should have run — HTML entities decoded.
	if info.Author != "Automattic & Friends" {
		t.Errorf("want decoded author, got %q", info.Author)
	}
	if info.Type != Plugin {
		t.Errorf("want type=plugin, got %v", info.Type)
	}
}

func TestWordPressClient_GetInfo_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	wc := &WordPressClient{http: newTestHTTPClient(srv), itemType: Plugin}
	_, err := wc.GetInfo(context.Background(), "nonexistent-plugin")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestWordPressClient_GetInfo_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	wc := &WordPressClient{http: newTestHTTPClient(srv), itemType: Plugin}
	_, err := wc.GetInfo(context.Background(), "some-plugin")
	if err == nil {
		t.Fatal("expected error for 500, got nil")
	}
}

func TestWordPressClient_GetInfo_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not-json")) //nolint:errcheck
	}))
	defer srv.Close()

	wc := &WordPressClient{http: newTestHTTPClient(srv), itemType: Plugin}
	_, err := wc.GetInfo(context.Background(), "some-plugin")
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func TestWordPressClient_GetVersions(t *testing.T) {
	payload := ItemInfo{
		Slug:    "classic-editor",
		Version: "1.6.3",
		Versions: FlexVersions{
			"1.6.3": "https://downloads.wordpress.org/classic-editor.1.6.3.zip",
			"1.6.2": "https://downloads.wordpress.org/classic-editor.1.6.2.zip",
			"trunk": "https://downloads.wordpress.org/classic-editor.zip",
		},
	}
	body, _ := json.Marshal(payload)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	wc := &WordPressClient{http: newTestHTTPClient(srv), itemType: Plugin}
	versions, err := wc.GetVersions(context.Background(), "classic-editor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("want 2 versions (trunk excluded), got %d", len(versions))
	}
	if _, ok := versions["trunk"]; ok {
		t.Error("trunk should be excluded from versions")
	}
}

func TestWordPressClient_DownloadURL_WithVersion(t *testing.T) {
	wc := &WordPressClient{itemType: Plugin}
	got := wc.DownloadURL("akismet", "5.3")
	want := "https://downloads.wordpress.org/plugin/akismet.5.3.zip"
	if got != want {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestWordPressClient_DownloadURL_NoVersion(t *testing.T) {
	wc := &WordPressClient{itemType: Plugin}
	got := wc.DownloadURL("akismet", "")
	want := "https://downloads.wordpress.org/plugin/akismet.zip"
	if got != want {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestWordPressClient_DownloadURL_Theme(t *testing.T) {
	wc := &WordPressClient{itemType: Theme}
	got := wc.DownloadURL("astra", "3.9.0")
	want := "https://downloads.wordpress.org/theme/astra.3.9.0.zip"
	if got != want {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestWordPressClient_Browse_SinglePage(t *testing.T) {
	br := BrowseResponse{
		Info: PageInfo{Page: 1, Pages: 1, Results: 2},
		Plugins: []ItemInfo{
			{Slug: "woocommerce", Name: "WooCommerce"},
			{Slug: "jetpack", Name: "Jetpack"},
		},
	}
	body, _ := json.Marshal(br)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	wc := &WordPressClient{http: newTestHTTPClient(srv), itemType: Plugin}
	items, err := wc.Browse(context.Background(), "popular", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 2 {
		t.Errorf("want 2 items, got %d", len(items))
	}
}

func TestWordPressClient_Browse_LimitTruncates(t *testing.T) {
	br := BrowseResponse{
		Info: PageInfo{Page: 1, Pages: 1, Results: 5},
		Plugins: []ItemInfo{
			{Slug: "p1"}, {Slug: "p2"}, {Slug: "p3"}, {Slug: "p4"}, {Slug: "p5"},
		},
	}
	body, _ := json.Marshal(br)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	wc := &WordPressClient{http: newTestHTTPClient(srv), itemType: Plugin}
	items, err := wc.Browse(context.Background(), "popular", 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 3 {
		t.Errorf("want 3 items after truncation, got %d", len(items))
	}
}

func TestWordPressClient_Browse_MultiPage(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		var br BrowseResponse
		if page == 1 {
			br = BrowseResponse{
				Info:    PageInfo{Page: 1, Pages: 2, Results: 4},
				Plugins: []ItemInfo{{Slug: "p1"}, {Slug: "p2"}},
			}
		} else {
			br = BrowseResponse{
				Info:    PageInfo{Page: 2, Pages: 2, Results: 4},
				Plugins: []ItemInfo{{Slug: "p3"}, {Slug: "p4"}},
			}
		}
		body, _ := json.Marshal(br)
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	wc := &WordPressClient{http: newTestHTTPClient(srv), itemType: Plugin}
	items, err := wc.Browse(context.Background(), "popular", 300) // more than 250 per page triggers multi-page
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 4 {
		t.Errorf("want 4 items across 2 pages, got %d", len(items))
	}
}

func TestWordPressClient_Browse_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	wc := &WordPressClient{http: newTestHTTPClient(srv), itemType: Plugin}
	_, err := wc.Browse(context.Background(), "popular", 10)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestWordPressClient_Search(t *testing.T) {
	br := BrowseResponse{
		Info:    PageInfo{Page: 1, Pages: 1, Results: 1},
		Plugins: []ItemInfo{{Slug: "akismet", Name: "Akismet"}},
	}
	body, _ := json.Marshal(br)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("request[search]") == "" {
			// Accept any search — the URL is constructed by Browse/Search
		}
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()

	wc := &WordPressClient{http: newTestHTTPClient(srv), itemType: Plugin}
	items, err := wc.Search(context.Background(), "akismet", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("want 1 result, got %d", len(items))
	}
}

func TestWordPressClient_infoURL_Plugin(t *testing.T) {
	wc := &WordPressClient{itemType: Plugin}
	got := wc.infoURL("akismet")
	want := fmt.Sprintf("%s/plugins/info/1.0/akismet.json", wpAPIBase)
	if got != want {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestWordPressClient_infoURL_Theme(t *testing.T) {
	wc := &WordPressClient{itemType: Theme}
	got := wc.infoURL("astra")
	want := fmt.Sprintf("%s/themes/info/1.2/astra", wpAPIBase)
	if got != want {
		t.Errorf("want %s, got %s", want, got)
	}
}
