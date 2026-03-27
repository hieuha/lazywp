package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// testClient builds a Client pointing at the given test server.
// maxRetries=2, baseDelay=1ms keeps tests fast.
func testClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := &Client{
		inner:       srv.Client(),
		rateLimiter: NewRateLimiter(map[string]float64{}),
		maxRetries:  2,
		baseDelay:   1 * time.Millisecond,
	}
	return c, srv
}

func TestClient_Do_Success(t *testing.T) {
	c, srv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
}

func TestClient_Do_Retry5xx(t *testing.T) {
	var calls atomic.Int32
	c, srv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200 after retry, got %d", resp.StatusCode)
	}
	if calls.Load() != 2 {
		t.Errorf("want 2 calls, got %d", calls.Load())
	}
}

func TestClient_Do_MaxRetriesExceeded(t *testing.T) {
	var calls atomic.Int32
	c, srv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	_, err := c.Do(context.Background(), req)
	if err == nil {
		t.Fatal("expected error after max retries, got nil")
	}
	// maxRetries=2 means 3 total attempts
	if calls.Load() != 3 {
		t.Errorf("want 3 total calls, got %d", calls.Load())
	}
}

func TestClient_Do_429PassThrough(t *testing.T) {
	c, srv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("want 429, got %d", resp.StatusCode)
	}
}

func TestClient_Do_ContextCancel(t *testing.T) {
	// Block inside the handler until context is cancelled.
	started := make(chan struct{})
	c, srv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		// Wait until the request context is cancelled.
		<-r.Context().Done()
		w.WriteHeader(http.StatusOK)
	})

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)

	done := make(chan error, 1)
	go func() {
		_, err := c.Do(ctx, req)
		done <- err
	}()

	<-started
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error after context cancel, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Do to return")
	}
}

func TestClient_Get_Success(t *testing.T) {
	c, srv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("want GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	})

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
}

func TestClient_GetBody_Success(t *testing.T) {
	want := []byte(`{"hello":"world"}`)
	c, srv := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(want) //nolint:errcheck
	})

	got, err := c.GetBody(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("want %s, got %s", want, got)
	}
}
