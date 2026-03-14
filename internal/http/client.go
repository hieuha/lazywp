package http

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/hieuha/lazywp/internal/config"
)

// Client wraps the standard HTTP client with retry, rate limiting, and proxy support.
type Client struct {
	inner       *http.Client
	rateLimiter *RateLimiter
	proxy       *ProxyRotator
	keyRotator  *KeyRotator
	maxRetries  int
	baseDelay   time.Duration
}

// NewClient creates an HTTP client from config.
func NewClient(cfg *config.Config) (*Client, error) {
	var proxy *ProxyRotator
	if len(cfg.Proxies) > 0 {
		var err error
		proxy, err = NewProxyRotator(cfg.Proxies, ProxyStrategy(cfg.ProxyStrategy))
		if err != nil {
			return nil, fmt.Errorf("proxy setup: %w", err)
		}
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	// Set proxy function if configured
	if proxy != nil {
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			return proxy.Next()
		}
	}

	return &Client{
		inner: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Minute,
		},
		rateLimiter: NewRateLimiter(cfg.RateLimits),
		proxy:       proxy,
		keyRotator:  NewKeyRotator(cfg.WPScanKeys),
		maxRetries:  cfg.RetryMax,
		baseDelay:   cfg.RetryBaseDelayDuration(),
	}, nil
}

// Do executes an HTTP request with rate limiting and retry logic.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	domain := req.URL.Hostname()

	if err := c.rateLimiter.Wait(ctx, domain); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}

	var lastErr error
	for attempt := range c.maxRetries + 1 {
		if attempt > 0 {
			delay := c.baseDelay * (1 << (attempt - 1)) // exponential backoff
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
			// Re-apply rate limit on retry
			if err := c.rateLimiter.Wait(ctx, domain); err != nil {
				return nil, fmt.Errorf("rate limit: %w", err)
			}
		}

		resp, err := c.inner.Do(req.WithContext(ctx))
		if err != nil {
			lastErr = err
			continue
		}

		// Success
		if resp.StatusCode < 500 && resp.StatusCode != 429 {
			return resp, nil
		}

		// Handle 429 Too Many Requests
		if resp.StatusCode == 429 {
			if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
				if secs, err := strconv.Atoi(retryAfter); err == nil {
					select {
					case <-ctx.Done():
						resp.Body.Close()
						return nil, ctx.Err()
					case <-time.After(time.Duration(secs) * time.Second):
					}
				}
			}
		}

		lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL)
		resp.Body.Close()
	}
	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// Get is a convenience method for GET requests.
func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req)
}

// GetBody fetches a URL and returns the body bytes.
func (c *Client) GetBody(ctx context.Context, url string) ([]byte, error) {
	resp, err := c.Get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// KeyRotator returns the client's key rotator for WPScan auth.
func (c *Client) GetKeyRotator() *KeyRotator {
	return c.keyRotator
}

// Inner returns the underlying http.Client (for download streaming).
func (c *Client) Inner() *http.Client {
	return c.inner
}
