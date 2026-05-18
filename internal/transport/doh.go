// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type DoHOption func(*dohOptions)

type dohOptions struct {
	tlsConfig *tls.Config
}

type DoHChannel struct {
	endpoint string
	client   *http.Client
	timeout  time.Duration

	mu     sync.Mutex
	health Health
}

func NewDoHChannel(endpoint string, timeout time.Duration, opts ...DoHOption) (*DoHChannel, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("doh: parse endpoint: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("doh: endpoint must be https, got %q", u.Scheme)
	}
	cfg := dohOptions{}
	for _, o := range opts {
		o(&cfg)
	}
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     cfg.tlsConfig,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	return &DoHChannel{
		endpoint: endpoint,
		client:   &http.Client{Transport: tr, Timeout: timeout},
		timeout:  timeout,
		health:   Health{SuccessRate: 1.0, BudgetTokens: 200},
	}, nil
}

func (c *DoHChannel) Query(ctx context.Context, q []byte) ([]byte, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(q))
	if err != nil {
		c.recordErr()
		return nil, fmt.Errorf("doh: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.client.Do(req)
	if err != nil {
		c.recordErr()
		return nil, fmt.Errorf("doh: do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.recordErr()
		return nil, fmt.Errorf("doh: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		c.recordErr()
		return nil, fmt.Errorf("doh: read body: %w", err)
	}
	c.recordOK(time.Since(start))
	return b, nil
}

func (c *DoHChannel) MaxResponseBytes() int { return 16384 }
func (c *DoHChannel) Kind() Kind            { return KindDoH }
func (c *DoHChannel) Close() error {
	c.client.CloseIdleConnections()
	return nil
}

func (c *DoHChannel) Health() Health {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}

func (c *DoHChannel) recordOK(rtt time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.RTTEMA = ema(c.health.RTTEMA, rtt, 0.2)
	c.health.SuccessRate = ema01(c.health.SuccessRate, 1.0, 0.05)
}

func (c *DoHChannel) recordErr() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.LastError = time.Now()
	c.health.SuccessRate = ema01(c.health.SuccessRate, 0.0, 0.05)
}
