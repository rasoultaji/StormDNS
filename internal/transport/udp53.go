// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type UDP53Channel struct {
	addr    *net.UDPAddr
	timeout time.Duration
	mu      sync.Mutex
	health  Health
}

func NewUDP53Channel(resolverAddr string, timeout time.Duration) (*UDP53Channel, error) {
	ua, err := net.ResolveUDPAddr("udp", resolverAddr)
	if err != nil {
		return nil, fmt.Errorf("udp53: resolve %s: %w", resolverAddr, err)
	}
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &UDP53Channel{addr: ua, timeout: timeout,
		health: Health{SuccessRate: 1.0, BudgetTokens: 200}}, nil
}

func (c *UDP53Channel) Query(ctx context.Context, q []byte) ([]byte, error) {
	start := time.Now()
	conn, err := net.DialUDP("udp", nil, c.addr)
	if err != nil {
		c.recordErr()
		return nil, fmt.Errorf("udp53: dial: %w", err)
	}
	defer conn.Close()

	deadline := start.Add(c.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(q); err != nil {
		c.recordErr()
		return nil, fmt.Errorf("udp53: write: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		c.recordErr()
		return nil, fmt.Errorf("udp53: read: %w", err)
	}
	c.recordOK(time.Since(start))
	return buf[:n], nil
}

func (c *UDP53Channel) MaxResponseBytes() int { return 4096 }
func (c *UDP53Channel) Kind() Kind            { return Kind53UDP }
func (c *UDP53Channel) Close() error          { return nil }

func (c *UDP53Channel) Health() Health {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}

func (c *UDP53Channel) recordOK(rtt time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.RTTEMA = ema(c.health.RTTEMA, rtt, 0.2)
	c.health.SuccessRate = ema01(c.health.SuccessRate, 1.0, 0.05)
}

func (c *UDP53Channel) recordErr() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.LastError = time.Now()
	c.health.SuccessRate = ema01(c.health.SuccessRate, 0.0, 0.05)
}

func ema(prev, sample time.Duration, alpha float64) time.Duration {
	if prev == 0 {
		return sample
	}
	return time.Duration(float64(prev)*(1-alpha) + float64(sample)*alpha)
}

func ema01(prev, sample, alpha float64) float64 {
	return prev*(1-alpha) + sample*alpha
}
