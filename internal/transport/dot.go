// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"
)

type DoTChannel struct {
	addr      string
	tlsConfig *tls.Config
	timeout   time.Duration

	mu     sync.Mutex
	conn   *tls.Conn
	health Health
}

func NewDoTChannel(addr string, timeout time.Duration, tlsConfig *tls.Config) (*DoTChannel, error) {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &DoTChannel{
		addr:      addr,
		tlsConfig: tlsConfig,
		timeout:   timeout,
		health:    Health{SuccessRate: 1.0, BudgetTokens: 200},
	}, nil
}

func (c *DoTChannel) ensureConn(ctx context.Context) (*tls.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	d := &tls.Dialer{Config: c.tlsConfig}
	raw, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("dot: dial: %w", err)
	}
	c.conn = raw.(*tls.Conn)
	return c.conn, nil
}

func (c *DoTChannel) Query(ctx context.Context, q []byte) ([]byte, error) {
	start := time.Now()
	conn, err := c.ensureConn(ctx)
	if err != nil {
		c.recordErr()
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = start.Add(c.timeout)
	}
	_ = conn.SetDeadline(deadline)

	frame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(q)))
	copy(frame[2:], q)
	if _, err := conn.Write(frame); err != nil {
		c.dropConn()
		c.recordErr()
		return nil, fmt.Errorf("dot: write: %w", err)
	}
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		c.dropConn()
		c.recordErr()
		return nil, fmt.Errorf("dot: read hdr: %w", err)
	}
	n := binary.BigEndian.Uint16(hdr)
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		c.dropConn()
		c.recordErr()
		return nil, fmt.Errorf("dot: read body: %w", err)
	}
	c.recordOK(time.Since(start))
	return buf, nil
}

func (c *DoTChannel) dropConn() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

func (c *DoTChannel) MaxResponseBytes() int { return 16384 }
func (c *DoTChannel) Kind() Kind            { return KindDoT }
func (c *DoTChannel) Close() error {
	c.dropConn()
	return nil
}

func (c *DoTChannel) Health() Health {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}

func (c *DoTChannel) recordOK(rtt time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.RTTEMA = ema(c.health.RTTEMA, rtt, 0.2)
	c.health.SuccessRate = ema01(c.health.SuccessRate, 1.0, 0.05)
}

func (c *DoTChannel) recordErr() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.LastError = time.Now()
	c.health.SuccessRate = ema01(c.health.SuccessRate, 0.0, 0.05)
}
