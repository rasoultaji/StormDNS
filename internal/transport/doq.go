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

	"github.com/quic-go/quic-go"
)

// DoQChannel implements QueryChannel over DNS-over-QUIC (RFC 9250).
// One bidi QUIC stream is opened per query. ALPN is "doq".
type DoQChannel struct {
	addr      string
	tlsConfig *tls.Config
	timeout   time.Duration

	mu     sync.Mutex
	sess   *quic.Conn
	health Health
}

// NewDoQChannel creates a DoQChannel. The first query triggers the QUIC
// handshake. If tlsConfig is nil a minimal config with NextProtos=["doq"] is
// used; if it omits NextProtos, "doq" is appended.
func NewDoQChannel(addr string, timeout time.Duration, tlsConfig *tls.Config) (*DoQChannel, error) {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{NextProtos: []string{"doq"}}
	} else if len(tlsConfig.NextProtos) == 0 {
		c := tlsConfig.Clone()
		c.NextProtos = []string{"doq"}
		tlsConfig = c
	}
	return &DoQChannel{
		addr:      addr,
		tlsConfig: tlsConfig,
		timeout:   timeout,
		health:    Health{SuccessRate: 1.0, BudgetTokens: 200},
	}, nil
}

// ensure returns the live QUIC connection, dialling if necessary.
func (c *DoQChannel) ensure(ctx context.Context) (*quic.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != nil {
		return c.sess, nil
	}
	sess, err := quic.DialAddr(ctx, c.addr, c.tlsConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("doq: dial: %w", err)
	}
	c.sess = sess
	return sess, nil
}

// Query opens one bidi stream, writes a 2-byte length-prefixed request,
// half-closes the write side, and reads a 2-byte length-prefixed response.
func (c *DoQChannel) Query(ctx context.Context, q []byte) ([]byte, error) {
	start := time.Now()

	sess, err := c.ensure(ctx)
	if err != nil {
		c.recordErr()
		return nil, err
	}

	str, err := sess.OpenStreamSync(ctx)
	if err != nil {
		c.dropSess()
		c.recordErr()
		return nil, fmt.Errorf("doq: open stream: %w", err)
	}

	// Set stream deadline from context or channel timeout.
	if dl, ok := ctx.Deadline(); ok {
		_ = str.SetDeadline(dl)
	} else {
		_ = str.SetDeadline(time.Now().Add(c.timeout))
	}

	// Write 2-byte length prefix followed by the DNS message.
	frame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(q)))
	copy(frame[2:], q)
	if _, err := str.Write(frame); err != nil {
		_ = str.Close()
		c.recordErr()
		return nil, fmt.Errorf("doq: write: %w", err)
	}
	// Half-close the write side per RFC 9250 §4.2.
	if err := str.Close(); err != nil {
		c.recordErr()
		return nil, fmt.Errorf("doq: close write: %w", err)
	}

	// Read 2-byte length header then body.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(str, hdr); err != nil {
		c.recordErr()
		return nil, fmt.Errorf("doq: read hdr: %w", err)
	}
	n := binary.BigEndian.Uint16(hdr)
	buf := make([]byte, n)
	if _, err := io.ReadFull(str, buf); err != nil {
		c.recordErr()
		return nil, fmt.Errorf("doq: read body: %w", err)
	}

	c.recordOK(time.Since(start))
	return buf, nil
}

func (c *DoQChannel) dropSess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != nil {
		_ = c.sess.CloseWithError(0, "")
		c.sess = nil
	}
}

func (c *DoQChannel) MaxResponseBytes() int { return 16384 }
func (c *DoQChannel) Kind() Kind            { return KindDoQ }

// Close tears down the underlying QUIC connection.
func (c *DoQChannel) Close() error {
	c.dropSess()
	return nil
}

func (c *DoQChannel) Health() Health {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}

func (c *DoQChannel) recordOK(rtt time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.RTTEMA = ema(c.health.RTTEMA, rtt, 0.2)
	c.health.SuccessRate = ema01(c.health.SuccessRate, 1.0, 0.05)
}

func (c *DoQChannel) recordErr() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.LastError = time.Now()
	c.health.SuccessRate = ema01(c.health.SuccessRate, 0.0, 0.05)
}
