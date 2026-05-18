// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package mockresolver

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

// Config holds failure-injection parameters for the mock resolver.
type Config struct {
	// LossRate is the probability [0.0, 1.0] that a query is silently dropped.
	LossRate float64
	// LatencyMin / LatencyMax add artificial delay before responding.
	LatencyMin time.Duration
	LatencyMax time.Duration
	// Sinkhole, if non-nil, overrides the AuthHandler for all queries.
	Sinkhole func(q []byte) []byte
	// Rand is the random source; a seeded source is created if nil.
	Rand *rand.Rand
}

// AuthHandler is the callback invoked with each incoming query.
// It returns the response bytes to send back to the caller.
type AuthHandler func(q []byte) []byte

// MockResolver is a lightweight in-process UDP listener that simulates a
// public DNS resolver with configurable failure injection.
type MockResolver struct {
	cfg    Config
	mu     sync.Mutex
	randMu sync.Mutex
	conns  []interface{ Close() error }
}

// New creates a MockResolver with the given Config.
func New(cfg Config) *MockResolver {
	if cfg.Rand == nil {
		cfg.Rand = rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec
	}
	return &MockResolver{cfg: cfg}
}

// StartUDP binds a UDP listener on an OS-assigned loopback port, starts
// serving in a background goroutine, and returns the "host:port" address.
// Panics on listen failure (test helper).
func (m *MockResolver) StartUDP(auth AuthHandler) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	m.mu.Lock()
	m.conns = append(m.conns, pc)
	m.mu.Unlock()
	go m.serveUDP(pc, auth)
	return pc.LocalAddr().String()
}

// Close shuts down all listeners started by this MockResolver.
func (m *MockResolver) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.conns {
		_ = c.Close()
	}
	m.conns = nil
	return nil
}

// serveUDP is the per-listener read loop.
func (m *MockResolver) serveUDP(pc net.PacketConn, auth AuthHandler) {
	buf := make([]byte, 65536)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			// Listener was closed — normal shutdown.
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			m.maybeSleep()
			if m.cfg.LossRate > 0 && m.randFloat64() < m.cfg.LossRate {
				return // drop
			}
			var resp []byte
			if m.cfg.Sinkhole != nil {
				resp = m.cfg.Sinkhole(q)
			} else {
				resp = auth(q)
			}
			_, _ = pc.WriteTo(resp, addr)
		}()
	}
}

// maybeSleep injects artificial latency when configured.
func (m *MockResolver) maybeSleep() {
	if m.cfg.LatencyMin <= 0 && m.cfg.LatencyMax <= 0 {
		return
	}
	span := m.cfg.LatencyMax - m.cfg.LatencyMin
	if span < 0 {
		span = 0
	}
	d := m.cfg.LatencyMin + time.Duration(m.randInt63n(int64(span)+1))
	time.Sleep(d)
}

// randFloat64 is a concurrency-safe wrapper around cfg.Rand.Float64().
func (m *MockResolver) randFloat64() float64 {
	m.randMu.Lock()
	defer m.randMu.Unlock()
	return m.cfg.Rand.Float64()
}

// randInt63n is a concurrency-safe wrapper around cfg.Rand.Int63n().
func (m *MockResolver) randInt63n(n int64) int64 {
	m.randMu.Lock()
	defer m.randMu.Unlock()
	return m.cfg.Rand.Int63n(n)
}
