// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"stormdns-go/internal/transport"
)

type fakeChannel struct {
	inflight int32
	maxSeen  int32
}

func (f *fakeChannel) Query(_ context.Context, _ []byte) ([]byte, error) {
	cur := atomic.AddInt32(&f.inflight, 1)
	for {
		prev := atomic.LoadInt32(&f.maxSeen)
		if cur <= prev || atomic.CompareAndSwapInt32(&f.maxSeen, prev, cur) {
			break
		}
	}
	time.Sleep(10 * time.Millisecond)
	atomic.AddInt32(&f.inflight, -1)
	return []byte{0xAA}, nil
}
func (f *fakeChannel) MaxResponseBytes() int      { return 4096 }
func (f *fakeChannel) Health() transport.Health   { return transport.Health{} }
func (f *fakeChannel) Kind() transport.Kind       { return transport.KindDoH }
func (f *fakeChannel) Close() error               { return nil }

func TestV2Pump_RespectsInflightCap(t *testing.T) {
	ch := &fakeChannel{}
	pump := NewV2Pump(ch, 4)
	defer pump.Close()

	var done atomic.Int32
	for i := 0; i < 32; i++ {
		go func() {
			_, _ = pump.Query(context.Background(), []byte{1, 2, 3})
			done.Add(1)
		}()
	}
	deadline := time.Now().Add(3 * time.Second)
	for done.Load() < 32 {
		if time.Now().After(deadline) {
			t.Fatalf("pump never drained: %d done", done.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ch.maxSeen > 4 {
		t.Fatalf("inflight cap violated: maxSeen=%d", ch.maxSeen)
	}
	if ch.maxSeen < 2 {
		t.Fatalf("pump didn't parallelize: maxSeen=%d", ch.maxSeen)
	}
}
