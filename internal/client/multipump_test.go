// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"stormdns-go/internal/transport"
)

type errChannel struct {
	kind  transport.Kind
	err   error
	calls int32
}

func (e *errChannel) Query(_ context.Context, _ []byte) ([]byte, error) {
	atomic.AddInt32(&e.calls, 1)
	if e.err != nil {
		return nil, e.err
	}
	return []byte{0x77}, nil
}
func (e *errChannel) MaxResponseBytes() int    { return 1232 }
func (e *errChannel) Health() transport.Health { return transport.Health{} }
func (e *errChannel) Kind() transport.Kind     { return e.kind }
func (e *errChannel) Close() error             { return nil }

func TestMultiPump_PicksBestThenFailsOver(t *testing.T) {
	slow := &errChannel{kind: transport.Kind53UDP, err: errors.New("primary down")}
	fast := &errChannel{kind: transport.KindDoH}
	mp := NewMultiPump([]MultiPumpEntry{
		{Pump: NewV2Pump(slow, 4), Score: 10.0},
		{Pump: NewV2Pump(fast, 4), Score: 5.0},
	})
	defer mp.Close()

	resp, err := mp.Query(context.Background(), []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("empty response")
	}
	if atomic.LoadInt32(&slow.calls) != 1 {
		t.Fatalf("expected primary to be tried once, got %d", slow.calls)
	}
	if atomic.LoadInt32(&fast.calls) != 1 {
		t.Fatalf("expected failover to fast, got %d", fast.calls)
	}
}

func TestMultiPump_AllFail(t *testing.T) {
	a := &errChannel{kind: transport.Kind53UDP, err: errors.New("a")}
	b := &errChannel{kind: transport.KindDoH, err: errors.New("b")}
	mp := NewMultiPump([]MultiPumpEntry{
		{Pump: NewV2Pump(a, 4), Score: 10.0},
		{Pump: NewV2Pump(b, 4), Score: 5.0},
	})
	defer mp.Close()
	if _, err := mp.Query(context.Background(), []byte{1}); err == nil {
		t.Fatal("expected error when all pumps fail")
	}
}
