// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package mockresolver

import (
	"bytes"
	"context"
	"testing"
	"time"

	"stormdns-go/internal/transport"
)

func TestMockResolver_UDP53Roundtrip(t *testing.T) {
	m := New(Config{})
	defer m.Close()

	auth := func(q []byte) []byte {
		return q
	}
	addr := m.StartUDP(auth)

	ch, _ := transport.NewUDP53Channel(addr, time.Second)
	defer ch.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := ch.Query(ctx, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !bytes.Equal(r, []byte{1, 2, 3, 4}) {
		t.Fatalf("got %x", r)
	}
}

func TestMockResolver_DropRate(t *testing.T) {
	m := New(Config{LossRate: 1.0})
	defer m.Close()

	auth := func(q []byte) []byte { return q }
	addr := m.StartUDP(auth)

	ch, _ := transport.NewUDP53Channel(addr, 200*time.Millisecond)
	defer ch.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := ch.Query(ctx, []byte{1}); err == nil {
		t.Fatal("expected timeout under 100% drop")
	}
}
