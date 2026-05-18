//go:build livenet

// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"stormdns-go/internal/transport"
)

func TestLiveResolver_BasicProbe(t *testing.T) {
	psk := os.Getenv("PHANTOM_DNS_PROBE_PSK")
	if psk == "" {
		t.Skip("PHANTOM_DNS_PROBE_PSK must be set for this test")
	}
	ch, err := transport.NewUDP53Channel("1.1.1.1:53", 3*time.Second)
	if err != nil {
		t.Fatalf("NewUDP53Channel: %v", err)
	}
	defer ch.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, err := transport.ProbeAuthenticity(ctx, ch, []byte(psk))
	if err != nil {
		t.Fatalf("ProbeAuthenticity: %v", err)
	}
	if !ok {
		t.Fatal("authenticity probe failed against live resolver")
	}
}
