// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestCapabilityProbe_UDP53Success(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := buildBenignDNSResponse(buf[:n])
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	ch, _ := NewUDP53Channel(pc.LocalAddr().String(), time.Second)
	defer ch.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cap, err := ProbeCapability(ctx, ch)
	if err != nil {
		t.Fatalf("ProbeCapability: %v", err)
	}
	if !cap.Working {
		t.Fatal("expected working=true")
	}
	if cap.RTT <= 0 {
		t.Fatal("expected positive RTT")
	}
}

func TestCapabilityProbe_TimeoutMarksUnhealthy(t *testing.T) {
	ch, _ := NewUDP53Channel("127.0.0.1:1", 200*time.Millisecond)
	defer ch.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	cap, err := ProbeCapability(ctx, ch)
	if err == nil && cap.Working {
		t.Fatal("expected probe to fail or mark unhealthy")
	}
}

func buildBenignDNSResponse(q []byte) []byte {
	r := make([]byte, len(q))
	copy(r, q)
	if len(r) >= 4 {
		r[2] = 0x81
		r[3] = 0x80
	}
	return r
}
