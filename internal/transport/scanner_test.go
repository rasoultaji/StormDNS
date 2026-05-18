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
	"net"
	"testing"
	"time"

	"stormdns-go/internal/handshake"
)

// mkAuthResolver pretends to be a public resolver that ALSO acts as
// our auth NS for this test. For test simplicity, the entire UDP packet
// is treated as: [16-byte client_random][PSK-AEAD sealed PROBE envelope].
// The response is: [16-byte server_random][PSK-AEAD sealed PROBE_ACK envelope].
func mkAuthResolver(t *testing.T, psk []byte) string {
	t.Helper()
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 16+16 {
				continue
			}
			random := buf[:16]
			env := buf[16:n]
			plain, err := handshake.PSKAEADOpen(psk, "probe",
				handshake.DirClient, random, env, random)
			if err != nil {
				continue
			}
			srv := bytes.Repeat([]byte{0x77}, 16)
			ackEnv, _ := handshake.PSKAEADSeal(psk, "probe",
				handshake.DirServer, srv, plain, srv)
			resp := append(srv, ackEnv...)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestAuthenticityProbe_Pass(t *testing.T) {
	psk := bytes.Repeat([]byte{0x42}, 32)
	addr := mkAuthResolver(t, psk)
	ch, _ := NewUDP53Channel(addr, 2*time.Second)
	defer ch.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ok, err := ProbeAuthenticity(ctx, ch, psk)
	if err != nil {
		t.Fatalf("ProbeAuthenticity: %v", err)
	}
	if !ok {
		t.Fatal("expected authenticity probe to pass")
	}
}

func TestAuthenticityProbe_Reject_WrongPSK(t *testing.T) {
	psk := bytes.Repeat([]byte{0x42}, 32)
	addr := mkAuthResolver(t, psk)
	ch, _ := NewUDP53Channel(addr, 1*time.Second)
	defer ch.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ok, _ := ProbeAuthenticity(ctx, ch, bytes.Repeat([]byte{0x99}, 32))
	if ok {
		t.Fatal("expected probe to FAIL under wrong PSK")
	}
}
