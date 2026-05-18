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
)

func mkUDPEchoResolver(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestUDP53_QueryEchoes(t *testing.T) {
	addr := mkUDPEchoResolver(t)
	ch, err := NewUDP53Channel(addr, 2*time.Second)
	if err != nil {
		t.Fatalf("NewUDP53Channel: %v", err)
	}
	defer ch.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	q := []byte{0x01, 0x02, 0x03, 0x04}
	r, err := ch.Query(ctx, q)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !bytes.Equal(r, q) {
		t.Fatalf("echo mismatch: got %x want %x", r, q)
	}
	if ch.Kind() != Kind53UDP {
		t.Fatalf("Kind = %v", ch.Kind())
	}
}
