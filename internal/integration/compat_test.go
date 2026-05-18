// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package integration

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/client"
	"stormdns-go/internal/udpserver"
	"stormdns-go/internal/vpnproto"
)

// newV2Server starts an in-process resolver/auth-NS adapter that
// implements the V2 INIT/INIT_ACK exchange. Returns the listen addr
// and the registry (for follow-on assertions).
func newV2Server(t *testing.T, psk []byte, acceptV2 bool) (string, *udpserver.V2SessionRegistry) {
	t.Helper()
	reg := udpserver.NewV2SessionRegistry(psk)
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			raw := append([]byte(nil), buf[:n]...)
			if !acceptV2 {
				continue // simulate v1-only server: drop v2 traffic silently
			}
			v2 := udpserver.DecodeV2FrameFromQueryBytes(raw)
			if v2 == nil || v2.Header.Type != Enums.PACKET_V2_INIT {
				continue
			}
			if len(v2.EncryptedPayload) < 16 {
				continue
			}
			cr := v2.EncryptedPayload[:16]
			env := v2.EncryptedPayload[16:]
			ack, sess, err := reg.AcceptInit(env, cr, nil, time.Now())
			if err != nil {
				continue
			}
			resp := vpnproto.V2Frame{
				Header: vpnproto.V2Header{
					Type:  Enums.PACKET_V2_INIT_ACK,
					ChCls: vpnproto.ChClsNarrow,
				},
				EncryptedPayload: append(append([]byte(nil), sess.ServerRandom...), ack...),
				Tag:              bytes.Repeat([]byte{0}, 16),
			}
			_, _ = pc.WriteTo(resp.Marshal(), addr)
		}
	}()
	return pc.LocalAddr().String(), reg
}

func TestCompat_V2ClientV2Server(t *testing.T) {
	psk := bytes.Repeat([]byte{0x01}, 32)
	addr, _ := newV2Server(t, psk, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	sess, err := client.RunV2Handshake(ctx, addr, psk)
	if err != nil {
		t.Fatalf("RunV2Handshake: %v", err)
	}
	if sess == nil || sess.SessionID == 0 {
		t.Fatal("session not established")
	}
}

func TestCompat_V2ClientV1Server_ReturnsError(t *testing.T) {
	psk := bytes.Repeat([]byte{0x02}, 32)
	addr, _ := newV2Server(t, psk, false)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err := client.RunV2Handshake(ctx, addr, psk)
	if err == nil {
		t.Fatal("expected handshake to fail against v1-only server")
	}
}
