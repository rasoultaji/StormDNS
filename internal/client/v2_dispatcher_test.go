// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package client

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/handshake"
	"stormdns-go/internal/udpserver"
	"stormdns-go/internal/vpnproto"
)

// mkV2AuthResolverAdapter pretends to be a public resolver that immediately
// delivers to our auth NS. For test simplicity, the entire UDP packet IS
// the v2 frame bytes (no DNS-label encoding). The response is the v2
// frame bytes of the INIT_ACK.
func mkV2AuthResolverAdapter(t *testing.T, psk []byte) (string, *udpserver.V2SessionRegistry) {
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
			v2 := udpserver.DecodeV2FrameFromQueryBytes(raw)
			if v2 == nil {
				continue
			}
			if v2.Header.Type != Enums.PACKET_V2_INIT {
				continue
			}
			// The client_random comes from the test convention: it's
			// packed at the front of the v2 frame's EncryptedPayload.
			// Look at v2_dispatcher.go to see exactly how RunV2Handshake
			// wraps the INIT envelope.
			// For this naked-test convention, the dispatcher embeds:
			//   EncryptedPayload = clientRandom (16B) || sealed INIT envelope
			if len(v2.EncryptedPayload) < 16 {
				continue
			}
			cr := v2.EncryptedPayload[:16]
			env := v2.EncryptedPayload[16:]
			ack, sess, err := reg.AcceptInit(env, cr, nil, time.Now())
			if err != nil {
				continue
			}
			// Build a V2_INIT_ACK frame with EncryptedPayload = serverRandom || ack
			respFrame := vpnproto.V2Frame{
				Header: vpnproto.V2Header{
					Type: Enums.PACKET_V2_INIT_ACK, ChCls: vpnproto.ChClsNarrow,
				},
				EncryptedPayload: append(append([]byte(nil), sess.ServerRandom...), ack...),
				Tag:              bytes.Repeat([]byte{0}, 16),
			}
			_, _ = pc.WriteTo(respFrame.Marshal(), addr)
		}
	}()
	return pc.LocalAddr().String(), reg
}

func TestV2Dispatcher_HandshakeCompletes(t *testing.T) {
	psk := bytes.Repeat([]byte{0x55}, 32)
	addr, _ := mkV2AuthResolverAdapter(t, psk)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sess, err := RunV2Handshake(ctx, addr, psk)
	if err != nil {
		t.Fatalf("RunV2Handshake: %v", err)
	}
	if sess == nil || sess.SessionID == 0 {
		t.Fatal("session not established")
	}
	_ = handshake.DefaultClockSkew
}
