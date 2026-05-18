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
	"testing"
	"time"

	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/client"
	"stormdns-go/internal/test/mockresolver"
	"stormdns-go/internal/udpserver"
	"stormdns-go/internal/vpnproto"
)

func TestHostile_HandshakeUnderLoss(t *testing.T) {
	psk := bytes.Repeat([]byte{0x04}, 32)
	reg := udpserver.NewV2SessionRegistry(psk)
	m := mockresolver.New(mockresolver.Config{
		LossRate:   0.05,
		LatencyMin: 150 * time.Millisecond,
		LatencyMax: 250 * time.Millisecond,
	})
	defer m.Close()
	addr := m.StartUDP(func(q []byte) []byte {
		v2 := udpserver.DecodeV2FrameFromQueryBytes(q)
		if v2 == nil || v2.Header.Type != Enums.PACKET_V2_INIT {
			return nil
		}
		if len(v2.EncryptedPayload) < 16 {
			return nil
		}
		cr := v2.EncryptedPayload[:16]
		env := v2.EncryptedPayload[16:]
		ack, sess, err := reg.AcceptInit(env, cr, time.Now())
		if err != nil {
			return nil
		}
		resp := vpnproto.V2Frame{
			Header: vpnproto.V2Header{
				Type:  Enums.PACKET_V2_INIT_ACK,
				ChCls: vpnproto.ChClsNarrow,
			},
			EncryptedPayload: append(append([]byte(nil), sess.ServerRandom...), ack...),
			Tag:              bytes.Repeat([]byte{0}, 16),
		}
		return resp.Marshal()
	})

	// Even with 5% loss + 250ms latency, the client should complete the
	// handshake within a few retries.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := retryHandshake(ctx, addr, psk, 10)
	if err != nil {
		t.Fatalf("handshake under hostile network: %v", err)
	}
	if sess == nil {
		t.Fatal("nil session")
	}
}

// retryHandshake mimics the dispatcher's retry-on-timeout behavior.
func retryHandshake(ctx context.Context, addr string, psk []byte, attempts int) (*client.V2ClientSession, error) {
	var last error
	for i := 0; i < attempts; i++ {
		sub, cancel := context.WithTimeout(ctx, 2*time.Second)
		sess, err := client.RunV2Handshake(sub, addr, psk)
		cancel()
		if err == nil {
			return sess, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}
