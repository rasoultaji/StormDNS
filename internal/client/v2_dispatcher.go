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
	"fmt"
	"time"

	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/handshake"
	"stormdns-go/internal/transport"
	"stormdns-go/internal/vpnproto"
)

// V2ClientSession is the result of a completed v2 1-RTT handshake.
type V2ClientSession struct {
	SessionID uint16
	Keys      handshake.SessionKeys
}

// RunV2Handshake performs the 1-RTT v2 handshake against a UDP/53 resolver.
func RunV2Handshake(ctx context.Context, resolverAddr string, psk []byte) (*V2ClientSession, error) {
	ch, err := transport.NewUDP53Channel(resolverAddr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer ch.Close()
	return RunV2HandshakeOn(ctx, ch, psk)
}

// RunV2HandshakeOn performs the 1-RTT v2 handshake using a provided QueryChannel.
// This allows callers to inject test channels or alternative transports.
//
// Wire convention:
//
//	INIT frame  EncryptedPayload = clientRandom (16 B) || sealed INIT envelope
//	ACK  frame  EncryptedPayload = serverRandom (16 B) || sealed INIT_ACK envelope
//
// The randoms are transmitted explicitly in the payload prefix rather than
// extracted from AAD, keeping the dispatcher decoupled from outer-frame encoding.
func RunV2HandshakeOn(ctx context.Context, ch transport.QueryChannel, psk []byte) (*V2ClientSession, error) {
	cs, env, err := handshake.ClientStart(psk, 0, time.Now().UTC(), nil)
	if err != nil {
		return nil, fmt.Errorf("v2 dispatcher: ClientStart: %w", err)
	}

	// Build INIT frame: EncryptedPayload = clientRandom (16 B) || sealed envelope.
	payload := append(append([]byte(nil), cs.ClientRandom...), env...)
	initFrame := vpnproto.V2Frame{
		Header:           vpnproto.V2Header{Type: Enums.PACKET_V2_INIT, ChCls: vpnproto.ChClsNarrow},
		EncryptedPayload: payload,
		Tag:              bytes.Repeat([]byte{0}, 16),
	}
	resp, err := ch.Query(ctx, initFrame.Marshal())
	if err != nil {
		return nil, fmt.Errorf("v2 dispatcher: INIT query: %w", err)
	}

	var ackFrame vpnproto.V2Frame
	if err := ackFrame.Unmarshal(resp); err != nil {
		return nil, fmt.Errorf("v2 dispatcher: ack unmarshal: %w", err)
	}
	if ackFrame.Header.Type != Enums.PACKET_V2_INIT_ACK {
		return nil, fmt.Errorf("v2 dispatcher: unexpected ack type 0x%x", ackFrame.Header.Type)
	}
	if len(ackFrame.EncryptedPayload) < 16 {
		return nil, fmt.Errorf("v2 dispatcher: ack payload too short (%d B)", len(ackFrame.EncryptedPayload))
	}
	serverRandom := ackFrame.EncryptedPayload[:16]
	ackEnv := ackFrame.EncryptedPayload[16:]

	if err := cs.Finish(psk, ackEnv, serverRandom); err != nil {
		return nil, fmt.Errorf("v2 dispatcher: Finish: %w", err)
	}
	return &V2ClientSession{SessionID: cs.SessionID, Keys: cs.Keys}, nil
}
