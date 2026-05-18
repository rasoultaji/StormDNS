// Copyright (c) 2025 StormDNS Authors. All rights reserved.
// SPDX-License-Identifier: MIT
//
// ██████  ██   ██  █████  ███    ██ ████████  ██████  ███    ███     ██████  ███    ██ ███████
// ██   ██ ██   ██ ██   ██ ████   ██    ██    ██    ██ ████  ████     ██   ██ ████   ██ ██
// ██████  ███████ ███████ ██ ██  ██    ██    ██    ██ ██ ████ ██     ██   ██ ██ ██  ██ ███████
// ██      ██   ██ ██   ██ ██  ██ ██    ██    ██    ██ ██  ██  ██     ██   ██ ██  ██ ██      ██
// ██      ██   ██ ██   ██ ██   ████    ██     ██████  ██      ██     ██████  ██   ████ ███████

package udpserver

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"stormdns-go/internal/config"
	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/handshake"
	"stormdns-go/internal/security"
	VpnProto "stormdns-go/internal/vpnproto"
)

func TestV2Session_HandshakeAccept(t *testing.T) {
	psk := bytes.Repeat([]byte{0x55}, 32)
	reg := NewV2SessionRegistry(psk)

	// ClientStart returns (*ClientState, env, err).
	cs, env, err := handshake.ClientStart(psk, 0, time.Now().UTC())
	if err != nil {
		t.Fatalf("ClientStart: %v", err)
	}

	// AcceptInit takes the env + clientRandom.
	// Server constructs its own server_random internally.
	ack, sess, err := reg.AcceptInit(env, cs.ClientRandom, time.Now())
	if err != nil {
		t.Fatalf("AcceptInit: %v", err)
	}
	if sess == nil {
		t.Fatal("nil session")
	}
	// Client.Finish takes (psk, ackEnv, serverRandom)
	if err := cs.Finish(psk, ack, sess.ServerRandom); err != nil {
		t.Fatalf("Client.Finish: %v", err)
	}
	if !bytes.Equal(cs.Keys.ClientToServer, sess.Keys.ClientToServer) {
		t.Fatal("keys diverged across sides")
	}
	if reg.Get(sess.SessionID) == nil {
		t.Fatal("registry didn't store the session")
	}
}

func TestV2Session_AcceptInit_RejectsReplay(t *testing.T) {
	psk := bytes.Repeat([]byte{0x55}, 32)
	reg := NewV2SessionRegistry(psk)

	cs, env, _ := handshake.ClientStart(psk, 0, time.Now().UTC())
	_, _, err := reg.AcceptInit(env, cs.ClientRandom, time.Now())
	if err != nil {
		t.Fatalf("first accept: %v", err)
	}
	_, _, err = reg.AcceptInit(env, cs.ClientRandom, time.Now())
	if err == nil {
		t.Fatal("expected replay to be rejected")
	}
}

// minimalServerConfig returns a ServerConfig with only the fields that New()
// requires to not panic. Domain is left nil; only codec-keyed fields matter.
func minimalServerConfig() config.ServerConfig {
	cfg := config.ServerConfig{
		MaxPacketSize:               1024,
		MaxConcurrentRequests:       4,
		DNSRequestWorkers:           1,
		DeferredSessionWorkers:      1,
		DeferredSessionQueueLimit:   8,
		SessionOrphanQueueInitialCap: 4,
		StreamQueueInitialCapacity:  4,
		DNSFragmentStoreCapacity:    4,
		SOCKS5FragmentStoreCapacity: 4,
		MaxStreamsPerSession:         4,
		SessionInitReuseTTLSeconds:  60,
		RecentlyClosedStreamTTLSeconds: 60,
		RecentlyClosedStreamCap:     10,
		MinVPNLabelLength:           3,
		DataEncryptionMethod:        1,
		SupportedUploadCompressionTypes:   []int{0},
		SupportedDownloadCompressionTypes: []int{0},
	}
	return cfg
}

// TestServerHandleV2_INITRegistersSession verifies that handleV2 with a
// PACKET_V2_INIT frame runs the handshake end-to-end and stores the new
// session in s.v2sessions. It also checks that the DNS response contains a
// parseable INIT_ACK V2Frame.
func TestServerHandleV2_INITRegistersSession(t *testing.T) {
	// Use a 32-char hex key so security.NewCodec(method=1) derives a 32-byte key.
	rawKey := "0102030405060708090a0b0c0d0e0f10"
	codec, err := security.NewCodec(1, rawKey)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	cfg := minimalServerConfig()
	srv := New(cfg, nil, codec)
	if srv.v2sessions == nil {
		t.Fatal("v2sessions not initialised by New()")
	}

	psk := codec.RawKey()

	// Client side: produce clientRandom and sealed INIT envelope.
	cs, env, err := handshake.ClientStart(psk, 0, time.Now().UTC())
	if err != nil {
		t.Fatalf("ClientStart: %v", err)
	}

	// Wire-encode the INIT frame: EncryptedPayload = clientRandom(16) || env.
	initPayload := make([]byte, 16+len(env))
	copy(initPayload[:16], cs.ClientRandom)
	copy(initPayload[16:], env)

	initFrame := VpnProto.V2Frame{
		Header: VpnProto.V2Header{
			Type:      Enums.PACKET_V2_INIT,
			ChCls:     VpnProto.ChClsNarrow,
			SessionID: 0,
			StreamID:  0,
			SeqNum:    0,
		},
		EncryptedPayload: initPayload,
		Tag:              make([]byte, VpnProto.V2TagLen),
	}

	// Minimal synthetic DNS query header (12 bytes) to give handleV2 a tx ID.
	fakeRequest := make([]byte, 12)
	binary.BigEndian.PutUint16(fakeRequest[0:2], 0xABCD) // tx ID
	binary.BigEndian.PutUint16(fakeRequest[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(fakeRequest[4:6], 1)      // QDCOUNT=1

	resp := srv.handleV2(fakeRequest, initFrame)
	if resp == nil {
		t.Fatal("handleV2 returned nil for INIT frame")
	}

	// The DNS response header must echo the request transaction ID.
	if len(resp) < 12 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	gotTxID := binary.BigEndian.Uint16(resp[0:2])
	if gotTxID != 0xABCD {
		t.Errorf("tx ID mismatch: got 0x%04x, want 0xABCD", gotTxID)
	}
	// QR bit must be set (bit 15 of flags word).
	gotFlags := binary.BigEndian.Uint16(resp[2:4])
	if gotFlags&0x8000 == 0 {
		t.Errorf("QR bit not set in response flags: 0x%04x", gotFlags)
	}

	// Decode the TXT-record DNS response and get the raw V2Frame bytes back.
	frameBytes, err := ExtractV2FrameBytesFromTXTResponse(resp)
	if err != nil {
		t.Fatalf("ExtractV2FrameBytesFromTXTResponse: %v", err)
	}
	var ackFrame VpnProto.V2Frame
	if err := ackFrame.Unmarshal(frameBytes); err != nil {
		t.Fatalf("Unmarshal INIT_ACK frame: %v", err)
	}
	if ackFrame.Header.Type != Enums.PACKET_V2_INIT_ACK {
		t.Errorf("expected PACKET_V2_INIT_ACK (0x%02x), got 0x%02x",
			Enums.PACKET_V2_INIT_ACK, ackFrame.Header.Type)
	}

	// The EncryptedPayload must be at least serverRandom(16) + some ack envelope.
	if len(ackFrame.EncryptedPayload) < 16 {
		t.Fatalf("INIT_ACK payload too short: %d bytes", len(ackFrame.EncryptedPayload))
	}
	serverRandom := ackFrame.EncryptedPayload[:16]
	ackEnv := ackFrame.EncryptedPayload[16:]

	// The registry must now hold the new session.
	sid := ackFrame.Header.SessionID
	sess := srv.v2sessions.Get(sid)
	if sess == nil {
		t.Fatalf("session %d not found in registry after INIT", sid)
	}

	// Complete the client-side handshake and verify keys match.
	if err := cs.Finish(psk, ackEnv, serverRandom); err != nil {
		t.Fatalf("Client.Finish: %v", err)
	}
	if !bytes.Equal(cs.Keys.ClientToServer, sess.Keys.ClientToServer) {
		t.Fatal("ClientToServer keys diverged between client and server")
	}
	if !bytes.Equal(cs.Keys.ServerToClient, sess.Keys.ServerToClient) {
		t.Fatal("ServerToClient keys diverged between client and server")
	}
}
