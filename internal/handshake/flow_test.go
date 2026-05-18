// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package handshake

import (
	"bytes"
	"testing"
	"time"
)

// TestHandshakeRoundTrip exercises the full 1-RTT client↔server flow.
// ClientStart returns the client's random so the test can pass it to
// ServerAccept as the nonce source (in production the v2 frame header
// carries the random in plaintext before the AEAD envelope).
func TestHandshakeRoundTrip(t *testing.T) {
	psk := bytes.Repeat([]byte{0x99}, 32)

	// Client builds INIT; returns its ClientRandom so the server side
	// can derive the correct nonce without a v2 frame header yet.
	cState, initEnvelope, err := ClientStart(psk, 0, time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("ClientStart: %v", err)
	}

	// Server receives INIT. clientRandom is passed explicitly (in production
	// it comes from the outer v2 frame header — see Task 11).
	sState, ackEnvelope, err := ServerAccept(psk, initEnvelope, cState.ClientRandom, nil)
	if err != nil {
		t.Fatalf("ServerAccept: %v", err)
	}

	// Client finishes with INIT_ACK. serverRandom is passed explicitly
	// (same rationale as above).
	if err := cState.Finish(psk, ackEnvelope, sState.ServerRandom); err != nil {
		t.Fatalf("Client.Finish: %v", err)
	}

	// Both sides must have derived identical session keys.
	if !bytes.Equal(cState.Keys.ClientToServer, sState.Keys.ClientToServer) {
		t.Fatal("K_c2s mismatch across sides")
	}
	if !bytes.Equal(cState.Keys.ServerToClient, sState.Keys.ServerToClient) {
		t.Fatal("K_s2c mismatch across sides")
	}
	if cState.SessionID == 0 || cState.SessionID != sState.SessionID {
		t.Fatalf("session id mismatch: c=%d s=%d", cState.SessionID, sState.SessionID)
	}
}

// TestHandshakeRejectsBadPSK verifies that ServerAccept fails when the
// server uses a different PSK than the client.
func TestHandshakeRejectsBadPSK(t *testing.T) {
	cState, initEnvelope, err := ClientStart(
		bytes.Repeat([]byte{0xAA}, 32), 0, time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("ClientStart: %v", err)
	}
	_, _, err = ServerAccept(
		bytes.Repeat([]byte{0xBB}, 32),
		initEnvelope,
		cState.ClientRandom,
		nil,
	)
	if err == nil {
		t.Fatal("ServerAccept must fail under wrong PSK")
	}
}

// TestHandshakeRejectsReplay ensures a replayed INIT envelope is rejected
// by ServerAcceptWithReplay.
func TestHandshakeRejectsReplay(t *testing.T) {
	psk := bytes.Repeat([]byte{0x99}, 32)
	cState, env, err := ClientStart(psk, 0, time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("ClientStart: %v", err)
	}
	cache := NewReplayCache(time.Minute, 1024)
	now := time.Now()

	if _, _, err := ServerAcceptWithReplay(psk, env, cState.ClientRandom, nil, cache, now); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	if _, _, err := ServerAcceptWithReplay(psk, env, cState.ClientRandom, nil, cache, now); err == nil {
		t.Fatal("replayed INIT must be rejected")
	}
}
