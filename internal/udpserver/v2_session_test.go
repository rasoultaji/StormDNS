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
	"testing"
	"time"

	"stormdns-go/internal/handshake"
)

func TestV2Session_HandshakeAccept(t *testing.T) {
	psk := bytes.Repeat([]byte{0x55}, 32)
	reg := NewV2SessionRegistry(psk)

	// ClientStart returns (*ClientState, env, err).
	cs, env, err := handshake.ClientStart(psk, 0, time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("ClientStart: %v", err)
	}

	// AcceptInit takes the env + clientRandom + ackAAD.
	// Pass nil ackAAD (server constructs its own server_random internally).
	ack, sess, err := reg.AcceptInit(env, cs.ClientRandom, nil, time.Now())
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

	cs, env, _ := handshake.ClientStart(psk, 0, time.Now().UTC(), nil)
	_, _, err := reg.AcceptInit(env, cs.ClientRandom, nil, time.Now())
	if err != nil {
		t.Fatalf("first accept: %v", err)
	}
	_, _, err = reg.AcceptInit(env, cs.ClientRandom, nil, time.Now())
	if err == nil {
		t.Fatal("expected replay to be rejected")
	}
}
