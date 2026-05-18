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
	"sync"
	"time"

	"stormdns-go/internal/handshake"
)

// V2Session is the server-side state for one v2 session.
type V2Session struct {
	SessionID    uint16
	Keys         handshake.SessionKeys
	ServerRandom []byte // 16 B, needed for client Finish AAD
	LastSeen     time.Time
}

// V2SessionRegistry holds per-session keys + a replay cache for INIT.
type V2SessionRegistry struct {
	psk    []byte
	replay *handshake.ReplayCache

	mu       sync.RWMutex
	sessions map[uint16]*V2Session
}

// NewV2SessionRegistry creates a registry that uses psk for all handshakes.
func NewV2SessionRegistry(psk []byte) *V2SessionRegistry {
	return &V2SessionRegistry{
		psk:      append([]byte(nil), psk...),
		replay:   handshake.NewReplayCache(handshake.DefaultReplayWindow, 4096),
		sessions: make(map[uint16]*V2Session),
	}
}

// AcceptInit runs the server-side handshake on a fresh INIT envelope.
// clientRandom is the 16-byte random extracted from the outer v2 frame
// (in the integrated path that is the frame header bytes from Task 21).
// ackAAD is optional AAD to pass to the server-side seal of INIT_ACK.
func (r *V2SessionRegistry) AcceptInit(env []byte, clientRandom []byte, ackAAD []byte, now time.Time) ([]byte, *V2Session, error) {
	sstate, ack, err := handshake.ServerAcceptWithReplay(r.psk, env, clientRandom, ackAAD, r.replay, now)
	if err != nil {
		return nil, nil, err
	}
	s := &V2Session{
		SessionID:    sstate.SessionID,
		Keys:         sstate.Keys,
		ServerRandom: sstate.ServerRandom,
		LastSeen:     now,
	}
	r.mu.Lock()
	r.sessions[s.SessionID] = s
	r.mu.Unlock()
	return ack, s, nil
}

// Get returns the V2Session for the given session ID, or nil if not found.
func (r *V2SessionRegistry) Get(sid uint16) *V2Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[sid]
}

// Touch updates the LastSeen timestamp for the given session ID.
func (r *V2SessionRegistry) Touch(sid uint16, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[sid]; ok {
		s.LastSeen = now
	}
}
