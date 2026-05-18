// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package handshake

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrHandshakeReplay  = errors.New("handshake: replayed INIT")
	ErrHandshakeSkew    = errors.New("handshake: timestamp outside window")
	ErrHandshakeOpen    = errors.New("handshake: INIT/INIT_ACK open failed")
	DefaultClockSkew    = 5 * time.Minute
	DefaultReplayWindow = 10 * time.Minute
)

// ClientState is held by the client between ClientStart and Finish.
// ClientRandom is exported so the caller can pass it to the server as the
// nonce source — in production it is carried in the outer v2 frame header
// before the AEAD envelope (see Task 11 for the integrated path).
type ClientState struct {
	ephPriv      *ecdh.PrivateKey
	ClientRandom []byte // 16 B; visible to caller for nonce handoff
	SessionID    uint16
	Keys         SessionKeys
}

// ServerState is returned by ServerAccept after a successful INIT open.
// ServerRandom is exported so the caller can pass it back to the client as
// the ack-nonce source — same reasoning as ClientState.ClientRandom.
type ServerState struct {
	ServerRandom []byte // 16 B; visible to caller for nonce handoff
	SessionID    uint16
	Keys         SessionKeys
}

// ClientStart generates the client's ephemeral X25519 keypair, builds and
// seals the INIT message under PSK-AEAD.
//
// proposedSessionID = 0 means "server picks".
// The nonce is derived from ClientRandom, which the caller must forward to the
// server out-of-band (e.g. in the outer v2 frame header).
func ClientStart(psk []byte, proposedSessionID uint16, now time.Time) (*ClientState, []byte, error) {
	priv, pub, err := GenerateEphemeral()
	if err != nil {
		return nil, nil, err
	}
	cr := make([]byte, 16)
	if _, err := rand.Read(cr); err != nil {
		return nil, nil, fmt.Errorf("handshake: rand client_random: %w", err)
	}
	msg := Init{
		EphPubC:         pub,
		ClientRandom:    cr,
		ProposedSession: proposedSessionID,
		CapabilityBits:  capV2Default(),
		Timestamp:       now.UTC(),
	}
	sealed, err := PSKAEADSeal(psk, "init", DirClient, cr, msg.Marshal(), nil)
	if err != nil {
		return nil, nil, err
	}
	return &ClientState{ephPriv: priv, ClientRandom: cr}, sealed, nil
}

// ServerAccept opens an INIT envelope, derives the session keys, and returns
// the INIT_ACK envelope plus the populated ServerState.
//
// clientRandom must be the 16-byte random the client used as the AEAD nonce
// (i.e. ClientState.ClientRandom). In the integrated v2 path (Task 11) this
// comes from the outer frame header; in tests it is passed directly from the
// ClientState returned by ClientStart.
func ServerAccept(psk, initEnvelope, clientRandom []byte) (*ServerState, []byte, error) {
	return serverAcceptCommon(psk, initEnvelope, clientRandom, nil, time.Now())
}

// ServerAcceptWithReplay is like ServerAccept but consults a ReplayCache to
// deduplicate INIT messages and enforces the clock-skew window from spec §6.2.
func ServerAcceptWithReplay(psk, initEnvelope, clientRandom []byte, cache *ReplayCache, now time.Time) (*ServerState, []byte, error) {
	return serverAcceptCommon(psk, initEnvelope, clientRandom, cache, now)
}

func serverAcceptCommon(psk, initEnvelope, clientRandom []byte, cache *ReplayCache, now time.Time) (*ServerState, []byte, error) {
	if len(clientRandom) != 16 {
		return nil, nil, fmt.Errorf("handshake: clientRandom must be 16 bytes, got %d", len(clientRandom))
	}
	plain, err := PSKAEADOpen(psk, "init", DirClient, clientRandom, initEnvelope, nil)
	if err != nil {
		return nil, nil, ErrHandshakeOpen
	}
	var msg Init
	if err := msg.Unmarshal(plain); err != nil {
		return nil, nil, err
	}
	if absD(now.Sub(msg.Timestamp)) > DefaultClockSkew {
		return nil, nil, ErrHandshakeSkew
	}
	if cache != nil && !cache.Add(msg.ClientRandom, now) {
		return nil, nil, ErrHandshakeReplay
	}

	ephPriv, ephPub, err := GenerateEphemeral()
	if err != nil {
		return nil, nil, err
	}
	sr := make([]byte, 16)
	if _, err := rand.Read(sr); err != nil {
		return nil, nil, fmt.Errorf("handshake: rand server_random: %w", err)
	}
	dh, err := DHCompute(ephPriv, msg.EphPubC)
	if err != nil {
		return nil, nil, err
	}
	keys, err := DeriveSessionKeys(psk, dh, msg.ClientRandom, sr)
	if err != nil {
		return nil, nil, err
	}
	sid := msg.ProposedSession
	if sid == 0 {
		sid = randomSessionID()
	}
	ack := InitAck{
		EphPubS:         ephPub,
		ServerRandom:    sr,
		AcceptedSession: sid,
		CapabilityBits:  capV2Default(),
	}
	sealed, err := PSKAEADSeal(psk, "init", DirServer, sr, ack.Marshal(), nil)
	if err != nil {
		return nil, nil, err
	}
	return &ServerState{ServerRandom: sr, SessionID: sid, Keys: keys}, sealed, nil
}

// Finish is called by the client when the INIT_ACK comes back.
//
// serverRandom is the 16-byte random the server used as the AEAD nonce
// (i.e. ServerState.ServerRandom). In the integrated v2 path (Task 11) this
// comes from the outer frame header; in tests it is passed directly from the
// ServerState returned by ServerAccept.
func (cs *ClientState) Finish(psk, ackEnvelope, serverRandom []byte) error {
	if len(serverRandom) != 16 {
		return fmt.Errorf("handshake: serverRandom must be 16 bytes, got %d", len(serverRandom))
	}
	plain, err := PSKAEADOpen(psk, "init", DirServer, serverRandom, ackEnvelope, nil)
	if err != nil {
		return ErrHandshakeOpen
	}
	var msg InitAck
	if err := msg.Unmarshal(plain); err != nil {
		return err
	}
	dh, err := DHCompute(cs.ephPriv, msg.EphPubS)
	if err != nil {
		return err
	}
	keys, err := DeriveSessionKeys(psk, dh, cs.ClientRandom, msg.ServerRandom)
	if err != nil {
		return err
	}
	cs.Keys = keys
	cs.SessionID = msg.AcceptedSession
	return nil
}

func capV2Default() uint16 { return 0x0001 }

func randomSessionID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	sid := uint16(b[0])<<8 | uint16(b[1])
	if sid == 0 {
		sid = 1
	}
	return sid
}

func absD(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// ---------------------------------------------------------------------------
// ReplayCache — tiny FIFO keyed by client_random.
// ---------------------------------------------------------------------------

// ReplayCache deduplicates INIT messages within a sliding time window.
// It is safe for concurrent use.
type ReplayCache struct {
	window time.Duration
	cap    int
	mu     sync.Mutex
	order  []replayEntry
	seen   map[string]time.Time
}

type replayEntry struct {
	key string
	at  time.Time
}

// NewReplayCache returns a ReplayCache that remembers entries for window and
// holds at most capacity entries at a time.
func NewReplayCache(window time.Duration, capacity int) *ReplayCache {
	return &ReplayCache{
		window: window,
		cap:    capacity,
		seen:   make(map[string]time.Time, capacity),
	}
}

// Add records seeing random at time now. Returns false if it was already seen
// within the window (indicating a replay); returns true otherwise.
func (r *ReplayCache) Add(random []byte, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evict(now)
	key := string(random)
	if _, dup := r.seen[key]; dup {
		return false
	}
	r.seen[key] = now
	r.order = append(r.order, replayEntry{key: key, at: now})
	if len(r.order) > r.cap {
		drop := r.order[0]
		r.order = r.order[1:]
		delete(r.seen, drop.key)
	}
	return true
}

func (r *ReplayCache) evict(now time.Time) {
	cutoff := now.Add(-r.window)
	cut := 0
	for cut < len(r.order) && r.order[cut].at.Before(cutoff) {
		delete(r.seen, r.order[cut].key)
		cut++
	}
	if cut > 0 {
		r.order = r.order[cut:]
	}
}
