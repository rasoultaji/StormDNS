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
)

type Role byte

const (
	IsClient Role = iota
	IsServer
)

type rekeyState int

const (
	rekeyStateIdle rekeyState = iota
	rekeyStateOurs                 // we initiated, waiting for peer
	rekeyStatePeer                 // we responded to peer
	rekeyStateAdoptedClient        // collision; server adopted client's ephemeral
	rekeyStateDone
)

// RekeyCoordinator owns the state for one rekey exchange. One per session
// per direction of initiation.
type RekeyCoordinator struct {
	role      Role
	state     rekeyState
	ourPriv   *ecdh.PrivateKey
	ourPub    []byte
	ourRandom []byte
	peerPub   []byte
	newKeys   SessionKeys
	psk       []byte
}

func NewRekeyCoordinator(role Role, psk []byte) *RekeyCoordinator {
	// Defensive copy of PSK to prevent external mutation
	pskCopy := append([]byte(nil), psk...)
	return &RekeyCoordinator{role: role, psk: pskCopy}
}

func (r *RekeyCoordinator) Start(current SessionKeys) (ourPub []byte, sealedMsg []byte, err error) {
	if r.state != rekeyStateIdle {
		return nil, nil, fmt.Errorf("rekey: cannot start from state %d", r.state)
	}
	priv, pub, err := GenerateEphemeral()
	if err != nil {
		return nil, nil, err
	}
	rnd := make([]byte, 16)
	if _, err := rand.Read(rnd); err != nil {
		return nil, nil, err
	}
	r.ourPriv = priv
	r.ourPub = pub
	r.ourRandom = rnd
	r.state = rekeyStateOurs
	// sealedMsg is left empty here; the outer v2 frame layer (Task 8)
	// will seal {ourPub || ourRandom} under the *current* session key
	// and ship it as PACKET_V2_REKEY. We return ourPub for the test.
	_ = current
	return pub, nil, nil
}

func (r *RekeyCoordinator) HandlePeer(current SessionKeys, peerPub []byte) (replyPub, sealedMsg []byte, err error) {
	switch r.state {
	case rekeyStateIdle:
		priv, pub, err := GenerateEphemeral()
		if err != nil {
			return nil, nil, err
		}
		r.ourPriv = priv
		r.ourPub = pub
		r.peerPub = peerPub
		if err := r.deriveNew(current); err != nil {
			return nil, nil, err
		}
		r.state = rekeyStatePeer
		return pub, nil, nil
	case rekeyStateOurs:
		// Collision. Spec §6.5: client wins. Server discards its own
		// ephemeral and adopts the client's.
		if r.role == IsServer {
			r.ourPriv = nil
			r.ourPub = nil
			priv, pub, err := GenerateEphemeral()
			if err != nil {
				return nil, nil, err
			}
			r.ourPriv = priv
			r.ourPub = pub
			r.peerPub = peerPub
			if err := r.deriveNew(current); err != nil {
				return nil, nil, err
			}
			r.state = rekeyStateAdoptedClient
			return pub, nil, nil
		}
		return nil, nil, errors.New("rekey: client ignores server's parallel REKEY")
	default:
		return nil, nil, fmt.Errorf("rekey: cannot handle peer from state %d", r.state)
	}
}

func (r *RekeyCoordinator) Finish(peerPub []byte) (SessionKeys, error) {
	if r.state != rekeyStateOurs {
		return SessionKeys{}, fmt.Errorf("rekey: cannot finish from state %d", r.state)
	}
	r.peerPub = peerPub
	keys, err := r.deriveFromHandshakeStyle()
	if err != nil {
		return SessionKeys{}, err
	}
	r.newKeys = keys
	r.state = rekeyStateDone
	return keys, nil
}

func (r *RekeyCoordinator) NewKeys() SessionKeys { return r.newKeys }

func (r *RekeyCoordinator) deriveNew(current SessionKeys) error {
	keys, err := r.deriveFromHandshakeStyle()
	if err != nil {
		return err
	}
	r.newKeys = keys
	_ = current
	return nil
}

// deriveFromHandshakeStyle derives new session keys using DH and deterministic salt.
//
// STUB salt construction — Task 8 will replace this with the real one
// (clientRandom' || serverRandom') from the v2 REKEY message bodies.
//
// To ensure both sides derive identical keys, we use a deterministic salt
// derived from the DH shared secret itself (which is identical on both sides).
// We split the 32-byte DH output into two 16-byte chunks to feed the salt
// parameters that DeriveSessionKeys expects.
func (r *RekeyCoordinator) deriveFromHandshakeStyle() (SessionKeys, error) {
	dh, err := DHCompute(r.ourPriv, r.peerPub)
	if err != nil {
		return SessionKeys{}, err
	}
	// Deterministic salt derived from the shared DH (same on both sides).
	// Task 8 replaces this with (clientRandom' || serverRandom').
	// Split the 32-byte DH into two 16-byte chunks that both sides agree on.
	saltBytes := dh[:16]
	salt2 := dh[16:32]
	return DeriveSessionKeys(r.psk, dh, saltBytes, salt2)
}
