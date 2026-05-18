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
	"fmt"
)

// GenerateEphemeral returns an X25519 keypair drawn from crypto/rand.
func GenerateEphemeral() (priv *ecdh.PrivateKey, pub []byte, err error) {
	curve := ecdh.X25519()
	priv, err = curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: ecdh GenerateKey: %w", err)
	}
	pub = priv.PublicKey().Bytes()
	return priv, pub, nil
}

// DHCompute returns the X25519 shared secret for our private key and the
// peer's 32-byte public key bytes.
func DHCompute(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	curve := ecdh.X25519()
	peer, err := curve.NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("handshake: bad peer pubkey: %w", err)
	}
	dh, err := priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("handshake: ECDH: %w", err)
	}
	return dh, nil
}
