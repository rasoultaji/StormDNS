// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package handshake

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Direction identifies which side sealed the message. It is mixed into
// the AEAD nonce so client→server and server→client traffic cannot be
// cross-replayed even if the random field collides.
type Direction byte

const (
	DirClient Direction = 0x01
	DirServer Direction = 0x02
)

var ErrPSKAEADOpen = errors.New("handshake: PSK-AEAD open failed")

// PSKAEADSeal encrypts plaintext under HKDF(PSK, label)-derived key using
// ChaCha20-Poly1305. The 12-byte nonce is: direction || random[0..10].
// `random` MUST be 16 bytes; only its first 11 are used for the nonce so
// the full 16-byte field can also be carried in the message as client_random
// or server_random per spec §6.1.
func PSKAEADSeal(psk []byte, label string, dir Direction, random, plaintext, aad []byte) ([]byte, error) {
	if len(random) != 16 {
		return nil, fmt.Errorf("handshake: random must be 16 bytes, got %d", len(random))
	}
	key := DerivePSKAEADKey(psk, label)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("handshake: chacha20poly1305.New: %w", err)
	}
	nonce := buildNonce(dir, random)
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// PSKAEADOpen reverses PSKAEADSeal. Returns ErrPSKAEADOpen on tag failure.
func PSKAEADOpen(psk []byte, label string, dir Direction, random, ciphertext, aad []byte) ([]byte, error) {
	if len(random) != 16 {
		return nil, fmt.Errorf("handshake: random must be 16 bytes, got %d", len(random))
	}
	key := DerivePSKAEADKey(psk, label)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("handshake: chacha20poly1305.New: %w", err)
	}
	nonce := buildNonce(dir, random)
	out, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrPSKAEADOpen
	}
	return out, nil
}

func buildNonce(dir Direction, random []byte) []byte {
	nonce := make([]byte, 12)
	nonce[0] = byte(dir)
	copy(nonce[1:], random[0:11])
	return nonce
}
