// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package handshake

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// SessionKeys are the per-direction AEAD keys derived after the v2 handshake.
type SessionKeys struct {
	ClientToServer []byte // 32 B, used by client to seal, server to open
	ServerToClient []byte // 32 B, used by server to seal, client to open
}

// DeriveSessionKeys runs the HKDF schedule from spec §6.3.
//   prk   = HKDF-Extract(salt = clientRandom || serverRandom,
//                        ikm  = PSK || dh)
//   K_c2s = HKDF-Expand(prk, "phantom-dns-c2s-v1", 32)
//   K_s2c = HKDF-Expand(prk, "phantom-dns-s2c-v1", 32)
func DeriveSessionKeys(psk, dh, clientRandom, serverRandom []byte) (SessionKeys, error) {
	if len(psk) == 0 || len(dh) == 0 {
		return SessionKeys{}, fmt.Errorf("handshake: empty psk or dh")
	}
	if len(clientRandom) != 16 || len(serverRandom) != 16 {
		return SessionKeys{}, fmt.Errorf("handshake: random fields must be 16 bytes each")
	}

	salt := make([]byte, 0, 32)
	salt = append(salt, clientRandom...)
	salt = append(salt, serverRandom...)

	ikm := make([]byte, 0, len(psk)+len(dh))
	ikm = append(ikm, psk...)
	ikm = append(ikm, dh...)

	c2s, err := hkdfDerive(salt, ikm, "phantom-dns-c2s-v1", 32)
	if err != nil {
		return SessionKeys{}, err
	}
	s2c, err := hkdfDerive(salt, ikm, "phantom-dns-s2c-v1", 32)
	if err != nil {
		return SessionKeys{}, err
	}
	return SessionKeys{ClientToServer: c2s, ServerToClient: s2c}, nil
}

// DerivePSKAEADKey derives a 32-byte AEAD key bound to a label
// (e.g. "init" or "probe") and the PSK only — no per-session salt.
// Used by PSK-AEAD-seal/open in handshake.go.
func DerivePSKAEADKey(psk []byte, label string) []byte {
	info := "phantom-dns-" + label + "-v1"
	key, _ := hkdfDerive(nil, psk, info, 32)
	return key
}

func hkdfDerive(salt, ikm []byte, info string, outLen int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, []byte(info))
	out := make([]byte, outLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf expand %q: %w", info, err)
	}
	return out, nil
}
