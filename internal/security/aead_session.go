// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package security

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

type AEADDirection byte

const (
	DirClientToServer AEADDirection = 0x01
	DirServerToClient AEADDirection = 0x02
)

var ErrAEADOpen = errors.New("security: v2 AEAD open failed")

// SessionAEAD wraps chacha20poly1305 with the v2 nonce convention:
//   nonce = direction(1) || sessionID(2) || seqNum(4) || zero(5)   = 12 B
type SessionAEAD struct {
	key []byte
}

func NewSessionAEAD(key []byte) (*SessionAEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("security: session key must be 32 bytes, got %d", len(key))
	}
	if _, err := chacha20poly1305.New(key); err != nil {
		return nil, err
	}
	return &SessionAEAD{key: append([]byte(nil), key...)}, nil
}

// Seal returns (ciphertext, tag). The 16-byte tag is split out so callers
// can write it into the v2 frame's trailer field.
func (s *SessionAEAD) Seal(dir AEADDirection, sessionID uint16, seqNum uint32, plaintext, aad []byte) ([]byte, []byte, error) {
	aead, err := chacha20poly1305.New(s.key)
	if err != nil {
		return nil, nil, err
	}
	nonce := buildSessionNonce(dir, sessionID, seqNum)
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	ct := sealed[:len(sealed)-16]
	tag := sealed[len(sealed)-16:]
	return ct, tag, nil
}

func (s *SessionAEAD) Open(dir AEADDirection, sessionID uint16, seqNum uint32, ciphertext, tag, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(s.key)
	if err != nil {
		return nil, err
	}
	if len(tag) != 16 {
		return nil, fmt.Errorf("security: tag must be 16 bytes, got %d", len(tag))
	}
	nonce := buildSessionNonce(dir, sessionID, seqNum)
	combined := make([]byte, 0, len(ciphertext)+len(tag))
	combined = append(combined, ciphertext...)
	combined = append(combined, tag...)
	pt, err := aead.Open(nil, nonce, combined, aad)
	if err != nil {
		return nil, ErrAEADOpen
	}
	return pt, nil
}

func buildSessionNonce(dir AEADDirection, sessionID uint16, seqNum uint32) []byte {
	var nonce [12]byte
	nonce[0] = byte(dir)
	binary.BigEndian.PutUint16(nonce[1:3], sessionID)
	binary.BigEndian.PutUint32(nonce[3:7], seqNum)
	// bytes 7..11 stay zero
	return nonce[:]
}
