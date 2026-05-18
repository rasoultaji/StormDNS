// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package security

import (
	"bytes"
	"testing"
)

func TestSessionAEAD_RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	a, err := NewSessionAEAD(key)
	if err != nil {
		t.Fatalf("NewSessionAEAD: %v", err)
	}
	header := []byte{0x82, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x01}
	payload := []byte("hello phantom")
	ct, tag, err := a.Seal(DirClientToServer, 0x1234, 1, payload, header)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(tag) != 16 {
		t.Fatalf("tag len = %d", len(tag))
	}
	pt, err := a.Open(DirClientToServer, 0x1234, 1, ct, tag, header)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Fatalf("pt mismatch")
	}
}

func TestSessionAEAD_TamperHeader(t *testing.T) {
	a, _ := NewSessionAEAD(bytes.Repeat([]byte{1}, 32))
	header := []byte{0x82, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x01}
	ct, tag, _ := a.Seal(DirClientToServer, 0x1234, 1, []byte("x"), header)
	header[0] ^= 1
	if _, err := a.Open(DirClientToServer, 0x1234, 1, ct, tag, header); err == nil {
		t.Fatal("expected open to fail when AAD/header bytes change")
	}
}

func TestSessionAEAD_NonceCounterUniqueness(t *testing.T) {
	a, _ := NewSessionAEAD(bytes.Repeat([]byte{1}, 32))
	header := []byte{0x82, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	ct1, _, _ := a.Seal(DirClientToServer, 0x0001, 1, []byte("same"), header)
	ct2, _, _ := a.Seal(DirClientToServer, 0x0001, 2, []byte("same"), header)
	if bytes.Equal(ct1, ct2) {
		t.Fatal("two different SeqNums must produce different ciphertext")
	}
}
