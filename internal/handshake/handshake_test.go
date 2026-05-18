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
)

func TestPSKAEAD_RoundTrip(t *testing.T) {
	psk := bytes.Repeat([]byte{0x77}, 32)
	plaintext := []byte("hello phantom dns")
	aad := []byte("v2-header-bytes")
	random := bytes.Repeat([]byte{0x33}, 16)

	sealed, err := PSKAEADSeal(psk, "init", DirClient, random, plaintext, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Equal(sealed, plaintext) {
		t.Fatal("seal did not encrypt")
	}

	opened, err := PSKAEADOpen(psk, "init", DirClient, random, sealed, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened = %q, want %q", opened, plaintext)
	}
}

func TestPSKAEAD_TamperedCiphertext(t *testing.T) {
	psk := bytes.Repeat([]byte{0x77}, 32)
	random := bytes.Repeat([]byte{0x33}, 16)
	sealed, _ := PSKAEADSeal(psk, "init", DirClient, random,
		[]byte("payload"), []byte("aad"))
	sealed[0] ^= 0x01
	if _, err := PSKAEADOpen(psk, "init", DirClient, random, sealed, []byte("aad")); err == nil {
		t.Fatal("expected open to fail on tampered ciphertext")
	}
}

func TestPSKAEAD_TamperedAAD(t *testing.T) {
	psk := bytes.Repeat([]byte{0x77}, 32)
	random := bytes.Repeat([]byte{0x33}, 16)
	sealed, _ := PSKAEADSeal(psk, "init", DirClient, random,
		[]byte("payload"), []byte("aad"))
	if _, err := PSKAEADOpen(psk, "init", DirClient, random, sealed, []byte("AAD")); err == nil {
		t.Fatal("expected open to fail on changed AAD")
	}
}

func TestPSKAEAD_WrongDirection(t *testing.T) {
	psk := bytes.Repeat([]byte{0x77}, 32)
	random := bytes.Repeat([]byte{0x33}, 16)
	sealed, _ := PSKAEADSeal(psk, "init", DirClient, random,
		[]byte("p"), []byte("aad"))
	if _, err := PSKAEADOpen(psk, "init", DirServer, random, sealed, []byte("aad")); err == nil {
		t.Fatal("expected open to fail when direction byte differs")
	}
}

func TestPSKAEAD_DistinctLabels(t *testing.T) {
	psk := bytes.Repeat([]byte{0x77}, 32)
	random := bytes.Repeat([]byte{0x33}, 16)
	sealed, _ := PSKAEADSeal(psk, "init", DirClient, random,
		[]byte("p"), []byte("aad"))
	if _, err := PSKAEADOpen(psk, "probe", DirClient, random, sealed, []byte("aad")); err == nil {
		t.Fatal("expected open to fail when label differs (different key)")
	}
}
