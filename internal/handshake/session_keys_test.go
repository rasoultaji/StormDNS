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

func TestDeriveSessionKeys_Deterministic(t *testing.T) {
	psk := bytes.Repeat([]byte{0x11}, 32)
	dh := bytes.Repeat([]byte{0x22}, 32)
	cr := bytes.Repeat([]byte{0x33}, 16)
	sr := bytes.Repeat([]byte{0x44}, 16)

	a, err := DeriveSessionKeys(psk, dh, cr, sr)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}
	b, err := DeriveSessionKeys(psk, dh, cr, sr)
	if err != nil {
		t.Fatalf("DeriveSessionKeys (2): %v", err)
	}
	if !bytes.Equal(a.ClientToServer, b.ClientToServer) {
		t.Fatal("K_c2s not deterministic")
	}
	if !bytes.Equal(a.ServerToClient, b.ServerToClient) {
		t.Fatal("K_s2c not deterministic")
	}
	if bytes.Equal(a.ClientToServer, a.ServerToClient) {
		t.Fatal("K_c2s and K_s2c must differ")
	}
	if len(a.ClientToServer) != 32 || len(a.ServerToClient) != 32 {
		t.Fatalf("session key length: got c2s=%d s2c=%d, want 32 each",
			len(a.ClientToServer), len(a.ServerToClient))
	}
}

func TestDeriveSessionKeys_InputSensitivity(t *testing.T) {
	psk := bytes.Repeat([]byte{0x11}, 32)
	dh := bytes.Repeat([]byte{0x22}, 32)
	cr := bytes.Repeat([]byte{0x33}, 16)
	sr := bytes.Repeat([]byte{0x44}, 16)

	base, _ := DeriveSessionKeys(psk, dh, cr, sr)

	altDH := bytes.Repeat([]byte{0x23}, 32)
	diff, _ := DeriveSessionKeys(psk, altDH, cr, sr)
	if bytes.Equal(base.ClientToServer, diff.ClientToServer) {
		t.Fatal("changing DH must change K_c2s")
	}
}

func TestDerivePSKAEADKey_Distinct(t *testing.T) {
	psk := bytes.Repeat([]byte{0x55}, 32)
	initKey := DerivePSKAEADKey(psk, "init")
	probeKey := DerivePSKAEADKey(psk, "probe")
	if bytes.Equal(initKey, probeKey) {
		t.Fatal("init and probe PSK-AEAD keys must differ")
	}
	if len(initKey) != 32 || len(probeKey) != 32 {
		t.Fatalf("key length: init=%d probe=%d, want 32", len(initKey), len(probeKey))
	}
}
