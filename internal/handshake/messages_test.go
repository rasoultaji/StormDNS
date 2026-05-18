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
	"time"
)

func TestInitRoundTrip(t *testing.T) {
	orig := Init{
		EphPubC:         bytesRepeat(0xAA, 32),
		ClientRandom:    bytesRepeat(0xBB, 16),
		ProposedSession: 0x1234,
		CapabilityBits:  0x0001,
		Timestamp:       time.Unix(1_700_000_000, 0).UTC(),
	}
	enc := orig.Marshal()
	if len(enc) != initMsgLen {
		t.Fatalf("marshal len = %d, want %d", len(enc), initMsgLen)
	}
	var got Init
	if err := got.Unmarshal(enc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bytes.Equal(got.EphPubC, orig.EphPubC) {
		t.Fatalf("eph_pub_c mismatch")
	}
	if !bytes.Equal(got.ClientRandom, orig.ClientRandom) {
		t.Fatalf("client_random mismatch")
	}
	if got.ProposedSession != orig.ProposedSession {
		t.Fatalf("session id mismatch: got %d want %d", got.ProposedSession, orig.ProposedSession)
	}
	if got.CapabilityBits != orig.CapabilityBits {
		t.Fatalf("capability bits mismatch")
	}
	if !got.Timestamp.Equal(orig.Timestamp) {
		t.Fatalf("timestamp mismatch: got %v want %v", got.Timestamp, orig.Timestamp)
	}
}

func TestInitAckRoundTrip(t *testing.T) {
	orig := InitAck{
		EphPubS:        bytesRepeat(0xCC, 32),
		ServerRandom:   bytesRepeat(0xDD, 16),
		AcceptedSession: 0x5678,
		CapabilityBits: 0x0001,
	}
	enc := orig.Marshal()
	if len(enc) != initAckMsgLen {
		t.Fatalf("marshal len = %d, want %d", len(enc), initAckMsgLen)
	}
	var got InitAck
	if err := got.Unmarshal(enc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bytes.Equal(got.EphPubS, orig.EphPubS) || !bytes.Equal(got.ServerRandom, orig.ServerRandom) {
		t.Fatalf("pubkey/random mismatch")
	}
	if got.AcceptedSession != orig.AcceptedSession || got.CapabilityBits != orig.CapabilityBits {
		t.Fatalf("session/cap mismatch")
	}
}

func TestInitUnmarshal_ShortBuf(t *testing.T) {
	var got Init
	if err := got.Unmarshal(make([]byte, 5)); err == nil {
		t.Fatal("expected error on short buffer")
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
