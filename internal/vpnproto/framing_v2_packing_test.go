// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"bytes"
	"testing"

	Enums "stormdns-go/internal/enums"
)

func TestPackV2_RoundTrip(t *testing.T) {
	mk := func(seq uint32, payload string) V2Frame {
		return V2Frame{
			Header: V2Header{
				Type: Enums.PACKET_V2_DATA, ChCls: ChClsWide,
				SessionID: 7, StreamID: 9, SeqNum: seq,
			},
			EncryptedPayload: []byte(payload),
			Tag:              bytes.Repeat([]byte{0xEE}, 16),
		}
	}
	frames := []V2Frame{mk(1, "alpha"), mk(2, "beta"), mk(3, "gamma")}
	packed, err := PackV2(frames, 16384)
	if err != nil {
		t.Fatalf("PackV2: %v", err)
	}

	got, err := UnpackV2(packed)
	if err != nil {
		t.Fatalf("UnpackV2: %v", err)
	}
	if len(got) != len(frames) {
		t.Fatalf("got %d frames, want %d", len(got), len(frames))
	}
	for i := range frames {
		if got[i].Header != frames[i].Header {
			t.Errorf("frame[%d] header mismatch", i)
		}
		if !bytes.Equal(got[i].EncryptedPayload, frames[i].EncryptedPayload) {
			t.Errorf("frame[%d] payload mismatch", i)
		}
	}
}

func TestPackV2_RespectsBudget(t *testing.T) {
	big := V2Frame{
		Header: V2Header{Type: Enums.PACKET_V2_DATA, ChCls: ChClsWide,
			SessionID: 1, StreamID: 1, SeqNum: 1},
		EncryptedPayload: bytes.Repeat([]byte{1}, 100),
		Tag:              bytes.Repeat([]byte{0}, 16),
	}
	if _, err := PackV2([]V2Frame{big}, 50); err == nil {
		t.Fatal("expected PackV2 to fail when first frame doesn't fit in budget")
	}
}
