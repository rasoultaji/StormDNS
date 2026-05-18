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

func TestV2Header_RoundTrip(t *testing.T) {
	h := V2Header{
		Type:      Enums.PACKET_V2_DATA,
		ChCls:     ChClsWide,
		SessionID: 0x1234,
		StreamID:  0x5678,
		SeqNum:    0xDEADBEEF,
	}
	buf := h.Marshal()
	if len(buf) != V2HeaderLen {
		t.Fatalf("len = %d, want %d", len(buf), V2HeaderLen)
	}
	var got V2Header
	if err := got.Unmarshal(buf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != h {
		t.Fatalf("got %+v want %+v", got, h)
	}
}

func TestV2Header_RejectsV1Type(t *testing.T) {
	buf := make([]byte, V2HeaderLen)
	buf[0] = 0x0F // v1 PACKET_STREAM_DATA, high bit clear
	var h V2Header
	if err := h.Unmarshal(buf); err == nil {
		t.Fatal("expected unmarshal to reject low-bit-only Type as not v2")
	}
}

func TestV2Header_ChClsValidation(t *testing.T) {
	h := V2Header{Type: Enums.PACKET_V2_DATA, ChCls: 0x05}
	buf := h.Marshal()
	var got V2Header
	if err := got.Unmarshal(buf); err == nil {
		t.Fatal("expected error on unknown ChCls value")
	}
}

func TestIsV2Type(t *testing.T) {
	if !IsV2Type(Enums.PACKET_V2_DATA) {
		t.Fatal("V2 data should be v2")
	}
	if IsV2Type(Enums.PACKET_STREAM_DATA) {
		t.Fatal("v1 packet should not be v2")
	}
	if IsV2Type(Enums.PACKET_ERROR_DROP) {
		t.Fatal("0xFF is reserved, not a v2 type")
	}
}

func TestV2Frame_PayloadAttach(t *testing.T) {
	h := V2Header{
		Type:      Enums.PACKET_V2_DATA,
		ChCls:     ChClsNarrow,
		SessionID: 1, StreamID: 1, SeqNum: 1,
	}
	payload := []byte("hello")
	f := V2Frame{Header: h, EncryptedPayload: payload, Tag: bytes.Repeat([]byte{0xAA}, 16)}
	buf := f.Marshal()
	if len(buf) != V2HeaderLen+len(payload)+V2TagLen {
		t.Fatalf("frame len = %d, want %d", len(buf), V2HeaderLen+len(payload)+V2TagLen)
	}
	var got V2Frame
	if err := got.Unmarshal(buf); err != nil {
		t.Fatalf("unmarshal frame: %v", err)
	}
	if got.Header != h {
		t.Fatalf("header mismatch")
	}
	if !bytes.Equal(got.EncryptedPayload, payload) {
		t.Fatalf("payload mismatch")
	}
	if !bytes.Equal(got.Tag, f.Tag) {
		t.Fatalf("tag mismatch")
	}
}
