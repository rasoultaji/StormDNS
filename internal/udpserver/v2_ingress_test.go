// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"bytes"
	"testing"

	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/vpnproto"
)

func TestServerV2Ingress_RejectsNonV2(t *testing.T) {
	v1 := []byte{Enums.PACKET_STREAM_DATA, 0x00, 0x00, 0x01}
	if vpnproto.DetectVersion(v1) == vpnproto.VersionV2 {
		t.Fatal("classification regression")
	}
}

func TestServerV2Ingress_DecodesValidV2Frame(t *testing.T) {
	h := vpnproto.V2Header{
		Type:      Enums.PACKET_V2_INIT,
		ChCls:     vpnproto.ChClsNarrow,
		SessionID: 0,
		StreamID:  0,
		SeqNum:    0,
	}
	frame := vpnproto.V2Frame{
		Header:           h,
		EncryptedPayload: nil,
		Tag:              bytes.Repeat([]byte{0xAA}, 16),
	}
	raw := frame.Marshal()
	if vpnproto.DetectVersion(raw) != vpnproto.VersionV2 {
		t.Fatal("expected v2 classification")
	}

	out := DecodeV2FrameFromQueryBytes(raw)
	if out == nil {
		t.Fatal("DecodeV2FrameFromQueryBytes returned nil")
	}
	if out.Header.Type != Enums.PACKET_V2_INIT {
		t.Fatalf("type = 0x%x", out.Header.Type)
	}
}
