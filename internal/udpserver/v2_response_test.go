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

	"stormdns-go/internal/antidpi"
	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/vpnproto"
)

func TestBuildV2DNSResponse_A(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78}
	f := vpnproto.V2Frame{
		Header: vpnproto.V2Header{Type: Enums.PACKET_V2_DATA, ChCls: vpnproto.ChClsNarrow,
			SessionID: 1, StreamID: 1, SeqNum: 1},
		EncryptedPayload: payload,
		Tag:              bytes.Repeat([]byte{0}, 16),
	}
	resp := BuildV2DNSResponse([]vpnproto.V2Frame{f}, antidpi.RRTypeA)
	if len(resp) == 0 {
		t.Fatal("expected non-empty response body")
	}
	got, err := ExtractV2FrameBytesFromAResponse(resp)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	want := f.Marshal()
	if !bytes.HasPrefix(got, want) {
		t.Fatalf("reassembled bytes don't start with original frame")
	}
}

func TestAuthDomainAllowlist(t *testing.T) {
	allow := []string{"a.example.com", "b.example.net"}
	cases := []struct {
		fqdn string
		ok   bool
	}{
		{"data.a.example.com", true},
		{"x.y.b.example.net", true},
		{"a.example.com", true},
		{"evil.example.org", false},
		{"a.example.com.attacker.net", false},
	}
	for _, c := range cases {
		if got := IsAllowedAuthFQDN(c.fqdn, allow); got != c.ok {
			t.Errorf("IsAllowedAuthFQDN(%q) = %v, want %v", c.fqdn, got, c.ok)
		}
	}
}
