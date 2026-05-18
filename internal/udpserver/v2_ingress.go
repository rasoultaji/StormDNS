// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"stormdns-go/internal/antidpi"
	"stormdns-go/internal/vpnproto"
)

// ExtractV2FrameFromQName takes the DNS query labels (without the auth
// domain suffix) and decodes them back into raw frame bytes using the
// antidpi label shaper's permissive decoder.
func ExtractV2FrameFromQName(labels []string) ([]byte, error) {
	return antidpi.DecodeLabels(labels)
}

// DecodeV2FrameFromQueryBytes is the next layer: given raw v2 wire bytes
// (header + payload + tag) it returns the parsed V2Frame or nil if the
// bytes don't classify as v2.
func DecodeV2FrameFromQueryBytes(raw []byte) *vpnproto.V2Frame {
	if vpnproto.DetectVersion(raw) != vpnproto.VersionV2 {
		return nil
	}
	var f vpnproto.V2Frame
	if err := f.Unmarshal(raw); err != nil {
		return nil
	}
	return &f
}
