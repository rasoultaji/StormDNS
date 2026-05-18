// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package vpnproto

type Version int

const (
	VersionUnknown Version = iota
	VersionV1
	VersionV2
)

func (v Version) String() string {
	switch v {
	case VersionV1:
		return "v1"
	case VersionV2:
		return "v2"
	}
	return "unknown"
}

// DetectVersion classifies a raw frame by its leading Type byte.
// Treats 0xFF (PACKET_ERROR_DROP) as v1 — it's not a v2 type and v1
// owns that codepoint.
func DetectVersion(buf []byte) Version {
	if len(buf) == 0 {
		return VersionUnknown
	}
	t := buf[0]
	if t == 0xFF {
		return VersionV1
	}
	if IsV2Type(t) {
		if len(buf) < V2HeaderLen+V2TagLen {
			return VersionUnknown
		}
		return VersionV2
	}
	return VersionV1
}
