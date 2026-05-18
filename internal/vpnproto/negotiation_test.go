// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package vpnproto

import "testing"

func TestDetectVersion(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		want Version
	}{
		{"v1-stream-data", []byte{0x0F, 0x00, 0x00, 0x01}, VersionV1},
		{"v1-error-drop", []byte{0xFF, 0x00, 0x00, 0x01}, VersionV1},
		{"v2-data", []byte{0x82, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, VersionV2},
		{"too-short", []byte{}, VersionUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DetectVersion(c.buf)
			if got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}
