// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package integration

import (
	"bytes"

	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/vpnproto"
)

// BuildInitAckFrame is exported in case more tests need it.
func BuildInitAckFrame(serverRandom, ackEnvelope []byte) []byte {
	f := vpnproto.V2Frame{
		Header: vpnproto.V2Header{
			Type:  Enums.PACKET_V2_INIT_ACK,
			ChCls: vpnproto.ChClsNarrow,
		},
		EncryptedPayload: append(append([]byte(nil), serverRandom...), ackEnvelope...),
		Tag:              bytes.Repeat([]byte{0}, 16),
	}
	return f.Marshal()
}
