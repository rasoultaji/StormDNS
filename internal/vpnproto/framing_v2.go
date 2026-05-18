// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"encoding/binary"
	"errors"
	"fmt"

	Enums "stormdns-go/internal/enums"
)

// V2 frame constants per spec §5.2.
const (
	V2HeaderLen = 10 // Type+ChCls+SessionID(2)+StreamID(2)+SeqNum(4)
	V2TagLen    = 16

	ChClsNarrow byte = 0 // UDP/53 sender
	ChClsWide   byte = 1 // DoH/DoT/DoQ sender
)

var (
	ErrNotV2Type      = errors.New("vpnproto: type byte high bit not set; not a v2 frame")
	ErrUnknownChCls   = errors.New("vpnproto: unknown channel class byte")
	ErrShortV2Header  = errors.New("vpnproto: buffer shorter than v2 header")
	ErrShortV2Frame   = errors.New("vpnproto: buffer shorter than v2 frame minimum (header+tag)")
)

// IsV2Type reports whether t is in the v2 reserved range.
// v1 uses 0x00..0x37 plus 0xFF (PACKET_ERROR_DROP). v2 uses 0x80..0xFE.
func IsV2Type(t uint8) bool {
	return t >= 0x80 && t < 0xFF
}

type V2Header struct {
	Type      uint8
	ChCls     uint8
	SessionID uint16
	StreamID  uint16
	SeqNum    uint32
}

func (h V2Header) Marshal() []byte {
	buf := make([]byte, V2HeaderLen)
	buf[0] = h.Type
	buf[1] = h.ChCls
	binary.BigEndian.PutUint16(buf[2:4], h.SessionID)
	binary.BigEndian.PutUint16(buf[4:6], h.StreamID)
	binary.BigEndian.PutUint32(buf[6:10], h.SeqNum)
	return buf
}

func (h *V2Header) Unmarshal(buf []byte) error {
	if len(buf) < V2HeaderLen {
		return ErrShortV2Header
	}
	if !IsV2Type(buf[0]) {
		return ErrNotV2Type
	}
	switch buf[1] {
	case ChClsNarrow, ChClsWide:
	default:
		return fmt.Errorf("%w: 0x%02x", ErrUnknownChCls, buf[1])
	}
	h.Type = buf[0]
	h.ChCls = buf[1]
	h.SessionID = binary.BigEndian.Uint16(buf[2:4])
	h.StreamID = binary.BigEndian.Uint16(buf[4:6])
	h.SeqNum = binary.BigEndian.Uint32(buf[6:10])
	return nil
}

// V2Frame is the on-wire shape: header || encrypted-payload || tag.
type V2Frame struct {
	Header           V2Header
	EncryptedPayload []byte
	Tag              []byte
}

func (f V2Frame) Marshal() []byte {
	out := make([]byte, 0, V2HeaderLen+len(f.EncryptedPayload)+V2TagLen)
	out = append(out, f.Header.Marshal()...)
	out = append(out, f.EncryptedPayload...)
	out = append(out, f.Tag...)
	return out
}

func (f *V2Frame) Unmarshal(buf []byte) error {
	if len(buf) < V2HeaderLen+V2TagLen {
		return ErrShortV2Frame
	}
	if err := f.Header.Unmarshal(buf[:V2HeaderLen]); err != nil {
		return err
	}
	payloadEnd := len(buf) - V2TagLen
	f.EncryptedPayload = append([]byte(nil), buf[V2HeaderLen:payloadEnd]...)
	f.Tag = append([]byte(nil), buf[payloadEnd:]...)
	return nil
}

// V2TypeName is for logs / errors.
func V2TypeName(t uint8) string {
	switch t {
	case Enums.PACKET_V2_INIT:
		return "V2_INIT"
	case Enums.PACKET_V2_INIT_ACK:
		return "V2_INIT_ACK"
	case Enums.PACKET_V2_DATA:
		return "V2_DATA"
	case Enums.PACKET_V2_ACK:
		return "V2_ACK"
	case Enums.PACKET_V2_NACK:
		return "V2_NACK"
	case Enums.PACKET_V2_REKEY:
		return "V2_REKEY"
	case Enums.PACKET_V2_REKEY_ACK:
		return "V2_REKEY_ACK"
	case Enums.PACKET_V2_PROBE:
		return "V2_PROBE"
	case Enums.PACKET_V2_PROBE_ACK:
		return "V2_PROBE_ACK"
	case Enums.PACKET_V2_CLOSE:
		return "V2_CLOSE"
	case Enums.PACKET_V2_PACKED:
		return "V2_PACKED"
	}
	return fmt.Sprintf("V2_UNKNOWN(0x%02x)", t)
}
