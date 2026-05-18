// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"bytes"
	"encoding/binary"

	"stormdns-go/internal/antidpi"
	"stormdns-go/internal/vpnproto"
)

// BuildV2DNSResponse takes one or more v2 frames and emits a DNS
// answer-section body (without the leading DNS header).
func BuildV2DNSResponse(frames []vpnproto.V2Frame, rrtype antidpi.RRType) []byte {
	var raw []byte
	for _, f := range frames {
		raw = append(raw, f.Marshal()...)
	}
	switch rrtype {
	case antidpi.RRTypeA:
		return chunkAsRRs(raw, 4, uint16(antidpi.RRTypeA))
	case antidpi.RRTypeAAAA:
		return chunkAsRRs(raw, 16, uint16(antidpi.RRTypeAAAA))
	case antidpi.RRTypeTXT:
		return encodeAsTXT(raw)
	default:
		return chunkAsRRs(raw, 4, uint16(antidpi.RRTypeA))
	}
}

// chunkAsRRs slices `raw` into fixed-width RRs.
// Each RR: NAME(2-byte pointer to question, 0xC00C) + TYPE(2) + CLASS(2,
// IN=1) + TTL(4, 60) + RDLENGTH(2) + RDATA(chunkSize).
func chunkAsRRs(raw []byte, chunkSize int, rrType uint16) []byte {
	var buf bytes.Buffer
	for i := 0; i < len(raw); i += chunkSize {
		end := i + chunkSize
		var chunk []byte
		if end <= len(raw) {
			chunk = raw[i:end]
		} else {
			chunk = make([]byte, chunkSize)
			copy(chunk, raw[i:])
		}
		buf.WriteByte(0xC0)
		buf.WriteByte(0x0C)
		binary.Write(&buf, binary.BigEndian, rrType)        //nolint:errcheck
		binary.Write(&buf, binary.BigEndian, uint16(1))     //nolint:errcheck // class IN
		binary.Write(&buf, binary.BigEndian, uint32(60))    //nolint:errcheck // TTL
		binary.Write(&buf, binary.BigEndian, uint16(chunkSize)) //nolint:errcheck
		buf.Write(chunk)
	}
	return buf.Bytes()
}

func encodeAsTXT(raw []byte) []byte {
	var rdata bytes.Buffer
	for len(raw) > 0 {
		n := len(raw)
		if n > 255 {
			n = 255
		}
		rdata.WriteByte(byte(n))
		rdata.Write(raw[:n])
		raw = raw[n:]
	}
	var buf bytes.Buffer
	buf.WriteByte(0xC0)
	buf.WriteByte(0x0C)
	binary.Write(&buf, binary.BigEndian, uint16(antidpi.RRTypeTXT)) //nolint:errcheck
	binary.Write(&buf, binary.BigEndian, uint16(1))                  //nolint:errcheck
	binary.Write(&buf, binary.BigEndian, uint32(60))                 //nolint:errcheck
	binary.Write(&buf, binary.BigEndian, uint16(rdata.Len()))        //nolint:errcheck
	buf.Write(rdata.Bytes())
	return buf.Bytes()
}

// ExtractV2FrameBytesFromAResponse is the test-side decoder
// matching chunkAsRRs(_, 4, RRTypeA).
func ExtractV2FrameBytesFromAResponse(body []byte) ([]byte, error) {
	var out []byte
	i := 0
	for i < len(body) {
		if i+12 > len(body) {
			break
		}
		rdlen := int(binary.BigEndian.Uint16(body[i+10 : i+12]))
		start := i + 12
		end := start + rdlen
		if end > len(body) {
			break
		}
		out = append(out, body[start:end]...)
		i = end
	}
	return out, nil
}
