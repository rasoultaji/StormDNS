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

// dnsRespHeaderSize is the fixed 12-byte DNS message header.
const dnsRespHeaderSize = 12

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

// v2ARRSize is the byte-length of one synthetic A-record RR produced by
// chunkAsRRs(..., 4, RRTypeA): NAME(2)+TYPE(2)+CLASS(2)+TTL(4)+RDLEN(2)+RDATA(4) = 16.
const v2ARRSize = 16

// WrapV2FrameAsDNSResponse builds a complete DNS response that carries
// frame bytes in the answer section (A-record chunked). requestPacket is the
// original DNS query; its first 12 bytes supply the ID and Flags for the
// response header. answerBody is the bytes returned by BuildV2DNSResponse with
// RRTypeA; the ANCOUNT is derived from len(answerBody)/v2ARRSize.
//
// Wire layout:
//
//	DNS header (12 B): ID | QR=1,RA=1,RCODE=0 | QDCOUNT=0 | ANCOUNT=N | ...
//	answer body (variable): the bytes returned by BuildV2DNSResponse
//
// The question section is intentionally omitted so the frame bytes land at a
// known, minimal offset — v2 clients parse the answer section directly.
func WrapV2FrameAsDNSResponse(requestPacket []byte, answerBody []byte) []byte {
	// Determine the DNS transaction ID from the request (bytes 0–1).
	var txID uint16
	if len(requestPacket) >= dnsRespHeaderSize {
		txID = uint16(requestPacket[0])<<8 | uint16(requestPacket[1])
	}

	// Flags: QR=1 (response), AA=0, TC=0, RD=copy from request, RA=1, RCODE=0.
	var reqFlags uint16
	if len(requestPacket) >= 4 {
		reqFlags = uint16(requestPacket[2])<<8 | uint16(requestPacket[3])
	}
	const (
		flagQR uint16 = 1 << 15
		flagRD uint16 = 1 << 8
		flagRA uint16 = 1 << 7
	)
	respFlags := flagQR | flagRA
	if reqFlags&flagRD != 0 {
		respFlags |= flagRD
	}

	// Compute answer count from answer-body length.
	answerCount := uint16(0)
	if v2ARRSize > 0 && len(answerBody) > 0 {
		answerCount = uint16(len(answerBody) / v2ARRSize)
	}

	resp := make([]byte, dnsRespHeaderSize+len(answerBody))
	binary.BigEndian.PutUint16(resp[0:2], txID)
	binary.BigEndian.PutUint16(resp[2:4], respFlags)
	binary.BigEndian.PutUint16(resp[4:6], 0)           // QDCOUNT = 0
	binary.BigEndian.PutUint16(resp[6:8], answerCount) // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0)          // NSCOUNT = 0
	binary.BigEndian.PutUint16(resp[10:12], 0)         // ARCOUNT = 0
	copy(resp[dnsRespHeaderSize:], answerBody)
	return resp
}

// BuildV2RawTXTDNSResponse builds a complete DNS TXT-record response carrying
// frameBytes verbatim (no padding). This is used for INIT_ACK where exact byte
// boundaries matter (the payload contains an AEAD ciphertext).
//
// Wire layout:
//
//	DNS header (12 B): ID copied from requestPacket | QR=1,RA=1,RCODE=0
//	TXT RR: NAME=0xC00C | TYPE=TXT | CLASS=IN | TTL=0 | RDLEN | length-prefixed strings
//
// Returns nil if requestPacket is shorter than 12 bytes or frameBytes is empty.
func BuildV2RawTXTDNSResponse(requestPacket []byte, frameBytes []byte) []byte {
	if len(requestPacket) < dnsRespHeaderSize || len(frameBytes) == 0 {
		return nil
	}

	// Build TXT RDATA: length-prefixed 255-byte strings.
	rdataBuf := &bytes.Buffer{}
	raw := frameBytes
	for len(raw) > 0 {
		n := len(raw)
		if n > 255 {
			n = 255
		}
		rdataBuf.WriteByte(byte(n))
		rdataBuf.Write(raw[:n])
		raw = raw[n:]
	}
	rdata := rdataBuf.Bytes()

	// TXT RR: 2 (ptr name) + 2 (type) + 2 (class) + 4 (ttl) + 2 (rdlen) + rdatalen
	rrLen := 2 + 2 + 2 + 4 + 2 + len(rdata)

	// Flags: QR=1, RA=1, RD mirrored from request.
	reqFlags := uint16(requestPacket[2])<<8 | uint16(requestPacket[3])
	const (
		flagQR uint16 = 1 << 15
		flagRD uint16 = 1 << 8
		flagRA uint16 = 1 << 7
	)
	respFlags := flagQR | flagRA
	if reqFlags&flagRD != 0 {
		respFlags |= flagRD
	}

	resp := make([]byte, dnsRespHeaderSize+rrLen)
	txID := uint16(requestPacket[0])<<8 | uint16(requestPacket[1])
	binary.BigEndian.PutUint16(resp[0:2], txID)
	binary.BigEndian.PutUint16(resp[2:4], respFlags)
	binary.BigEndian.PutUint16(resp[4:6], 0)    // QDCOUNT
	binary.BigEndian.PutUint16(resp[6:8], 1)    // ANCOUNT = 1
	binary.BigEndian.PutUint16(resp[8:10], 0)   // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 0)  // ARCOUNT

	off := dnsRespHeaderSize
	// NAME: pointer to offset 12 (0xC00C, the question name — omitted here,
	// so we point to byte 12 which is right after the header).
	resp[off] = 0xC0
	resp[off+1] = 0x0C
	off += 2
	binary.BigEndian.PutUint16(resp[off:off+2], 16)   // TYPE = TXT
	off += 2
	binary.BigEndian.PutUint16(resp[off:off+2], 1)    // CLASS = IN
	off += 2
	binary.BigEndian.PutUint32(resp[off:off+4], 0)    // TTL = 0
	off += 4
	binary.BigEndian.PutUint16(resp[off:off+2], uint16(len(rdata))) // RDLEN
	off += 2
	copy(resp[off:], rdata)
	return resp
}

// ExtractV2FrameBytesFromTXTResponse is the symmetric decoder for
// BuildV2RawTXTDNSResponse. It strips the 12-byte DNS header and the TXT
// RR wrapper, returning the raw frame bytes.
func ExtractV2FrameBytesFromTXTResponse(resp []byte) ([]byte, error) {
	const rrFixed = 2 + 2 + 2 + 4 + 2 // NAME+TYPE+CLASS+TTL+RDLEN = 12 bytes
	if len(resp) < dnsRespHeaderSize+rrFixed {
		return nil, bytes.ErrTooLarge
	}
	body := resp[dnsRespHeaderSize:]
	if len(body) < rrFixed {
		return nil, bytes.ErrTooLarge
	}
	rdlen := int(binary.BigEndian.Uint16(body[rrFixed-2 : rrFixed]))
	rdata := body[rrFixed:]
	if len(rdata) < rdlen {
		return nil, bytes.ErrTooLarge
	}
	rdata = rdata[:rdlen]

	// Strip length-prefix bytes to recover the raw frame data.
	var out []byte
	i := 0
	for i < len(rdata) {
		n := int(rdata[i])
		i++
		if i+n > len(rdata) {
			break
		}
		out = append(out, rdata[i:i+n]...)
		i += n
	}
	return out, nil
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
