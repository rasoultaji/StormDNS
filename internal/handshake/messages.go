// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package handshake

import (
	"encoding/binary"
	"errors"
	"time"
)

// Wire-format constants for the INIT / INIT_ACK plaintext bodies.
// Layout matches spec §6.1.
const (
	initMsgLen    = 32 + 16 + 2 + 2 + 8 // eph_pub_c + client_random + sess + cap + ts
	initAckMsgLen = 32 + 16 + 2 + 2     // eph_pub_s + server_random + sess + cap
)

var ErrShortHandshakeBuf = errors.New("handshake: buffer too short")

type Init struct {
	EphPubC         []byte // 32 B
	ClientRandom    []byte // 16 B
	ProposedSession uint16
	CapabilityBits  uint16
	Timestamp       time.Time
}

func (m Init) Marshal() []byte {
	buf := make([]byte, initMsgLen)
	copy(buf[0:32], m.EphPubC)
	copy(buf[32:48], m.ClientRandom)
	binary.BigEndian.PutUint16(buf[48:50], m.ProposedSession)
	binary.BigEndian.PutUint16(buf[50:52], m.CapabilityBits)
	binary.BigEndian.PutUint64(buf[52:60], uint64(m.Timestamp.Unix()))
	return buf
}

func (m *Init) Unmarshal(buf []byte) error {
	if len(buf) < initMsgLen {
		return ErrShortHandshakeBuf
	}
	m.EphPubC = append([]byte(nil), buf[0:32]...)
	m.ClientRandom = append([]byte(nil), buf[32:48]...)
	m.ProposedSession = binary.BigEndian.Uint16(buf[48:50])
	m.CapabilityBits = binary.BigEndian.Uint16(buf[50:52])
	m.Timestamp = time.Unix(int64(binary.BigEndian.Uint64(buf[52:60])), 0).UTC()
	return nil
}

type InitAck struct {
	EphPubS         []byte // 32 B
	ServerRandom    []byte // 16 B
	AcceptedSession uint16
	CapabilityBits  uint16
}

func (m InitAck) Marshal() []byte {
	buf := make([]byte, initAckMsgLen)
	copy(buf[0:32], m.EphPubS)
	copy(buf[32:48], m.ServerRandom)
	binary.BigEndian.PutUint16(buf[48:50], m.AcceptedSession)
	binary.BigEndian.PutUint16(buf[50:52], m.CapabilityBits)
	return buf
}

func (m *InitAck) Unmarshal(buf []byte) error {
	if len(buf) < initAckMsgLen {
		return ErrShortHandshakeBuf
	}
	m.EphPubS = append([]byte(nil), buf[0:32]...)
	m.ServerRandom = append([]byte(nil), buf[32:48]...)
	m.AcceptedSession = binary.BigEndian.Uint16(buf[48:50])
	m.CapabilityBits = binary.BigEndian.Uint16(buf[50:52])
	return nil
}
