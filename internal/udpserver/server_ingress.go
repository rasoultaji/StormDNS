// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"errors"
	"fmt"
	"strings"
	"time"

	DnsParser "stormdns-go/internal/dnsparser"
	domainMatcher "stormdns-go/internal/domainmatcher"
	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

func (s *Server) handlePacket(packet []byte) []byte {
	parsed, err := DnsParser.ParseDNSRequestLite(packet)
	if err != nil {
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}

		return s.buildNoDataResponseLogged(packet, "request-parse-failed")
	}

	if !parsed.HasQuestion {
		return s.buildNoDataResponseLogged(packet, "request-has-no-question")
	}

	decision := s.domainMatcher.Match(parsed)
	if decision.Action == domainMatcher.ActionProcess {
		response := s.handleTunnelCandidate(packet, parsed, decision)
		if response != nil {
			return response
		}

		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-process-failed")
	}

	if decision.Action == domainMatcher.ActionFormatError || decision.Action == domainMatcher.ActionNoData {
		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-no-data")
	}

	return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-no-data")
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision) []byte {
	// v2 dispatch: extract the per-label slice from the full request name,
	// try antidpi decoding, and classify. v1 traffic falls through unchanged.
	if decision.BaseDomain != "" && len(decision.RequestName) > len(decision.BaseDomain)+1 {
		subdomainEnd := len(decision.RequestName) - len(decision.BaseDomain) - 1
		labelSlice := strings.Split(decision.RequestName[:subdomainEnd], ".")
		if rawBytes, err := ExtractV2FrameFromQName(labelSlice); err == nil {
			if v2Frame := DecodeV2FrameFromQueryBytes(rawBytes); v2Frame != nil {
				if resp := s.handleV2(packet, *v2Frame); resp != nil {
					return resp
				}
				return s.buildNoDataResponseLiteLogged(packet, parsed, "v2-dispatched")
			}
		}
	}

	vpnPacket, err := VpnProto.ParseInflatedFromLabels(decision.Labels, s.codec)
	if err != nil {
		if errors.Is(err, VpnProto.ErrInvalidFragmentInfo) {
			s.fragmentInvalidHeader.Add(1)
		}
		return s.buildNoDataResponseLiteLogged(packet, parsed, "vpn-proto-parse-failed")
	}

	if vpnPacket.PacketType == Enums.PACKET_SESSION_CLOSE {
		s.handleSessionCloseNotice(vpnPacket, time.Now())
		return s.buildNoDataResponseLiteLogged(packet, parsed, "session-close-notice")
	}

	if !isPreSessionRequestType(vpnPacket.PacketType) {
		validation := s.validatePostSessionPacket(packet, decision.RequestName, vpnPacket)
		if !validation.ok {
			return validation.response
		}

		if !s.handlePostSessionPacket(vpnPacket, validation.record) {
			return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("post-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
		}

		return s.serveQueuedOrPong(packet, decision.RequestName, validation.record, time.Now())
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_MTU_UP_REQ:
		return s.handleMTUUpRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_MTU_DOWN_REQ:
		return s.handleMTUDownRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_SESSION_INIT:
		return s.handleSessionInitRequest(packet, decision, vpnPacket)
	default:
		return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("pre-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
	}
}

// handleV2 is the entry point for decoded v2 frames. Returns a DNS response
// byte slice when the frame produces a reply (e.g. INIT → INIT_ACK), or nil
// when the frame is silently handled / dropped.
//
// requestPacket is the raw DNS query bytes and is used to copy the transaction
// ID and RD flag into the DNS response header.
func (s *Server) handleV2(requestPacket []byte, f VpnProto.V2Frame) []byte {
	switch f.Header.Type {
	case Enums.PACKET_V2_INIT:
		return s.handleV2Init(requestPacket, f)
	default:
		// TODO(Phase G follow-up): handle DATA, ACK, CLOSE, etc.
		// Non-INIT v2 frames are not yet implemented; log and drop.
		if s.log != nil {
			s.log.Debugf("v2: drop unhandled frame type 0x%02x (Phase G follow-up)", f.Header.Type)
		}
		return nil
	}
}

// handleV2Init handles a PACKET_V2_INIT frame: runs the server-side handshake
// via V2SessionRegistry.AcceptInit and returns a DNS response carrying the
// INIT_ACK V2Frame, or nil on error.
//
// Wire convention (per spec §5.3):
//
//	INIT  query  EncryptedPayload = clientRandom(16) || sealed-INIT-envelope
//	INIT_ACK reply EncryptedPayload = serverRandom(16) || sealed-INIT_ACK-envelope
func (s *Server) handleV2Init(requestPacket []byte, f VpnProto.V2Frame) []byte {
	const clientRandomLen = 16
	if len(f.EncryptedPayload) < clientRandomLen {
		if s.log != nil {
			s.log.Debugf("v2 INIT: payload too short (%d bytes)", len(f.EncryptedPayload))
		}
		return nil
	}

	clientRandom := f.EncryptedPayload[:clientRandomLen]
	env := f.EncryptedPayload[clientRandomLen:]

	ack, sess, err := s.v2sessions.AcceptInit(env, clientRandom, time.Now())
	if err != nil {
		if s.log != nil {
			s.log.Debugf("v2 INIT: AcceptInit failed: %v", err)
		}
		return nil
	}

	// Build the INIT_ACK frame: EncryptedPayload = serverRandom(16) || ack-envelope.
	ackPayload := make([]byte, clientRandomLen+len(ack))
	copy(ackPayload[:clientRandomLen], sess.ServerRandom)
	copy(ackPayload[clientRandomLen:], ack)

	respFrame := VpnProto.V2Frame{
		Header: VpnProto.V2Header{
			Type:      Enums.PACKET_V2_INIT_ACK,
			ChCls:     f.Header.ChCls,
			SessionID: sess.SessionID,
			StreamID:  0,
			SeqNum:    0,
		},
		EncryptedPayload: ackPayload,
		Tag:              make([]byte, VpnProto.V2TagLen),
	}

	// Use a TXT-record DNS response so the frame bytes are stored without any
	// A-record 4-byte padding — the AEAD ciphertext must be delivered verbatim.
	return BuildV2RawTXTDNSResponse(requestPacket, respFrame.Marshal())
}
