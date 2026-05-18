// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package transport

import (
	"context"
	"crypto/rand"
	"fmt"

	"stormdns-go/internal/handshake"
)

// ProbeAuthenticity sends a PSK-sealed PROBE through ch and verifies a
// PSK-sealed PROBE_ACK returns. Returns true iff the server proves it
// holds the PSK (i.e., the response wasn't sinkhole-injected).
//
// Wire format used here is the "naked PROBE" testing convention:
//
//	[16 B client_random][sealed envelope...]
//
// The integrated path in Task 21+ wraps this inside the DNS query carrier
// produced by the antidpi label shaper.
func ProbeAuthenticity(ctx context.Context, ch QueryChannel, psk []byte) (bool, error) {
	cr := make([]byte, 16)
	if _, err := rand.Read(cr); err != nil {
		return false, fmt.Errorf("scanner: rand: %w", err)
	}
	env, err := handshake.PSKAEADSeal(psk, "probe",
		handshake.DirClient, cr, []byte("phantom-dns-probe"), cr)
	if err != nil {
		return false, fmt.Errorf("scanner: seal: %w", err)
	}
	q := append(append([]byte(nil), cr...), env...)
	resp, err := ch.Query(ctx, q)
	if err != nil {
		return false, err
	}
	if len(resp) < 32 {
		return false, fmt.Errorf("scanner: response too short")
	}
	sr := resp[:16]
	ackEnv := resp[16:]
	if _, err := handshake.PSKAEADOpen(psk, "probe",
		handshake.DirServer, sr, ackEnv, sr); err != nil {
		return false, fmt.Errorf("scanner: PROBE_ACK auth failed: %w", err)
	}
	return true, nil
}

// ScanResult is what the scanner reports per (resolver, channel) pair.
type ScanResult struct {
	Resolver  ResolverSpec
	Channel   Kind
	Working   bool
	Authentic bool
	Cap       ChannelCapability
}

// ScanFunc is the shape used by integration glue to inject channel
// construction for a given (resolver, kind).
type ScanFunc func(spec ResolverSpec, kind Kind) (QueryChannel, error)

// ScanAll runs capability and authenticity probes against every
// configured resolver across the channels they advertise.
func ScanAll(ctx context.Context, resolvers []ResolverSpec, psk []byte, dial ScanFunc) []ScanResult {
	var out []ScanResult
	for _, r := range resolvers {
		for _, k := range []Kind{Kind53UDP, KindDoH, KindDoT, KindDoQ} {
			if !resolverSupports(r, k) {
				continue
			}
			ch, err := dial(r, k)
			if err != nil {
				out = append(out, ScanResult{Resolver: r, Channel: k,
					Cap: ChannelCapability{LastErr: err}})
				continue
			}
			cap, err := ProbeCapability(ctx, ch)
			res := ScanResult{Resolver: r, Channel: k, Cap: cap,
				Working: err == nil && cap.Working}
			if res.Working {
				if ok, _ := ProbeAuthenticity(ctx, ch, psk); ok {
					res.Authentic = true
				}
			}
			_ = ch.Close()
			out = append(out, res)
		}
	}
	return out
}

func resolverSupports(r ResolverSpec, k Kind) bool {
	switch k {
	case Kind53UDP:
		return r.IP != ""
	case KindDoH:
		return r.DoH != ""
	case KindDoT:
		return r.DoT != ""
	case KindDoQ:
		return r.DoQ != ""
	}
	return false
}
