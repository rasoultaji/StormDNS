// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package transport

import (
	"context"
	"errors"
	"time"
)

// ChannelCapability summarises a (resolver, channel) probe outcome.
type ChannelCapability struct {
	Working     bool
	RTT         time.Duration
	MaxBytes    int
	PassRRTypes []uint16
	LastErr     error
}

var ErrProbeShort = errors.New("transport: probe response too short")

// ProbeCapability issues a benign A-record query against ch and times it.
// The benign query is `A example.com`. We accept any response of at least
// 12 bytes (the DNS header) as "working" — we don't validate the answer body.
func ProbeCapability(ctx context.Context, ch QueryChannel) (ChannelCapability, error) {
	start := time.Now()
	q := benignQuery("example.com.")
	resp, err := ch.Query(ctx, q)
	if err != nil {
		return ChannelCapability{Working: false, LastErr: err}, err
	}
	if len(resp) < 12 {
		return ChannelCapability{Working: false, LastErr: ErrProbeShort}, ErrProbeShort
	}
	return ChannelCapability{
		Working:  true,
		RTT:      time.Since(start),
		MaxBytes: ch.MaxResponseBytes(),
	}, nil
}

// benignQuery returns a minimal RFC 1035 DNS query for `qname` IN A with ID 0.
func benignQuery(qname string) []byte {
	labels := encodeQName(qname)
	buf := make([]byte, 12+len(labels)+4)
	buf[2] = 0x01 // flags: RD=1
	buf[5] = 0x01 // QDCOUNT=1
	copy(buf[12:], labels)
	buf[12+len(labels)+0] = 0x00
	buf[12+len(labels)+1] = 0x01 // QTYPE=A
	buf[12+len(labels)+2] = 0x00
	buf[12+len(labels)+3] = 0x01 // QCLASS=IN
	return buf
}

func encodeQName(name string) []byte {
	out := make([]byte, 0, len(name)+1)
	label := make([]byte, 0, 16)
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '.' {
			out = append(out, byte(len(label)))
			out = append(out, label...)
			label = label[:0]
			continue
		}
		label = append(label, c)
	}
	if len(label) > 0 {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0x00)
	return out
}
