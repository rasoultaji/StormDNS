// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package antidpi

import (
	"math/rand"
	"sort"
)

type RRType uint16

const (
	RRTypeA     RRType = 1
	RRTypeAAAA  RRType = 28
	RRTypeTXT   RRType = 16
	RRTypeSVCB  RRType = 64
	RRTypeHTTPS RRType = 65
)

func (r RRType) String() string {
	switch r {
	case RRTypeA:
		return "A"
	case RRTypeAAAA:
		return "AAAA"
	case RRTypeTXT:
		return "TXT"
	case RRTypeSVCB:
		return "SVCB"
	case RRTypeHTTPS:
		return "HTTPS"
	}
	return "UNKNOWN"
}

type RRTypeMix struct {
	A, AAAA, TXT, SVCB, HTTPS int
}

type RRTypePolicy struct {
	rng     *rand.Rand
	buckets []rrBucket
	total   int
}

type rrBucket struct {
	t   RRType
	cum int
}

func NewRRTypePolicy(mix RRTypeMix, src rand.Source) *RRTypePolicy {
	raw := []rrBucket{
		{RRTypeA, mix.A},
		{RRTypeAAAA, mix.AAAA},
		{RRTypeTXT, mix.TXT},
		{RRTypeSVCB, mix.SVCB},
		{RRTypeHTTPS, mix.HTTPS},
	}
	sort.SliceStable(raw, func(i, j int) bool { return raw[i].cum > raw[j].cum })
	p := &RRTypePolicy{rng: rand.New(src)}
	acc := 0
	for _, b := range raw {
		if b.cum == 0 {
			continue
		}
		acc += b.cum
		p.buckets = append(p.buckets, rrBucket{t: b.t, cum: acc})
	}
	p.total = acc
	return p
}

func (p *RRTypePolicy) Pick() RRType {
	if p.total == 0 || len(p.buckets) == 0 {
		return RRTypeA
	}
	r := p.rng.Intn(p.total)
	for _, b := range p.buckets {
		if r < b.cum {
			return b.t
		}
	}
	return p.buckets[len(p.buckets)-1].t
}

func (p *RRTypePolicy) BiasOnPassthrough(passthrough map[RRType]bool) {
	var kept []rrBucket
	acc := 0
	prev := 0
	for _, b := range p.buckets {
		w := b.cum - prev
		prev = b.cum
		if passthrough[b.t] {
			acc += w
			kept = append(kept, rrBucket{t: b.t, cum: acc})
		}
	}
	p.buckets = kept
	p.total = acc
}
