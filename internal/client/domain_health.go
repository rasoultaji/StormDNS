// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic and initialization for the StormDNS client.
// This file (domain_health.go) implements per-domain health tracking with auto-park/unpark.
// ==============================================================================
package client

import (
	"math/rand"
	"sync"
	"time"
)

type DomainSpec struct {
	FQDN   string
	Weight int
}

type DomainHealth struct {
	now     func() time.Time
	mu      sync.Mutex
	domains map[string]*domainState
	order   []string
}

type domainState struct {
	weight      int
	successRate float64
	windowSucc  int
	windowFail  int
	parked      bool
	unparkAt    time.Time
}

const (
	domainParkThreshold = 0.7
	domainParkInterval  = 10 * time.Minute
	domainWindowSize    = 100
)

func NewDomainHealth(specs []DomainSpec, now func() time.Time) *DomainHealth {
	d := &DomainHealth{
		now:     now,
		domains: make(map[string]*domainState, len(specs)),
	}
	for _, s := range specs {
		w := s.Weight
		if w <= 0 {
			w = 1
		}
		d.domains[s.FQDN] = &domainState{weight: w, successRate: 1.0}
		d.order = append(d.order, s.FQDN)
	}
	return d
}

func (d *DomainHealth) RecordSuccess(fqdn string) { d.update(fqdn, true) }
func (d *DomainHealth) RecordFailure(fqdn string) { d.update(fqdn, false) }

func (d *DomainHealth) update(fqdn string, ok bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, exists := d.domains[fqdn]
	if !exists {
		return
	}
	if ok {
		s.windowSucc++
	} else {
		s.windowFail++
	}
	total := s.windowSucc + s.windowFail
	if total >= domainWindowSize {
		s.successRate = float64(s.windowSucc) / float64(total)
		s.windowSucc = 0
		s.windowFail = 0
		if s.successRate < domainParkThreshold {
			s.parked = true
			s.unparkAt = d.now().Add(domainParkInterval)
		}
	} else if total >= 10 {
		ratio := float64(s.windowSucc) / float64(total)
		if ratio < 0.2 {
			s.parked = true
			s.unparkAt = d.now().Add(domainParkInterval)
		}
	}
}

func (d *DomainHealth) IsParked(fqdn string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.domains[fqdn]
	if !ok {
		return false
	}
	if s.parked && d.now().After(s.unparkAt) {
		s.parked = false
		s.successRate = 1.0
	}
	return s.parked
}

func (d *DomainHealth) Pick() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	candidates := make([]string, 0, len(d.order))
	weights := make([]int, 0, len(d.order))
	total := 0
	now := d.now()
	for _, name := range d.order {
		s := d.domains[name]
		if s.parked && now.Before(s.unparkAt) {
			continue
		}
		if s.parked {
			s.parked = false
			s.successRate = 1.0
		}
		candidates = append(candidates, name)
		weights = append(weights, s.weight)
		total += s.weight
	}
	if total == 0 {
		return ""
	}
	r := rand.Intn(total)
	for i, w := range weights {
		if r < w {
			return candidates[i]
		}
		r -= w
	}
	return candidates[len(candidates)-1]
}
