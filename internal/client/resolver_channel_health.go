// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the StormDNS client.
// This file (resolver_channel_health.go) tracks per-(resolver, channel) health
// state for the v2 pick path. The v1 balancer (balancer.go) is unmodified.
// ==============================================================================
package client

import (
	"sync"
	"time"

	"stormdns-go/internal/transport"
)

// ResolverChannelKey uniquely identifies a (resolver, channel-kind) pair.
type ResolverChannelKey struct {
	ResolverID string
	Channel    transport.Kind
}

// ResolverChannelHealth tracks EMA RTT and rolling success rate per key and
// parks keys whose success rate drops below rchParkThreshold.
type ResolverChannelHealth struct {
	mu    sync.Mutex
	state map[ResolverChannelKey]*rchState
}

type rchState struct {
	rttEMA      time.Duration
	successRate float64
	tokenBucket int
	lastErr     time.Time
	parked      bool
	unparkAt    time.Time
}

const (
	rchParkThreshold = 0.5
	rchParkInterval  = 5 * time.Minute
	rchDefaultBudget = 200
)

// NewResolverChannelHealth creates an empty ResolverChannelHealth tracker.
func NewResolverChannelHealth() *ResolverChannelHealth {
	return &ResolverChannelHealth{state: make(map[ResolverChannelKey]*rchState)}
}

// get returns (or lazily initialises) the state for a key. Caller must hold mu.
func (r *ResolverChannelHealth) get(k ResolverChannelKey) *rchState {
	s, ok := r.state[k]
	if !ok {
		s = &rchState{successRate: 1.0, tokenBucket: rchDefaultBudget}
		r.state[k] = s
	}
	return s
}

// RecordSuccess updates the RTT EMA and nudges the success rate upward.
func (r *ResolverChannelHealth) RecordSuccess(k ResolverChannelKey, rtt time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.get(k)
	if s.rttEMA == 0 {
		s.rttEMA = rtt
	} else {
		s.rttEMA = time.Duration(float64(s.rttEMA)*0.8 + float64(rtt)*0.2)
	}
	s.successRate = s.successRate*0.95 + 1.0*0.05
}

// RecordFailure nudges the success rate downward and parks the key if it falls
// below rchParkThreshold.
func (r *ResolverChannelHealth) RecordFailure(k ResolverChannelKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.get(k)
	s.successRate = s.successRate * 0.95
	s.lastErr = time.Now()
	if s.successRate < rchParkThreshold && !s.parked {
		s.parked = true
		s.unparkAt = time.Now().Add(rchParkInterval)
	}
}

// IsParked reports whether the key is currently in the parked (backoff) state.
// Automatically unparks keys whose park window has elapsed.
func (r *ResolverChannelHealth) IsParked(k ResolverChannelKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.get(k)
	if s.parked && time.Now().After(s.unparkAt) {
		s.parked = false
		s.successRate = 1.0
	}
	return s.parked
}

// Score returns a higher-is-better score for the key.
// Parked keys score 0. Healthy keys score successRate * (1000 / (rttMs + 50)).
func (r *ResolverChannelHealth) Score(k ResolverChannelKey) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.get(k)
	if s.parked && time.Now().Before(s.unparkAt) {
		return 0
	}
	if s.parked {
		// Auto-unpark if window elapsed.
		s.parked = false
		s.successRate = 1.0
	}
	rttMs := float64(s.rttEMA / time.Millisecond)
	if rttMs <= 0 {
		rttMs = 100
	}
	return s.successRate * (1000.0 / (rttMs + 50.0))
}
