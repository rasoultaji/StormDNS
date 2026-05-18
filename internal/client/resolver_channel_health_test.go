// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package client

import (
	"testing"
	"time"

	"stormdns-go/internal/transport"
)

func TestResolverChannelHealth_TracksPerChannelSeparately(t *testing.T) {
	rch := NewResolverChannelHealth()
	key := ResolverChannelKey{ResolverID: "cf", Channel: transport.Kind53UDP}
	keyDoH := ResolverChannelKey{ResolverID: "cf", Channel: transport.KindDoH}

	rch.RecordSuccess(key, 50*time.Millisecond)
	for i := 0; i < 50; i++ {
		rch.RecordFailure(keyDoH)
	}
	if rch.IsParked(key) {
		t.Fatal("cf/udp53 should be healthy")
	}
	if !rch.IsParked(keyDoH) {
		t.Fatal("cf/doh should be parked after sustained failure")
	}
}

func TestResolverChannelHealth_ScoreIsPositiveForHealthy(t *testing.T) {
	rch := NewResolverChannelHealth()
	key := ResolverChannelKey{ResolverID: "google", Channel: transport.KindDoH}

	rch.RecordSuccess(key, 30*time.Millisecond)
	score := rch.Score(key)
	if score <= 0 {
		t.Fatalf("expected positive score for healthy key, got %f", score)
	}
}

func TestResolverChannelHealth_ScoreIsZeroForParked(t *testing.T) {
	rch := NewResolverChannelHealth()
	key := ResolverChannelKey{ResolverID: "bad", Channel: transport.KindDoT}

	for i := 0; i < 50; i++ {
		rch.RecordFailure(key)
	}
	score := rch.Score(key)
	if score != 0 {
		t.Fatalf("expected zero score for parked key, got %f", score)
	}
}

func TestPickV2_SelectsHighestScore(t *testing.T) {
	rch := NewResolverChannelHealth()

	fast := ResolverChannelKey{ResolverID: "fast", Channel: transport.Kind53UDP}
	slow := ResolverChannelKey{ResolverID: "slow", Channel: transport.Kind53UDP}

	rch.RecordSuccess(fast, 10*time.Millisecond)
	rch.RecordSuccess(slow, 500*time.Millisecond)

	pool := []ResolverChannelKey{slow, fast}
	pick, ok := PickV2(pool, rch)
	if !ok {
		t.Fatal("expected a valid pick")
	}
	if pick.ResolverID != "fast" {
		t.Fatalf("expected fast resolver, got %s", pick.ResolverID)
	}
}

func TestPickV2_ReturnsFalseWhenAllParked(t *testing.T) {
	rch := NewResolverChannelHealth()

	key := ResolverChannelKey{ResolverID: "bad", Channel: transport.KindDoH}
	for i := 0; i < 50; i++ {
		rch.RecordFailure(key)
	}

	pool := []ResolverChannelKey{key}
	_, ok := PickV2(pool, rch)
	if ok {
		t.Fatal("expected no pick when all keys are parked")
	}
}
