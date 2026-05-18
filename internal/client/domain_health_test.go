// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic and initialization for the StormDNS client.
// This file (domain_health_test.go) tests per-domain health tracking and parking.
// ==============================================================================
package client

import (
	"testing"
	"time"
)

func TestDomainHealth_ParksOnFailure(t *testing.T) {
	h := NewDomainHealth([]DomainSpec{
		{FQDN: "a.example.com", Weight: 1},
		{FQDN: "b.example.com", Weight: 1},
	}, time.Now)
	for i := 0; i < 100; i++ {
		h.RecordFailure("a.example.com")
	}
	if !h.IsParked("a.example.com") {
		t.Fatal("expected a.example.com to be parked")
	}
}

func TestDomainHealth_PickAvoidsParked(t *testing.T) {
	h := NewDomainHealth([]DomainSpec{
		{FQDN: "a.example.com", Weight: 1},
		{FQDN: "b.example.com", Weight: 1},
	}, time.Now)
	for i := 0; i < 100; i++ {
		h.RecordFailure("a.example.com")
	}
	for i := 0; i < 10; i++ {
		if h.Pick() == "a.example.com" {
			t.Fatal("Pick returned parked domain")
		}
	}
}

func TestDomainHealth_UnparkAfterBackoff(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	clock := &mockClock{t: now}
	h := NewDomainHealth([]DomainSpec{{FQDN: "x.example.com", Weight: 1}}, clock.Now)
	for i := 0; i < 100; i++ {
		h.RecordFailure("x.example.com")
	}
	if !h.IsParked("x.example.com") {
		t.Fatal("expected park")
	}
	clock.t = now.Add(11 * time.Minute)
	if h.IsParked("x.example.com") {
		t.Fatal("expected unpark after backoff")
	}
}

type mockClock struct{ t time.Time }

func (m *mockClock) Now() time.Time { return m.t }
