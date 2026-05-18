// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package transport

import (
	"context"
	"time"
)

type Kind int

const (
	Kind53UDP Kind = iota
	KindDoH
	KindDoT
	KindDoQ
)

func (k Kind) String() string {
	switch k {
	case Kind53UDP:
		return "udp53"
	case KindDoH:
		return "doh"
	case KindDoT:
		return "dot"
	case KindDoQ:
		return "doq"
	}
	return "unknown"
}

type Health struct {
	RTTEMA       time.Duration
	SuccessRate  float64
	BudgetTokens int
	LastError    time.Time
	Parked       bool
	UnparkAt     time.Time
}

// QueryChannel sends one DNS query and returns one DNS response.
// Implementations connect only to *public DNS resolvers* — see Task 18
// for the no-direct-route validator.
type QueryChannel interface {
	Query(ctx context.Context, dnsMessage []byte) ([]byte, error)
	MaxResponseBytes() int
	Health() Health
	Kind() Kind
	Close() error
}
