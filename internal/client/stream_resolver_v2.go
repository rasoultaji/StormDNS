// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package client

import (
	"context"

	"stormdns-go/internal/transport"
)

// V2Pump wraps a QueryChannel with a bounded concurrency semaphore
// matching the per-channel inflight cap from [arq] config.
type V2Pump struct {
	ch     transport.QueryChannel
	tokens chan struct{}
}

func NewV2Pump(ch transport.QueryChannel, inflight int) *V2Pump {
	if inflight < 1 {
		inflight = 1
	}
	return &V2Pump{ch: ch, tokens: make(chan struct{}, inflight)}
}

func (p *V2Pump) Query(ctx context.Context, q []byte) ([]byte, error) {
	select {
	case p.tokens <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-p.tokens }()
	return p.ch.Query(ctx, q)
}

func (p *V2Pump) Close() error { return p.ch.Close() }
