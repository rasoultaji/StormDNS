// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

type MultiPumpEntry struct {
	Pump  *V2Pump
	Score float64
}

// MultiPump fans out queries across multiple V2Pumps, trying the
// highest-scored pump first and falling over to the next on error.
// Spec §9.6: default K=3 top-scored pairs.
type MultiPump struct {
	entries []MultiPumpEntry
	topK    int
}

func NewMultiPump(entries []MultiPumpEntry) *MultiPump {
	cp := append([]MultiPumpEntry(nil), entries...)
	sort.Slice(cp, func(i, j int) bool { return cp[i].Score > cp[j].Score })
	topK := 3
	if len(cp) < topK {
		topK = len(cp)
	}
	return &MultiPump{entries: cp, topK: topK}
}

var ErrAllPumpsFailed = errors.New("multipump: all entries returned error")

func (m *MultiPump) Query(ctx context.Context, q []byte) ([]byte, error) {
	if len(m.entries) == 0 {
		return nil, fmt.Errorf("multipump: no entries")
	}
	var lastErr error
	tried := 0
	for _, e := range m.entries {
		if tried >= m.topK {
			break
		}
		tried++
		resp, err := e.Pump.Query(ctx, q)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("%w: last=%v", ErrAllPumpsFailed, lastErr)
}

func (m *MultiPump) Close() error {
	for _, e := range m.entries {
		_ = e.Pump.Close()
	}
	return nil
}
