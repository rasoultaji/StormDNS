// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package antidpi

import (
	"math/rand"
	"testing"
	"time"
)

func TestJitterRange(t *testing.T) {
	j := NewJitter(80*time.Millisecond, 0.4, rand.NewSource(123))
	const N = 1000
	var sum time.Duration
	for i := 0; i < N; i++ {
		d := j.Next()
		if d < 0 {
			t.Fatalf("negative jitter: %v", d)
		}
		if d > 5*time.Second {
			t.Fatalf("absurd jitter: %v", d)
		}
		sum += d
	}
	avg := sum / N
	if avg < 60*time.Millisecond || avg > 150*time.Millisecond {
		t.Errorf("average jitter %v outside (60ms,150ms)", avg)
	}
}
