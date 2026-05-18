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
)

func TestRRTypePolicy_HonorsWeights(t *testing.T) {
	p := NewRRTypePolicy(RRTypeMix{A: 60, AAAA: 30, TXT: 10}, rand.NewSource(1))
	counts := map[RRType]int{}
	for i := 0; i < 10000; i++ {
		counts[p.Pick()]++
	}
	total := counts[RRTypeA] + counts[RRTypeAAAA] + counts[RRTypeTXT]
	if total != 10000 {
		t.Fatalf("unexpected RR types appearing; counts=%+v", counts)
	}
	if counts[RRTypeA] < 5000 || counts[RRTypeA] > 7000 {
		t.Errorf("A count %d outside (5000,7000) for 60%% weight", counts[RRTypeA])
	}
	if counts[RRTypeTXT] > 1500 || counts[RRTypeTXT] < 500 {
		t.Errorf("TXT count %d outside (500,1500) for 10%% weight", counts[RRTypeTXT])
	}
}

func TestRRTypePolicy_BiasOnPassthrough(t *testing.T) {
	p := NewRRTypePolicy(RRTypeMix{A: 50, HTTPS: 30, SVCB: 20}, rand.NewSource(2))
	passthrough := map[RRType]bool{RRTypeA: true}
	p.BiasOnPassthrough(passthrough)
	for i := 0; i < 100; i++ {
		if p.Pick() != RRTypeA {
			t.Fatalf("after bias, only A should be picked")
		}
	}
}

func TestDefaultDictionary_NonEmpty(t *testing.T) {
	if len(DefaultDictionary) == 0 {
		t.Fatal("default dictionary should ship with non-empty content")
	}
	for _, w := range DefaultDictionary {
		if len(w) < 2 || len(w) > 12 {
			t.Errorf("dict entry %q outside (2..12)", w)
		}
	}
}
