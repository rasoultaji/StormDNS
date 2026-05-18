// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package antidpi

import "testing"

func TestPickBucket(t *testing.T) {
	buckets := []int{128, 256, 512, 1024, 1232}
	cases := []struct {
		have int
		want int
	}{
		{0, 128}, {100, 128}, {128, 128}, {200, 256}, {257, 512},
		{1200, 1232}, {1300, 1300},
	}
	for _, c := range cases {
		if got := PickBucket(c.have, buckets); got != c.want {
			t.Errorf("PickBucket(%d) = %d, want %d", c.have, got, c.want)
		}
	}
}

func TestPaddingBytes(t *testing.T) {
	n := PaddingBytes(200, 256, 8)
	if n < 0 {
		t.Fatalf("padding bytes negative: %d", n)
	}
}
