// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package antidpi

// PickBucket returns the smallest bucket >= currentSize, or currentSize
// itself if it exceeds all buckets.
func PickBucket(currentSize int, buckets []int) int {
	for _, b := range buckets {
		if b >= currentSize {
			return b
		}
	}
	return currentSize
}

// PaddingBytes returns padding-option byte count to bring carrier to target.
func PaddingBytes(currentSize, target, overhead int) int {
	n := target - currentSize - overhead
	if n < 0 {
		return 0
	}
	return n
}

var DefaultBucketsNarrow = []int{128, 256, 512, 1024, 1232}
var DefaultBucketsWide = []int{512, 1024, 2048, 4096, 8192, 16384}
