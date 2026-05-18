// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package compression

import (
	"bytes"
	"testing"
)

func TestLZ4_RoundTrip(t *testing.T) {
	src := bytes.Repeat([]byte("phantom-dns-"), 100)
	ct, err := CompressLZ4(src)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("compressed empty")
	}
	pt, err := DecompressLZ4(ct)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(pt, src) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestLZ4_RatioBeatsRaw(t *testing.T) {
	src := bytes.Repeat([]byte("AAAAAAAA"), 100)
	ct, _ := CompressLZ4(src)
	if len(ct) >= len(src) {
		t.Fatalf("ratio: ct=%d src=%d", len(ct), len(src))
	}
}
