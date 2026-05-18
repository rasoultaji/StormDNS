// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package antidpi

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
)

func TestLabelShape_RoundTrip(t *testing.T) {
	shaper := NewLabelShaper(rand.NewSource(42), nil)
	payload := []byte{0x00, 0x11, 0x22, 0xFF, 0xAA, 0x55, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}
	labels := shaper.Encode(payload)
	if len(labels) < 1 {
		t.Fatal("encoder returned no labels")
	}
	decoded, err := DecodeLabels(labels)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("round-trip mismatch: got %x want %x", decoded, payload)
	}
}

func TestLabelShape_DictionaryFragmentsAreIgnoredOnDecode(t *testing.T) {
	dict := []string{"cdn", "img", "api"}
	shaper := NewLabelShaper(rand.NewSource(1), dict)
	payload := []byte("hello-phantom-dns")
	labels := shaper.Encode(payload)

	sawDict := false
	for _, l := range labels {
		for _, d := range dict {
			if strings.EqualFold(l, d) {
				sawDict = true
			}
		}
	}
	if !sawDict {
		t.Skip("RNG didn't pick a dict fragment with this seed; not a correctness bug")
	}

	decoded, err := DecodeLabels(labels)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("decode mismatch: got %q want %q", decoded, payload)
	}
}

func TestLabelShape_LabelLengthBounds(t *testing.T) {
	shaper := NewLabelShaper(rand.NewSource(7), nil)
	payload := bytes.Repeat([]byte{0xAA}, 200)
	labels := shaper.Encode(payload)
	for _, l := range labels {
		if len(l) == 0 || len(l) > MaxLabelChars {
			t.Fatalf("label %q out of bounds (1..%d)", l, MaxLabelChars)
		}
	}
}

func TestDecodeLabels_RejectsInvalid(t *testing.T) {
	if _, err := DecodeLabels([]string{"!!!not-base32hex!!!"}); err == nil {
		t.Fatal("expected error on garbage labels")
	}
}
