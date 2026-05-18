// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package antidpi

import (
	"encoding/base32"
	"errors"
	"fmt"
	"math/rand"
	"strings"
)

// Spec §7.1: labels are base32hex-encoded fragments of frame bytes,
// split into 2..5 labels, optionally interleaved with dictionary fragments.
// We use a single-character ASCII prefix to distinguish encoded from
// dictionary labels: 'e' = encoded, 'd' = dictionary.
const (
	labelMarkerEncoded = 'e'
	labelMarkerDict    = 'd'
	MaxLabelChars      = 30
	MinLabelChars      = 3
)

var ErrBadLabelShape = errors.New("antidpi: malformed label shape")

var encoder = base32.HexEncoding.WithPadding(base32.NoPadding)

// LabelShaper encodes raw frame bytes into a sequence of DNS labels
// using a deterministic-per-seed shape.
type LabelShaper struct {
	rng        *rand.Rand
	dictionary []string
}

func NewLabelShaper(src rand.Source, dictionary []string) *LabelShaper {
	return &LabelShaper{rng: rand.New(src), dictionary: dictionary}
}

// Encode produces a sequence of DNS labels carrying payload bytes.
// The first character of every label is the marker; the rest is either
// a base32hex chunk or a dictionary fragment.
func (s *LabelShaper) Encode(payload []byte) []string {
	full := encoder.EncodeToString(payload)
	maxChunk := MaxLabelChars - 1
	minChunk := MinLabelChars - 1

	var out []string
	for len(full) > 0 {
		n := minChunk + s.rng.Intn(maxChunk-minChunk+1)
		if n > len(full) {
			n = len(full)
		}
		out = append(out, string(labelMarkerEncoded)+strings.ToLower(full[:n]))
		full = full[n:]

		if len(s.dictionary) > 0 && s.rng.Intn(5) == 0 {
			frag := s.dictionary[s.rng.Intn(len(s.dictionary))]
			out = append(out, string(labelMarkerDict)+frag)
		}
	}
	return out
}

// DecodeLabels reconstructs the payload from a label sequence.
// Dictionary-marked labels are skipped.
func DecodeLabels(labels []string) ([]byte, error) {
	var enc strings.Builder
	enc.Grow(64)
	for _, l := range labels {
		if len(l) < 2 {
			return nil, fmt.Errorf("%w: label too short %q", ErrBadLabelShape, l)
		}
		switch l[0] {
		case labelMarkerEncoded:
			enc.WriteString(strings.ToUpper(l[1:]))
		case labelMarkerDict:
			// skip
		default:
			return nil, fmt.Errorf("%w: unknown label marker %q", ErrBadLabelShape, l[0:1])
		}
	}
	out, err := encoder.DecodeString(enc.String())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadLabelShape, err)
	}
	return out, nil
}
