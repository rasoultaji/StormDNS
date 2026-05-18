// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package antidpi

import (
	"math"
	"math/rand"
	"time"
)

// Jitter returns log-normal-distributed durations for inter-query spacing.
type Jitter struct {
	mu    float64
	sigma float64
	rng   *rand.Rand
}

func NewJitter(mean time.Duration, sigma float64, src rand.Source) *Jitter {
	meanSec := mean.Seconds()
	if meanSec <= 0 {
		meanSec = 0.001
	}
	mu := math.Log(meanSec) - sigma*sigma/2
	return &Jitter{mu: mu, sigma: sigma, rng: rand.New(src)}
}

func (j *Jitter) Next() time.Duration {
	n := j.rng.NormFloat64()*j.sigma + j.mu
	secs := math.Exp(n)
	return time.Duration(secs * float64(time.Second))
}
