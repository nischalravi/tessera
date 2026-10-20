package queue

import (
	"math/rand/v2"
	"time"
)

// Backoff is the wait before a failed job runs again: Base doubling with each
// attempt up to Max, then spread by Jitter (0.2 is plus or minus 20%) so jobs
// that failed together do not retry together.
type Backoff struct {
	Base, Max time.Duration
	Jitter    float64
	// Rand returns a number in [0,1); nil uses math/rand. Tests fix it.
	Rand func() float64
}

// DefaultBackoff waits about 10s, 20s, 40s ... up to 15 minutes.
var DefaultBackoff = Backoff{Base: 10 * time.Second, Max: 15 * time.Minute, Jitter: 0.2}

// Delay is the wait after attempts attempts have failed (attempts >= 1).
func (b Backoff) Delay(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := b.Base
	for i := 1; i < attempts && d < b.Max; i++ {
		d *= 2
	}
	if b.Max > 0 && d > b.Max {
		d = b.Max
	}
	r := rand.Float64 // #nosec G404 -- jitter only, not a secret
	if b.Rand != nil {
		r = b.Rand
	}
	f := 1 + b.Jitter*(2*r()-1)
	return time.Duration(float64(d) * f)
}
