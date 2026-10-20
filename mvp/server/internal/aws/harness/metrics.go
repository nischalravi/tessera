package harness

import (
	"fmt"
	"math"
	"sort"
)

// Normal quantiles. z95Two is the two-sided 95% quantile (the ends of a 95%
// interval); z95One is the one-sided 95% quantile (a 95% lower bound).
const (
	z95Two = 1.959963984540054
	z95One = 1.6448536269514722
)

// Wilson returns the two-sided 95% Wilson score interval for k successes in n
// trials. n == 0 gives [0, 1].
func Wilson(k, n int) (lo, hi float64) { return wilsonZ(k, n, z95Two) }

// LowerBound95 is the one-sided 95% Wilson lower bound the gate uses (§13.7).
// The design quotes tolerances of 38 disagreements at n = 10,000 and 16 at
// n = 5,000 for "the Wilson 95% lower bound"; those numbers hold for the
// one-sided bound (z = 1.645). The two-sided interval's lower end (z = 1.96)
// would allow only 36 and 15, so the stated tolerances decide which one the
// gate is.
func LowerBound95(k, n int) float64 {
	lo, _ := wilsonZ(k, n, z95One)
	return lo
}

func wilsonZ(k, n int, z float64) (lo, hi float64) {
	if n <= 0 {
		return 0, 1
	}
	nf, p, z2 := float64(n), float64(k)/float64(n), z*z
	denom := 1 + z2/nf
	centre := p + z2/(2*nf)
	margin := z * math.Sqrt(p*(1-p)/nf+z2/(4*nf*nf))
	lo, hi = (centre-margin)/denom, (centre+margin)/denom
	// The closed forms leave rounding dust at k == 0 and k == n.
	if k == 0 {
		lo = 0
	}
	if k == n {
		hi = 1
	}
	return math.Max(lo, 0), math.Min(hi, 1)
}

// Tally is an agree count out of a total.
type Tally struct {
	Agree int `json:"agree"`
	Total int `json:"total"`
}

func (t *Tally) add(ok bool) {
	t.Total++
	if ok {
		t.Agree++
	}
}

// Rate is Agree/Total, 1 when nothing was checked.
func (t Tally) Rate() float64 {
	if t.Total == 0 {
		return 1
	}
	return float64(t.Agree) / float64(t.Total)
}

// Metrics aggregates checks into M1 to M4 and C (§13.6). Stratum S6 set checks
// and secondary-oracle checks are tallied apart and never enter M1 or C.
type Metrics struct {
	Sampled    int               `json:"sampled"` // gate-eligible checks from the primary oracle, whatever their outcome
	Covered    int               `json:"covered"`
	M1         Tally             `json:"m1"`
	M2         Tally             `json:"m2"`
	M3         Tally             `json:"m3"`
	M4         Tally             `json:"m4"`
	Excluded   map[Exclusion]int `json:"excluded"`
	PerStratum map[Stratum]Tally `json:"per_stratum"`
	PerService map[string]Tally  `json:"per_service"`
	SetChecks  int               `json:"set_checks"` // S6, not gated
	Propagated int               `json:"propagated"` // disagreements that agreed after the settle re-probe
}

// NewMetrics returns an empty aggregate.
func NewMetrics() *Metrics {
	return &Metrics{Excluded: map[Exclusion]int{}, PerStratum: map[Stratum]Tally{}, PerService: map[string]Tally{}}
}

// Add folds one check in.
func (m *Metrics) Add(c Check) {
	if c.Exclusion == ExcludedNotAuthority {
		m.Excluded[c.Exclusion]++
		return
	}
	if !c.Stratum.GateEligible() {
		m.SetChecks++
		return
	}
	m.Sampled++
	if c.Propagation {
		m.Propagated++
	}
	if c.Covered {
		m.Covered++
	}
	if c.Verdict == Excluded {
		m.Excluded[c.Exclusion]++
		return
	}
	ok := c.Verdict == Agree
	m.M1.add(ok)
	st := m.PerStratum[c.Stratum]
	st.add(ok)
	m.PerStratum[c.Stratum] = st
	sv := m.PerService[c.Service]
	sv.add(ok)
	m.PerService[c.Service] = sv
	for _, x := range []struct {
		v *bool
		t *Tally
	}{{c.M2, &m.M2}, {c.M3, &m.M3}, {c.M4, &m.M4}} {
		if x.v != nil {
			x.t.add(*x.v)
		}
	}
}

// Coverage is C: covered / sampled (1 when nothing was sampled).
func (m *Metrics) Coverage() float64 {
	if m.Sampled == 0 {
		return 1
	}
	return float64(m.Covered) / float64(m.Sampled)
}

// WilsonLB is the one-sided 95% Wilson lower bound of M1.
func (m *Metrics) WilsonLB() float64 { return LowerBound95(m.M1.Agree, m.M1.Total) }

// GateConfig holds the thresholds of §13.7.
type GateConfig struct {
	MinN         int     // minimum gate-eligible checks
	MinLowerBand float64 // Wilson lower bound of M1
	MinCoverage  float64 // C
	StratumFloor float64 // a stratum below this point agreement opens a P1
}

// DefaultGate is the nightly gate: n >= 10,000, Wilson LB >= 99.5%, C >= 97%,
// zero S1 disagreements, and a 99% point-agreement floor per stratum.
var DefaultGate = GateConfig{MinN: 10000, MinLowerBand: 0.995, MinCoverage: 0.97, StratumFloor: 0.99}

// GateResult is the verdict on a set of metrics.
type GateResult struct {
	Pass     bool      `json:"pass"`
	N        int       `json:"n"`
	M1       float64   `json:"m1"`
	WilsonLB float64   `json:"wilson_lb"`
	Coverage float64   `json:"coverage"`
	S1Misses int       `json:"s1_disagreements"`
	Failures []string  `json:"failures"`
	P1Strata []Stratum `json:"p1_strata"`
}

// Gate applies the nightly gate (§13.7). P1 strata are reported but do not
// themselves fail the gate; the design opens an issue for them.
func (m *Metrics) Gate(cfg GateConfig) GateResult {
	s1 := m.PerStratum[S1GoldenDeployed]
	r := GateResult{N: m.M1.Total, M1: m.M1.Rate(), WilsonLB: m.WilsonLB(), Coverage: m.Coverage(), S1Misses: s1.Total - s1.Agree}
	fail := func(format string, args ...any) { r.Failures = append(r.Failures, fmt.Sprintf(format, args...)) }
	if r.N < cfg.MinN {
		fail("n = %d, need at least %d gate-eligible checks", r.N, cfg.MinN)
	}
	if r.WilsonLB < cfg.MinLowerBand {
		fail("Wilson 95%% lower bound of M1 = %.5f, need >= %.5f", r.WilsonLB, cfg.MinLowerBand)
	}
	if r.Coverage < cfg.MinCoverage {
		fail("coverage C = %.4f, need >= %.4f", r.Coverage, cfg.MinCoverage)
	}
	if r.S1Misses > 0 {
		fail("%d S1 disagreement(s), need 0", r.S1Misses)
	}
	for st, t := range m.PerStratum {
		if t.Total > 0 && t.Rate() < cfg.StratumFloor {
			r.P1Strata = append(r.P1Strata, st)
		}
	}
	sort.Slice(r.P1Strata, func(i, j int) bool { return r.P1Strata[i] < r.P1Strata[j] })
	r.Pass = len(r.Failures) == 0
	return r
}

// MaxDisagreements is the most disagreements out of n checks whose Wilson lower
// bound still meets lb (the tolerance quoted in §13.7: 38 at n = 10,000).
func MaxDisagreements(n int, lb float64) int {
	best := -1
	for d := 0; d <= n; d++ {
		if LowerBound95(n-d, n) >= lb {
			best = d
		} else {
			break
		}
	}
	return best
}
