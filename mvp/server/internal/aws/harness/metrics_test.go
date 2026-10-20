package harness

import (
	"math"
	"testing"
)

// TestWilsonAgainstPublishedValues checks the Wilson score interval against
// Newcombe (1998), "Two-sided confidence intervals for the single proportion:
// comparison of seven methods", Table I, method 3 (Wilson score, no continuity
// correction), at 95%.
func TestWilsonAgainstPublishedValues(t *testing.T) {
	for _, tc := range []struct {
		k, n   int
		lo, hi float64
	}{
		{81, 263, 0.2553, 0.3662},
		{15, 148, 0.0624, 0.1605},
		{0, 20, 0.0000, 0.1611},
		{1, 29, 0.0061, 0.1718},
		{20, 20, 0.8389, 1.0000},
	} {
		lo, hi := Wilson(tc.k, tc.n)
		if math.Abs(lo-tc.lo) > 6e-4 || math.Abs(hi-tc.hi) > 6e-4 {
			t.Errorf("Wilson(%d,%d) = [%.4f, %.4f], published [%.4f, %.4f]", tc.k, tc.n, lo, hi, tc.lo, tc.hi)
		}
	}
	if lo, hi := Wilson(0, 0); lo != 0 || hi != 1 {
		t.Errorf("Wilson(0,0) = [%v, %v]", lo, hi)
	}
}

// TestGateTolerances pins the numbers quoted in design §13.7.
func TestGateTolerances(t *testing.T) {
	for _, tc := range []struct{ n, want int }{{10000, 38}, {5000, 16}} {
		if got := MaxDisagreements(tc.n, 0.995); got != tc.want {
			t.Errorf("MaxDisagreements(%d) = %d, design says %d", tc.n, got, tc.want)
		}
	}
	// One more than the tolerance fails the bound; the tolerance passes.
	if lo := LowerBound95(10000-38, 10000); lo < 0.995 {
		t.Errorf("38 disagreements in 10,000: LB %.5f", lo)
	}
	if lo := LowerBound95(10000-39, 10000); lo >= 0.995 {
		t.Errorf("39 disagreements in 10,000: LB %.5f", lo)
	}
	// The two-sided interval is stricter: it tolerates 36, not 38. The gate
	// follows the design's numbers (see LowerBound95).
	if lo, _ := Wilson(10000-37, 10000); lo >= 0.995 {
		t.Errorf("two-sided lower end at 37 disagreements: %.5f", lo)
	}
}

func fill(m *Metrics, st Stratum, agree, disagree, unsupported int) {
	for i := 0; i < agree; i++ {
		m.Add(Check{Stratum: st, Service: "s3", Verdict: Agree, Covered: true})
	}
	for i := 0; i < disagree; i++ {
		m.Add(Check{Stratum: st, Service: "s3", Verdict: Disagree, Covered: true})
	}
	for i := 0; i < unsupported; i++ {
		m.Add(Check{Stratum: st, Service: "s3", Verdict: Excluded, Exclusion: ExcludedUnsupported})
	}
}

func TestGate(t *testing.T) {
	cases := []struct {
		name string
		set  func(m *Metrics)
		pass bool
		fail string // substring of the failure
		p1   []Stratum
	}{
		{"green", func(m *Metrics) { fill(m, S2GrammarFuzz, 10050, 5, 0) }, true, "", nil},
		{"too few checks", func(m *Metrics) { fill(m, S2GrammarFuzz, 9000, 0, 0) }, false, "n = 9000", nil},
		{"bound too low", func(m *Metrics) { fill(m, S2GrammarFuzz, 10000, 60, 0) }, false, "Wilson", []Stratum{}},
		{"coverage too low", func(m *Metrics) { fill(m, S2GrammarFuzz, 10050, 0, 400) }, false, "coverage", nil},
		{"an S1 disagreement", func(m *Metrics) {
			fill(m, S2GrammarFuzz, 10050, 0, 0)
			fill(m, S1GoldenDeployed, 59, 1, 0)
		}, false, "S1", []Stratum{S1GoldenDeployed}},
		{"a weak stratum is a P1 but not a gate failure", func(m *Metrics) {
			fill(m, S2GrammarFuzz, 20000, 0, 0)
			fill(m, S4Probes, 195, 5, 0)
		}, true, "", []Stratum{S4Probes}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMetrics()
			tc.set(m)
			r := m.Gate(DefaultGate)
			if r.Pass != tc.pass {
				t.Fatalf("pass = %v, failures %v", r.Pass, r.Failures)
			}
			if tc.fail != "" && !containsAny(r.Failures, tc.fail) {
				t.Fatalf("failures %v lack %q", r.Failures, tc.fail)
			}
			if len(tc.p1) > 0 && (len(r.P1Strata) == 0 || r.P1Strata[0] != tc.p1[0]) {
				t.Fatalf("P1 strata %v, want %v", r.P1Strata, tc.p1)
			}
		})
	}
}

func containsAny(ss []string, sub string) bool {
	for _, s := range ss {
		if len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func TestMetricsCountingRules(t *testing.T) {
	m := NewMetrics()
	f := true
	m.Add(Check{Stratum: S2GrammarFuzz, Service: "s3", Verdict: Agree, Covered: true, M2: &f, M3: &f})
	m.Add(Check{Stratum: S2GrammarFuzz, Service: "iam", Verdict: Disagree, Covered: true})
	m.Add(Check{Stratum: S2GrammarFuzz, Verdict: Excluded, Exclusion: ExcludedInvalid})
	m.Add(Check{Stratum: S2GrammarFuzz, Verdict: Excluded, Exclusion: ExcludedNotAuthority}) // a secondary oracle: not a sample
	m.Add(Check{Stratum: S6SetChecks, Verdict: Agree, Covered: true})                        // not gated
	m.Add(Check{Stratum: S4Probes, Service: "s3", Verdict: Agree, Covered: true, Propagation: true})
	if m.Sampled != 4 || m.Covered != 3 || m.M1.Total != 3 || m.M1.Agree != 2 || m.SetChecks != 1 || m.Propagated != 1 {
		t.Fatalf("%+v", m)
	}
	if m.Excluded[ExcludedInvalid] != 1 || m.Excluded[ExcludedNotAuthority] != 1 || m.M2.Total != 1 || m.M3.Agree != 1 {
		t.Fatalf("%+v", m)
	}
	if got := m.Coverage(); got != 0.75 {
		t.Fatalf("C = %v, want 0.75: unsupported and invalid checks stay in the denominator", got)
	}
	if m.PerService["iam"].Total != 1 || m.PerStratum[S4Probes].Total != 1 {
		t.Fatalf("%+v", m)
	}
}
