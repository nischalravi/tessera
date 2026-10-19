package harness

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
)

// ExcludedEngineError: the engine could not answer the request at all (for
// example an action outside the catalog). Counted, not covered.
const ExcludedEngineError Exclusion = "engine_error"

// Runner runs checks: it asks the engine and the routed oracle about the same
// spec and compares the answers.
type Runner struct {
	Catalog eval.Catalog
	Oracles map[OracleKind]Oracle
	// Settle waits out IAM and KMS eventual consistency before a disagreeing
	// probe is asked again (§13.5: 10 minutes). Nil skips the re-probe, as
	// offline replay does.
	Settle func(ctx context.Context) error
	// Now supplies the clock for latency; nil records zero latency.
	Now func() time.Time
}

// NewRunner returns a runner over the given oracles.
func NewRunner(cat eval.Catalog, oracles ...Oracle) *Runner {
	m := map[OracleKind]Oracle{}
	for _, o := range oracles {
		m[o.Kind()] = o
	}
	return &Runner{Catalog: cat, Oracles: m}
}

// Run executes one check. A check that cannot be compared (a refused policy,
// an engine error) comes back as an excluded Check, not an error; an error means
// the run itself is broken (a missing oracle, a failed oracle call).
func (r *Runner) Run(ctx context.Context, s *RequestSpec) (*Check, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	base := Check{SpecID: s.ID, SpecHash: s.Hash(), Stratum: s.Stratum, Verdict: Excluded}
	base.Service, _, _ = strings.Cut(strings.ToLower(s.Action), ":")
	ours, w, err := Decide(ctx, r.Catalog, s)
	var ref *RefusalError
	switch {
	case errors.As(err, &ref):
		base.Exclusion = Exclusion(ref.Reason)
		base.Note = ref.Detail
		return &base, nil
	case err != nil:
		base.Exclusion, base.Note = ExcludedEngineError, err.Error()
		return &base, nil
	}
	kind := Route(s)
	o, ok := r.Oracles[kind]
	if !ok {
		return nil, fmt.Errorf("harness: spec %s routes to the %s oracle, which is not configured", s.ID, kind)
	}
	start := r.now()
	ans, err := o.Ask(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("harness: spec %s: %w", s.ID, err)
	}
	c := Compare(s, ours, w, ans, true)
	c.LatencyMS = r.now().Sub(start).Milliseconds()

	// Every probe disagreement is re-probed after the settle window (§13.5).
	if kind == OracleProbe && c.Verdict == Disagree && r.Settle != nil {
		if err := r.Settle(ctx); err != nil {
			return nil, err
		}
		again, err := o.Ask(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("harness: spec %s: re-probe: %w", s.ID, err)
		}
		c2 := Compare(s, ours, w, again, true)
		c2.LatencyMS, c2.Settled = c.LatencyMS, true
		if c2.Verdict == Agree {
			c2.Propagation, c2.Note = true, "PROPAGATION: agreed after the settle re-probe"
		}
		c = c2
	}
	return &c, nil
}

func (r *Runner) now() time.Time {
	if r.Now == nil {
		return time.Time{}
	}
	return r.Now()
}

// Evidence is what Classify reads about one divergence (§13.9 step 2).
type Evidence struct {
	Ours      *authz.Decision
	Primary   *Answer // the routed oracle's answer
	Alternate *Answer // another oracle's answer, if one applies (a second simulator, or the simulator for a probe check)
	Probe     *Answer // a live probe of the same check, if one was run
	Settle    *Answer // the re-probe after the settle window
	// ContextMismatch and FixtureDrift are set by the callers that detect them
	// (the request builder, and the snapshot-versus-manifest comparison).
	ContextMismatch bool
	FixtureDrift    bool
}

func agrees(ours *authz.Decision, a *Answer) bool {
	if a == nil || a.Status != AnswerOK {
		return false
	}
	return (ours.Outcome == authz.Allow) == (a.Decision == DecisionAllowed)
}

func sameAllow(a, b *Answer) bool {
	return a != nil && b != nil && a.Status == AnswerOK && b.Status == AnswerOK && (a.Decision == DecisionAllowed) == (b.Decision == DecisionAllowed)
}

// Classify applies the auto-classification rules of §13.9 in order and returns
// the class with a one-line justification. A divergence no rule explains is
// UNCLASSIFIED and goes to manual triage.
func Classify(e Evidence) (DivergenceClass, string) {
	if e.FixtureDrift {
		return ClassFixtureDrift, "the snapshot differs from the Terraform manifest"
	}
	for _, r := range e.Ours.FidelityReasons {
		if r.Code == authz.ReasonCatalogMiss {
			return ClassCatalogStale, "the action or key is missing from the pinned catalog"
		}
	}
	if e.ContextMismatch || (e.Primary != nil && len(e.Primary.Missing) > 0) {
		return ClassContextMismatch, "the oracle ran with different context than the engine"
	}
	if agrees(e.Ours, e.Settle) {
		return ClassPropagation, "agreement after the settle re-probe"
	}
	for _, r := range e.Ours.FidelityReasons {
		if strings.HasPrefix(string(r.Code), "AMBIGUITY:") {
			return ClassDocAmbiguity, "touches " + string(r.Code)
		}
	}
	if e.Probe != nil && e.Primary != nil && e.Primary.Oracle != OracleProbe {
		switch {
		case agrees(e.Ours, e.Probe) && !agrees(e.Ours, e.Primary):
			return ClassSimulatorLimitation, "the probe agrees with the engine; the simulator disagrees with both"
		case !agrees(e.Ours, e.Probe) && sameAllow(e.Primary, e.Probe):
			return ClassEngineBug, "the probe and the simulator agree with each other and disagree with the engine"
		}
	}
	if e.Alternate != nil && e.Primary != nil && sameAllow(e.Primary, e.Alternate) && !agrees(e.Ours, e.Primary) {
		return ClassEngineBug, "two oracles agree with each other and disagree with the engine"
	}
	return ClassUnclassified, "no rule applies; manual triage"
}
