package eval

import (
	"fmt"
	"sort"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// maxFlips bounds the re-runs of §7.9. A decision with more flagged components
// than this treats the extra ones as outcome-sensitive (the safe side).
const maxFlips = 64

// component is one approximated part of the decision: a statement or a gate.
// Its alternative reading is an altSet; the reasons say why it is flagged.
type component struct {
	alt     altSet
	reasons []authz.FidelityReason
}

func stmtDetail(se *stmtEval) string {
	return fmt.Sprintf("%s statement %d", se.ref.SourceARN, se.ref.StatementIndex)
}

// assess implements §7.9: each flagged component is flipped in turn and steps
// 2 to 6 re-run; only a component whose flip changes the outcome is
// outcome-sensitive and can lower the fidelity.
func (e *evaluator) assess(base *verdict) error {
	var comps []component
	for _, se := range e.allStmts {
		if len(se.amb) == 0 {
			continue
		}
		c := component{alt: altSet{stmt: map[string]authz.Tri{se.key: se.alt}}}
		for _, id := range se.amb {
			c.reasons = append(c.reasons, authz.FidelityReason{Code: authz.AmbiguityReason(id), Detail: stmtDetail(se)})
		}
		comps = append(comps, c)
	}
	gate := func(name string, code authz.ReasonCode, detail string) {
		comps = append(comps, component{
			alt:     altSet{gates: map[string]bool{name: true}},
			reasons: []authz.FidelityReason{{Code: code, Detail: detail}},
		})
	}
	nonFalse := func(k MatchKind) bool { return !base.rb[k].IsFalse() }
	if e.class == classIAM && !base.cross {
		if e.isTrust && (nonFalse(MatchSelf) || nonFalse(MatchParent)) {
			gate(gateA3, authz.AmbiguityReason("A3"), "a same-account trust policy names the caller")
		}
		if nonFalse(MatchWildcard) {
			gate(gateA9, authz.AmbiguityReason("A9"), "a plain \"*\" principal in a same-account resource policy")
		}
		if e.rbpUnverified && e.rbpAllowed {
			gate(gateRBPExplicit, authz.ReasonServiceRBPRuleUnverified, "service "+e.prefix+" has no verified resource-policy rule")
		}
	}
	if e.p.Kind == model.FederatedUserSession && len(e.sp) == 0 {
		gate(gateA11, authz.AmbiguityReason("A11"), "a federated-user session has no session policy")
	}
	shadowStmts := 0
	for _, l := range e.shadowRCP {
		for _, d := range l.docs {
			shadowStmts += len(d.stmts)
		}
	}
	if shadowStmts > 0 {
		gate(gateA14, authz.AmbiguityReason("A14"), "RCPs are attached but "+e.prefix+" is not in the RCP service list")
	}
	if e.vpceUnknown {
		gate(gateVPCE, authz.ReasonVPCEPolicyUnknown, "the VPC endpoint's policy is not in the snapshot")
	}
	if e.crossAssumed {
		gate(gateCross, authz.ReasonCode(reasonResourceAccountUnknown), "the resource's account is not in the snapshot; same account assumed")
	}

	for i := range comps {
		if err := e.rctx.Err(); err != nil {
			return err
		}
		sensitive := i >= maxFlips || e.combine(&comps[i].alt).outcome != base.outcome
		for _, r := range comps[i].reasons {
			e.addReason(string(r.Code), r.Detail, sensitive)
		}
	}
	return nil
}

// fidelity summarizes the recorded reasons: UNSUPPORTED for the fail-closed
// codes, APPROXIMATE if any outcome-sensitive reason remains, else EXACT.
func (e *evaluator) fidelity() (authz.Fidelity, []authz.FidelityReason) {
	rs := make([]authz.FidelityReason, 0, len(e.reasons))
	for _, r := range e.reasons {
		rs = append(rs, *r)
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Code != rs[j].Code {
			return rs[i].Code < rs[j].Code
		}
		return rs[i].Detail < rs[j].Detail
	})
	f := authz.Exact
	for _, r := range rs {
		if !r.OutcomeSensitive {
			continue
		}
		switch r.Code {
		case authz.ReasonPolicyUnparseable, authz.ReasonCatalogMiss:
			return authz.Unsupported, rs
		}
		f = authz.Approximate
	}
	return f, rs
}
