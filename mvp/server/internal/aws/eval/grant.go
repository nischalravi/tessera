package eval

import (
	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// altSet selects other readings of the ambiguities for one combine run (§7.9):
// stmt overrides a statement's match, gates switches a named assumption.
type altSet struct {
	stmt  map[string]authz.Tri
	gates map[string]bool
}

// Gate names used by altSet.gates.
const (
	gateA3          = "A3"           // trust naming the caller also needs an identity allow
	gateA9          = "A9"           // plain "*" principal is capped by boundary and session
	gateA11         = "A11"          // federated session without a session policy is not limited
	gateA14         = "A14"          // RCPs of unsupported services are applied anyway
	gateRBPExplicit = "rbp_explicit" // the service's resource policy must name the account
	gateVPCE        = "vpce"         // an endpoint with an unknown policy blocks the request
	gateCross       = "cross"        // the resource is in another account
)

func (a *altSet) gate(name string) bool { return a != nil && a.gates[name] }

// verdict is the result of §7.2 steps 2 to 6 under one altSet.
type verdict struct {
	d, rcpOK, scpOK, idAllow, pbOK, spOK, grant, g authz.Tri
	rb                                             [8]authz.Tri // indexed by MatchKind
	blockRCP, blockSCP                             *level
	explicit                                       bool // the resource policy must name the account
	cross                                          bool
	outcome                                        authz.Outcome
	denyKind                                       authz.DenyKind
	residual                                       authz.Residual
}

func (e *evaluator) val(se *stmtEval, a *altSet) authz.Tri {
	if a != nil {
		if v, ok := a.stmt[se.key]; ok {
			return v
		}
	}
	return se.match
}

// anyAllow is any(Allow statements match) over docs.
func (e *evaluator) anyAllow(ds []*docEntry, a *altSet) authz.Tri {
	r := authz.F
	for _, d := range ds {
		for _, se := range d.stmts {
			if se.effect == model.EffectAllow {
				r = r.Or(e.val(se, a))
			}
		}
	}
	return r
}

// gateLevels is the conjunction over org levels of "an Allow matches at the
// level"; it also returns the first level that blocked.
func (e *evaluator) gateLevels(ls []*level, a *altSet) (authz.Tri, *level) {
	r := authz.T
	var block *level
	for _, l := range ls {
		ok := e.anyAllow(l.docs, a)
		if ok.IsFalse() && block == nil {
			block = l
		}
		r = r.And(ok)
	}
	return r, block
}

func (e *evaluator) rbTable(a *altSet) (rb [8]authz.Tri) {
	for _, d := range e.rbp {
		for _, se := range d.stmts {
			if se.effect != model.EffectAllow {
				continue
			}
			v := e.val(se, a)
			if v.IsFalse() {
				continue
			}
			for k := MatchSelf; k <= MatchService; k++ {
				if se.kinds.Has(k) {
					rb[k] = rb[k].Or(v)
				}
			}
		}
	}
	return rb
}

func (e *evaluator) simplify(t authz.Tri) authz.Tri {
	if !t.IsUnknown() {
		return t
	}
	return authz.U(Simplify(t.Residual(), e.cat.MultivaluedKey))
}

// combine is §7.2 steps 2 to 6 for one reading of the ambiguities.
func (e *evaluator) combine(a *altSet) *verdict {
	v := &verdict{}
	d := authz.F
	for _, se := range e.denies {
		d = d.Or(e.val(se, a))
	}
	rcp := e.rcp
	if a.gate(gateA14) && e.shadowRCP != nil {
		rcp = e.shadowRCP
		for _, se := range e.shadowDenies {
			d = d.Or(e.val(se, a))
		}
	}
	v.d = d
	v.rcpOK, v.blockRCP = e.gateLevels(rcp, a)
	v.scpOK, v.blockSCP = e.gateLevels(e.scp, a)

	v.idAllow, v.pbOK, v.spOK = authz.F, authz.T, authz.T
	if e.class == classIAM {
		v.idAllow = e.anyAllow(e.id, a)
		if e.hasBoundary {
			v.pbOK = e.anyAllow(e.pb, a)
		}
		switch {
		case e.p.Kind == model.FederatedUserSession && len(e.sp) == 0:
			v.spOK = authz.Bool(a.gate(gateA11)) // A11: should not exist
		case (e.p.Kind == model.RoleSession || e.p.Kind == model.FederatedUserSession) && len(e.sp) > 0:
			v.spOK = e.anyAllow(e.sp, a)
		}
	}
	v.rb = e.rbTable(a)
	v.explicit = e.requiresExplicit || a.gate(gateRBPExplicit)
	v.cross = e.cross != a.gate(gateCross)

	switch e.class {
	case classService:
		v.grant = v.rb[MatchService].Or(v.rb[MatchWildcard])
	case classAnonymous:
		v.grant = v.rb[MatchWildcard]
	case classProvider:
		v.grant = v.rb[MatchSelf].Or(v.rb[MatchWildcard])
	default:
		if v.cross {
			v.grant = e.crossAccountGrant(v)
		} else {
			v.grant = e.sameAccountGrant(v, a)
		}
	}
	if e.rootDefault && !v.explicit {
		v.grant = authz.T
	}

	v.g = authz.T
	switch {
	case len(e.vpce) > 0:
		v.g = e.anyAllow(e.vpce, a)
	case e.vpceUnknown && a.gate(gateVPCE):
		v.g = authz.F
	}

	policy := v.grant.And(v.rcpOK).And(v.scpOK)
	ap := e.simplify(policy.And(v.g))
	full := e.simplify(ap.And(v.d.Not()))
	switch {
	case full.IsTrue():
		v.outcome, v.residual = authz.Allow, authz.Const(true)
	case full.IsFalse():
		v.outcome, v.residual = authz.Deny, authz.Const(false)
		switch {
		case v.d.IsTrue():
			v.denyKind = authz.Explicit
		case ap.IsFalse():
			v.denyKind = authz.Implicit
			if !e.simplify(policy).IsFalse() && v.g.IsFalse() {
				v.denyKind = authz.Guardrail
			}
		default:
			v.denyKind = 0 // depends on the context (§9.5)
		}
	default:
		v.outcome, v.residual = authz.Conditional, full.Residual()
	}
	return v
}

// sameAccountGrant is the principal-type matrix of §7.4.
func (e *evaluator) sameAccountGrant(v *verdict, a *altSet) authz.Tri {
	identity := v.idAllow.And(v.pbOK).And(v.spOK)
	wildcard := v.rb[MatchWildcard]
	if a.gate(gateA9) {
		wildcard = wildcard.And(v.pbOK).And(v.spOK)
	}
	direct := v.rb[MatchSelf].Or(v.rb[MatchWildcardPrincipalARN]).Or(wildcard)
	parent := v.rb[MatchParent].And(v.pbOK).And(v.spOK)
	if a.gate(gateA3) {
		direct = direct.And(identity)
		parent = v.rb[MatchParent].And(identity)
	}
	idp := identity
	if v.explicit {
		idp = idp.And(v.rb[MatchAccount])
	}
	return idp.Or(direct).Or(parent)
}

// crossAccountGrant is §7.7: both accounts must allow.
func (e *evaluator) crossAccountGrant(v *verdict) authz.Tri {
	principalSide := v.idAllow.And(v.pbOK).And(v.spOK)
	resourceSide := v.rb[MatchSelf].Or(v.rb[MatchParent]).Or(v.rb[MatchAccount]).
		Or(v.rb[MatchWildcard]).Or(v.rb[MatchWildcardPrincipalARN])
	return principalSide.And(resourceSide)
}
