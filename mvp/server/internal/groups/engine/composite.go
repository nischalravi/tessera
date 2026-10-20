package engine

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Eval applies a composite operator to "is a member of factor k" flags, in
// factor order: union is any, intersection is all, complement (two factors) is
// the first and not the second (design §6.1). No factors is the empty set.
func Eval(op store.CompositeOp, in []bool) bool {
	if len(in) == 0 {
		return false
	}
	switch op {
	case store.CompIntersection:
		for _, v := range in {
			if !v {
				return false
			}
		}
		return true
	case store.CompComplement:
		return len(in) == 2 && in[0] && !in[1]
	default: // union
		for _, v := range in {
			if v {
				return true
			}
		}
		return false
	}
}

// ValidOp reports whether op is a composite operator and n factors suit it:
// at least two for union and intersection, exactly two for complement.
func ValidOp(op store.CompositeOp, n int) bool {
	switch op {
	case store.CompUnion, store.CompIntersection:
		return n >= 2 && n <= MaxFactors
	case store.CompComplement:
		return n == 2
	}
	return false
}

// SetFactors replaces a composite group's factor list and the factor edges of
// the dependency graph, refusing a cycle (a *CycleError). It maintains the
// closure and levels but does not recompute members: call RecomputeGroup.
func (e *Engine) SetFactors(tx *store.TenantTx, now time.Time, g store.GroupID, factors []store.GroupID) error {
	if err := Touch(tx, now); err != nil {
		return err
	}
	members := store.MembersListID(tx.Tenant())
	old, err := tx.GrpFactors(g)
	if err != nil {
		return err
	}
	for _, f := range old {
		if err := e.RemoveEdge(tx, store.GrpDep{Parent: g, Child: f, Kind: store.DepFactor, List: members}); err != nil {
			return err
		}
	}
	if err := tx.SetGrpFactors(g, factors); err != nil {
		return err
	}
	for _, f := range factors {
		if err := e.AddEdge(tx, store.GrpDep{Parent: g, Child: f, Kind: store.DepFactor, List: members}); err != nil {
			return err
		}
	}
	return nil
}

// ClearFactors drops every factor of a group (when it stops being a composite).
func (e *Engine) ClearFactors(tx *store.TenantTx, now time.Time, g store.GroupID) error {
	return e.SetFactors(tx, now, g, nil)
}

// IsMember reports whether an identity is a member of a group's list right
// now. It reads the materialized row and then re-checks the rows' own dates:
// a direct membership whose disabled_at has passed does not count even if the
// time wheel has not yet removed it (design §6.4; Grouper GRP-7325). A member
// whose enabled_from has passed but is not yet applied is not yet a member.
func (e *Engine) IsMember(tx *store.TenantTx, now time.Time, g store.GroupID, l store.ListID, identity int64) (bool, error) {
	n, err := tx.GrpEffectiveSupport(g, l, identity)
	if err != nil || n == 0 {
		return false, err
	}
	return confirm(tx, now, g, l, identity, 0)
}

const maxConfirmDepth = 64

// confirm re-derives membership from the rows' dates, following only the
// branches the materialized rows say are members.
func confirm(tx *store.TenantTx, now time.Time, g store.GroupID, l store.ListID, identity int64, depth int) (bool, error) {
	if depth > maxConfirmDepth {
		return false, nil
	}
	m, err := loadMeta(tx, now, g)
	if err != nil || !m.live {
		return false, err
	}
	if m.g.Definition != store.DefinitionBasic {
		in := make([]bool, len(m.factors))
		for i, f := range m.factors {
			n, err := tx.GrpEffectiveSupport(f, l, identity)
			if err != nil {
				return false, err
			}
			if n > 0 {
				if in[i], err = confirm(tx, now, f, l, identity, depth+1); err != nil {
					return false, err
				}
			}
		}
		return Eval(m.op, in), nil
	}
	if ok, err := tx.GrpDirectIdentityActive(g, l, identity, now); err != nil || ok {
		return ok, err
	}
	children, err := tx.GrpDirectActiveChildren(g, l, now)
	if err != nil {
		return false, err
	}
	for _, c := range children {
		n, err := tx.GrpEffectiveSupport(c, l, identity)
		if err != nil {
			return false, err
		}
		if n == 0 {
			continue
		}
		if ok, err := confirm(tx, now, c, l, identity, depth+1); err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}
