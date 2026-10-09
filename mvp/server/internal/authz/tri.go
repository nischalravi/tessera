package authz

// Tri is a three-valued result: T, F, or U(φ) where φ is a residual (§7.1).
// The operations are Kleene logic that also builds the formula:
//
//	T ∧ x = x, F ∧ x = F, U(φ) ∧ U(ψ) = U(φ∧ψ)
//	T ∨ x = T, F ∨ x = x, U(φ) ∨ U(ψ) = U(φ∨ψ)
//	¬T = F, ¬F = T, ¬U(φ) = U(¬φ)
//
// The zero Tri is F. In concrete mode no U ever occurs (§9.4).
type Tri struct {
	state triState
	phi   Residual // set only when state == triUnknown
}

type triState uint8

const (
	triFalse triState = iota
	triTrue
	triUnknown
)

// T is the true value.
var T = Tri{state: triTrue}

// F is the false value.
var F = Tri{state: triFalse}

// Bool lifts a Go bool.
func Bool(b bool) Tri {
	if b {
		return T
	}
	return F
}

// U returns U(φ). A nil φ or a Const collapses to the matching constant, so a
// Tri is unknown only when it carries a non-constant formula.
func U(phi Residual) Tri {
	switch p := phi.(type) {
	case nil:
		return F
	case Const:
		return Bool(bool(p))
	}
	return Tri{state: triUnknown, phi: phi}
}

// IsTrue reports whether t is T.
func (t Tri) IsTrue() bool { return t.state == triTrue }

// IsFalse reports whether t is F.
func (t Tri) IsFalse() bool { return t.state == triFalse }

// IsUnknown reports whether t is U(φ).
func (t Tri) IsUnknown() bool { return t.state == triUnknown }

// Residual returns Const(true), Const(false), or φ for U(φ).
func (t Tri) Residual() Residual {
	switch t.state {
	case triTrue:
		return Const(true)
	case triUnknown:
		return t.phi
	}
	return Const(false)
}

// And is Kleene conjunction.
func (t Tri) And(o Tri) Tri {
	switch {
	case t.IsFalse() || o.IsFalse():
		return F
	case t.IsTrue():
		return o
	case o.IsTrue():
		return t
	}
	return Tri{state: triUnknown, phi: And{Terms: []Residual{t.phi, o.phi}}}
}

// Or is Kleene disjunction.
func (t Tri) Or(o Tri) Tri {
	switch {
	case t.IsTrue() || o.IsTrue():
		return T
	case t.IsFalse():
		return o
	case o.IsFalse():
		return t
	}
	return Tri{state: triUnknown, phi: Or{Terms: []Residual{t.phi, o.phi}}}
}

// Not is Kleene negation.
func (t Tri) Not() Tri {
	switch t.state {
	case triTrue:
		return F
	case triFalse:
		return T
	}
	return Tri{state: triUnknown, phi: Not{Term: t.phi}}
}

// String renders T, F or U.
func (t Tri) String() string {
	switch t.state {
	case triTrue:
		return "T"
	case triUnknown:
		return "U"
	}
	return "F"
}

// AnyOf is the disjunction of ts (F when empty).
func AnyOf(ts ...Tri) Tri {
	r := F
	for _, t := range ts {
		r = r.Or(t)
	}
	return r
}

// AllOf is the conjunction of ts (T when empty).
func AllOf(ts ...Tri) Tri {
	r := T
	for _, t := range ts {
		r = r.And(t)
	}
	return r
}
