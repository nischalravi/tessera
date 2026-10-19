package authz

import (
	"sort"
	"strconv"
	"strings"
)

// Lit is a literal of a residual in negation normal form: an atom that is
// wanted true (Want) or wanted false (a Not around the atom).
type Lit struct {
	Atom Atom
	Want bool
}

// KeySolver is the per-key domain solver of §9.5 step 2. The residual
// simplifier is platform-neutral, so the operator semantics live behind this
// interface (the AWS implementation is in internal/aws/eval).
//
// Consistent reports whether the conjunction of lits, all over one condition
// key, can be true in some request context. It must return false only when it
// is certain the conjunction is unsatisfiable; "cannot decide" is true. That
// keeps simplification sound: a residual left alone is merely larger.
type KeySolver interface {
	Consistent(key string, lits []Lit) bool
}

// Simplify returns an equivalent, smaller residual (§9.5): it pushes negation
// down to the atoms, folds constants, flattens nested And/Or, removes
// duplicate and contradictory literals, and (when s is not nil) asks s about
// the literals on each key of a conjunction or disjunction. A conjunction that
// s calls inconsistent becomes false; a disjunction whose negation is
// inconsistent (a key-complete cover) becomes true.
//
// Negation is never pushed into an atom: not (StringEquals k v) is not
// StringNotEquals k v, because the two differ when k is absent or the atom has
// a qualifier or IfExists. Not therefore stays around atoms.
func Simplify(r Residual, s KeySolver) Residual {
	return simplify(nnf(r, false), s)
}

// nnf converts r to negation normal form: Not only directly around an Atom.
func nnf(r Residual, neg bool) Residual {
	switch t := r.(type) {
	case nil:
		return Const(neg)
	case Const:
		return Const(bool(t) != neg)
	case Atom:
		if neg {
			return Not{Term: t}
		}
		return t
	case Not:
		return nnf(t.Term, !neg)
	case And:
		terms := make([]Residual, len(t.Terms))
		for i, x := range t.Terms {
			terms[i] = nnf(x, neg)
		}
		if neg {
			return Or{Terms: terms}
		}
		return And{Terms: terms}
	case Or:
		terms := make([]Residual, len(t.Terms))
		for i, x := range t.Terms {
			terms[i] = nnf(x, neg)
		}
		if neg {
			return And{Terms: terms}
		}
		return Or{Terms: terms}
	}
	return Const(neg)
}

func simplify(r Residual, s KeySolver) Residual {
	switch t := r.(type) {
	case And:
		return combine(t.Terms, true, s)
	case Or:
		return combine(t.Terms, false, s)
	}
	return r
}

// combine simplifies a conjunction (and == true) or disjunction.
func combine(in []Residual, and bool, s KeySolver) Residual {
	var terms []Residual
	seen := map[string]bool{}
	var add func(x Residual) (decided bool)
	add = func(x Residual) bool {
		x = simplify(x, s)
		switch t := x.(type) {
		case Const:
			// The identity element is dropped; the absorbing one decides.
			return bool(t) != and
		case And:
			if and {
				for _, y := range t.Terms {
					if add(y) {
						return true
					}
				}
				return false
			}
		case Or:
			if !and {
				for _, y := range t.Terms {
					if add(y) {
						return true
					}
				}
				return false
			}
		}
		k := residualKey(x)
		if seen[k] {
			return false
		}
		seen[k] = true
		terms = append(terms, x)
		return false
	}
	for _, x := range in {
		if add(x) {
			return Const(!and)
		}
	}
	// Complementary literals: x and not x.
	for k := range seen {
		if strings.HasPrefix(k, "!") && seen[k[1:]] {
			return Const(!and)
		}
	}
	if s != nil && keysInconsistent(terms, and, s) {
		return Const(!and)
	}
	switch len(terms) {
	case 0:
		return Const(and)
	case 1:
		return terms[0]
	}
	if and {
		return And{Terms: terms}
	}
	return Or{Terms: terms}
}

// keysInconsistent groups the literal terms by key and asks the solver. For a
// disjunction it asks about the negated literals: the disjunction is true in
// every context exactly when their conjunction is unsatisfiable.
func keysInconsistent(terms []Residual, and bool, s KeySolver) bool {
	var order []string
	groups := map[string][]Lit{}
	for _, x := range terms {
		var l Lit
		switch t := x.(type) {
		case Atom:
			l = Lit{Atom: t, Want: and}
		case Not:
			a, ok := t.Term.(Atom)
			if !ok {
				continue
			}
			l = Lit{Atom: a, Want: !and}
		default:
			continue
		}
		if _, ok := groups[l.Atom.Key]; !ok {
			order = append(order, l.Atom.Key)
		}
		groups[l.Atom.Key] = append(groups[l.Atom.Key], l)
	}
	for _, k := range order {
		if !s.Consistent(k, groups[k]) {
			return true
		}
	}
	return false
}

// residualKey is the canonical form used for deduplication; a Not around an
// atom is "!" plus the atom's key.
func residualKey(r Residual) string {
	switch t := r.(type) {
	case Atom:
		return atomKey(t)
	case Not:
		return "!" + residualKey(t.Term)
	case Const:
		return strconv.FormatBool(bool(t))
	case And:
		return "&(" + joinKeys(t.Terms) + ")"
	case Or:
		return "|(" + joinKeys(t.Terms) + ")"
	}
	return "?"
}

func joinKeys(ts []Residual) string {
	ks := make([]string, len(ts))
	for i, t := range ts {
		ks[i] = residualKey(t)
	}
	return strings.Join(ks, ",")
}

// atomKey identifies an atom by what it tests, not by where it came from:
// Source and RawKey are ignored and the values are a sorted, unique set.
func atomKey(a Atom) string {
	vals := append([]string(nil), a.Values...)
	sort.Strings(vals)
	var b strings.Builder
	b.WriteString("a:")
	b.WriteString(a.Op)
	b.WriteByte('|')
	b.WriteString(a.Key)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(int(a.Qualifier)))
	if a.IfExists {
		b.WriteString("|ie")
	}
	prev, have := "", false
	for _, v := range vals {
		if have && v == prev {
			continue
		}
		prev, have = v, true
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	return b.String()
}
