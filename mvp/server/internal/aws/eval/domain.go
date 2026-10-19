package eval

import (
	"math/big"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

// Solver is the per-key domain solver (§9.5 step 2). It implements
// authz.KeySolver for AWS conditions.
//
// It decides whether the literals on one key can all hold, by treating the key
// as "absent, or present with one value x" and testing a finite set of
// candidate values that covers every region the atoms can tell apart. It only
// ever says "inconsistent" when it has proved it; it skips (treats as
// satisfiable) any literal it cannot model: a qualifier, a variable in the
// values, an unknown operator, a multivalued key, or atoms of mixed value
// types on one key.
type Solver struct {
	// Multivalued reports multivalued keys; nil means the global ones.
	Multivalued func(lowerKey string) bool
}

var _ authz.KeySolver = Solver{}

// Simplify is authz.Simplify with the AWS solver.
func Simplify(r authz.Residual, multivalued func(lowerKey string) bool) authz.Residual {
	return authz.Simplify(r, Solver{Multivalued: multivalued})
}

// Consistent implements authz.KeySolver.
func (s Solver) Consistent(key string, lits []authz.Lit) bool {
	multi := s.Multivalued
	if multi == nil {
		multi = policy.IsGlobalMultivaluedKey
	}
	if multi(asciiLower(key)) {
		return true
	}
	var use []authz.Lit
	for _, l := range lits {
		if _, ok := opSpecs[l.Atom.Op]; !ok || l.Atom.Qualifier != authz.NoQualifier {
			continue
		}
		if variableOperator(l.Atom.Op) && anyVariable(l.Atom.Values) {
			continue
		}
		use = append(use, l)
	}
	if len(use) == 0 {
		return true
	}
	return absentFeasible(use) || emptySetFeasible(use) || presentFeasible(use)
}

// emptySetFeasible: the key is present with the empty set of values (EvalAtom
// treats [""] the same way). Every ordinary atom is then "no match", so its
// truth is whether it is negated, IfExists does not help, and Null:false holds.
func emptySetFeasible(lits []authz.Lit) bool {
	for _, l := range lits {
		sp := opSpecs[l.Atom.Op]
		var t bool
		if sp.fam == famNull {
			t = anyEqualFold(l.Atom.Values, "false")
		} else {
			t = sp.neg
		}
		if t != l.Want {
			return false
		}
	}
	return true
}

func anyVariable(vals []string) bool {
	for _, v := range vals {
		if strings.Contains(v, "${") {
			return true
		}
	}
	return false
}

// absentFeasible: every literal has its wanted truth when the key is absent.
func absentFeasible(lits []authz.Lit) bool {
	for _, l := range lits {
		sp := opSpecs[l.Atom.Op]
		var t bool
		switch {
		case sp.fam == famNull:
			t = anyEqualFold(l.Atom.Values, "true")
		case l.Atom.IfExists:
			t = true
		default:
			t = sp.neg
		}
		if t != l.Want {
			return false
		}
	}
	return true
}

func anyEqualFold(vals []string, s string) bool {
	for _, v := range vals {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// literalPatterns wraps policy values as unsubstituted patterns.
func literalPatterns(vals []string) []Pattern {
	ps := make([]Pattern, len(vals))
	for i, v := range vals {
		ps[i] = Pattern{Segs: []Seg{{Text: v}}}
	}
	return ps
}

// truthAt is the truth of a non-Null literal when the key is present with the
// single value x.
func truthAt(l authz.Lit, x string) bool {
	sp := opSpecs[l.Atom.Op]
	if x == "" {
		return sp.neg == l.Want // the empty set: handled by emptySetFeasible
	}
	found := false
	for _, w := range literalPatterns(l.Atom.Values) {
		if posMatch(sp, x, w) {
			found = true
			break
		}
	}
	return (found != sp.neg) == l.Want
}

// presentFeasible: some single value x makes every literal come out as wanted.
func presentFeasible(lits []authz.Lit) bool {
	var vals []authz.Lit
	for _, l := range lits {
		sp := opSpecs[l.Atom.Op]
		if sp.fam == famNull {
			// A present key satisfies Null:false and fails Null:true.
			if anyEqualFold(l.Atom.Values, "false") != l.Want {
				return false
			}
			continue
		}
		vals = append(vals, l)
	}
	if len(vals) == 0 {
		return true
	}
	fam := valueFamily(opSpecs[vals[0].Atom.Op].fam)
	for _, l := range vals[1:] {
		if valueFamily(opSpecs[l.Atom.Op].fam) != fam {
			return true // mixed value types: not modelled
		}
	}
	cands, complete := candidates(fam, vals)
	if !complete {
		return true
	}
	for _, x := range cands {
		ok := true
		for _, l := range vals {
			if !truthAt(l, x) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// valueFamily groups operators that read the context value the same way.
func valueFamily(f family) family {
	switch f {
	case famString, famFold, famLike:
		return famString
	}
	return f
}

// candidates returns values that cover every region the literals can
// distinguish, and false when it cannot (the caller then assumes satisfiable).
func candidates(fam family, lits []authz.Lit) ([]string, bool) {
	switch fam {
	case famString:
		// If any literal needs the value to equal one of a fixed set, the
		// candidates are exactly that set.
		for _, l := range lits {
			sp := opSpecs[l.Atom.Op]
			if l.Atom.Op == "StringEquals" || l.Atom.Op == "StringNotEquals" {
				if l.Want != sp.neg {
					return append([]string(nil), l.Atom.Values...), true
				}
			}
		}
		return nil, false
	case famBool:
		return []string{"true", "false", "neither"}, true
	case famNumeric:
		return numericCandidates(lits)
	case famDate:
		return dateCandidates(lits)
	case famIP:
		return ipCandidates(lits), true
	}
	return nil, false
}

func numericCandidates(lits []authz.Lit) ([]string, bool) {
	var consts []*big.Rat
	prec := 0
	for _, l := range lits {
		for _, v := range l.Atom.Values {
			if d, ok := parseDecimal(v); ok {
				consts = append(consts, d.rat())
				if len(d.frac) > prec {
					prec = len(d.frac)
				}
			}
		}
	}
	sort.Slice(consts, func(i, j int) bool { return consts[i].Cmp(consts[j]) < 0 })
	uniq := consts[:0]
	for _, c := range consts {
		if len(uniq) == 0 || uniq[len(uniq)-1].Cmp(c) != 0 {
			uniq = append(uniq, c)
		}
	}
	out := []string{"neither"} // not a number: only matters for negated operators
	if len(uniq) == 0 {
		return append(out, "0"), true
	}
	one := big.NewRat(1, 1)
	half := big.NewRat(1, 2)
	str := func(r *big.Rat) string { return r.FloatString(prec + 1) }
	out = append(out, str(new(big.Rat).Sub(uniq[0], one)), str(new(big.Rat).Add(uniq[len(uniq)-1], one)))
	for i, c := range uniq {
		out = append(out, str(c))
		if i+1 < len(uniq) {
			mid := new(big.Rat).Add(c, uniq[i+1])
			out = append(out, str(mid.Mul(mid, half)))
		}
	}
	return out, true
}

func dateCandidates(lits []authz.Lit) ([]string, bool) {
	var consts []int64 // nanoseconds since the epoch
	for _, l := range lits {
		for _, v := range l.Atom.Values {
			if d, ok := parseDate(v); ok {
				if d.sec > 9_000_000_000 || d.sec < -9_000_000_000 {
					return nil, false // nanoseconds would overflow int64; not modelled
				}
				consts = append(consts, d.sec*1_000_000_000+int64(d.nsec))
			}
		}
	}
	sort.Slice(consts, func(i, j int) bool { return consts[i] < consts[j] })
	out := []string{"neither"}
	if len(consts) == 0 {
		return append(out, "0"), true
	}
	pts := []int64{consts[0] - 1, consts[len(consts)-1] + 1}
	for i, c := range consts {
		pts = append(pts, c)
		if i+1 < len(consts) {
			pts = append(pts, c+(consts[i+1]-c)/2)
		}
	}
	for _, p := range pts {
		sec, ns := p/1_000_000_000, p%1_000_000_000
		if ns < 0 {
			sec--
			ns += 1_000_000_000
		}
		t := time.Unix(sec, ns).UTC()
		if t.Year() < 0 || t.Year() > 9999 {
			return nil, false
		}
		out = append(out, t.Format(time.RFC3339Nano))
	}
	return out, true
}

func ipCandidates(lits []authz.Lit) []string {
	out := []string{"neither", "0.0.0.0", "::"}
	add := func(a netip.Addr) {
		if a.IsValid() {
			out = append(out, a.String())
		}
	}
	for _, l := range lits {
		for _, v := range l.Atom.Values {
			if p, ok := parseIPPolicy(v); ok {
				first, last := p.Addr(), lastAddr(p)
				add(first)
				add(first.Prev())
				add(last)
				add(last.Next())
			}
		}
	}
	return out
}
