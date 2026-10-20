package eval

import (
	"fmt"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"pgregory.net/rapid"
)

// The soundness invariant of §9.4: for any total context c consistent with a
// partial context, the concrete result of a condition is true exactly when the
// residual left by symbolic evaluation holds at c. The residual is also run
// through Simplify (with the domain solver), so every simplification and every
// solver verdict is checked against concrete evaluation.

// keySpec describes one generated context key.
type keySpec struct {
	name   string
	ops    []string
	values []string // pool for policy values and request values
	multi  bool
}

var soundKeys = []keySpec{
	{name: "k:str", ops: []string{"StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase", "StringLike", "StringNotLike", "Null"},
		values: []string{"a", "b", "A", "ab", "a*", "?b", "*", "", "true", "false"}},
	{name: "k:num", ops: []string{"NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals", "Null"},
		values: []string{"1", "2", "2.0", "-1", "0", "x", "10", "1.5", ""}},
	{name: "k:date", ops: []string{"DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals", "Null"},
		values: []string{"2026-01-01T00:00:00Z", "2026-06-01", "1790812800", "2026-01-01T01:00:00+01:00", "1767225600", "never"}},
	{name: "k:ip", ops: []string{"IpAddress", "NotIpAddress", "Null"},
		values: []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.3", "192.168.0.0/16", "::1", "2001:db8::/32", "junk", "::ffff:10.0.0.1"}},
	{name: "k:bool", ops: []string{"Bool", "Null", "StringEquals"},
		values: []string{"true", "false", "TRUE", "maybe"}},
	{name: "aws:tagkeys", multi: true, ops: []string{"StringEquals", "StringNotEquals", "StringLike", "Null"},
		values: []string{"a", "b", "env", "e*"}},
	{name: "k:arn", ops: []string{"ArnLike", "ArnNotLike", "ArnEquals", "Null"},
		values: []string{"arn:aws:s3:::b", "arn:aws:s3:::*", "arn:aws:sqs:us-east-1:*", "arn:aws:sqs:us-east-1:1:q", "nope"}},
}

func drawAtom(t *rapid.T, label string) authz.Atom {
	return drawAtomFor(t, label, rapid.SampledFrom(soundKeys).Draw(t, label+"key"))
}

func drawAtomFor(t *rapid.T, label string, ks keySpec) authz.Atom {
	op := rapid.SampledFrom(ks.ops).Draw(t, label+"op")
	n := rapid.IntRange(1, 3).Draw(t, label+"nvals")
	vals := make([]string, n)
	for i := range vals {
		vals[i] = rapid.SampledFrom(ks.values).Draw(t, fmt.Sprintf("%sval%d", label, i))
	}
	if op == "Null" {
		vals = []string{rapid.SampledFrom([]string{"true", "false"}).Draw(t, label+"null")}
	}
	a := atom(op, ks.name, vals...)
	if op != "Null" {
		a.IfExists = rapid.Bool().Draw(t, label+"ifx")
		a.Qualifier = rapid.SampledFrom([]authz.Qualifier{authz.NoQualifier, authz.NoQualifier, authz.NoQualifier, authz.ForAllValues, authz.ForAnyValue}).Draw(t, label+"q")
	}
	// A variable now and then, pointing at another key.
	if variableOperator(op) && rapid.IntRange(0, 5).Draw(t, label+"var") == 0 {
		vals[0] = "${k:str}"
	}
	return a
}

func drawValue(t *rapid.T, ks keySpec, label string, allowUnknown bool) ContextValue {
	states := []KeyState{Absent, Present, Present}
	if allowUnknown {
		states = append(states, Unknown, Unknown, Unknown)
	}
	switch rapid.SampledFrom(states).Draw(t, label+"state") {
	case Absent:
		return AbsentValue
	case Unknown:
		return UnknownValue
	}
	max := 1 // single-valued keys hold one value or the empty set
	if ks.multi {
		max = 3
	}
	n := rapid.IntRange(0, max).Draw(t, label+"n")
	vals := make([]string, n)
	for i := range vals {
		vals[i] = rapid.SampledFrom(ks.values).Draw(t, fmt.Sprintf("%sv%d", label, i))
	}
	return PresentValues(vals...)
}

// soundnessProp is the property, shared by the rapid test and the fuzz target.
func soundnessProp(t *rapid.T) {
	// A condition: 1 to 4 atoms ANDed; sometimes a second condition ORed in and
	// the whole thing negated, the way allow and deny statements combine.
	nAtoms := rapid.IntRange(1, 4).Draw(t, "atoms")
	var conds [2][]authz.Atom
	for i := 0; i < nAtoms; i++ {
		conds[0] = append(conds[0], drawAtom(t, fmt.Sprintf("a%d", i)))
	}
	two := rapid.Bool().Draw(t, "two")
	negate := rapid.Bool().Draw(t, "negate")
	if two {
		for i := 0; i < rapid.IntRange(1, 2).Draw(t, "atoms2"); i++ {
			conds[1] = append(conds[1], drawAtom(t, fmt.Sprintf("b%d", i)))
		}
	}

	partial := &Context{Mode: Symbolic, Values: map[string]ContextValue{}}
	total := &Context{Mode: Concrete, Values: map[string]ContextValue{}}
	for _, ks := range soundKeys {
		pv := drawValue(t, ks, ks.name+"/partial", true)
		partial.Values[ks.name] = pv
		if pv.State == Unknown {
			total.Values[ks.name] = drawValue(t, ks, ks.name+"/total", false)
		} else {
			total.Values[ks.name] = pv
		}
	}

	eval := func(ctx *Context) authz.Tri {
		r, _, _ := EvalConditions(conds[0], ctx, true)
		if two {
			r2, _, _ := EvalConditions(conds[1], ctx, true)
			r = r.Or(r2)
		}
		if negate {
			r = r.Not()
		}
		return r
	}

	concrete := eval(total)
	if concrete.IsUnknown() {
		t.Fatalf("concrete evaluation produced U: %s", authz.Render(concrete.Residual(), authz.RenderOptions{}))
	}
	sym := eval(partial)
	phi := sym.Residual()
	simp := Simplify(phi, nil)
	for name, r := range map[string]authz.Residual{"residual": phi, "simplified": simp} {
		got := EvalResidual(r, total, true)
		if got.IsUnknown() || got.IsTrue() != concrete.IsTrue() {
			t.Fatalf("%s disagrees: concrete=%s residual(c)=%s\nresidual: %s\ntotal: %+v",
				name, concrete, got, authz.Render(r, authz.RenderOptions{}), total.Values)
		}
	}
	// Symbolic T or F must agree with the concrete result for every total context.
	if !sym.IsUnknown() && sym.IsTrue() != concrete.IsTrue() {
		t.Fatalf("symbolic %s but concrete %s", sym, concrete)
	}
	// Rendering never panics and is stable.
	if a, b := authz.Render(simp, authz.RenderOptions{}), authz.Render(simp, authz.RenderOptions{}); a != b {
		t.Fatalf("render not deterministic")
	}
	// Simplification is idempotent.
	if again := Simplify(simp, nil); authz.Render(again, authz.RenderOptions{MaxDisjuncts: 1 << 20}) != authz.Render(simp, authz.RenderOptions{MaxDisjuncts: 1 << 20}) {
		t.Fatalf("simplify not idempotent")
	}
}

func TestSymbolicSoundness(t *testing.T) {
	rapid.Check(t, soundnessProp)
}

func FuzzSymbolicSoundness(f *testing.F) {
	for _, seed := range [][]byte{{}, {1, 2, 3, 4, 5, 6, 7, 8}, []byte("tessera symbolic soundness seed 0123456789")} {
		f.Add(seed)
	}
	f.Fuzz(rapid.MakeFuzz(soundnessProp))
}

// TestSolverAgainstEnumeration checks each solver verdict of "inconsistent"
// against brute force over a grid of single values, absent and the empty set.
func TestSolverAgainstEnumeration(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ks := rapid.SampledFrom(soundKeys[:5]).Draw(t, "key")
		n := rapid.IntRange(1, 4).Draw(t, "n")
		var lits []authz.Lit
		for i := 0; i < n; i++ {
			a := drawAtomFor(t, fmt.Sprintf("l%d", i), ks)
			a.Qualifier = authz.NoQualifier
			lits = append(lits, authz.Lit{Atom: a, Want: rapid.Bool().Draw(t, fmt.Sprintf("w%d", i))})
		}
		if (Solver{}).Consistent(ks.name, lits) {
			return // "cannot rule out" is always sound
		}
		states := []ContextValue{AbsentValue, PresentValues()}
		for _, v := range ks.values {
			states = append(states, PresentValues(v))
		}
		for _, v := range []string{"3", "-0.5", "2026-03-01T00:00:00Z", "10.2.3.4", "8.8.8.8", "2001:db8::1", "zzz", "0"} {
			states = append(states, PresentValues(v))
		}
		for _, st := range states {
			ctx := ctxOf(Concrete, map[string]ContextValue{ks.name: st})
			all := true
			for _, l := range lits {
				if EvalAtom(l.Atom, ctx, true).Result.IsTrue() != l.Want {
					all = false
					break
				}
			}
			if all {
				t.Fatalf("solver said inconsistent but %+v satisfies %+v", st, lits)
			}
		}
	})
}
