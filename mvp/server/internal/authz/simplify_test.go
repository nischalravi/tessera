package authz

import (
	"reflect"
	"strings"
	"testing"
)

func a(op, key string, vals ...string) Atom {
	return Atom{Op: op, Key: key, RawKey: key, Values: vals}
}

// stubSolver says a key is inconsistent when its literals include both of the
// named atoms wanted true.
type stubSolver struct {
	calls   int
	badKeys map[string]bool
}

func (s *stubSolver) Consistent(key string, lits []Lit) bool {
	s.calls++
	return !s.badKeys[key]
}

func TestSimplifyStructural(t *testing.T) {
	x, y, z := a("StringEquals", "x", "1"), a("StringEquals", "y", "1"), a("StringEquals", "z", "1")
	tests := []struct {
		name string
		in   Residual
		want Residual
	}{
		{"nil is false", nil, Const(false)},
		{"const", Const(true), Const(true)},
		{"and identity", And{Terms: []Residual{Const(true), x}}, x},
		{"and absorbing", And{Terms: []Residual{x, Const(false), y}}, Const(false)},
		{"or identity", Or{Terms: []Residual{Const(false), x}}, x},
		{"or absorbing", Or{Terms: []Residual{x, Const(true)}}, Const(true)},
		{"empty and", And{}, Const(true)},
		{"empty or", Or{}, Const(false)},
		{"flatten and", And{Terms: []Residual{x, And{Terms: []Residual{y, z}}}}, And{Terms: []Residual{x, y, z}}},
		{"flatten or", Or{Terms: []Residual{Or{Terms: []Residual{x, y}}, z}}, Or{Terms: []Residual{x, y, z}}},
		{"dedupe", And{Terms: []Residual{x, y, x}}, And{Terms: []Residual{x, y}}},
		{"dedupe ignores value order and source", Or{Terms: []Residual{
			a("StringEquals", "k", "1", "2"),
			Atom{Op: "StringEquals", Key: "k", RawKey: "K", Values: []string{"2", "1", "1"}, Source: &StmtRef{PolicyID: "p"}},
		}}, a("StringEquals", "k", "1", "2")},
		{"dedupe respects qualifier", Or{Terms: []Residual{x, Atom{Op: "StringEquals", Key: "x", Values: []string{"1"}, Qualifier: ForAnyValue}}},
			Or{Terms: []Residual{x, Atom{Op: "StringEquals", Key: "x", Values: []string{"1"}, Qualifier: ForAnyValue}}}},
		{"dedupe respects IfExists", And{Terms: []Residual{x, Atom{Op: "StringEquals", Key: "x", Values: []string{"1"}, IfExists: true}}},
			And{Terms: []Residual{x, Atom{Op: "StringEquals", Key: "x", Values: []string{"1"}, IfExists: true}}}},
		{"contradiction", And{Terms: []Residual{x, y, Not{Term: x}}}, Const(false)},
		{"excluded middle", Or{Terms: []Residual{x, Not{Term: x}}}, Const(true)},
		{"double negation", Not{Term: Not{Term: x}}, x},
		{"not const", Not{Term: Const(false)}, Const(true)},
		{"de morgan and", Not{Term: And{Terms: []Residual{x, y}}}, Or{Terms: []Residual{Not{Term: x}, Not{Term: y}}}},
		{"de morgan or", Not{Term: Or{Terms: []Residual{x, y}}}, And{Terms: []Residual{Not{Term: x}, Not{Term: y}}}},
		{"not stays around the atom", Not{Term: x}, Not{Term: x}},
		{"nested", And{Terms: []Residual{Or{Terms: []Residual{x, Const(true)}}, y}}, y},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Simplify(tc.in, nil)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %#v\nwant %#v", got, tc.want)
			}
			if again := Simplify(got, nil); !reflect.DeepEqual(again, got) {
				t.Errorf("not idempotent: %#v then %#v", got, again)
			}
		})
	}
}

func TestSimplifyUsesSolver(t *testing.T) {
	x1, x2, y := a("StringEquals", "x", "1"), a("StringEquals", "x", "2"), a("StringEquals", "y", "1")
	s := &stubSolver{badKeys: map[string]bool{"x": true}}

	if got := Simplify(And{Terms: []Residual{x1, y, x2}}, s); got != Const(false) {
		t.Errorf("inconsistent conjunction: %#v", got)
	}
	// For an Or the solver is asked about the negations: it calls the key
	// inconsistent, so the disjunction is a cover and is true.
	if got := Simplify(Or{Terms: []Residual{x1, y, x2}}, s); got != Const(true) {
		t.Errorf("covering disjunction: %#v", got)
	}
	// Other keys are left alone.
	if got := Simplify(And{Terms: []Residual{y, a("StringEquals", "y", "2")}}, s); got == Const(false) {
		t.Error("consistent key must stay")
	}
	// Non-literal terms are not passed to the solver.
	s2 := &stubSolver{}
	Simplify(And{Terms: []Residual{Or{Terms: []Residual{x1, y}}, a("StringEquals", "w", "1")}}, s2)
	if s2.calls == 0 {
		t.Error("solver should be consulted")
	}
	// Literals reach the solver with the right polarity.
	var seen []Lit
	Simplify(And{Terms: []Residual{x1, Not{Term: x2}}}, solverFunc(func(_ string, l []Lit) bool { seen = append(seen, l...); return true }))
	if len(seen) != 2 || !seen[0].Want || seen[1].Want {
		t.Errorf("polarity: %+v", seen)
	}
	seen = nil
	Simplify(Or{Terms: []Residual{x1, Not{Term: x2}}}, solverFunc(func(_ string, l []Lit) bool { seen = append(seen, l...); return true }))
	if len(seen) != 2 || seen[0].Want || !seen[1].Want {
		t.Errorf("or polarity: %+v", seen)
	}
}

type solverFunc func(key string, lits []Lit) bool

func (f solverFunc) Consistent(key string, lits []Lit) bool { return f(key, lits) }

func TestSimplifyDoesNotMutateInput(t *testing.T) {
	x, y := a("StringEquals", "x", "1"), a("StringEquals", "y", "1")
	in := And{Terms: []Residual{Or{Terms: []Residual{x, y}}, Not{Term: And{Terms: []Residual{x, y}}}}}
	before := Render(in, RenderOptions{})
	Simplify(in, nil)
	if Render(in, RenderOptions{}) != before {
		t.Error("input changed")
	}
}

func TestRender(t *testing.T) {
	src := &StmtRef{PolicyKind: "identity", SourceARN: "arn:aws:iam::1:policy/DevPolicy", StatementIndex: 2}
	scp := &StmtRef{PolicyKind: "scp", OrgLevel: "ou-prod", SourceARN: "arn:aws:organizations::1:policy/o-1/service_control_policy/p-1/RegionGuard", StatementIndex: 0}
	mfa := Atom{Op: "Bool", Key: "aws:multifactorauthpresent", RawKey: "aws:MultiFactorAuthPresent", Values: []string{"true"}, Source: src}
	ip := Atom{Op: "IpAddress", Key: "aws:sourceip", RawKey: "aws:SourceIp", Values: []string{"10.0.0.0/8"}, Source: scp}
	vpc := Atom{Op: "StringEquals", Key: "aws:sourcevpce", RawKey: "aws:SourceVpce", Values: []string{"vpce-0abc"}, Source: scp}
	tests := []struct {
		name string
		in   Residual
		want string
	}{
		{"true", Const(true), "always"},
		{"false", Const(false), "never"},
		{"atom", mfa, "(aws:MultiFactorAuthPresent = true) [identity: DevPolicy#2]"},
		{"design example, DNF", And{Terms: []Residual{mfa, Or{Terms: []Residual{ip, vpc}}}},
			"[(aws:MultiFactorAuthPresent = true) AND (aws:SourceIp in 10.0.0.0/8)] OR [(aws:MultiFactorAuthPresent = true) AND (aws:SourceVpce = vpce-0abc)]" +
				" [identity: DevPolicy#2, scp ou-prod: RegionGuard#0]"},
		{"negated atom", Not{Term: ip}, "(NOT aws:SourceIp in 10.0.0.0/8) [scp ou-prod: RegionGuard#0]"},
		{"deny pushes through De Morgan", Not{Term: Or{Terms: []Residual{Atom{Op: "StringNotEquals", Key: "aws:requestedregion", RawKey: "aws:RequestedRegion", Values: []string{"eu-west-1"}}}}},
			"(NOT aws:RequestedRegion != eu-west-1)"},
		{"multi value", Atom{Op: "StringEquals", Key: "k", Values: []string{"a", "b"}}, "(k in {a, b})"},
		{"qualifier and ifexists", Atom{Op: "StringLike", Key: "aws:tagkeys", Values: []string{"env*"}, Qualifier: ForAllValues, IfExists: true},
			"(every value of aws:tagkeys matches env* (if present))"},
		{"null", Atom{Op: "Null", Key: "k", Values: []string{"true"}}, "(k is absent)"},
		{"numeric", Atom{Op: "NumericLessThanEquals", Key: "n", Values: []string{"5"}}, "(n <= 5)"},
		{"ignore case", Atom{Op: "StringEqualsIgnoreCase", Key: "k", Values: []string{"a"}}, "(k = a (ignoring case))"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Render(tc.in, RenderOptions{}); got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

func TestRenderCollapsesDisjuncts(t *testing.T) {
	var terms []Residual
	for _, v := range []string{"1", "2", "3", "4", "5", "6"} {
		terms = append(terms, a("StringEquals", "k"+v, v))
	}
	got := Render(Or{Terms: terms}, RenderOptions{})
	if want := "(k1 = 1) OR (k2 = 2) OR (k3 = 3) OR (k4 = 4) OR … (2 more)"; got != want {
		t.Errorf("got %s want %s", got, want)
	}
	if got := Render(Or{Terms: terms}, RenderOptions{MaxDisjuncts: 6}); strings.Contains(got, "more") {
		t.Errorf("limit 6 must show all: %s", got)
	}
}

func TestRenderBoundsDNFExpansion(t *testing.T) {
	// (a1 or b1) and (a2 or b2) and ... 2^20 conjunctions if expanded.
	var and []Residual
	for i := 0; i < 20; i++ {
		k := string(rune('a' + i))
		and = append(and, Or{Terms: []Residual{a("StringEquals", k, "1"), a("StringEquals", k, "2")}})
	}
	got := Render(And{Terms: and}, RenderOptions{})
	if len(got) == 0 || len(got) > 4096 {
		t.Fatalf("rendered %d bytes", len(got))
	}
	if !strings.Contains(got, " AND ") {
		t.Errorf("tree fallback expected: %s", got)
	}
}
