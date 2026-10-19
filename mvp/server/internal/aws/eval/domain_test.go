package eval

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
)

func lit(op, key string, want bool, vals ...string) authz.Lit {
	return authz.Lit{Atom: atom(op, key, vals...), Want: want}
}

func TestSolverConsistent(t *testing.T) {
	ifExists := func(l authz.Lit) authz.Lit { l.Atom.IfExists = true; return l }
	qualified := func(l authz.Lit) authz.Lit { l.Atom.Qualifier = authz.ForAnyValue; return l }
	tests := []struct {
		name string
		key  string
		lits []authz.Lit
		want bool
	}{
		{"equal and equal", "k", []authz.Lit{lit("StringEquals", "k", true, "a"), lit("StringEquals", "k", true, "a")}, true},
		{"two different literals", "k", []authz.Lit{lit("StringEquals", "k", true, "a"), lit("StringEquals", "k", true, "b")}, false},
		{"overlapping sets", "k", []authz.Lit{lit("StringEquals", "k", true, "a", "b"), lit("StringEquals", "k", true, "b", "c")}, true},
		{"equals and not equals", "k", []authz.Lit{lit("StringEquals", "k", true, "a"), lit("StringNotEquals", "k", true, "a")}, false},
		{"equals set minus members", "k", []authz.Lit{lit("StringEquals", "k", true, "a", "b"), lit("StringNotEquals", "k", true, "a"), lit("StringNotEquals", "k", true, "b")}, false},
		{"not-equals alone", "k", []authz.Lit{lit("StringNotEquals", "k", true, "a")}, true},
		{"like against literal", "k", []authz.Lit{lit("StringLike", "k", true, "a*"), lit("StringEquals", "k", true, "b")}, false},
		{"like admits literal", "k", []authz.Lit{lit("StringLike", "k", true, "a*"), lit("StringEquals", "k", true, "abc")}, true},
		{"two likes are not decided", "k", []authz.Lit{lit("StringLike", "k", true, "a*"), lit("StringLike", "k", true, "*b")}, true},
		{"ignore case plus not equals is satisfiable", "k", []authz.Lit{lit("StringEqualsIgnoreCase", "k", true, "a"), lit("StringNotEquals", "k", true, "a")}, true},
		{"numeric empty interval", "n", []authz.Lit{lit("NumericLessThan", "n", true, "5"), lit("NumericGreaterThan", "n", true, "10")}, false},
		{"numeric open interval", "n", []authz.Lit{lit("NumericLessThan", "n", true, "5"), lit("NumericGreaterThan", "n", true, "4")}, true},
		{"numeric closed point", "n", []authz.Lit{lit("NumericLessThanEquals", "n", true, "5"), lit("NumericGreaterThanEquals", "n", true, "5")}, true},
		{"numeric lt vs ge", "n", []authz.Lit{lit("NumericLessThan", "n", true, "5"), lit("NumericGreaterThanEquals", "n", true, "5")}, false},
		{"numeric eq vs ne", "n", []authz.Lit{lit("NumericEquals", "n", true, "5"), lit("NumericNotEquals", "n", true, "5.0")}, false},
		{"numeric negated literal wanted false", "n", []authz.Lit{lit("NumericLessThan", "n", false, "5"), lit("NumericLessThan", "n", true, "5")}, false},
		{"date empty interval", "d", []authz.Lit{lit("DateLessThan", "d", true, "2026-01-01T00:00:00Z"), lit("DateGreaterThan", "d", true, "2026-06-01T00:00:00Z")}, false},
		{"date window", "d", []authz.Lit{lit("DateGreaterThan", "d", true, "2026-01-01T00:00:00Z"), lit("DateLessThan", "d", true, "2026-06-01T00:00:00Z")}, true},
		{"ip disjoint", "i", []authz.Lit{lit("IpAddress", "i", true, "10.0.0.0/8"), lit("IpAddress", "i", true, "192.168.0.0/16")}, false},
		{"ip carve out", "i", []authz.Lit{lit("IpAddress", "i", true, "10.0.0.0/8"), lit("NotIpAddress", "i", true, "10.1.0.0/16")}, true},
		{"ip carve everything", "i", []authz.Lit{lit("IpAddress", "i", true, "10.1.0.0/16"), lit("NotIpAddress", "i", true, "10.0.0.0/8")}, false},
		{"ip v4 vs v6", "i", []authz.Lit{lit("IpAddress", "i", true, "10.0.0.0/8"), lit("IpAddress", "i", true, "::1")}, false},
		{"bool both", "b", []authz.Lit{lit("Bool", "b", true, "true"), lit("Bool", "b", true, "false")}, false},
		{"bool true only", "b", []authz.Lit{lit("Bool", "b", true, "true")}, true},
		{"null true with positive", "k", []authz.Lit{lit("Null", "k", true, "true"), lit("StringEquals", "k", true, "a")}, false},
		{"null true with negated", "k", []authz.Lit{lit("Null", "k", true, "true"), lit("StringNotEquals", "k", true, "a")}, true},
		{"null false with positive", "k", []authz.Lit{lit("Null", "k", true, "false"), lit("StringEquals", "k", true, "a")}, true},
		{"null false with negated absent-only truth", "k", []authz.Lit{lit("Null", "k", true, "false"), lit("StringEquals", "k", false, "a"), lit("StringLike", "k", false, "*")}, true}, // present with the empty set
		{"IfExists is true when absent", "k", []authz.Lit{ifExists(lit("StringEquals", "k", true, "a")), lit("Null", "k", true, "true")}, true},
		{"IfExists is not true when present", "k", []authz.Lit{ifExists(lit("StringEquals", "k", true, "a")), lit("Null", "k", true, "false"), lit("StringEquals", "k", true, "b")}, false},
		{"mixed families are not modelled", "k", []authz.Lit{lit("StringEquals", "k", true, "5"), lit("NumericGreaterThan", "k", true, "9")}, true},
		{"qualified literals are skipped", "k", []authz.Lit{qualified(lit("StringEquals", "k", true, "a")), lit("StringEquals", "k", true, "b")}, true},
		{"variables are skipped", "k", []authz.Lit{lit("StringEquals", "k", true, "${aws:username}"), lit("StringEquals", "k", true, "b")}, true},
		{"multivalued keys are not modelled", "aws:tagkeys", []authz.Lit{lit("StringEquals", "aws:tagkeys", true, "a"), lit("StringEquals", "aws:tagkeys", true, "b")}, true},
		{"unknown operator is skipped", "k", []authz.Lit{lit("Frobnicate", "k", true, "a"), lit("StringEquals", "k", true, "b")}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Solver{}).Consistent(tc.key, tc.lits); got != tc.want {
				t.Errorf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestSimplifyWithSolver(t *testing.T) {
	x := func(op string, vals ...string) authz.Atom { return atom(op, "k", vals...) }
	// Key-complete covers become true; contradictions become false.
	cover := authz.Or{Terms: []authz.Residual{x("Null", "true"), x("Null", "false")}}
	if got := Simplify(cover, nil); got != authz.Const(true) {
		t.Errorf("Null cover: %#v", got)
	}
	cover2 := authz.Or{Terms: []authz.Residual{x("StringEquals", "a"), x("StringNotEquals", "a")}}
	if got := Simplify(cover2, nil); got != authz.Const(true) {
		t.Errorf("equals cover: %#v", got)
	}
	// Bool true or Bool false is not a cover: the key may be present with a
	// value that is neither (a documented difference from §9.5's example).
	boolCover := authz.Or{Terms: []authz.Residual{x("Bool", "true"), x("Bool", "false"), x("Null", "true")}}
	if got := Simplify(boolCover, nil); got == authz.Const(true) {
		t.Error("Bool cover must not be decided without a type guarantee")
	}
	dead := authz.And{Terms: []authz.Residual{x("IpAddress", "10.0.0.0/8"), x("IpAddress", "192.168.0.0/16")}}
	if got := Simplify(dead, nil); got != authz.Const(false) {
		t.Errorf("ip contradiction: %#v", got)
	}
	// Independent patterns stay as a residual (RESIDUAL_UNDECIDED, §9.5.4).
	two := authz.And{Terms: []authz.Residual{x("StringLike", "a*"), x("StringLike", "*b")}}
	if _, ok := Simplify(two, nil).(authz.And); !ok {
		t.Error("two likes must stay")
	}
}
