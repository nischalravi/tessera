package authz

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEnumTextRoundTrip(t *testing.T) {
	type pair struct {
		v    any
		text string
	}
	for _, tc := range []pair{
		{Allow, "allow"}, {Deny, "deny"}, {Conditional, "conditional"},
		{Explicit, "explicit"}, {Implicit, "implicit"}, {Guardrail, "guardrail"}, {DenyKind(0), ""},
		{Exact, "exact"}, {Approximate, "approximate"}, {Unsupported, "unsupported"},
		{NoQualifier, ""}, {ForAllValues, "ForAllValues"}, {ForAnyValue, "ForAnyValue"},
	} {
		b, err := json.Marshal(tc.v)
		if err != nil {
			t.Fatalf("marshal %v: %v", tc.v, err)
		}
		if want, _ := json.Marshal(tc.text); string(b) != string(want) {
			t.Errorf("marshal %v = %s, want %s", tc.v, b, want)
		}
		ptr := reflect.New(reflect.TypeOf(tc.v))
		if err := json.Unmarshal(b, ptr.Interface()); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if got := ptr.Elem().Interface(); got != tc.v {
			t.Errorf("round trip %v = %v", tc.v, got)
		}
	}
	var o Outcome
	if err := o.UnmarshalText([]byte("Allow")); err == nil {
		t.Error("enum text must be case-sensitive")
	}
	if _, err := Outcome(9).MarshalText(); err == nil {
		t.Error("out-of-range enum must not marshal")
	}
	if Outcome(9).String() != "" {
		t.Error("out-of-range enum String must be empty")
	}
}

func TestEnumStrings(t *testing.T) {
	for _, tc := range []struct {
		got, want string
	}{
		{Outcome(0).String(), ""}, {Allow.String(), "allow"}, {Deny.String(), "deny"}, {Conditional.String(), "conditional"}, {Outcome(4).String(), ""},
		{DenyKind(0).String(), ""}, {Explicit.String(), "explicit"}, {Implicit.String(), "implicit"}, {Guardrail.String(), "guardrail"}, {DenyKind(4).String(), ""},
		{Fidelity(0).String(), ""}, {Exact.String(), "exact"}, {Approximate.String(), "approximate"}, {Unsupported.String(), "unsupported"}, {Fidelity(4).String(), ""},
		{NoQualifier.String(), ""}, {ForAllValues.String(), "ForAllValues"}, {ForAnyValue.String(), "ForAnyValue"}, {Qualifier(3).String(), ""},
	} {
		if tc.got != tc.want {
			t.Errorf("String() = %q, want %q", tc.got, tc.want)
		}
	}
	for _, m := range []interface{ MarshalText() ([]byte, error) }{Outcome(4), DenyKind(4), Fidelity(4), Qualifier(3)} {
		if _, err := m.MarshalText(); err == nil {
			t.Errorf("%T out of range must not marshal", m)
		}
	}
	for _, u := range []interface{ UnmarshalText([]byte) error }{new(DenyKind), new(Fidelity), new(Qualifier)} {
		if err := u.UnmarshalText([]byte("nope")); err == nil {
			t.Errorf("%T accepted an unknown name", u)
		}
	}
}

func TestReasonCodes(t *testing.T) {
	if AmbiguityReason("A3") != "AMBIGUITY:A3" {
		t.Errorf("AmbiguityReason = %q", AmbiguityReason("A3"))
	}
	b, err := json.Marshal(FidelityReason{Code: ReasonPolicyUnparseable, Detail: "d", OutcomeSensitive: true})
	if err != nil || string(b) != `{"code":"POLICY_UNPARSEABLE","detail":"d","outcome_sensitive":true}` {
		t.Errorf("FidelityReason JSON = %s, %v", b, err)
	}
}

// Residual is a closed sum type: exactly these five types implement it.
func TestResidualSumType(t *testing.T) {
	for _, r := range []Residual{Const(true), And{}, Or{}, Not{Term: Const(false)}, Atom{Op: "Null", Key: "k"}} {
		r.isResidual() // the marker method is callable and does nothing
	}
}

func TestAWSEvalDecision(t *testing.T) {
	for _, tc := range []struct {
		d    Decision
		want string
	}{
		{Decision{Outcome: Allow}, "allowed"},
		{Decision{Outcome: Deny, DenyKind: Explicit}, "explicitDeny"},
		{Decision{Outcome: Deny, DenyKind: Implicit}, "implicitDeny"},
		{Decision{Outcome: Deny, DenyKind: Guardrail}, "implicitDeny"},
		{Decision{Outcome: Conditional}, ""},
	} {
		if got := tc.d.AWSEvalDecision(); got != tc.want {
			t.Errorf("%v/%v = %q, want %q", tc.d.Outcome, tc.d.DenyKind, got, tc.want)
		}
	}
}

func TestTriKleeneTables(t *testing.T) {
	a := U(Atom{Op: "Bool", Key: "aws:securetransport", Values: []string{"true"}})
	b := U(Atom{Op: "Null", Key: "aws:sourceip", Values: []string{"true"}})
	vals := map[string]Tri{"T": T, "F": F, "U": a}
	and := map[[2]string]string{
		{"T", "T"}: "T", {"T", "F"}: "F", {"T", "U"}: "U",
		{"F", "T"}: "F", {"F", "F"}: "F", {"F", "U"}: "F",
		{"U", "T"}: "U", {"U", "F"}: "F", {"U", "U"}: "U",
	}
	or := map[[2]string]string{
		{"T", "T"}: "T", {"T", "F"}: "T", {"T", "U"}: "T",
		{"F", "T"}: "T", {"F", "F"}: "F", {"F", "U"}: "U",
		{"U", "T"}: "T", {"U", "F"}: "U", {"U", "U"}: "U",
	}
	for k, want := range and {
		if got := vals[k[0]].And(vals[k[1]]).String(); got != want {
			t.Errorf("%s ∧ %s = %s, want %s", k[0], k[1], got, want)
		}
	}
	for k, want := range or {
		if got := vals[k[0]].Or(vals[k[1]]).String(); got != want {
			t.Errorf("%s ∨ %s = %s, want %s", k[0], k[1], got, want)
		}
	}
	if T.Not() != F || F.Not() != T || !a.Not().IsUnknown() {
		t.Error("negation table is wrong")
	}
	// The formula is built, not lost.
	got := a.And(b).Residual()
	want := And{Terms: []Residual{a.Residual(), b.Residual()}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("U∧U residual = %#v", got)
	}
	if !reflect.DeepEqual(a.Or(b).Residual(), Or{Terms: []Residual{a.Residual(), b.Residual()}}) {
		t.Error("U∨U residual is wrong")
	}
	if !reflect.DeepEqual(a.Not().Residual(), Not{Term: a.Residual()}) {
		t.Error("¬U residual is wrong")
	}
	if U(Const(true)) != T || U(Const(false)) != F || U(nil) != F {
		t.Error("U of a constant must collapse")
	}
	if T.Residual() != Const(true) || F.Residual() != Const(false) {
		t.Error("constant residuals are wrong")
	}
	var zero Tri
	if !zero.IsFalse() {
		t.Error("the zero Tri must be F")
	}
	if !AnyOf().IsFalse() || !AllOf().IsTrue() || !AnyOf(F, T).IsTrue() || !AllOf(T, a).IsUnknown() {
		t.Error("AnyOf/AllOf are wrong")
	}
}
