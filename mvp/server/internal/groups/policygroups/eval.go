package policygroups

import (
	"fmt"
	"strings"
)

// The evaluator answers "is this identity a member of the policy group" from the
// policy text and the identity's facts, without the engine: it is the per-request
// PDP of design §8.6 (an AuthZEN decision point would call it). Its semantics are
// the Cedar semantics of the fragment: a policy applies when its condition holds;
// the identity is a member when some permit applies and no forbid does. Every
// attribute read of a validated file is guarded (lower.go), so Cedar's error on a
// missing attribute cannot occur and "missing" is simply "not equal".
// TestPolicyGroups_PDPAgreesWithEngine checks that the engine's materialized
// membership equals this evaluator's answer.

// Subject is what a decision needs to know about an identity.
type Subject interface {
	// InGroup reports whether the identity is in the named group (a reference
	// group, an exception group or another policy group).
	InGroup(name string) (bool, error)
	// Attr returns the identity's values of an attribute: one for a string
	// attribute, any number for a set; none (or ok false) when it has none.
	Attr(name string) (values []string, ok bool)
}

// Decide reports whether the subject is a member of the file's group.
func (f *File) Decide(s Subject) (bool, error) {
	permitted := false
	for _, p := range f.Policies {
		if p.Effect == Permit && permitted {
			continue // already permitted: only a forbid can change the answer
		}
		ok, err := Eval(p.Cond, s)
		if err != nil {
			return false, err
		}
		if !ok {
			continue
		}
		if p.Effect == Forbid {
			return false, nil
		}
		permitted = true
	}
	return permitted, nil
}

// Eval evaluates a condition for a subject.
func Eval(x Expr, s Subject) (bool, error) {
	switch n := x.(type) {
	case And:
		l, err := Eval(n.L, s)
		if err != nil || !l {
			return false, err
		}
		return Eval(n.R, s)
	case Or:
		l, err := Eval(n.L, s)
		if err != nil || l {
			return l, err
		}
		return Eval(n.R, s)
	case Not:
		v, err := Eval(n.X, s)
		return !v, err
	case InGroup:
		return s.InGroup(n.Name)
	case AttrEq:
		vals, ok := s.Attr(n.Attr)
		return ok && len(vals) == 1 && vals[0] == n.Value, nil
	case AttrIn:
		vals, ok := s.Attr(n.Attr)
		if !ok || len(vals) != 1 {
			return false, nil
		}
		for _, v := range n.Values {
			if vals[0] == v {
				return true, nil
			}
		}
		return false, nil
	case AttrContains:
		vals, ok := s.Attr(n.Attr)
		if !ok {
			return false, nil
		}
		for _, v := range vals {
			if v == n.Value {
				return true, nil
			}
		}
		return false, nil
	case AttrHas:
		vals, ok := s.Attr(n.Attr)
		return ok && len(vals) > 0, nil
	}
	return false, fmt.Errorf("policygroups: unknown condition %T", x)
}

// String renders a condition in the fragment's Cedar syntax (for messages and tests).
func String(x Expr) string {
	switch n := x.(type) {
	case And:
		return "(" + String(n.L) + " && " + String(n.R) + ")"
	case Or:
		return "(" + String(n.L) + " || " + String(n.R) + ")"
	case Not:
		return "!(" + String(n.X) + ")"
	case InGroup:
		return fmt.Sprintf("principal in Tessera::Group::%q", n.Name)
	case AttrEq:
		return fmt.Sprintf("principal.%s == %q", n.Attr, n.Value)
	case AttrIn:
		q := make([]string, len(n.Values))
		for i, v := range n.Values {
			q[i] = fmt.Sprintf("%q", v)
		}
		return fmt.Sprintf("principal.%s in [%s]", n.Attr, strings.Join(q, ", "))
	case AttrContains:
		return fmt.Sprintf("principal.%s.contains(%q)", n.Attr, n.Value)
	case AttrHas:
		return "principal has " + n.Attr
	}
	return "?"
}
