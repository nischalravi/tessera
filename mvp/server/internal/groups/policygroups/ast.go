// Package policygroups is "policy groups as code" (design
// docs/design/groups-grouper-parity.md §8, K4): a restricted, decidable fragment
// of Cedar describes who belongs to a group, as `allow - deny` over reference
// groups and identity attributes. The package parses and validates the fragment
// (parse.go, lower.go), compiles a policy file to hash-consed composite trees
// that the membership engine already evaluates (compile.go, apply.go), keeps the
// attribute groups `sys:attr:*` current (index.go), answers "is this identity a
// member" straight from the policy, the way a PDP does (eval.go), and shows what
// a change would do before it is merged (diff.go).
//
// There is no Cedar library in the repository, and the fragment is small enough
// that its parser and evaluator are written here instead of added as a
// dependency (see docs/design/groups-policy-repo-example.md). The fragment is
// valid Cedar, so a file can also be given to the Cedar CLI or a Cedar PDP.
package policygroups

import (
	"fmt"
	"sort"
	"strings"
)

// Effect of a policy.
type Effect int

// Policy effects.
const (
	Permit Effect = iota
	Forbid
)

func (e Effect) String() string {
	if e == Forbid {
		return "forbid"
	}
	return "permit"
}

// Pos is a position in a policy file (1-based).
type Pos struct{ Line, Col int }

func (p Pos) String() string { return fmt.Sprintf("%d:%d", p.Line, p.Col) }

// Expr is a condition of the fragment: `&&`, `||`, `!` over the four atoms.
type Expr interface{ pos() Pos }

type (
	// And is `l && r`.
	And struct {
		L, R Expr
		At   Pos
	}
	// Or is `l || r`.
	Or struct {
		L, R Expr
		At   Pos
	}
	// Not is `!x`.
	Not struct {
		X  Expr
		At Pos
	}
	// InGroup is `principal in Tessera::Group::"name"`.
	InGroup struct {
		Name string
		At   Pos
	}
	// AttrEq is `principal.attr == "value"`.
	AttrEq struct {
		Attr, Value string
		At          Pos
	}
	// AttrIn is `principal.attr in ["a", "b"]`.
	AttrIn struct {
		Attr   string
		Values []string
		At     Pos
	}
	// AttrContains is `principal.attr.contains("value")` on a set attribute.
	AttrContains struct {
		Attr, Value string
		At          Pos
	}
	// AttrHas is `principal has attr`.
	AttrHas struct {
		Attr string
		At   Pos
	}
)

func (x And) pos() Pos          { return x.At }
func (x Or) pos() Pos           { return x.At }
func (x Not) pos() Pos          { return x.At }
func (x InGroup) pos() Pos      { return x.At }
func (x AttrEq) pos() Pos       { return x.At }
func (x AttrIn) pos() Pos       { return x.At }
func (x AttrContains) pos() Pos { return x.At }
func (x AttrHas) pos() Pos      { return x.At }

// Policy is one `permit` or `forbid`: its effect and the condition under which
// it applies (every `when` clause and the negation of every `unless` clause,
// conjoined).
type Policy struct {
	ID     string
	Effect Effect
	Cond   Expr
	At     Pos
}

// File is a policy file: the policies of one group.
type File struct {
	Path      string
	Group     string // the group's full name, from the policies' resource
	Display   string // @display
	Owner     string // @owner
	Provision []string
	Policies  []*Policy
}

// Groups returns the names of the groups the file refers to, sorted, lower-cased
// and without duplicates, with the position of the first use of each.
func (f *File) Groups() ([]string, map[string]Pos) {
	at := map[string]Pos{}
	for _, p := range f.Policies {
		walk(p.Cond, func(x Expr) {
			if g, ok := x.(InGroup); ok {
				k := strings.ToLower(g.Name)
				if _, seen := at[k]; !seen {
					at[k] = g.At
				}
			}
		})
	}
	out := make([]string, 0, len(at))
	for k := range at {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, at
}

// walk calls fn on every node of x, parents first.
func walk(x Expr, fn func(Expr)) {
	if x == nil {
		return
	}
	fn(x)
	switch n := x.(type) {
	case And:
		walk(n.L, fn)
		walk(n.R, fn)
	case Or:
		walk(n.L, fn)
		walk(n.R, fn)
	case Not:
		walk(n.X, fn)
	}
}

// Diagnostic is one finding in a policy file.
type Diagnostic struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Col  int    `json:"col"`
	Code string `json:"code"`
	Msg  string `json:"message"`
}

func (d Diagnostic) String() string {
	return fmt.Sprintf("%s:%d:%d: %s: %s", d.Path, d.Line, d.Col, d.Code, d.Msg)
}

// Diagnostic codes.
const (
	CodeSyntax         = "syntax"
	CodeUnsupported    = "unsupported"
	CodeInvalidPolicy  = "invalid_policy"
	CodeUnknownAttr    = "unknown_attribute"
	CodeTypeMismatch   = "type_mismatch"
	CodeUnguardedAttr  = "unguarded_attribute"
	CodeInvalidValue   = "invalid_value"
	CodeUnknownGroup   = "unknown_group"
	CodeGroupDeleted   = "group_deleted"
	CodeUnbounded      = "unbounded_negation"
	CodeDuplicateGroup = "duplicate_group"
	CodeNotPolicyGroup = "not_policy_group"
	CodePolicyManaged  = "policy_managed"
	CodeInvalidCommit  = "invalid_commit"
	CodeTooManyFiles   = "too_many_files"
	CodeFileTooLarge   = "file_too_large"
	CodeDuplicatePath  = "duplicate_path"
	CodeInvalidPath    = "invalid_path"
	CodeReferenceCycle = "cycle"
	CodeHashCollision  = "hash_collision"
	CodeInvalidSchema  = "invalid_schema"
)

// ValidationError carries every finding of a refused change.
type ValidationError struct{ Diags []Diagnostic }

func (e *ValidationError) Error() string {
	if len(e.Diags) == 0 {
		return "policygroups: invalid policy"
	}
	s := e.Diags[0].String()
	if len(e.Diags) > 1 {
		s += fmt.Sprintf(" (and %d more)", len(e.Diags)-1)
	}
	return s
}
