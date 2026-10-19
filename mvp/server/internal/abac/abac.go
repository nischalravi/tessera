// Package abac is Tessera's attribute condition language: a small JSON
// expression over typed attributes of the identity, the resource and the
// request context, used by birthright rules, request eligibility and SoD
// policy scopes (issue #162).
//
// A condition is one of
//
//	{"all": [c, ...]}   every part holds
//	{"any": [c, ...]}   at least one part holds
//	{"not": c}          the part does not hold
//	{"attr": "identity.department", "op": "eq", "value": "Finance"}
//
// Operators: eq, ne, in (value is a list), prefix, exists, gt, gte, lt, lte
// (numbers, or RFC 3339 times). It is data, never code: evaluation is a pure,
// deterministic walk of the tree with no side effects.
//
// Missing attributes deny. Evaluation is three-valued (Kleene): a comparison
// on an attribute the subject does not have is unknown, not false, and
// not(unknown) is still unknown; only a condition that evaluates to true
// grants. So "not (department = Finance)" does not grant to a person with no
// department. exists is the one test that is never unknown.
package abac

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Limits keep a condition small enough to review and cheap to evaluate.
const (
	MaxDepth      = 8
	MaxNodes      = 100
	MaxListValues = 50
	MaxStringLen  = 200
	MaxAttrLen    = 80
)

// Operators.
const (
	OpEq     = "eq"
	OpNe     = "ne"
	OpIn     = "in"
	OpPrefix = "prefix"
	OpExists = "exists"
	OpGt     = "gt"
	OpGte    = "gte"
	OpLt     = "lt"
	OpLte    = "lte"
)

var ops = map[string]bool{OpEq: true, OpNe: true, OpIn: true, OpPrefix: true, OpExists: true, OpGt: true, OpGte: true,
	OpLt: true, OpLte: true}

// Namespaces an attribute name may start with.
var Namespaces = []string{"identity", "resource", "context"}

var attrRE = regexp.MustCompile(`^(identity|resource|context)\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

// Node is one condition. Exactly one of All, Any, Not or Attr is set.
type Node struct {
	All   []*Node `json:"all,omitempty"`
	Any   []*Node `json:"any,omitempty"`
	Not   *Node   `json:"not,omitempty"`
	Attr  string  `json:"attr,omitempty"`
	Op    string  `json:"op,omitempty"`
	Value any     `json:"value,omitempty"`
}

// Error is an invalid condition.
type Error struct{ Msg string }

func (e *Error) Error() string { return "abac: " + e.Msg }

func bad(format string, args ...any) error { return &Error{Msg: fmt.Sprintf(format, args...)} }

// Parse reads and validates a condition from JSON. Unknown fields, trailing
// data and anything over the limits are refused.
func Parse(raw []byte) (*Node, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var n Node
	if err := dec.Decode(&n); err != nil {
		return nil, bad("not a valid condition: %v", err)
	}
	if dec.More() {
		return nil, bad("trailing data after the condition")
	}
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return &n, nil
}

// Validate checks the shape, the operators and the limits.
func (n *Node) Validate() error {
	count := 0
	return n.validate(1, &count)
}

func (n *Node) validate(depth int, count *int) error {
	if n == nil {
		return bad("empty condition")
	}
	if depth > MaxDepth {
		return bad("conditions nest at most %d deep", MaxDepth)
	}
	if *count++; *count > MaxNodes {
		return bad("a condition has at most %d parts", MaxNodes)
	}
	forms := 0
	for _, set := range []bool{n.All != nil, n.Any != nil, n.Not != nil, n.Attr != ""} {
		if set {
			forms++
		}
	}
	if forms != 1 {
		return bad("each part is exactly one of all, any, not or an attribute test")
	}
	switch {
	case n.All != nil || n.Any != nil:
		parts, name := n.All, "all"
		if n.Any != nil {
			parts, name = n.Any, "any"
		}
		if len(parts) == 0 {
			return bad("%s needs at least one part", name)
		}
		if n.Op != "" || n.Value != nil {
			return bad("%s takes no op or value", name)
		}
		for _, p := range parts {
			if err := p.validate(depth+1, count); err != nil {
				return err
			}
		}
	case n.Not != nil:
		if n.Op != "" || n.Value != nil {
			return bad("not takes no op or value")
		}
		return n.Not.validate(depth+1, count)
	default:
		return n.validateTest()
	}
	return nil
}

func scalar(v any) bool {
	switch x := v.(type) {
	case string:
		return len(x) <= MaxStringLen
	case float64, bool:
		return true
	}
	return false
}

func (n *Node) validateTest() error {
	if len(n.Attr) > MaxAttrLen || !attrRE.MatchString(n.Attr) {
		return bad("attribute %q is not identity.<name>, resource.<name> or context.<name>", n.Attr)
	}
	if !ops[n.Op] {
		return bad("unknown operator %q", n.Op)
	}
	switch n.Op {
	case OpExists:
		if n.Value != nil {
			return bad("exists takes no value")
		}
	case OpIn:
		l, ok := n.Value.([]any)
		if !ok || len(l) == 0 || len(l) > MaxListValues {
			return bad("in takes a list of 1 to %d values", MaxListValues)
		}
		for _, v := range l {
			if !scalar(v) {
				return bad("in lists strings, numbers or booleans")
			}
		}
	case OpPrefix:
		if s, ok := n.Value.(string); !ok || s == "" || len(s) > MaxStringLen {
			return bad("prefix takes a non-empty string")
		}
	case OpEq, OpNe:
		if !scalar(n.Value) {
			return bad("%s takes a string, number or boolean", n.Op)
		}
	default: // gt gte lt lte
		switch v := n.Value.(type) {
		case float64:
		case string:
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				return bad("%s takes a number or an RFC 3339 time", n.Op)
			}
		default:
			return bad("%s takes a number or an RFC 3339 time", n.Op)
		}
	}
	return nil
}

// Canonical returns the condition as compact JSON with a stable key order
// (what is stored and versioned).
func (n *Node) Canonical() (string, error) {
	b, err := json.Marshal(n)
	return string(b), err
}

// Attrs are the attribute values of one evaluation, by full name
// ("identity.department"). Values are string, float64 or bool; an absent key
// is a missing attribute.
type Attrs map[string]any

// Tri is the three-valued result of evaluating a part.
type Tri int

// Results.
const (
	False Tri = iota
	True
	Unknown
)

// Eval reports whether the condition holds. Unknown (a missing attribute, a
// type mismatch) is not a grant: Eval is true only when the condition is
// definitely true. A nil condition is false.
func Eval(n *Node, a Attrs) bool { return n.Tri(a) == True }

// Tri evaluates the condition to true, false or unknown.
func (n *Node) Tri(a Attrs) Tri {
	switch {
	case n == nil:
		return False
	case n.All != nil:
		out := True
		for _, p := range n.All {
			switch p.Tri(a) {
			case False:
				return False
			case Unknown:
				out = Unknown
			}
		}
		return out
	case n.Any != nil:
		out := False
		for _, p := range n.Any {
			switch p.Tri(a) {
			case True:
				return True
			case Unknown:
				out = Unknown
			}
		}
		return out
	case n.Not != nil:
		switch n.Not.Tri(a) {
		case True:
			return False
		case False:
			return True
		}
		return Unknown
	}
	return n.test(a)
}

func b2t(b bool) Tri {
	if b {
		return True
	}
	return False
}

func (n *Node) test(a Attrs) Tri {
	v, ok := a[n.Attr]
	if n.Op == OpExists {
		return b2t(ok && v != nil && v != "")
	}
	if !ok || v == nil || v == "" {
		return Unknown
	}
	switch n.Op {
	case OpEq:
		return b2t(equal(v, n.Value))
	case OpNe:
		return b2t(!equal(v, n.Value))
	case OpIn:
		l, _ := n.Value.([]any)
		for _, x := range l {
			if equal(v, x) {
				return True
			}
		}
		return False
	case OpPrefix:
		s, ok := v.(string)
		p, _ := n.Value.(string)
		if !ok {
			return Unknown
		}
		return b2t(strings.HasPrefix(s, p))
	}
	c, ok := compare(v, n.Value)
	if !ok {
		return Unknown
	}
	switch n.Op {
	case OpGt:
		return b2t(c > 0)
	case OpGte:
		return b2t(c >= 0)
	case OpLt:
		return b2t(c < 0)
	}
	return b2t(c <= 0) // lte
}

func equal(a, b any) bool {
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	}
	return false
}

// compare orders two numbers, or two RFC 3339 times.
func compare(a, b any) (int, bool) {
	if x, ok := a.(float64); ok {
		y, ok := b.(float64)
		if !ok {
			return 0, false
		}
		switch {
		case x < y:
			return -1, true
		case x > y:
			return 1, true
		}
		return 0, true
	}
	xs, ok1 := a.(string)
	ys, ok2 := b.(string)
	if !ok1 || !ok2 {
		return 0, false
	}
	x, err1 := time.Parse(time.RFC3339, xs)
	y, err2 := time.Parse(time.RFC3339, ys)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return x.Compare(y), true
}

// Attribute describes one attribute the platform supplies, for editors.
type Attribute struct {
	Name string `json:"name"`
	Type string `json:"type"` // string, number, boolean, time
	Note string `json:"note"`
}

// Catalog is every attribute Tessera supplies today.
var Catalog = []Attribute{
	{"identity.type", "string", "human, service or ai_agent"},
	{"identity.status", "string", "active, terminated, ..."},
	{"identity.name", "string", ""},
	{"identity.email", "string", ""},
	{"identity.department", "string", "from the HRIS"},
	{"identity.title", "string", "from the HRIS"},
	{"identity.manager_id", "number", "identity id of the manager"},
	{"identity.has_manager", "boolean", ""},
	{"identity.source", "string", "system the identity came from"},
	{"identity.tenure_days", "number", "days since hire"},
	{"identity.worker_type", "string", "people only: employee, contractor, intern, partner, vendor or guest (no lifecycle record: employee)"},
	{"resource.name", "string", "the role or catalog entitlement"},
	{"resource.risk", "string", "low, medium or high"},
	{"resource.system", "string", "catalog entitlements: the connected system"},
	{"resource.privileged", "boolean", "catalog entitlements"},
	{"context.time", "time", "evaluation time, RFC 3339 (UTC)"},
	{"context.hour", "number", "0-23, UTC"},
	{"context.weekday", "string", "mon, tue, ... sun (UTC)"},
	{"context.aal", "number", "authentication assurance level of the signed-in user; absent when not a request"},
}
