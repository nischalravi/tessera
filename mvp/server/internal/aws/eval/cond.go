package eval

import (
	"bytes"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
)

// family is the value type an operator coerces to.
type family uint8

const (
	famString family = iota
	famFold
	famLike
	famNumeric
	famDate
	famBool
	famBinary
	famIP
	famArn
	famNull
)

// rel is the comparison a numeric or date operator makes.
type rel uint8

const (
	relEq rel = iota
	relLt
	relLe
	relGt
	relGe
)

// opSpec describes a canonical operator: the positive test it is built from
// and whether the operator negates it. "Negated" means not-exists over the
// policy values, so a context value that fails to parse is "no match" and a
// negated operator is true for it (P-TYPEMISMATCH).
type opSpec struct {
	fam family
	rel rel
	neg bool
}

var opSpecs = map[string]opSpec{
	"StringEquals":              {fam: famString},
	"StringNotEquals":           {fam: famString, neg: true},
	"StringEqualsIgnoreCase":    {fam: famFold},
	"StringNotEqualsIgnoreCase": {fam: famFold, neg: true},
	"StringLike":                {fam: famLike},
	"StringNotLike":             {fam: famLike, neg: true},
	"NumericEquals":             {fam: famNumeric, rel: relEq},
	"NumericNotEquals":          {fam: famNumeric, rel: relEq, neg: true},
	"NumericLessThan":           {fam: famNumeric, rel: relLt},
	"NumericLessThanEquals":     {fam: famNumeric, rel: relLe},
	"NumericGreaterThan":        {fam: famNumeric, rel: relGt},
	"NumericGreaterThanEquals":  {fam: famNumeric, rel: relGe},
	"DateEquals":                {fam: famDate, rel: relEq},
	"DateNotEquals":             {fam: famDate, rel: relEq, neg: true},
	"DateLessThan":              {fam: famDate, rel: relLt},
	"DateLessThanEquals":        {fam: famDate, rel: relLe},
	"DateGreaterThan":           {fam: famDate, rel: relGt},
	"DateGreaterThanEquals":     {fam: famDate, rel: relGe},
	"Bool":                      {fam: famBool},
	"BinaryEquals":              {fam: famBinary},
	"IpAddress":                 {fam: famIP},
	"NotIpAddress":              {fam: famIP, neg: true},
	"ArnEquals":                 {fam: famArn},
	"ArnLike":                   {fam: famArn},
	"ArnNotEquals":              {fam: famArn, neg: true},
	"ArnNotLike":                {fam: famArn, neg: true},
	"Null":                      {fam: famNull},
}

// variableOperator: policy variables are substituted only in the values of
// String, ARN and Bool operators (§9.3).
func variableOperator(op string) bool {
	return strings.HasPrefix(op, "String") || strings.HasPrefix(op, "Arn") || op == "Bool"
}

func (r rel) holds(c int) bool {
	switch r {
	case relLt:
		return c < 0
	case relLe:
		return c <= 0
	case relGt:
		return c > 0
	case relGe:
		return c >= 0
	}
	return c == 0
}

// posMatch is the positive test of one context value v against one resolved
// policy value w. It is false when either side fails to parse.
func posMatch(sp opSpec, v string, w Pattern) bool {
	switch sp.fam {
	case famString:
		return v == w.String()
	case famFold:
		return strings.EqualFold(v, w.String())
	case famLike:
		return likeMatch(w, v)
	case famArn:
		return arnLikeMatch(w, v)
	case famNumeric:
		a, ok1 := parseDecimal(v)
		b, ok2 := parseDecimal(w.String())
		return ok1 && ok2 && sp.rel.holds(a.compare(b))
	case famDate:
		a, ok1 := parseDate(v)
		b, ok2 := parseDate(w.String())
		return ok1 && ok2 && sp.rel.holds(a.compare(b))
	case famBool:
		a, ok1 := parseBoolValue(v)
		b, ok2 := parseBoolValue(w.String())
		return ok1 && ok2 && a == b
	case famBinary:
		a, ok1 := decodeBinary(v)
		b, ok2 := decodeBinary(w.String())
		return ok1 && ok2 && bytes.Equal(a, b)
	case famIP:
		a, ok1 := parseIPValue(v)
		p, ok2 := parseIPPolicy(w.String())
		return ok1 && ok2 && p.Contains(a)
	}
	return false
}

// AtomResult is the outcome of one condition atom.
type AtomResult struct {
	Result authz.Tri
	Trace  authz.CondTrace
	// Ambiguities lists the register entries (§4.3) whose default decided
	// part of this result: "A5", "A6", "A7", "A8", "A17". Sorted, unique. The
	// engine decides whether they are outcome-sensitive.
	Ambiguities []string
}

// EvalAtom evaluates one atom against ctx following the truth table of §9.3.
// varsEnabled says whether the policy document substitutes variables.
//
// An unknown key gives U(atom). So does a value whose variable names an
// unknown key. An operator this package does not know also gives U(atom): it
// never gives a confident answer.
func EvalAtom(a authz.Atom, ctx *Context, varsEnabled bool) AtomResult {
	key := asciiLower(a.Key)
	cv := ctx.Lookup(key)
	out := AtomResult{Trace: authz.CondTrace{Atom: a, RequestState: cv.State.String()}}
	amb := map[string]bool{}
	finish := func(t authz.Tri) AtomResult {
		out.Result = t
		out.Trace.Result = triName(t)
		for id := range amb {
			out.Ambiguities = append(out.Ambiguities, id)
		}
		sort.Strings(out.Ambiguities)
		return out
	}

	sp, known := opSpecs[a.Op]
	if !known || cv.State == Unknown {
		return finish(authz.U(a))
	}
	multi := ctx.multivalued(key)
	if a.Qualifier != authz.NoQualifier && !multi {
		amb["A8"] = true
	}

	if sp.fam == famNull {
		// Qualifiers and IfExists do not apply to Null; NullIfExists is a lint
		// error that the parser keeps as written, and it evaluates as Null.
		want := "false"
		if cv.State == Absent {
			want = "true"
		}
		out.Trace.RequestValues = cv.Values
		for _, w := range a.Values {
			if strings.EqualFold(w, want) {
				return finish(authz.T)
			}
		}
		return finish(authz.F)
	}

	if cv.State == Absent {
		switch {
		case a.IfExists, a.Qualifier == authz.ForAllValues:
			return finish(authz.T)
		case a.Qualifier == authz.ForAnyValue:
			if sp.neg {
				amb["A5"] = true
			}
			return finish(authz.F)
		}
		if key == "aws:sourceip" && sp.fam == famIP {
			amb["A17"] = true
		}
		return finish(authz.Bool(sp.neg))
	}

	// Present. Resolve the policy values.
	vals := cv.Values
	if len(vals) == 1 && vals[0] == "" {
		vals = nil // the empty set, however it was spelled
	}
	out.Trace.RequestValues = cv.Values
	ws := make([]Pattern, 0, len(a.Values))
	subst := varsEnabled && variableOperator(a.Op)
	for _, raw := range a.Values {
		p, res := Substitute(raw, ctx, subst)
		switch res {
		case SubstUnknown:
			return finish(authz.U(a))
		case SubstNull:
			amb["A6"] = true
			continue // matches nothing
		}
		ws = append(ws, p)
	}
	exists := func(v string) bool {
		for _, w := range ws {
			if posMatch(sp, v, w) {
				return true
			}
		}
		return false
	}
	var r bool
	switch a.Qualifier {
	case authz.ForAllValues:
		r = true // vacuous for the empty set
		for _, v := range vals {
			if exists(v) == sp.neg {
				r = false
				break
			}
		}
	case authz.ForAnyValue:
		for _, v := range vals {
			if exists(v) != sp.neg {
				r = true
				break
			}
		}
	default:
		if multi && len(vals) > 1 {
			amb["A7"] = true
		}
		found := false
		for _, v := range vals {
			if exists(v) {
				found = true
				break
			}
		}
		r = found != sp.neg
	}
	return finish(authz.Bool(r))
}

func triName(t authz.Tri) string {
	switch {
	case t.IsTrue():
		return "true"
	case t.IsFalse():
		return "false"
	}
	return "unknown"
}

// EvalConditions evaluates a statement's condition: the atoms AND, in order.
// Every atom is evaluated, so the trace is complete even after one is false.
// A statement with no atoms is T. The third result is the sorted, unique union
// of the atoms' ambiguity ids.
func EvalConditions(atoms []authz.Atom, ctx *Context, varsEnabled bool) (authz.Tri, []authz.CondTrace, []string) {
	res := authz.T
	traces := make([]authz.CondTrace, 0, len(atoms))
	seen := map[string]bool{}
	var amb []string
	for _, a := range atoms {
		r := EvalAtom(a, ctx, varsEnabled)
		res = res.And(r.Result)
		traces = append(traces, r.Trace)
		for _, id := range r.Ambiguities {
			if !seen[id] {
				seen[id] = true
				amb = append(amb, id)
			}
		}
	}
	sort.Strings(amb)
	return res, traces, amb
}

// EvalResidual evaluates a residual under ctx: the atoms are evaluated with
// EvalAtom and combined with the residual's own connectives. Under a total
// context the result is T or F; it is how a residual is re-checked once more
// keys are pinned.
func EvalResidual(r authz.Residual, ctx *Context, varsEnabled bool) authz.Tri {
	switch t := r.(type) {
	case nil:
		return authz.F
	case authz.Const:
		return authz.Bool(bool(t))
	case authz.Atom:
		return EvalAtom(t, ctx, varsEnabled).Result
	case authz.Not:
		return EvalResidual(t.Term, ctx, varsEnabled).Not()
	case authz.And:
		res := authz.T
		for _, x := range t.Terms {
			res = res.And(EvalResidual(x, ctx, varsEnabled))
		}
		return res
	case authz.Or:
		res := authz.F
		for _, x := range t.Terms {
			res = res.Or(EvalResidual(x, ctx, varsEnabled))
		}
		return res
	}
	return authz.F
}
