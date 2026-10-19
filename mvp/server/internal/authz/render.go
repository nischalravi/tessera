package authz

import (
	"strconv"
	"strings"
)

// RenderOptions controls Render.
type RenderOptions struct {
	// MaxDisjuncts is how many alternatives of the DNF are shown before the
	// rest are collapsed into "… (N more)". 0 means the default of 4 (§9.5).
	MaxDisjuncts int
}

// maxDNFTerms bounds the distribution of And over Or. A residual that would
// expand past it is rendered as a tree instead, so a hostile policy cannot
// make the renderer exponential.
const maxDNFTerms = 256

// Render writes a residual for people, in DNF, for example
//
//	(aws:MultiFactorAuthPresent = true) AND (aws:SourceIp in 10.0.0.0/8) [identity: DevPolicy#2]
//
// The output is a pure function of r. Atoms that carry a Source are followed
// by the distinct statements that contributed them.
func Render(r Residual, opts RenderOptions) string {
	limit := opts.MaxDisjuncts
	if limit <= 0 {
		limit = 4
	}
	r = nnf(r, false)
	switch t := r.(type) {
	case Const:
		if bool(t) {
			return "always"
		}
		return "never"
	}
	disj, ok := dnf(r)
	if !ok {
		var refs sourceList
		return renderTree(r, &refs) + refs.String()
	}
	var refs sourceList
	parts := make([]string, 0, limit+1)
	for i, conj := range disj {
		if i == limit {
			parts = append(parts, "… ("+strconv.Itoa(len(disj)-limit)+" more)")
			break
		}
		lits := make([]string, len(conj))
		for j, l := range conj {
			lits[j] = "(" + renderLit(l, &refs) + ")"
		}
		parts = append(parts, strings.Join(lits, " AND "))
	}
	if len(disj) > 1 {
		// Bracket each conjunction so AND/OR nesting is unambiguous.
		for i, p := range parts {
			if strings.Contains(p, " AND ") && !strings.HasPrefix(p, "…") {
				parts[i] = "[" + p + "]"
			}
		}
	}
	return strings.Join(parts, " OR ") + refs.String()
}

// dnf distributes a negation-normal-form residual into a list of conjunctions
// of literals. ok is false if the expansion would exceed maxDNFTerms.
func dnf(r Residual) ([][]Residual, bool) {
	switch t := r.(type) {
	case Atom, Not:
		return [][]Residual{{r}}, true
	case Const:
		if bool(t) {
			return [][]Residual{{}}, true
		}
		return nil, true
	case Or:
		var out [][]Residual
		for _, x := range t.Terms {
			d, ok := dnf(x)
			if !ok {
				return nil, false
			}
			out = append(out, d...)
			if len(out) > maxDNFTerms {
				return nil, false
			}
		}
		return out, true
	case And:
		out := [][]Residual{{}}
		for _, x := range t.Terms {
			d, ok := dnf(x)
			if !ok {
				return nil, false
			}
			if len(out)*len(d) > maxDNFTerms {
				return nil, false
			}
			next := make([][]Residual, 0, len(out)*len(d))
			for _, a := range out {
				for _, b := range d {
					c := make([]Residual, 0, len(a)+len(b))
					c = append(append(c, a...), b...)
					next = append(next, c)
				}
			}
			out = next
		}
		return out, true
	}
	return nil, false
}

func renderTree(r Residual, refs *sourceList) string {
	switch t := r.(type) {
	case And:
		return renderJoin(t.Terms, " AND ", refs)
	case Or:
		return renderJoin(t.Terms, " OR ", refs)
	case Const:
		if bool(t) {
			return "always"
		}
		return "never"
	}
	return "(" + renderLit(r, refs) + ")"
}

func renderJoin(ts []Residual, sep string, refs *sourceList) string {
	parts := make([]string, len(ts))
	for i, x := range ts {
		parts[i] = renderTree(x, refs)
		if _, nested := x.(And); nested {
			parts[i] = "[" + parts[i] + "]"
		} else if _, nested := x.(Or); nested {
			parts[i] = "[" + parts[i] + "]"
		}
	}
	return strings.Join(parts, sep)
}

func renderLit(r Residual, refs *sourceList) string {
	switch t := r.(type) {
	case Atom:
		refs.add(t.Source)
		return AtomText(t)
	case Not:
		if a, ok := t.Term.(Atom); ok {
			refs.add(a.Source)
			return "NOT " + AtomText(a)
		}
	}
	return "?"
}

// AtomText describes one atom in words, e.g. "aws:SourceIp in 10.0.0.0/8".
func AtomText(a Atom) string {
	key := a.RawKey
	if key == "" {
		key = a.Key
	}
	subject := key
	switch a.Qualifier {
	case ForAllValues:
		subject = "every value of " + key
	case ForAnyValue:
		subject = "some value of " + key
	}
	var s string
	switch a.Op {
	case "Null":
		s = nullText(key, a.Values)
	default:
		s = subject + " " + opWords(a.Op, len(a.Values) > 1) + " " + valueText(a.Values)
		if a.Op == "StringEqualsIgnoreCase" || a.Op == "StringNotEqualsIgnoreCase" {
			s += " (ignoring case)"
		}
	}
	if a.IfExists && a.Op != "Null" {
		s += " (if present)"
	}
	return s
}

func nullText(key string, vals []string) string {
	if len(vals) == 1 {
		switch vals[0] {
		case "true":
			return key + " is absent"
		case "false":
			return key + " is present"
		}
	}
	return key + " presence is " + valueText(vals)
}

func valueText(vals []string) string {
	if len(vals) == 1 {
		return vals[0]
	}
	return "{" + strings.Join(vals, ", ") + "}"
}

func opWords(op string, many bool) string {
	switch op {
	case "StringEquals", "StringEqualsIgnoreCase", "ArnEquals", "ArnLike", "BinaryEquals", "NumericEquals", "DateEquals", "Bool":
		if many {
			return "in"
		}
		return "="
	case "StringNotEquals", "StringNotEqualsIgnoreCase", "ArnNotEquals", "ArnNotLike", "NumericNotEquals", "DateNotEquals":
		if many {
			return "not in"
		}
		return "!="
	case "StringLike":
		return "matches"
	case "StringNotLike":
		return "does not match"
	case "NumericLessThan", "DateLessThan":
		return "<"
	case "NumericLessThanEquals", "DateLessThanEquals":
		return "<="
	case "NumericGreaterThan", "DateGreaterThan":
		return ">"
	case "NumericGreaterThanEquals", "DateGreaterThanEquals":
		return ">="
	case "IpAddress":
		return "in"
	case "NotIpAddress":
		return "not in"
	}
	return op
}

// sourceList collects distinct statement references in first-use order.
type sourceList struct {
	seen []string
}

func (l *sourceList) add(s *StmtRef) {
	if s == nil {
		return
	}
	label := s.PolicyKind
	if s.OrgLevel != "" {
		label += " " + s.OrgLevel
	}
	name := s.PolicyID
	if i := strings.LastIndexAny(s.SourceARN, "/:"); i >= 0 && i+1 < len(s.SourceARN) {
		name = s.SourceARN[i+1:]
	} else if s.SourceARN != "" {
		name = s.SourceARN
	}
	ref := label + ": " + name + "#" + strconv.Itoa(s.StatementIndex)
	for _, x := range l.seen {
		if x == ref {
			return
		}
	}
	l.seen = append(l.seen, ref)
}

func (l *sourceList) String() string {
	if len(l.seen) == 0 {
		return ""
	}
	return " [" + strings.Join(l.seen, ", ") + "]"
}
