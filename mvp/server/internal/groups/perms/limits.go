package perms

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Limits (design §10.10, G-52). Grouper's limits are attribute assignments of a
// definition of type limit on a permission assignment; the limit's name picks
// what it checks and its values say how. Here a limit compiles to a Cedar
// `when` condition over `context`, and the same condition tree is what the
// per-request decision point (Decide) evaluates, so the text that is exported
// and the answer that is given cannot drift apart.
//
// The built-in kinds, matched on the extension of the limit's name, ignoring case:
//
//	amountLessThan  integer values; context.amount < N (several values: all must hold)
//	ipOnNetwork     string values, CIDRs; context.ip is in one of them
//	timeWindow      string values "H-H" (UTC hours, end exclusive); context.hour is in one of them
//	expression      string values "attr op literal" (op one of == != < <= > >=, literal an
//	                integer or a double-quoted string); every value must hold
//
// A limit whose context value is missing does not hold: limits fail closed.
// Several limits on one assignment must all hold.

// Limit kinds.
const (
	LimitAmountLessThan = "amountlessthan"
	LimitIPOnNetwork    = "iponnetwork"
	LimitTimeWindow     = "timewindow"
	LimitExpression     = "expression"
)

// Context is what a decision is asked about besides the subject, resource and
// action: values are int64 or string.
type Context map[string]any

// Cond is a compiled limit condition.
type Cond interface {
	// Cedar renders the condition in Cedar syntax over context.
	Cedar() string
	// Holds evaluates it for a context.
	Holds(Context) bool
}

type (
	// allOf holds when every part holds (an empty allOf holds).
	allOf []Cond
	// anyOf holds when one part holds.
	anyOf []Cond
	// cmp compares a context attribute with an integer or string literal.
	cmp struct {
		Attr string
		Op   string
		Int  *int64
		Str  *string
	}
	// ipIn holds when context.ip is in the prefix.
	ipIn struct{ Prefix netip.Prefix }
	// hourIn holds when context.hour is in [From, To).
	hourIn struct{ From, To int64 }
)

func (a allOf) Cedar() string { return join(a, " && ", "true") }
func (a anyOf) Cedar() string { return join(a, " || ", "false") }

func join(cs []Cond, sep, empty string) string {
	switch len(cs) {
	case 0:
		return empty
	case 1:
		return cs[0].Cedar()
	}
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = "(" + c.Cedar() + ")"
	}
	return strings.Join(parts, sep)
}

func (a allOf) Holds(c Context) bool {
	for _, x := range a {
		if !x.Holds(c) {
			return false
		}
	}
	return true
}

func (a anyOf) Holds(c Context) bool {
	for _, x := range a {
		if x.Holds(c) {
			return true
		}
	}
	return false
}

func (m cmp) Cedar() string {
	var lit string
	if m.Int != nil {
		lit = strconv.FormatInt(*m.Int, 10)
	} else {
		lit = strconv.Quote(*m.Str)
	}
	return fmt.Sprintf("context has %s && context.%s %s %s", m.Attr, m.Attr, m.Op, lit)
}

func (m cmp) Holds(c Context) bool {
	v, ok := c[m.Attr]
	if !ok {
		return false
	}
	if m.Int != nil {
		n, ok := v.(int64)
		if !ok {
			return false
		}
		return compare(n < *m.Int, n == *m.Int, m.Op)
	}
	s, ok := v.(string)
	if !ok {
		return false
	}
	return compare(s < *m.Str, s == *m.Str, m.Op)
}

func compare(less, equal bool, op string) bool {
	switch op {
	case "<":
		return less
	case "<=":
		return less || equal
	case ">":
		return !less && !equal
	case ">=":
		return !less
	case "==":
		return equal
	case "!=":
		return !equal
	}
	return false
}

func (i ipIn) Cedar() string {
	return fmt.Sprintf("context has ip && ip(context.ip).isInRange(ip(%q))", i.Prefix.String())
}

func (i ipIn) Holds(c Context) bool {
	s, ok := c["ip"].(string)
	if !ok {
		return false
	}
	a, err := netip.ParseAddr(s)
	return err == nil && i.Prefix.Contains(a.Unmap())
}

func (h hourIn) Cedar() string {
	return fmt.Sprintf("context has hour && context.hour >= %d && context.hour < %d", h.From, h.To)
}

func (h hourIn) Holds(c Context) bool {
	n, ok := c["hour"].(int64)
	return ok && n >= h.From && n < h.To
}

// ---------------------------------------------------------------- compiling

// LimitError is an invalid limit.
type LimitError struct{ Msg string }

func (e *LimitError) Error() string { return e.Msg }

func limitErr(format string, args ...any) error { return &LimitError{fmt.Sprintf(format, args...)} }

// Kind returns the canonical (lower case) kind of a limit name, or "" for one
// that is not built in. name is the name's extension or its full name.
func Kind(name string) string {
	if i := strings.LastIndex(name, ":"); i >= 0 {
		name = name[i+1:]
	}
	switch k := strings.ToLower(name); k {
	case LimitAmountLessThan, LimitIPOnNetwork, LimitTimeWindow, LimitExpression:
		return k
	}
	return ""
}

var (
	exprRE   = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9_]{0,31})\s*(==|!=|<=|>=|<|>)\s*(-?[0-9]{1,18}|"[^"\\\x00-\x1f]{0,256}")\s*$`)
	windowRE = regexp.MustCompile(`^\s*([0-9]{1,2})\s*-\s*([0-9]{1,2})\s*$`)
)

// CompileLimit turns one limit (its name and its values as text) into a
// condition, or says what is wrong with it.
func CompileLimit(name string, values []string) (Cond, error) {
	kind := Kind(name)
	if kind == "" {
		return nil, limitErr("limit %q is not one of amountLessThan, ipOnNetwork, timeWindow, expression", name)
	}
	if len(values) == 0 {
		return nil, limitErr("limit %q needs at least one value", name)
	}
	switch kind {
	case LimitAmountLessThan:
		out := allOf{}
		for _, v := range values {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return nil, limitErr("amountLessThan takes integers, not %q", v)
			}
			out = append(out, cmp{Attr: "amount", Op: "<", Int: &n})
		}
		return out, nil
	case LimitIPOnNetwork:
		out := anyOf{}
		for _, v := range values {
			p, err := netip.ParsePrefix(strings.TrimSpace(v))
			if err != nil {
				return nil, limitErr("ipOnNetwork takes CIDR prefixes, not %q", v)
			}
			out = append(out, ipIn{p.Masked()})
		}
		return out, nil
	case LimitTimeWindow:
		out := anyOf{}
		for _, v := range values {
			m := windowRE.FindStringSubmatch(v)
			if m == nil {
				return nil, limitErr("timeWindow takes hours as \"9-17\", not %q", v)
			}
			from, _ := strconv.ParseInt(m[1], 10, 64)
			to, _ := strconv.ParseInt(m[2], 10, 64)
			if from > 23 || to > 24 || from >= to {
				return nil, limitErr("timeWindow %q: hours are 0-23 and the end (at most 24) is after the start", v)
			}
			out = append(out, hourIn{from, to})
		}
		return out, nil
	}
	out := allOf{}
	for _, v := range values {
		m := exprRE.FindStringSubmatch(v)
		if m == nil {
			return nil, limitErr("expression %q is not \"attribute op literal\"", v)
		}
		c := cmp{Attr: m[1], Op: m[2]}
		if strings.HasPrefix(m[3], `"`) {
			s := m[3][1 : len(m[3])-1]
			c.Str = &s
			if c.Op != "==" && c.Op != "!=" {
				return nil, limitErr("expression %q: strings compare with == or != only", v)
			}
		} else {
			n, err := strconv.ParseInt(m[3], 10, 64)
			if err != nil {
				return nil, limitErr("expression %q: bad integer", v)
			}
			c.Int = &n
		}
		out = append(out, c)
	}
	return out, nil
}

// CompileLimits compiles an assignment's limits into one condition (all of
// them must hold). No limits is nil.
func CompileLimits(ls []Limit) (Cond, error) {
	if len(ls) == 0 {
		return nil, nil
	}
	out := allOf{}
	for _, l := range ls {
		c, err := CompileLimit(l.Name, l.Values)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
