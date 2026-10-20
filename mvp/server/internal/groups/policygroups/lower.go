package policygroups

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
)

// AttrType is the type of an identity attribute the policy may use.
type AttrType string

// Attribute types: a single string, or a set of strings.
const (
	AttrString AttrType = "string"
	AttrSet    AttrType = "set"
)

// AttrDef declares one identity attribute. A Required attribute exists on every
// identity; any other must be guarded in a condition with `principal has attr`
// before it is read, exactly as the Cedar validator demands of an optional
// attribute, because reading a missing one is an error in Cedar.
type AttrDef struct {
	Type     AttrType
	Required bool
}

// Schema is the set of identity attributes policy may use (the design's
// groups/schema.cedarschema, §8.4). Names are case-sensitive in a policy and
// must differ case-insensitively, because the attribute groups are named by them.
type Schema struct {
	Attrs map[string]AttrDef
}

var attrNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// DefaultSchema is what the identity record offers today: its type and status
// exist on every identity; department, title and source are optional.
func DefaultSchema() Schema {
	return Schema{Attrs: map[string]AttrDef{
		"type":       {Type: AttrString, Required: true},
		"status":     {Type: AttrString, Required: true},
		"department": {Type: AttrString},
		"title":      {Type: AttrString},
		"source":     {Type: AttrString},
	}}
}

// Validate checks the schema's names and types.
func (s Schema) Validate() error {
	seen := map[string]string{}
	for name, d := range s.Attrs {
		if !attrNameRE.MatchString(name) {
			return fmt.Errorf("policygroups: attribute %q: a name is a letter or '_' then letters, digits and '_'", name)
		}
		if d.Type != AttrString && d.Type != AttrSet {
			return fmt.Errorf("policygroups: attribute %q has type %q (string or set)", name, d.Type)
		}
		if d.Type == AttrSet && d.Required {
			return fmt.Errorf("policygroups: attribute %q: a set is never required (an empty set is the absence)", name)
		}
		k := strings.ToLower(name)
		if other, dup := seen[k]; dup {
			return fmt.Errorf("policygroups: attributes %q and %q differ only in case", other, name)
		}
		seen[k] = name
	}
	return nil
}

// ParseFile parses and validates one policy file against the schema: the
// fragment of design §8.2, the schema's attributes and types, and the guards on
// optional attributes. It returns every finding it can; File is nil if there is
// any. Whether the groups it names exist is checked by Apply and Diff.
func ParseFile(path, src string, schema Schema) (*File, []Diagnostic) {
	raws, diag := parseRaw(path, src)
	if diag != nil {
		return nil, []Diagnostic{*diag}
	}
	l := &lowerer{path: path, schema: schema}
	f := &File{Path: path}
	if len(raws) == 0 {
		l.add(Pos{1, 1}, CodeInvalidPolicy, "a policy file holds at least one permit or forbid")
	}
	ids := map[string]bool{}
	for i, rp := range raws {
		l.policy(f, rp, i, ids)
	}
	if f.Group != "" {
		if _, err := naming.Parse(f.Group); err != nil || f.Group == "" {
			l.add(Pos{1, 1}, CodeInvalidPolicy, "the group name %q is not a valid group name", f.Group)
		}
	}
	if len(l.diags) > 0 {
		return nil, l.diags
	}
	return f, nil
}

type lowerer struct {
	path   string
	schema Schema
	diags  []Diagnostic
}

func (l *lowerer) add(at Pos, code, format string, args ...any) {
	l.diags = append(l.diags, Diagnostic{Path: l.path, Line: at.Line, Col: at.Col, Code: code, Msg: fmt.Sprintf(format, args...)})
}

// knownAnnotations are the annotations of a policy group file (design §8.3).
var knownAnnotations = map[string]bool{"id": true, "group": true, "display": true, "owner": true, "provision": true}

func (l *lowerer) policy(f *File, rp *rawPolicy, idx int, ids map[string]bool) {
	for name, at := range rp.annotPos {
		if !knownAnnotations[name] {
			l.add(at, CodeInvalidPolicy, "unknown annotation @%s (known: id, group, display, owner, provision)", name)
		}
	}
	id := fmt.Sprintf("policy%d", idx)
	if v, ok := rp.annots["id"]; ok {
		if len(v) == 1 && v[0] != "" {
			id = v[0]
		} else {
			l.add(rp.annotPos["id"], CodeInvalidPolicy, "@id takes one non-empty string")
		}
	}
	if ids[id] {
		l.add(rp.at, CodeInvalidPolicy, "the policy id %q is used twice in this file", id)
	}
	ids[id] = true
	// every policy of a file names the same group, and @group, if given, agrees
	if f.Group == "" {
		f.Group = rp.resource
	} else if !naming.Equal(f.Group, rp.resource) {
		l.add(rp.resAt, CodeInvalidPolicy, "a policy file defines one group: found %q and %q", f.Group, rp.resource)
	}
	if v, ok := rp.annots["group"]; ok {
		if len(v) != 1 || !naming.Equal(v[0], rp.resource) {
			l.add(rp.annotPos["group"], CodeInvalidPolicy, "@group must name the policy's resource, %q", rp.resource)
		}
	}
	l.single(rp, "display", &f.Display)
	l.single(rp, "owner", &f.Owner)
	if v, ok := rp.annots["provision"]; ok {
		for _, s := range v {
			if !slicesContains(f.Provision, s) {
				f.Provision = append(f.Provision, s)
			}
		}
	}
	if len(rp.whens)+len(rp.unlesses) == 0 {
		l.add(rp.at, CodeInvalidPolicy, "a %s needs a when or unless condition: without one it would apply to every identity, which a group cannot list", rp.effect)
		return
	}
	var conds []Expr
	pol := &Policy{ID: id, Effect: rp.effect, At: rp.at}
	for _, w := range rp.whens {
		if e := l.lower(w); e != nil {
			conds = append(conds, e)
		}
	}
	for _, u := range rp.unlesses {
		if e := l.lower(u); e != nil {
			conds = append(conds, Not{X: e, At: u.at()})
		}
	}
	if len(conds) != len(rp.whens)+len(rp.unlesses) {
		return // a finding was added
	}
	for _, c := range conds {
		if pol.Cond == nil {
			pol.Cond = c
		} else {
			pol.Cond = And{L: pol.Cond, R: c, At: c.pos()}
		}
	}
	l.guards(pol.Cond, map[string]bool{})
	f.Policies = append(f.Policies, pol)
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// single reads a one-valued annotation into dst (the first policy to give it
// wins; a different value in another policy is a finding).
func (l *lowerer) single(rp *rawPolicy, name string, dst *string) {
	v, ok := rp.annots[name]
	if !ok {
		return
	}
	if len(v) != 1 {
		l.add(rp.annotPos[name], CodeInvalidPolicy, "@%s takes one string", name)
		return
	}
	if *dst != "" && *dst != v[0] {
		l.add(rp.annotPos[name], CodeInvalidPolicy, "@%s is given different values in one file", name)
		return
	}
	*dst = v[0]
	if len(v[0]) > 1024 {
		l.add(rp.annotPos[name], CodeInvalidPolicy, "@%s is at most 1024 bytes", name)
	}
}

// unsupported is the finding for a construct outside the fragment.
func (l *lowerer) unsupported(at Pos, what string) Expr {
	l.add(at, CodeUnsupported, "%s", what)
	return nil
}

func isPrincipal(n node) bool {
	v, ok := n.(nVar)
	return ok && v.name == "principal"
}

// principalAttr recognises `principal.attr`.
func principalAttr(n node) (nAttr, bool) {
	a, ok := n.(nAttr)
	if !ok || !isPrincipal(a.x) {
		return nAttr{}, false
	}
	return a, true
}

// lower admits the fragment of design §8.2 from the general tree.
func (l *lowerer) lower(n node) Expr {
	switch x := n.(type) {
	case nBin:
		return l.lowerBin(x)
	case nUn:
		if x.op == "!" {
			if e := l.lower(x.x); e != nil {
				return Not{X: e, At: x.p}
			}
			return nil
		}
		return l.unsupported(x.p, "arithmetic is not supported in a policy group condition")
	case nHas:
		if !isPrincipal(x.x) {
			return l.unsupported(x.p, "'has' applies to principal only: resource attributes are not available")
		}
		if strings.Contains(x.name, ".") {
			return l.unsupported(x.p, "nested attributes are not supported")
		}
		if !l.attr(x.p, x.name, "") {
			return nil
		}
		return AttrHas{Attr: x.name, At: x.p}
	case nCall:
		return l.lowerCall(x)
	case nVar:
		return l.unsupported(x.p, l.varMsg(x.name))
	case nAttr:
		if v, ok := x.x.(nVar); ok && v.name != "principal" {
			return l.unsupported(x.p, l.varMsg(v.name))
		}
		return l.unsupported(x.p, "an attribute is compared (== or in) or tested (has, contains), not used as a condition")
	case nStr, nInt, nBool, nSet, nEntity:
		return l.unsupported(n.at(), "a condition combines groups and attribute tests with &&, || and !")
	case nFn:
		return l.unsupported(x.p, fmt.Sprintf("extension functions such as %s() are not supported", x.name))
	case nLike:
		return l.unsupported(x.p, "'like' is not supported: compare an attribute with == or in")
	case nIs:
		return l.unsupported(x.p, "'is' is not supported")
	case nIf:
		return l.unsupported(x.p, "if-then-else is not supported")
	case nRecord:
		return l.unsupported(x.p, "records are not supported")
	}
	return l.unsupported(n.at(), "unsupported construct")
}

func (l *lowerer) varMsg(name string) string { return varMessage(name) }

func varMessage(name string) string {
	switch name {
	case "context":
		return "context is not available in a policy group condition"
	case "resource":
		return "resource attributes are not available in a policy group condition"
	case "action":
		return "action is not available in a policy group condition"
	}
	return "'principal' alone is not a condition"
}

func (l *lowerer) lowerBin(x nBin) Expr {
	switch x.op {
	case "&&", "||":
		le, re := l.lower(x.l), l.lower(x.r)
		if le == nil || re == nil {
			return nil
		}
		if x.op == "&&" {
			return And{L: le, R: re, At: x.p}
		}
		return Or{L: le, R: re, At: x.p}
	case "==":
		a, ok := principalAttr(x.l)
		if !ok {
			return l.badCompare(x)
		}
		s, ok := x.r.(nStr)
		if !ok {
			return l.unsupported(x.p, "an attribute is compared with a string literal")
		}
		if !l.attr(a.p, a.name, "==") || !l.value(s.p, s.val) {
			return nil
		}
		return AttrEq{Attr: a.name, Value: s.val, At: x.p}
	case "in":
		if isPrincipal(x.l) {
			return l.principalIn(x)
		}
		a, ok := principalAttr(x.l)
		if !ok {
			return l.badCompare(x)
		}
		set, ok := x.r.(nSet)
		if !ok {
			return l.unsupported(x.p, "'in' compares an attribute with a list of string literals")
		}
		if !l.attr(a.p, a.name, "in") {
			return nil
		}
		var vals []string
		for _, e := range set.elems {
			s, ok := e.(nStr)
			if !ok {
				return l.unsupported(e.at(), "the list holds string literals only")
			}
			if !l.value(s.p, s.val) {
				return nil
			}
			vals = append(vals, s.val)
		}
		if len(vals) == 0 {
			return l.unsupported(x.p, "the list is empty")
		}
		return AttrIn{Attr: a.name, Values: vals, At: x.p}
	case "!=":
		return l.unsupported(x.p, "'!=' is not supported: write !(principal.attr == \"...\")")
	case "<", "<=", ">", ">=":
		return l.unsupported(x.p, "comparison operators are not supported: attributes are strings, compared with == or in")
	}
	return l.unsupported(x.p, "arithmetic is not supported in a policy group condition")
}

func (l *lowerer) badCompare(x nBin) Expr {
	for _, side := range []node{x.l, x.r} {
		if msg := explain(side); msg != "" {
			return l.unsupported(x.p, msg)
		}
	}
	return l.unsupported(x.p, "the left side of "+x.op+" is principal.attribute (or principal, for 'in' on a group)")
}

// explain names the first construct outside the fragment inside n ("" if none
// is recognised), so a finding says what is wrong rather than where the shape differs.
func explain(n node) string {
	switch x := n.(type) {
	case nVar:
		if x.name != "principal" {
			return varMessage(x.name)
		}
	case nAttr:
		return explain(x.x)
	case nHas:
		return explain(x.x)
	case nCall:
		if m := explain(x.x); m != "" {
			return m
		}
		for _, a := range x.args {
			if m := explain(a); m != "" {
				return m
			}
		}
	case nFn:
		return fmt.Sprintf("extension functions such as %s() are not supported", x.name)
	case nBin:
		if x.op == "+" || x.op == "-" || x.op == "*" {
			return "arithmetic is not supported in a policy group condition"
		}
		if m := explain(x.l); m != "" {
			return m
		}
		return explain(x.r)
	case nUn:
		if x.op == "-" {
			return "arithmetic is not supported in a policy group condition"
		}
		return explain(x.x)
	case nRecord:
		return "records are not supported"
	case nSet:
		for _, e := range x.elems {
			if m := explain(e); m != "" {
				return m
			}
		}
	}
	return ""
}

// principalIn lowers `principal in Tessera::Group::"x"` and the list form, which
// is a union of groups.
func (l *lowerer) principalIn(x nBin) Expr {
	group := func(n node) (string, Pos, bool) {
		e, ok := n.(nEntity)
		if !ok || e.ty != "Tessera::Group" {
			l.add(n.at(), CodeUnsupported, "'principal in' names a group: Tessera::Group::\"name\"")
			return "", Pos{}, false
		}
		if _, err := naming.Parse(e.id); err != nil || e.id == "" {
			l.add(e.p, CodeInvalidPolicy, "%q is not a valid group name", e.id)
			return "", Pos{}, false
		}
		return e.id, e.p, true
	}
	if set, ok := x.r.(nSet); ok {
		var out Expr
		for _, e := range set.elems {
			name, at, ok := group(e)
			if !ok {
				return nil
			}
			g := InGroup{Name: name, At: at}
			if out == nil {
				out = g
			} else {
				out = Or{L: out, R: g, At: at}
			}
		}
		if out == nil {
			return l.unsupported(x.p, "the list is empty")
		}
		return out
	}
	name, at, ok := group(x.r)
	if !ok {
		return nil
	}
	return InGroup{Name: name, At: at}
}

func (l *lowerer) lowerCall(x nCall) Expr {
	a, ok := principalAttr(x.x)
	if !ok {
		if msg := explain(x.x); msg != "" {
			return l.unsupported(x.p, msg)
		}
		return l.unsupported(x.p, fmt.Sprintf("method %s() is not supported", x.method))
	}
	if x.method != "contains" || len(x.args) != 1 {
		return l.unsupported(x.p, fmt.Sprintf("method %s() is not supported: only principal.attr.contains(\"...\")", x.method))
	}
	s, ok := x.args[0].(nStr)
	if !ok {
		return l.unsupported(x.p, "contains takes a string literal")
	}
	if !l.attr(a.p, a.name, "contains") || !l.value(s.p, s.val) {
		return nil
	}
	return AttrContains{Attr: a.name, Value: s.val, At: x.p}
}

// attr checks an attribute against the schema and the operator against its type.
func (l *lowerer) attr(at Pos, name, op string) bool {
	d, ok := l.schema.Attrs[name]
	if !ok {
		known := make([]string, 0, len(l.schema.Attrs))
		for k := range l.schema.Attrs {
			known = append(known, k)
		}
		sort.Strings(known)
		l.add(at, CodeUnknownAttr, "the schema declares no attribute %q (declared: %s)", name, strings.Join(known, ", "))
		return false
	}
	switch {
	case op == "contains" && d.Type != AttrSet:
		l.add(at, CodeTypeMismatch, "attribute %q is a string: compare it with == or in; contains is for set attributes", name)
		return false
	case (op == "==" || op == "in") && d.Type != AttrString:
		l.add(at, CodeTypeMismatch, "attribute %q is a set: test it with contains", name)
		return false
	}
	return true
}

// MaxValueBytes bounds an attribute value literal.
const MaxValueBytes = 120

func (l *lowerer) value(at Pos, v string) bool {
	switch {
	case v == "":
		l.add(at, CodeInvalidValue, "an attribute value is not empty: an empty attribute is no attribute (use 'has')")
	case len(v) > MaxValueBytes:
		l.add(at, CodeInvalidValue, "an attribute value is at most %d bytes", MaxValueBytes)
	default:
		return true
	}
	return false
}

// guards enforces Cedar's rule for optional attributes: reading one is an error
// when it is missing, so it must be dominated by `principal has attr` in a
// conjunction to its left (Cedar's validator would reject the policy otherwise).
// With every read guarded, the engine's reading "a missing attribute is not equal
// to anything" and Cedar's coincide.
func (l *lowerer) guards(x Expr, guarded map[string]bool) {
	read := func(attr string, at Pos) {
		if d := l.schema.Attrs[attr]; !d.Required && !guarded[attr] {
			l.add(at, CodeUnguardedAttr, "attribute %q is optional: guard it with `principal has %s && ...` (reading a missing attribute is an error in Cedar)", attr, attr)
		}
	}
	switch n := x.(type) {
	case And:
		l.guards(n.L, guarded)
		inner := make(map[string]bool, len(guarded)+1)
		for k := range guarded {
			inner[k] = true
		}
		for _, a := range positiveHas(n.L) {
			inner[a] = true
		}
		l.guards(n.R, inner)
	case Or:
		l.guards(n.L, guarded)
		l.guards(n.R, guarded)
	case Not:
		l.guards(n.X, guarded)
	case AttrEq:
		read(n.Attr, n.At)
	case AttrIn:
		read(n.Attr, n.At)
	case AttrContains:
		read(n.Attr, n.At)
	}
}

// positiveHas lists the attributes a conjunction asserts present when it holds.
func positiveHas(x Expr) []string {
	switch n := x.(type) {
	case AttrHas:
		return []string{n.Attr}
	case And:
		return append(positiveHas(n.L), positiveHas(n.R)...)
	}
	return nil
}

// ---------------------------------------------------------------- attribute group names

// EncodeValue is the injective, case-safe form of an attribute value as a group
// name segment: lower-case letters, digits and '-' stay, every other byte
// becomes '_' and two hex digits. Names are unique case-insensitively, so
// "Main" and "main" must not collide.
func EncodeValue(v string) string {
	var sb strings.Builder
	for i := 0; i < len(v); i++ {
		b := v[i]
		if b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' {
			sb.WriteByte(b)
			continue
		}
		fmt.Fprintf(&sb, "_%02x", b)
	}
	return sb.String()
}

// Names of the system folders and groups of compiled policy.
const (
	// FolderPolicy holds the internal composite groups and the empty groups.
	FolderPolicy = "sys:policy"
	// FolderAttr holds one folder per attribute with a group per value.
	FolderAttr = "sys:attr"
	// HasGroup is the name of an attribute's "has the attribute" group.
	HasGroup = "_has"
)

// AttrGroupName is the full name of the group of identities whose attribute has
// the value (design §8.3: sys:attr:<name>:<value>). Attribute names are
// lower-cased because group names are case-insensitive.
func AttrGroupName(attr, value string) string {
	return FolderAttr + naming.Sep + strings.ToLower(attr) + naming.Sep + EncodeValue(value)
}

// HasGroupName is the full name of the group of identities that have the attribute.
func HasGroupName(attr string) string {
	return FolderAttr + naming.Sep + strings.ToLower(attr) + naming.Sep + HasGroup
}
