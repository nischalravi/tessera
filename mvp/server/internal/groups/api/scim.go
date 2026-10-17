package api

import (
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Read-only SCIM 2.0 server over the native groups (RFC 7643, RFC 7644; design
// §10.11 "G-98"). Users are the tenant's identities, Groups the native groups
// the caller may view, with their effective members. There are no writes: this
// is the read side that provisioning consumers (an application that pulls its
// groups) need. Filtering, paging and attribute selection follow RFC 7644 §3.4;
// sorting, PATCH, bulk and ETags are not supported (ServiceProviderConfig says so).

// SCIM schema URNs.
const (
	SchemaUser         = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError        = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaSPC          = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	// SchemaGroupExt carries what SCIM's Group has no field for.
	SchemaGroupExt = "urn:tessera:params:scim:schemas:extension:group:2.0:Group"
)

// SCIM limits.
const (
	// MaxCount is the most resources one page returns.
	MaxCount = 200
	// DefaultCount is the page size when count is not given.
	DefaultCount = 100
	// MaxMembers is the most members a Group resource lists; the extension says
	// when there were more.
	MaxMembers = 1000
	// MaxFilterLen bounds a filter expression.
	MaxFilterLen = 1000
)

// Meta is a resource's meta attribute.
type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	Location     string `json:"location"`
}

// Ref is a reference to a user or group: a member of a Group, a group of a User.
type Ref struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref"`
	Display string `json:"display"`
	Type    string `json:"type"`
}

// Email is a user's email.
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
}

// User is the SCIM User of an identity.
type User struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	ExternalID  string   `json:"externalId"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName"`
	Title       string   `json:"title,omitempty"`
	UserType    string   `json:"userType"`
	Active      bool     `json:"active"`
	Emails      []Email  `json:"emails,omitempty"`
	Groups      []Ref    `json:"groups,omitempty"`
	Meta        Meta     `json:"meta"`
}

// GroupExt is the Tessera extension of a Group.
type GroupExt struct {
	Type             string `json:"type"`
	Definition       string `json:"definition"`
	Status           string `json:"status"`
	MemberCount      int64  `json:"memberCount"`
	MembersTruncated bool   `json:"membersTruncated"`
}

// Group is the SCIM Group of a native group: its effective identities.
type Group struct {
	Schemas     []string  `json:"schemas"`
	ID          string    `json:"id"`
	DisplayName string    `json:"displayName"`
	Members     []Ref     `json:"members"`
	Meta        Meta      `json:"meta"`
	Ext         *GroupExt `json:"urn:tessera:params:scim:schemas:extension:group:2.0:Group,omitempty"`
}

// List is a ListResponse.
type List struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

// Error is a SCIM error response (RFC 7644 §3.12).
type Error struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail"`
}

// NewError builds an error response.
func NewError(status int, scimType, detail string) Error {
	return Error{Schemas: []string{SchemaError}, Status: strconv.Itoa(status), ScimType: scimType, Detail: detail}
}

// NewList builds a ListResponse (Resources is never null).
func NewList(total, start int, res []any) List {
	if res == nil {
		res = []any{}
	}
	return List{Schemas: []string{SchemaListResponse}, TotalResults: total, StartIndex: start, ItemsPerPage: len(res), Resources: res}
}

// UserName is the SCIM userName of an identity: its email, else its external id.
func UserName(i *store.Identity) string {
	if i.Email != nil && *i.Email != "" {
		return *i.Email
	}
	return i.ExternalID
}

// NewUser maps an identity to its SCIM User. base is the prefix of locations ("" for relative ones).
func NewUser(i *store.Identity, base string) User {
	id := strconv.FormatInt(i.ID, 10)
	u := User{Schemas: []string{SchemaUser}, ID: id, ExternalID: i.ExternalID, UserName: UserName(i), DisplayName: i.Name,
		UserType: i.Type, Active: i.Status == "active",
		Meta: Meta{ResourceType: "User", Created: store.RT(i.CreatedAt), Location: base + "/scim/v2/Users/" + id}}
	if i.Title != nil {
		u.Title = *i.Title
	}
	if i.Email != nil && *i.Email != "" {
		u.Emails = []Email{{Value: *i.Email, Type: "work", Primary: true}}
	}
	return u
}

// GroupRef is the reference to a group from a User.
func GroupRef(g *store.NativeGroup, base string) Ref {
	return Ref{Value: string(g.ID), Ref: base + "/scim/v2/Groups/" + string(g.ID), Display: g.Name, Type: "Group"}
}

// MemberRef is the reference to a user from a Group.
func MemberRef(id int64, name, base string) Ref {
	s := strconv.FormatInt(id, 10)
	return Ref{Value: s, Ref: base + "/scim/v2/Users/" + s, Display: name, Type: "User"}
}

// NewGroup maps a native group and its members to a SCIM Group. total is the
// number of effective members; members may be fewer (the first MaxMembers).
func NewGroup(g *store.NativeGroup, members []Ref, total int, base string) Group {
	if members == nil {
		members = []Ref{}
	}
	return Group{Schemas: []string{SchemaGroup, SchemaGroupExt}, ID: string(g.ID), DisplayName: g.Name, Members: members,
		Meta: Meta{ResourceType: "Group", Created: store.RT(g.CreatedAt), Location: base + "/scim/v2/Groups/" + string(g.ID)},
		Ext: &GroupExt{Type: string(g.Kind), Definition: string(g.Definition), Status: g.Status, MemberCount: int64(total),
			MembersTruncated: total > len(members)}}
}

// Select applies attributes and excludedAttributes (comma-separated attribute
// names) to a resource: with attributes only those, plus the always-returned
// schemas, id and meta, are kept; with excludedAttributes those are dropped
// (never id, schemas or meta). Names are compared without case.
func Select(resource any, attributes, excluded string) (any, error) {
	if attributes == "" && excluded == "" {
		return resource, nil
	}
	raw, err := json.Marshal(resource)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	always := map[string]bool{"schemas": true, "id": true, "meta": true}
	want := nameSet(attributes)
	drop := nameSet(excluded)
	for k := range m {
		lk := strings.ToLower(k)
		switch {
		case always[lk]:
		case len(want) > 0: // attributes wins over excludedAttributes (RFC 7644 §3.4.2.5)
			if !want[lk] {
				delete(m, k)
			}
		case drop[lk]:
			delete(m, k)
		}
	}
	return m, nil
}

func nameSet(csv string) map[string]bool {
	out := map[string]bool{}
	for _, n := range strings.Split(csv, ",") {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			out[n] = true
		}
	}
	return out
}

// ServiceProviderConfig describes what the server supports.
func ServiceProviderConfig(base string) map[string]any {
	return map[string]any{
		"schemas":          []string{SchemaSPC},
		"documentationUri": base + "/api/openapi/groups.json",
		"patch":            map[string]any{"supported": false},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": MaxCount},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		// no standard scheme names the API's own sign-in (a session cookie today, tokens later);
		// documentationUri says what a client needs
		"authenticationSchemes": []map[string]any{},
		"meta":                  map[string]any{"resourceType": "ServiceProviderConfig", "location": base + "/scim/v2/ServiceProviderConfig"},
	}
}

// ResourceTypes lists the two resource types.
func ResourceTypes(base string) []any {
	rt := func(id, name, endpoint, schema string) map[string]any {
		return map[string]any{"schemas": []string{SchemaResourceType}, "id": id, "name": name, "endpoint": endpoint, "schema": schema,
			"meta": map[string]any{"resourceType": "ResourceType", "location": base + "/scim/v2/ResourceTypes/" + id}}
	}
	g := rt("Group", "Group", "/Groups", SchemaGroup)
	g["schemaExtensions"] = []map[string]any{{"schema": SchemaGroupExt, "required": false}}
	return []any{rt("User", "User", "/Users", SchemaUser), g}
}

// ---------------------------------------------------------------- filter

// ErrFilter is a filter expression the server refuses (SCIM scimType invalidFilter).
type ErrFilter struct{ Detail string }

func (e *ErrFilter) Error() string { return "invalid filter: " + e.Detail }

// Filter is a parsed SCIM filter (RFC 7644 §3.4.2.2): attribute comparisons
// (eq ne co sw ew gt ge lt le pr) joined by and, or, not and parentheses.
// Comparisons of strings ignore case, as SCIM's default for strings does.
type Filter struct{ root fnode }

type fnode interface {
	eval(get func(attr string) []string) bool
}

type fcmp struct {
	attr, op, val string
}

type fand struct{ l, r fnode }
type forr struct{ l, r fnode }
type fnot struct{ x fnode }

func (c fcmp) eval(get func(string) []string) bool {
	vals := get(c.attr)
	if c.op == "pr" {
		return slices.ContainsFunc(vals, func(v string) bool { return v != "" })
	}
	want := strings.ToLower(c.val)
	match := func(v string) bool {
		v = strings.ToLower(v)
		switch c.op {
		case "eq":
			return v == want
		case "co":
			return strings.Contains(v, want)
		case "sw":
			return strings.HasPrefix(v, want)
		case "ew":
			return strings.HasSuffix(v, want)
		case "gt":
			return v > want
		case "ge":
			return v >= want
		case "lt":
			return v < want
		case "le":
			return v <= want
		}
		return false
	}
	if c.op == "ne" { // no value equals it (an attribute without values is not equal to anything)
		return !slices.ContainsFunc(vals, func(v string) bool { return strings.EqualFold(v, c.val) })
	}
	return slices.ContainsFunc(vals, match)
}
func (a fand) eval(get func(string) []string) bool { return a.l.eval(get) && a.r.eval(get) }
func (o forr) eval(get func(string) []string) bool { return o.l.eval(get) || o.r.eval(get) }
func (n fnot) eval(get func(string) []string) bool { return !n.x.eval(get) }

// Eval reports whether a resource matches. get returns the values of an
// attribute (lower-cased path such as "username" or "emails.value"), none when
// the resource has none.
func (f *Filter) Eval(get func(attr string) []string) bool { return f == nil || f.root.eval(get) }

// Single returns the comparison when the whole filter is one (a pushdown hint
// for a store search); ok is false for anything else.
func (f *Filter) Single() (attr, op, val string, ok bool) {
	if f == nil {
		return "", "", "", false
	}
	c, ok := f.root.(fcmp)
	return c.attr, c.op, c.val, ok
}

type ftok struct {
	kind byte // w word, s string, ( , )
	s    string
}

func lexFilter(s string) ([]ftok, error) {
	var out []ftok
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(' || c == ')':
			out = append(out, ftok{kind: c})
			i++
		case c == '"':
			j := i + 1
			for ; j < len(s); j++ {
				if s[j] == '\\' {
					j++
					continue
				}
				if s[j] == '"' {
					break
				}
			}
			if j >= len(s) {
				return nil, &ErrFilter{"unterminated string"}
			}
			var v string
			if err := json.Unmarshal([]byte(s[i:j+1]), &v); err != nil {
				return nil, &ErrFilter{"bad string literal"}
			}
			out = append(out, ftok{kind: 's', s: v})
			i = j + 1
		default:
			j := i
			for j < len(s) && s[j] != ' ' && s[j] != '\t' && s[j] != '(' && s[j] != ')' && s[j] != '"' {
				j++
			}
			out = append(out, ftok{kind: 'w', s: s[i:j]})
			i = j
		}
	}
	return out, nil
}

type fparser struct {
	toks    []ftok
	pos     int
	allowed map[string]bool
	depth   int
}

func (p *fparser) peek() *ftok {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *fparser) isWord(w string) bool {
	t := p.peek()
	return t != nil && t.kind == 'w' && strings.EqualFold(t.s, w)
}

// ParseFilter parses a SCIM filter. allowed is the set of attribute paths
// (lower-case) the resource type can be filtered on; anything else is refused.
// An empty filter is nil (it matches everything).
func ParseFilter(s string, allowed []string) (*Filter, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if len(s) > MaxFilterLen || !utf8.ValidString(s) {
		return nil, &ErrFilter{"the filter is too long or not text"}
	}
	toks, err := lexFilter(s)
	if err != nil {
		return nil, err
	}
	p := &fparser{toks: toks, allowed: map[string]bool{}}
	for _, a := range allowed {
		p.allowed[a] = true
	}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.peek() != nil {
		return nil, &ErrFilter{"unexpected " + p.describe()}
	}
	return &Filter{root: n}, nil
}

func (p *fparser) describe() string {
	t := p.peek()
	switch {
	case t == nil:
		return "end of the filter"
	case t.kind == 'w' || t.kind == 's':
		return strconv.Quote(t.s)
	}
	return strconv.Quote(string(rune(t.kind)))
}

func (p *fparser) or() (fnode, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.isWord("or") {
		p.pos++
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		l = forr{l, r}
	}
	return l, nil
}

func (p *fparser) and() (fnode, error) {
	l, err := p.factor()
	if err != nil {
		return nil, err
	}
	for p.isWord("and") {
		p.pos++
		r, err := p.factor()
		if err != nil {
			return nil, err
		}
		l = fand{l, r}
	}
	return l, nil
}

func (p *fparser) factor() (fnode, error) {
	if p.depth++; p.depth > 16 {
		return nil, &ErrFilter{"the filter is nested too deeply"}
	}
	defer func() { p.depth-- }()
	t := p.peek()
	if t == nil {
		return nil, &ErrFilter{"the filter ends where an attribute was expected"}
	}
	if p.isWord("not") {
		p.pos++
		if t := p.peek(); t == nil || t.kind != '(' {
			return nil, &ErrFilter{"not needs a parenthesized filter"}
		}
		x, err := p.group()
		if err != nil {
			return nil, err
		}
		return fnot{x}, nil
	}
	if t.kind == '(' {
		return p.group()
	}
	if t.kind != 'w' {
		return nil, &ErrFilter{"an attribute name was expected"}
	}
	attr := strings.ToLower(t.s)
	if !p.allowed[attr] {
		return nil, &ErrFilter{"unsupported attribute " + strconv.Quote(t.s)}
	}
	p.pos++
	opTok := p.peek()
	if opTok == nil || opTok.kind != 'w' {
		return nil, &ErrFilter{"an operator was expected after " + strconv.Quote(t.s)}
	}
	op := strings.ToLower(opTok.s)
	p.pos++
	if op == "pr" {
		return fcmp{attr: attr, op: op}, nil
	}
	if !slices.Contains([]string{"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"}, op) {
		return nil, &ErrFilter{"unsupported operator " + strconv.Quote(opTok.s)}
	}
	v := p.peek()
	if v == nil || (v.kind != 's' && v.kind != 'w') {
		return nil, &ErrFilter{"a value was expected after " + op}
	}
	p.pos++
	val := v.s
	if v.kind == 'w' && !slices.Contains([]string{"true", "false"}, strings.ToLower(val)) {
		if _, err := strconv.ParseFloat(val, 64); err != nil {
			return nil, &ErrFilter{"a value is a quoted string, a number, true or false"}
		}
	}
	return fcmp{attr: attr, op: op, val: strings.ToLower(val)}, nil
}

func (p *fparser) group() (fnode, error) {
	p.pos++ // (
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t == nil || t.kind != ')' {
		return nil, &ErrFilter{"a closing parenthesis was expected"}
	}
	p.pos++
	return n, nil
}

// IsFilterError reports whether err is an ErrFilter.
func IsFilterError(err error) (*ErrFilter, bool) {
	var fe *ErrFilter
	return fe, errors.As(err, &fe)
}
