// Package plan is Tessera's declarative groups plan (issue #49, GR-6; design
// docs/design/groups-grouper-parity.md §10.12): a YAML file that says which
// folders, groups, direct members and privileges should exist, a diff of it
// against the live state, a simulation of the membership impact, and an apply
// that sends the difference as audited requests with idempotency keys.
//
// A plan is data, never code (K6): there are no expressions, hooks or scripts,
// and templates are compiled-in, versioned expansions with typed inputs. The
// package has no storage and no HTTP client of its own: it talks to the API
// through the Client interface (the CLI supplies one that signs in with the
// OAuth device flow and DPoP of #14), so the server's route permission and
// object privileges decide every step.
//
// A plan is additive and idempotent. It creates what is missing, adds the
// members it lists, removes the members it lists under remove, and grants the
// privileges it lists. It never deletes folders or groups and never revokes a
// privilege, so applying a plan twice changes nothing the second time.
package plan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
)

// Limits of a plan file.
const (
	MaxFile       = 4 << 20
	MaxItems      = 20_000 // folders, groups, privileges and members together
	MaxTemplates  = 1_000  // template uses in one plan
	MaxParamBytes = 1024
)

// Spec is a plan file.
type Spec struct {
	Folders    []FolderSpec `yaml:"folders,omitempty"`
	Groups     []GroupSpec  `yaml:"groups,omitempty"`
	Privileges []PrivSpec   `yaml:"privileges,omitempty"`
}

// FolderSpec is a folder that should exist. With Template the folder is
// expanded into the template's folders, groups and privileges.
type FolderSpec struct {
	Name        string            `yaml:"name"`
	DisplayName string            `yaml:"display_name,omitempty"`
	Description string            `yaml:"description,omitempty"`
	DataOwner   string            `yaml:"data_owner,omitempty"`
	Template    string            `yaml:"template,omitempty"`
	Params      map[string]string `yaml:"params,omitempty"`
}

// GroupSpec is a group that should exist, with the direct members it should
// have (Add) and not have (Remove). Members are written identity:<id> (or the
// bare id) and group:<name>.
type GroupSpec struct {
	Name              string         `yaml:"name"`
	DisplayName       string         `yaml:"display_name,omitempty"`
	Description       string         `yaml:"description,omitempty"`
	Type              string         `yaml:"type,omitempty"` // group (default) or role
	DataOwner         string         `yaml:"data_owner,omitempty"`
	MemberDescription string         `yaml:"member_description,omitempty"`
	Composite         *CompositeSpec `yaml:"composite,omitempty"`
	Members           MembersSpec    `yaml:"members,omitempty"`
}

// CompositeSpec defines a composite group by an operator and its factors
// (group names). It applies when the group is created.
type CompositeSpec struct {
	Op      string   `yaml:"op"` // union, intersection or complement
	Factors []string `yaml:"factors"`
}

// MembersSpec lists the direct members to add and to remove.
type MembersSpec struct {
	Add    []string `yaml:"add,omitempty"`
	Remove []string `yaml:"remove,omitempty"`
}

// PrivSpec grants privileges on one folder or group.
type PrivSpec struct {
	Object string    `yaml:"object"` // folder:<name> or group:<name>
	Grant  GrantSpec `yaml:"grant"`
}

// GrantSpec maps a privilege to its holders (identity:<id>, group:<name>,
// everyone). Scope is self (the default: the privilege on the object only),
// one or sub (a folder's privilege inherited by the objects directly in it, or
// by everything below it).
type GrantSpec struct {
	Scope      string
	Privileges map[string][]string
}

// UnmarshalYAML reads {stem_admin: [...], scope: sub}: scope is the one scalar
// key, every other key is a privilege with a list of holders.
func (g *GrantSpec) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: grant is a mapping of privilege to holders, with an optional scope", n.Line)
	}
	g.Privileges = map[string][]string{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Value == "scope" {
			if v.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: scope is one word", v.Line)
			}
			g.Scope = v.Value
			continue
		}
		if _, dup := g.Privileges[k.Value]; dup {
			return fmt.Errorf("line %d: %s is listed twice", k.Line, k.Value)
		}
		var holders []string
		if err := v.Decode(&holders); err != nil {
			return fmt.Errorf("line %d: %s takes a list of holders", k.Line, k.Value)
		}
		g.Privileges[k.Value] = holders
	}
	return nil
}

// MarshalYAML writes the privileges in name order, then the scope.
func (g GrantSpec) MarshalYAML() (any, error) {
	n := &yaml.Node{Kind: yaml.MappingNode}
	names := make([]string, 0, len(g.Privileges))
	for p := range g.Privileges {
		names = append(names, p)
	}
	slices.Sort(names)
	for _, p := range names {
		seq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
		for _, h := range g.Privileges[p] {
			seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: h})
		}
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: p}, seq)
	}
	if g.Scope != "" {
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "scope"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: g.Scope})
	}
	return n, nil
}

// Parse reads a plan file strictly: unknown keys are errors, so a misspelt key
// is never silently ignored, and only one document is allowed.
func Parse(r io.Reader) (*Spec, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFile {
		return nil, fmt.Errorf("the plan is over %d MiB", MaxFile>>20)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var s Spec
	if err := dec.Decode(&s); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the plan is empty")
		}
		return nil, fmt.Errorf("the plan is not valid: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("the plan has more than one YAML document")
	}
	return &s, nil
}

// Marshal writes a plan as YAML.
func Marshal(s *Spec) ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return b.Bytes(), enc.Close()
}

// MemberRef is a member as a plan names it: an identity id or a group name.
type MemberRef struct {
	Identity int64
	Group    string
}

// Key is the comparison key of the reference ("identity:5", "group:<folded name>").
func (m MemberRef) Key() string {
	if m.Group != "" {
		return "group:" + naming.Fold(m.Group)
	}
	return "identity:" + strconv.FormatInt(m.Identity, 10)
}

// String is how the reference is written in a plan and in the diff.
func (m MemberRef) String() string {
	if m.Group != "" {
		return "group:" + m.Group
	}
	return "identity:" + strconv.FormatInt(m.Identity, 10)
}

// ParseMember reads identity:<id>, a bare id, or group:<name>.
func ParseMember(s string) (MemberRef, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "group:"):
		name := strings.TrimPrefix(s, "group:")
		if _, err := naming.Parse(name); err != nil || name == "" {
			return MemberRef{}, fmt.Errorf("%q is not a group name", s)
		}
		return MemberRef{Group: name}, nil
	case strings.HasPrefix(s, "identity:"):
		s = strings.TrimPrefix(s, "identity:")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 {
		return MemberRef{}, fmt.Errorf("member %q is identity:<id> or group:<name>", s)
	}
	return MemberRef{Identity: n}, nil
}

// Holder is who a privilege is granted to.
type Holder struct {
	Type     string // identity, group or everyone
	Identity int64
	Group    string
}

// Key is the comparison key of the holder.
func (h Holder) Key() string {
	switch h.Type {
	case "identity":
		return "identity:" + strconv.FormatInt(h.Identity, 10)
	case "group":
		return "group:" + naming.Fold(h.Group)
	}
	return "everyone"
}

func (h Holder) String() string {
	switch h.Type {
	case "identity":
		return "identity:" + strconv.FormatInt(h.Identity, 10)
	case "group":
		return "group:" + h.Group
	}
	return "everyone"
}

// ParseHolder reads identity:<id>, group:<name> or everyone.
func ParseHolder(s string) (Holder, error) {
	s = strings.TrimSpace(s)
	if s == "everyone" {
		return Holder{Type: "everyone"}, nil
	}
	if !strings.HasPrefix(s, "group:") && !strings.HasPrefix(s, "identity:") {
		return Holder{}, fmt.Errorf("holder %q is identity:<id>, group:<name> or everyone", s)
	}
	m, err := ParseMember(s)
	if err != nil {
		return Holder{}, fmt.Errorf("holder %q is identity:<id>, group:<name> or everyone", s)
	}
	if m.Group != "" {
		return Holder{Type: "group", Group: m.Group}, nil
	}
	return Holder{Type: "identity", Identity: m.Identity}, nil
}

// ObjectRef is the folder or group a privilege is on.
type ObjectRef struct {
	Type string // folder or group
	Name string
}

func (o ObjectRef) String() string { return o.Type + ":" + o.Name }

// ParseObject reads folder:<name> or group:<name>.
func ParseObject(s string) (ObjectRef, error) {
	typ, name, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || (typ != "folder" && typ != "group") {
		return ObjectRef{}, fmt.Errorf("object %q is folder:<name> or group:<name>", s)
	}
	if _, err := naming.Parse(name); err != nil || name == "" {
		return ObjectRef{}, fmt.Errorf("object %q has an invalid name", s)
	}
	return ObjectRef{Type: typ, Name: name}, nil
}

// Composite operators of the API.
var compositeOps = []string{"union", "intersection", "complement"}

// Validate checks a (template-expanded) spec without any server: names,
// members, holders, privileges and composites. Every error names the item.
func (s *Spec) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	items := len(s.Folders) + len(s.Groups) + len(s.Privileges)
	seen := map[string]string{}
	claim := func(kind, name string) {
		if prev, dup := seen[naming.Fold(name)]; dup {
			add("%s %q is already listed as a %s", kind, name, prev)
			return
		}
		seen[naming.Fold(name)] = kind
	}
	for _, f := range s.Folders {
		if _, err := naming.Parse(f.Name); err != nil || f.Name == "" {
			add("folder %q: not a valid name", f.Name)
			continue
		}
		claim("folder", f.Name)
		if err := naming.ValidateDisplay(f.DisplayName); err != nil {
			add("folder %q: %v", f.Name, err)
		}
	}
	for _, g := range s.Groups {
		if _, err := naming.Parse(g.Name); err != nil || g.Name == "" {
			add("group %q: not a valid name", g.Name)
			continue
		}
		if parent, _ := naming.Split(g.Name); parent == "" {
			add("group %q: a group lives in a folder (name it folder:group)", g.Name)
		}
		claim("group", g.Name)
		if err := naming.ValidateDisplay(g.DisplayName); err != nil {
			add("group %q: %v", g.Name, err)
		}
		if g.Type != "" && g.Type != "group" && g.Type != "role" {
			add("group %q: type is group or role", g.Name)
		}
		items += len(g.Members.Add) + len(g.Members.Remove)
		for _, m := range append(slices.Clone(g.Members.Add), g.Members.Remove...) {
			if _, err := ParseMember(m); err != nil {
				add("group %q: %v", g.Name, err)
			}
		}
		if c := g.Composite; c != nil {
			if !slices.Contains(compositeOps, c.Op) {
				add("group %q: composite op is union, intersection or complement", g.Name)
			}
			if len(c.Factors) < 2 || (c.Op == "complement" && len(c.Factors) != 2) {
				add("group %q: a composite has at least two factors (complement exactly two)", g.Name)
			}
			for _, f := range c.Factors {
				if _, err := naming.Parse(f); err != nil || f == "" {
					add("group %q: factor %q is not a group name", g.Name, f)
				}
			}
			if len(g.Members.Add) > 0 {
				add("group %q: a composite has no direct members", g.Name)
			}
		}
	}
	for _, p := range s.Privileges {
		o, err := ParseObject(p.Object)
		if err != nil {
			add("privilege on %q: %v", p.Object, err)
			continue
		}
		if len(p.Grant.Privileges) == 0 {
			add("privilege on %s: nothing is granted", o)
		}
		switch p.Grant.Scope {
		case "", "self", "one", "sub":
		default:
			add("privilege on %s: scope is self, one or sub", o)
		}
		if o.Type == "group" && p.Grant.Scope != "" && p.Grant.Scope != "self" {
			add("privilege on %s: only a folder's privileges are inherited", o)
		}
		for name, holders := range p.Grant.Privileges {
			switch typ := privObject(name); {
			case typ == "":
				add("privilege on %s: %q is not a privilege", o, name)
			case (p.Grant.Scope == "" || p.Grant.Scope == "self") && typ != o.Type:
				add("privilege on %s: %s is a %s privilege (grant it with scope one or sub on a folder)", o, name, typ)
			}
			if len(holders) == 0 {
				add("privilege on %s: %s has no holders", o, name)
			}
			items += len(holders)
			for _, h := range holders {
				if _, err := ParseHolder(h); err != nil {
					add("privilege on %s: %v", o, err)
				}
			}
		}
	}
	if items > MaxItems {
		add("the plan has %d items; at most %d", items, MaxItems)
	}
	if len(errs) > 20 {
		errs = append(errs[:20], fmt.Errorf("and %d more", len(errs)-20))
	}
	return errors.Join(errs...)
}
