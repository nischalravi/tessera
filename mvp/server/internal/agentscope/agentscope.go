// Package agentscope is the document model of AC-7 (issue #653, design docs/design/access-as-code-repo.md
// section 3.5): what an AI agent may do, declared as a file of the policy repository (agents/<key>.yaml, the
// tessera.agentscope/v1 document) and compiled into a graph invariant by internal/policy.
//
// A scope is a ceiling, not a grant. Once an agent has a scope, every effective permission it holds must be inside
// it (default deny): its action class (read, write, admin or delegate, see ClassOf) must be listed and its resource
// must match one of the listed resource classes (system, environment, tag and sensitivity). The scope also binds an
// agent to its owner: it may not hold what its owner does not (owner_ceiling, on unless the file turns it off). An
// agent without a scope is not touched; nhi-ownership and the agent views report it.
//
// The package is pure (no database, clock or network): internal/policybundle loads the files with it, the as-code
// package stores them, and internal/policy evaluates them.
package agentscope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Tag is the schema tag of the document.
const Tag = "tessera.agentscope/v1"

// The action classes of a permission (ClassOf). They are a closed set and have no hierarchy: a scope that allows
// write does not allow read.
const (
	ClassRead     = "read"
	ClassWrite    = "write"
	ClassAdmin    = "admin"
	ClassDelegate = "delegate"
)

// Classes lists the action classes in their canonical order.
var Classes = []string{ClassRead, ClassWrite, ClassAdmin, ClassDelegate}

// Limits of one document.
const (
	MaxResources = 50 // resource classes
	MaxValues    = 100
	MaxValueLen  = 128
)

var severities = []string{"critical", "high", "medium", "low"}

var (
	keyRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	valueRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:/@-]*$`)
)

// Doc is agents/<key>.yaml.
type Doc struct {
	Schema      string `yaml:"schema" json:"schema"`
	Key         string `yaml:"key" json:"key"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Severity of the findings (critical, high, medium, low); high when empty.
	Severity string   `yaml:"severity,omitempty" json:"severity,omitempty"`
	Agent    Selector `yaml:"agent" json:"agent"`
	Allow    Allow    `yaml:"allow" json:"allow"`
	// OwnerCeiling holds the agent to its owner: a permission the owner does not hold is a finding. Absent: true;
	// only false is written.
	OwnerCeiling *bool `yaml:"owner_ceiling,omitempty" json:"owner_ceiling,omitempty"`
}

// Selector names the agents a scope applies to: exactly one agent (Source and ExternalID, a row of the agent
// profiles) or every agent created from a blueprint (Blueprint, its app id).
type Selector struct {
	Source     string `yaml:"source,omitempty" json:"source,omitempty"`
	ExternalID string `yaml:"external_id,omitempty" json:"external_id,omitempty"`
	Blueprint  string `yaml:"blueprint,omitempty" json:"blueprint,omitempty"`
}

// Allow is what the agent may hold: an action class and a resource class, both.
type Allow struct {
	Actions   []string        `yaml:"actions" json:"actions"`
	Resources []ResourceClass `yaml:"resources" json:"resources"`
}

// ResourceClass matches resources: every field that is set must match (and), and a field lists alternatives (or).
// At least one field is set; a class never means "everything".
type ResourceClass struct {
	Systems      []string `yaml:"systems,omitempty" json:"systems,omitempty"`
	Environments []string `yaml:"environments,omitempty" json:"environments,omitempty"`
	TagsAny      []string `yaml:"tags_any,omitempty" json:"tags_any,omitempty"`
	// Sensitivity lists classification values (public, internal, pii, ...): connectors lift a resource's
	// classification tag into its tags, so this matches the same tags as tags_any under a name that says why.
	Sensitivity []string `yaml:"sensitivity,omitempty" json:"sensitivity,omitempty"`
}

// Finding is one problem with a document.
type Finding struct{ Code, Msg string }

// Parse reads one document strictly (unknown fields, a second document, anchors and aliases are refused), then
// checks it. The findings are every problem found; the document is usable when there are none. The document is
// returned normalised (Normalize).
func Parse(data []byte) (*Doc, []Finding) {
	var d Doc
	if err := decode(data, &d); err != nil {
		return nil, []Finding{{"invalid_document", err.Error()}}
	}
	d.Normalize()
	return &d, d.Check()
}

// FromJSON reads a stored document (Doc.JSON) and checks it.
func FromJSON(raw string) (*Doc, error) {
	var d Doc
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("agentscope: stored document: %w", err)
	}
	d.Normalize()
	if fs := d.Check(); len(fs) > 0 {
		return nil, fmt.Errorf("agentscope: stored document %q: %s: %s", d.Key, fs[0].Code, fs[0].Msg)
	}
	return &d, nil
}

func decode(data []byte, v any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("the file is empty")
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	if hasAlias(&root, 0) {
		return errors.New("YAML anchors and aliases are not accepted")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("the file holds more than one document")
	}
	return nil
}

func hasAlias(n *yaml.Node, depth int) bool {
	if n.Kind == yaml.AliasNode || n.Anchor != "" || depth > 64 {
		return true // deeper than any scope needs
	}
	for _, c := range n.Content {
		if hasAlias(c, depth+1) {
			return true
		}
	}
	return false
}

// Normalize puts the document in canonical form: severity filled in, lists lower-cased where they are
// case-insensitive, sorted and without repeats, resource classes sorted. Two files that mean the same normalise to
// the same bytes, so an export loads back as no change.
func (d *Doc) Normalize() {
	d.Key, d.Name, d.Description = strings.TrimSpace(d.Key), strings.TrimSpace(d.Name), strings.TrimSpace(d.Description)
	if d.Severity == "" {
		d.Severity = "high"
	}
	if d.OwnerCeiling != nil && *d.OwnerCeiling { // the default is not written
		d.OwnerCeiling = nil
	}
	acts := make([]string, 0, len(d.Allow.Actions))
	for _, c := range d.Allow.Actions {
		acts = append(acts, strings.ToLower(strings.TrimSpace(c)))
	}
	d.Allow.Actions = canonList(acts, func(a, b string) bool {
		if ra, rb := classRank(a), classRank(b); ra != rb {
			return ra < rb
		}
		return a < b
	})
	for i := range d.Allow.Resources {
		r := &d.Allow.Resources[i]
		r.Systems, r.Environments = lowerList(r.Systems), lowerList(r.Environments)
		r.TagsAny, r.Sensitivity = lowerList(r.TagsAny), lowerList(r.Sensitivity)
	}
	enc := func(r ResourceClass) string { b, _ := json.Marshal(r); return string(b) }
	sort.SliceStable(d.Allow.Resources, func(i, j int) bool { return enc(d.Allow.Resources[i]) < enc(d.Allow.Resources[j]) })
	d.Allow.Resources = slices.CompactFunc(d.Allow.Resources, func(a, b ResourceClass) bool { return enc(a) == enc(b) })
	d.Agent.Source = strings.TrimSpace(d.Agent.Source)
	d.Agent.ExternalID = strings.TrimSpace(d.Agent.ExternalID)
	d.Agent.Blueprint = strings.TrimSpace(d.Agent.Blueprint)
}

func classRank(c string) int {
	if i := slices.Index(Classes, c); i >= 0 {
		return i
	}
	return len(Classes)
}

func lowerList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return canonList(out, func(a, b string) bool { return a < b })
}

func canonList(in []string, less func(a, b string) bool) []string {
	out := slices.Clone(in)
	sort.SliceStable(out, func(i, j int) bool { return less(out[i], out[j]) })
	return slices.Compact(out)
}

// Check returns every problem of the document (nil when it is valid). It checks the shape only; whether the agent
// exists is for the caller that has the tenant.
func (d *Doc) Check() []Finding {
	var fs []Finding
	add := func(code, format string, args ...any) { fs = append(fs, Finding{code, fmt.Sprintf(format, args...)}) }
	if d.Schema != Tag {
		add("invalid_schema", "schema is %q; expected %q", d.Schema, Tag)
	}
	if !keyRE.MatchString(d.Key) {
		add("invalid_key", "key is 1 to 64 letters, digits, '.', '_', ':' or '-'")
	}
	if len(d.Name) == 0 || len(d.Name) > 120 {
		add("invalid_name", "name is 1 to 120 characters")
	}
	if len(d.Description) > 1000 {
		add("invalid_description", "description is at most 1000 characters")
	}
	if !slices.Contains(severities, d.Severity) {
		add("invalid_severity", "severity is one of %s", strings.Join(severities, ", "))
	}
	s := d.Agent
	switch {
	case s.Blueprint != "" && (s.Source != "" || s.ExternalID != ""):
		add("invalid_agent", "agent names a blueprint or an agent (source and external_id), not both")
	case s.Blueprint != "":
		if !validValue(s.Blueprint) {
			add("invalid_agent", "agent.blueprint is not a valid app id")
		}
	case s.Source == "" || s.ExternalID == "":
		add("invalid_agent", "agent needs source and external_id, or blueprint")
	case !validValue(s.Source) || !validValue(s.ExternalID):
		add("invalid_agent", "agent.source and agent.external_id hold letters, digits and . _ : / @ - only")
	}
	if len(d.Allow.Actions) == 0 {
		add("invalid_actions", "allow.actions lists at least one of %s", strings.Join(Classes, ", "))
	}
	for i, a := range d.Allow.Actions {
		if !slices.Contains(Classes, a) {
			add("invalid_actions", "action class %q is not one of %s", a, strings.Join(Classes, ", "))
		}
		if i > 0 && a == d.Allow.Actions[i-1] {
			add("invalid_actions", "action class %q is listed twice", a)
		}
	}
	if len(d.Allow.Resources) == 0 {
		add("invalid_resources", "allow.resources lists at least one resource class; an agent with a scope is denied everything else")
	}
	if len(d.Allow.Resources) > MaxResources {
		add("invalid_resources", "%d resource classes; at most %d", len(d.Allow.Resources), MaxResources)
	}
	for i, r := range d.Allow.Resources {
		if len(r.Systems)+len(r.Environments)+len(r.TagsAny)+len(r.Sensitivity) == 0 {
			add("invalid_resources", "resources[%d] sets no field; a class that matches everything is not accepted", i)
		}
		for _, l := range []struct {
			name string
			vals []string
		}{{"systems", r.Systems}, {"environments", r.Environments}, {"tags_any", r.TagsAny}, {"sensitivity", r.Sensitivity}} {
			if len(l.vals) > MaxValues {
				add("invalid_resources", "resources[%d].%s lists %d values; at most %d", i, l.name, len(l.vals), MaxValues)
				continue
			}
			for _, v := range l.vals {
				if !validValue(v) {
					add("invalid_resources", "resources[%d].%s: %q is empty, too long or holds a character outside letters, digits, space and . _ : / @ -", i, l.name, v)
				}
			}
		}
	}
	return fs
}

func validValue(v string) bool { return len(v) <= MaxValueLen && valueRE.MatchString(v) }

// YAML is the canonical file of the document: what an export writes.
func (d *Doc) YAML() ([]byte, error) {
	c := *d
	c.Normalize()
	return yaml.Marshal(&c)
}

// JSON is the canonical stored form of the document.
func (d *Doc) JSON() (string, error) {
	c := *d
	c.Normalize()
	b, err := json.Marshal(&c)
	return string(b), err
}

// Ceiling reports whether the agent is held to its owner.
func (d *Doc) Ceiling() bool { return d.OwnerCeiling == nil || *d.OwnerCeiling }

// ByBlueprint reports whether the scope applies to a blueprint's agents rather than one agent.
func (d *Doc) ByBlueprint() bool { return d.Agent.Blueprint != "" }

// Permits reports whether a permission of the given action class on a resource is inside the scope.
func (d *Doc) Permits(class, system string, env *string, tags []string) bool {
	if !slices.Contains(d.Allow.Actions, class) {
		return false
	}
	for i := range d.Allow.Resources {
		if d.Allow.Resources[i].matches(system, env, tags) {
			return true
		}
	}
	return false
}

func (r *ResourceClass) matches(system string, env *string, tags []string) bool {
	if len(r.Systems) > 0 && !slices.Contains(r.Systems, strings.ToLower(system)) {
		return false
	}
	if len(r.Environments) > 0 && (env == nil || !slices.Contains(r.Environments, strings.ToLower(*env))) {
		return false
	}
	return anyTag(r.TagsAny, tags) && anyTag(r.Sensitivity, tags)
}

// anyTag is true when want is empty (the field is not set) or the resource has one of its tags.
func anyTag(want, tags []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, t := range tags {
		if slices.Contains(want, strings.ToLower(t)) {
			return true
		}
	}
	return false
}
