package template

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/readiness/templates"
)

// Registry holds the parsed, linted templates.
type Registry struct {
	base      *Template
	templates map[string]*Template
	resolved  map[string]*Resolved
}

var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// Parse decodes one template file strictly: unknown keys (anywhere,
// including inside applies_when) are errors, so the vocabulary stays closed.
func Parse(name string, data []byte) (*Template, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var t Template
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("template %s: %w", name, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("template %s: more than one YAML document", name)
	}
	return &t, nil
}

// Load parses every *.yaml file in fsys, lints them and resolves each
// connector template against base. Any lint problem fails the load.
func Load(fsys fs.FS) (*Registry, error) {
	base, ts, err := parseAll(fsys)
	if err != nil {
		return nil, err
	}
	if probs := Lint(base, ts); len(probs) > 0 {
		msgs := make([]string, len(probs))
		for i, p := range probs {
			msgs[i] = p.String()
		}
		return nil, fmt.Errorf("readiness templates failed lint:\n  %s", strings.Join(msgs, "\n  "))
	}
	r := &Registry{base: base, templates: map[string]*Template{}, resolved: map[string]*Resolved{}}
	for _, t := range ts {
		r.templates[t.ID] = t
		r.resolved[t.ID] = resolve(base, t)
	}
	return r, nil
}

func parseAll(fsys fs.FS) (*Template, []*Template, error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(names)
	var base *Template
	var ts []*Template
	for _, n := range names {
		data, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, nil, err
		}
		t, err := Parse(n, data)
		if err != nil {
			return nil, nil, err
		}
		if want := strings.TrimSuffix(path.Base(n), ".yaml"); t.ID != want {
			return nil, nil, fmt.Errorf("template %s: id %q does not match the file name", n, t.ID)
		}
		if t.ID == "base" {
			base = t
		} else {
			ts = append(ts, t)
		}
	}
	if base == nil {
		return nil, nil, errors.New("readiness templates: base.yaml is missing")
	}
	return base, ts, nil
}

var (
	defaultOnce sync.Once
	defaultReg  *Registry
	defaultErr  error
)

// Default returns the registry of the templates embedded in the binary.
func Default() (*Registry, error) {
	defaultOnce.Do(func() { defaultReg, defaultErr = Load(templates.FS) })
	return defaultReg, defaultErr
}

// MustDefault is Default for callers that run after startup validated the
// embedded templates (the TestTemplates_Lint test and `tessera readiness lint`).
func MustDefault() *Registry {
	r, err := Default()
	if err != nil {
		panic(err)
	}
	return r
}

// IDs lists the connector template ids in a stable order.
func (r *Registry) IDs() []string {
	return slices.Sorted(maps.Keys(r.resolved))
}

// Get returns a copy of the resolved template.
func (r *Registry) Get(id string) (*Resolved, bool) {
	t, ok := r.resolved[id]
	if !ok {
		return nil, false
	}
	return t.Clone(), true
}

// ForConnectorType returns the template that covers a connector type
// ("ad", "demo-ad", ...).
func (r *Registry) ForConnectorType(ct string) (*Resolved, bool) {
	if id, ok := r.TemplateID(ct); ok {
		return r.Get(id)
	}
	return nil, false
}

// TemplateID returns the id of the template that covers a connector type.
func (r *Registry) TemplateID(ct string) (string, bool) {
	for id, t := range r.resolved {
		if slices.Contains(t.ConnectorTypes, ct) {
			return id, true
		}
	}
	return "", false
}

// ErrVersionUnavailable is returned when a pin names a major.minor that this
// build does not carry.
var ErrVersionUnavailable = errors.New("template version unavailable")

// ParsePin splits "ad@1.0" into the template id, major and minor.
func ParsePin(pin string) (id string, major, minor int, err error) {
	id, ver, ok := strings.Cut(pin, "@")
	parts := strings.Split(ver, ".")
	if !ok || id == "" || len(parts) != 2 {
		return "", 0, 0, fmt.Errorf("template pin %q: want template@major.minor", pin)
	}
	if major, err = strconv.Atoi(parts[0]); err != nil || major < 0 {
		return "", 0, 0, fmt.Errorf("template pin %q: bad major version", pin)
	}
	if minor, err = strconv.Atoi(parts[1]); err != nil || minor < 0 {
		return "", 0, 0, fmt.Errorf("template pin %q: bad minor version", pin)
	}
	return id, major, minor, nil
}

// Resolve returns the template a revision pinned. Patch releases apply
// automatically (wording, remediation links); a different major or minor is
// not substituted, because it may add or change gating items.
func (r *Registry) Resolve(pin string) (*Resolved, error) {
	id, major, minor, err := ParsePin(pin)
	if err != nil {
		return nil, err
	}
	t, ok := r.Get(id)
	if !ok {
		return nil, fmt.Errorf("%w: no template %q", ErrVersionUnavailable, id)
	}
	m := semver.FindStringSubmatch(t.Version)
	if m == nil || m[1] != strconv.Itoa(major) || m[2] != strconv.Itoa(minor) {
		return nil, fmt.Errorf("%w: %s is at %s", ErrVersionUnavailable, pin, t.Version)
	}
	return t, nil
}

func majorMinor(v string) string {
	if m := semver.FindStringSubmatch(v); m != nil {
		return m[1] + "." + m[2]
	}
	return v
}

func resolve(base, t *Template) *Resolved {
	r := &Resolved{
		ID: t.ID, Version: t.Version, DisplayName: t.DisplayName, ConnectorTypes: slices.Clone(t.ConnectorTypes),
		Role: t.Role, DefaultCorrelationKey: t.DefaultCorrelationKey, DefaultHRIDAttribute: t.DefaultHRIDAttribute,
		HostAllowlist: slices.Clone(t.HostAllowlist), RequiredAttributes: map[string][]string{},
		RecommendedAttributes: map[string][]string{}, Thresholds: map[string]float64{},
	}
	if r.Role == "" {
		r.Role = "account_source"
	}
	maps.Copy(r.Thresholds, base.Thresholds)
	maps.Copy(r.Thresholds, t.Thresholds)
	for k, v := range t.RequiredAttributes {
		r.RequiredAttributes[k] = slices.Clone(v)
	}
	for k, v := range t.RecommendedAttributes {
		r.RecommendedAttributes[k] = slices.Clone(v)
	}
	for _, src := range []*Template{base, t} {
		for _, it := range src.Items {
			c := cloneItem(it)
			c.TemplateLevel = c.Level
			c.Source = src.ID
			r.Items = append(r.Items, c)
		}
	}
	return r
}

// Clone deep-copies a resolved template.
func (r *Resolved) Clone() *Resolved {
	c := *r
	c.ConnectorTypes = slices.Clone(r.ConnectorTypes)
	c.HostAllowlist = slices.Clone(r.HostAllowlist)
	c.RequiredAttributes = map[string][]string{}
	for k, v := range r.RequiredAttributes {
		c.RequiredAttributes[k] = slices.Clone(v)
	}
	c.RecommendedAttributes = map[string][]string{}
	for k, v := range r.RecommendedAttributes {
		c.RecommendedAttributes[k] = slices.Clone(v)
	}
	c.Thresholds = maps.Clone(r.Thresholds)
	c.Items = make([]Item, len(r.Items))
	for i, it := range r.Items {
		c.Items[i] = cloneItem(it)
	}
	return &c
}

func cloneItem(it Item) Item {
	c := it
	c.DependsOn = slices.Clone(it.DependsOn)
	c.ConfigFields = slices.Clone(it.ConfigFields)
	c.Verify = make([]Verify, len(it.Verify))
	for i, v := range it.Verify {
		c.Verify[i] = Verify{Kind: v.Kind, Check: v.Check, Params: maps.Clone(v.Params), OnUnsupported: v.OnUnsupported}
	}
	if it.AppliesWhen != nil {
		aw := *it.AppliesWhen
		aw.WriteMode = slices.Clone(aw.WriteMode)
		aw.Role = slices.Clone(aw.Role)
		aw.TenantHasConnectionType = slices.Clone(aw.TenantHasConnectionType)
		c.AppliesWhen = &aw
	}
	return c
}
