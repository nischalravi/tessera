package template

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"
)

// Problem is one lint failure.
type Problem struct {
	Template, Item, Msg string
}

func (p Problem) String() string {
	if p.Item != "" {
		return fmt.Sprintf("%s: %s: %s", p.Template, p.Item, p.Msg)
	}
	return fmt.Sprintf("%s: %s", p.Template, p.Msg)
}

// LintFS parses and lints the templates in fsys without resolving them.
func LintFS(fsys fs.FS) ([]Problem, error) {
	base, ts, err := parseAll(fsys)
	if err != nil {
		return nil, err
	}
	return Lint(base, ts), nil
}

// Lint checks every template against the rules of design §3: unique item ids,
// known check names allowed for the connector type, a dependency DAG,
// required fields present, a remediation hint on every item, the closed
// applies_when vocabulary, and dependencies that are applicable wherever
// their dependants are.
func Lint(base *Template, ts []*Template) []Problem {
	var probs []Problem
	add := func(t, item, format string, args ...any) {
		probs = append(probs, Problem{t, item, fmt.Sprintf(format, args...)})
	}
	lintHeader(base, true, add)
	lintItems(base.ID, base.Items, nil, add)
	for _, t := range ts {
		lintHeader(t, false, add)
		lintItems(t.ID, t.Items, base.Items, add)
	}
	return probs
}

type addFn func(t, item, format string, args ...any)

func lintHeader(t *Template, isBase bool, add addFn) {
	if !semver.MatchString(t.Version) {
		add(t.ID, "", "version %q is not semver (major.minor.patch)", t.Version)
	}
	if t.DisplayName == "" {
		add(t.ID, "", "display_name is empty")
	}
	if isBase {
		if t.Extends != "" {
			add(t.ID, "", "base must not extend another template")
		}
	} else {
		if t.Extends != "base@1" {
			add(t.ID, "", "extends %q: want base@1", t.Extends)
		}
		if !slices.Contains(TemplateIDs, t.ID) {
			add(t.ID, "", "unknown template id (known: %s)", strings.Join(TemplateIDs, ", "))
		}
		if len(t.ConnectorTypes) == 0 {
			add(t.ID, "", "connector_types is empty")
		}
		if t.Role != "" && !slices.Contains(Roles, t.Role) {
			add(t.ID, "", "role %q is not one of %v", t.Role, Roles)
		}
		if len(t.RequiredAttributes["user"]) == 0 {
			add(t.ID, "", "required_attributes.user is empty")
		}
		if t.DefaultCorrelationKey == "" {
			add(t.ID, "", "default_correlation_key is empty")
		}
	}
	for k := range t.Thresholds {
		if _, ok := Thresholds[k]; !ok {
			add(t.ID, "", "unknown threshold %q", k)
		}
	}
}

func lintItems(tid string, items, baseItems []Item, add addFn) {
	all := map[string]*Item{}
	for i := range baseItems {
		all[baseItems[i].ID] = &baseItems[i]
	}
	seen := map[string]bool{}
	for i := range items {
		it := &items[i]
		if it.ID == "" {
			add(tid, fmt.Sprintf("#%d", i), "item has no id")
			continue
		}
		if seen[it.ID] || (baseItems != nil && all[it.ID] != nil) {
			add(tid, it.ID, "duplicate item id")
		}
		seen[it.ID] = true
		all[it.ID] = it
	}
	for i := range items {
		lintItem(tid, &items[i], all, add)
	}
	// cycles, over the template plus its base
	state := map[string]int{} // 0 new, 1 visiting, 2 done
	var visit func(id string, stack []string)
	visit = func(id string, stack []string) {
		switch state[id] {
		case 1:
			add(tid, id, "dependency cycle: %s", strings.Join(append(stack, id), " -> "))
			return
		case 2:
			return
		}
		state[id] = 1
		if it := all[id]; it != nil {
			for _, d := range it.DependsOn {
				if all[d] != nil {
					visit(d, append(stack, id))
				}
			}
		}
		state[id] = 2
	}
	for i := range items {
		visit(items[i].ID, nil)
	}
}

func lintItem(tid string, it *Item, all map[string]*Item, add addFn) {
	id := it.ID
	if strings.TrimSpace(it.Title) == "" {
		add(tid, id, "title is empty")
	}
	if !slices.Contains(Categories, it.Category) {
		add(tid, id, "category %q is not one of %v", it.Category, Categories)
	}
	if !it.Level.Valid() {
		add(tid, id, "level %q is not required, recommended or optional", it.Level)
	}
	if strings.TrimSpace(it.Why) == "" {
		add(tid, id, "why is empty")
	}
	if strings.TrimSpace(it.Remediation.Hint) == "" {
		add(tid, id, "remediation hint is empty")
	}
	if it.Remediation.Link != "" && !strings.HasPrefix(it.Remediation.Link, "https://") {
		add(tid, id, "remediation link must be https")
	}
	if len(it.Verify) == 0 {
		add(tid, id, "no verification")
	}
	for _, v := range it.Verify {
		if v.OnUnsupported != "" && (v.Kind != Live || v.OnUnsupported != Attestation) {
			add(tid, id, "on_unsupported takes the value attestation and only on a live check")
		}
		switch v.Kind {
		case Attestation:
			if v.Check != "" || len(v.Params) > 0 {
				add(tid, id, "an attestation takes no check or params")
			}
		case Live, Data:
			spec, ok := Checks[v.Check]
			switch {
			case !ok:
				add(tid, id, "unknown check %q", v.Check)
			case spec.Kind != v.Kind:
				add(tid, id, "check %q is a %s check, not %s", v.Check, spec.Kind, v.Kind)
			case !spec.Allowed(tid):
				add(tid, id, "check %q is not available for template %s", v.Check, tid)
			}
		default:
			add(tid, id, "verification kind %q is not attestation, live or data", v.Kind)
		}
	}
	for _, f := range it.ConfigFields {
		if !slices.Contains(ConfigFields, f) {
			add(tid, id, "unknown config field %q", f)
		}
	}
	lintAppliesWhen(tid, id, it.AppliesWhen, add)
	for _, d := range it.DependsOn {
		dep := all[d]
		switch {
		case d == id:
			add(tid, id, "depends on itself")
		case dep == nil:
			add(tid, id, "depends on unknown item %q", d)
		case !implies(it.AppliesWhen, dep.AppliesWhen):
			add(tid, id, "depends on %q, which is not applicable in every configuration where %s is", d, id)
		}
	}
}

func lintAppliesWhen(tid, id string, aw *AppliesWhen, add addFn) {
	if aw == nil {
		return
	}
	if len(aw.WriteMode) == 0 && len(aw.Role) == 0 && len(aw.TenantHasConnectionType) == 0 && aw.ConfigFlag == "" {
		add(tid, id, "applies_when is empty")
	}
	for _, v := range aw.WriteMode {
		if !slices.Contains(WriteModes, v) {
			add(tid, id, "applies_when.write_mode %q is not one of %v", v, WriteModes)
		}
	}
	for _, v := range aw.Role {
		if !slices.Contains(Roles, v) {
			add(tid, id, "applies_when.role %q is not one of %v", v, Roles)
		}
	}
	for _, v := range aw.TenantHasConnectionType {
		if !slices.Contains(TemplateIDs, v) {
			add(tid, id, "applies_when.tenant_has_connection_type %q is not a template id", v)
		}
	}
	if aw.ConfigFlag != "" && !slices.Contains(ConfigFlag, aw.ConfigFlag) {
		add(tid, id, "applies_when.config_flag %q is not one of %v", aw.ConfigFlag, ConfigFlag)
	}
}

// implies reports whether every configuration satisfying a also satisfies b.
func implies(a, b *AppliesWhen) bool {
	if b == nil {
		return true
	}
	if a == nil {
		return false
	}
	subset := func(x, y []string) bool {
		if len(y) == 0 {
			return true
		}
		if len(x) == 0 {
			return false
		}
		for _, v := range x {
			if !slices.Contains(y, v) {
				return false
			}
		}
		return true
	}
	// Each list means "any of these", so a is stricter when its list is a subset.
	return subset(a.WriteMode, b.WriteMode) && subset(a.Role, b.Role) &&
		subset(a.TenantHasConnectionType, b.TenantHasConnectionType) &&
		(b.ConfigFlag == "" || a.ConfigFlag == b.ConfigFlag)
}
