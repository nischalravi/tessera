package plan

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
)

// Templates are reviewed data compiled into the binary, not scripts (K6): each
// has an id, a version, typed inputs and a fixed expansion into folders,
// groups and privileges. A plan folder names one with `template:` and
// `params:`; the CLI's `groups templates` lists them.

// Param types of a template input.
const (
	ParamGroup = "group_name" // the full name of a group (checked as a name, not looked up here)
	ParamText  = "text"
)

// ParamDef describes one input of a template.
type ParamDef struct {
	Name        string
	Type        string
	Required    bool
	Description string
}

// Template is a versioned plan template.
type Template struct {
	ID          string
	Version     int
	Description string
	Params      []ParamDef
	expand      func(folder string, p map[string]string) Spec
}

// Templates lists the available templates by id.
func Templates() []Template { return slices.Clone(templates) }

// FindTemplate returns the template with the id.
func FindTemplate(id string) (Template, bool) {
	for _, t := range templates {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}

var templates = []Template{applicationTemplate}

// applicationTemplate is the Deployment Guide's standard application folder
// (design §3.15, G-06): a security folder with the application's admin group,
// and a service folder whose ref folder holds reference groups and whose policy
// folder holds the access policy group foo_user = foo_user_allow minus
// foo_user_deny, with foo_user_allow_manual (exceptions) nested in the allow
// group. The admin group administers the folder and everything under it.
var applicationTemplate = Template{
	ID:          "application",
	Version:     1,
	Description: "Deployment Guide structure for an application: security, service:ref and service:policy folders, the admin group, and the allow/deny/manual policy groups",
	Params: []ParamDef{
		{Name: "admins", Type: ParamGroup, Description: "a group whose members administer the application (nested in the admin group)"},
		{Name: "global_deny", Type: ParamGroup, Description: "a group of people denied everywhere (nested in the deny group)"},
	},
	expand: func(app string, p map[string]string) Spec {
		_, foo := naming.Split(app)
		n := func(rest string) string { return app + ":" + rest }
		admin := n("security:" + foo + "Admin")
		user := n("service:policy:" + foo + "_user")
		allow, manual, deny := user+"_allow", user+"_allow_manual", user+"_deny"
		var adminMembers, denyMembers []string
		if p["admins"] != "" {
			adminMembers = []string{"group:" + p["admins"]}
		}
		if p["global_deny"] != "" {
			denyMembers = []string{"group:" + p["global_deny"]}
		}
		return Spec{
			Folders: []FolderSpec{
				{Name: n("security"), DisplayName: "Security"},
				{Name: n("service"), DisplayName: "Service"},
				{Name: n("service:ref"), DisplayName: "Reference groups"},
				{Name: n("service:policy"), DisplayName: "Policy groups"},
			},
			Groups: []GroupSpec{
				{Name: admin, DisplayName: foo + " administrators", Description: "Administers the " + app + " folder and its groups",
					Members: MembersSpec{Add: adminMembers}},
				{Name: user, DisplayName: foo + " users", Description: "Access policy: " + foo + "_user_allow minus " + foo + "_user_deny",
					Composite: &CompositeSpec{Op: "complement", Factors: []string{allow, deny}}},
				{Name: allow, DisplayName: foo + " users (allow)", Description: "Who should have access, through reference groups",
					Members: MembersSpec{Add: []string{"group:" + manual}}},
				{Name: manual, DisplayName: foo + " users (allow, exceptions)", Description: "People allowed by exception, maintained by hand"},
				{Name: deny, DisplayName: foo + " users (deny)", Description: "Who must not have access",
					Members: MembersSpec{Add: denyMembers}},
			},
			Privileges: []PrivSpec{{Object: "folder:" + app, Grant: GrantSpec{Scope: "sub",
				Privileges: map[string][]string{"stem_admin": {"group:" + admin}, "admin": {"group:" + admin}}}}},
		}
	},
}

// Expand replaces every folder's template by its expansion and merges items
// that name the same folder or group (members and grants are combined; a field
// the plan itself sets wins over a template's). It validates template inputs.
func Expand(s *Spec) (*Spec, error) {
	out := &Spec{}
	uses := 0
	fIdx, gIdx := map[string]int{}, map[string]int{}
	putFolder := func(f FolderSpec, explicit bool) {
		k := naming.Fold(f.Name)
		i, ok := fIdx[k]
		if !ok {
			fIdx[k] = len(out.Folders)
			out.Folders = append(out.Folders, f)
			return
		}
		cur := &out.Folders[i]
		cur.DisplayName, cur.Description, cur.DataOwner = pick(cur.DisplayName, f.DisplayName, explicit),
			pick(cur.Description, f.Description, explicit), pick(cur.DataOwner, f.DataOwner, explicit)
	}
	putGroup := func(g GroupSpec, explicit bool) {
		k := naming.Fold(g.Name)
		i, ok := gIdx[k]
		if !ok {
			gIdx[k] = len(out.Groups)
			out.Groups = append(out.Groups, g)
			return
		}
		cur := &out.Groups[i]
		cur.DisplayName, cur.Description, cur.DataOwner = pick(cur.DisplayName, g.DisplayName, explicit),
			pick(cur.Description, g.Description, explicit), pick(cur.DataOwner, g.DataOwner, explicit)
		cur.MemberDescription, cur.Type = pick(cur.MemberDescription, g.MemberDescription, explicit), pick(cur.Type, g.Type, explicit)
		if g.Composite != nil && (cur.Composite == nil || explicit) {
			cur.Composite = g.Composite
		}
		cur.Members.Add = union(cur.Members.Add, g.Members.Add)
		cur.Members.Remove = union(cur.Members.Remove, g.Members.Remove)
	}
	for _, f := range s.Folders {
		if f.Template == "" {
			if len(f.Params) > 0 {
				return nil, fmt.Errorf("folder %q: params need a template", f.Name)
			}
			putFolder(f, true)
			continue
		}
		t, ok := FindTemplate(f.Template)
		if !ok {
			return nil, fmt.Errorf("folder %q: there is no template %q (see: tessera-cli groups templates)", f.Name, f.Template)
		}
		if uses++; uses > MaxTemplates {
			return nil, fmt.Errorf("a plan uses at most %d templates", MaxTemplates)
		}
		if _, err := naming.Parse(f.Name); err != nil || f.Name == "" {
			return nil, fmt.Errorf("folder %q: not a valid name", f.Name)
		}
		if err := checkParams(t, f); err != nil {
			return nil, err
		}
		exp := t.expand(f.Name, f.Params)
		own := f
		own.Template, own.Params = "", nil
		putFolder(own, true)
		for _, tf := range exp.Folders {
			putFolder(tf, false)
		}
		for _, tg := range exp.Groups {
			putGroup(tg, false)
		}
		out.Privileges = append(out.Privileges, exp.Privileges...)
	}
	for _, g := range s.Groups {
		putGroup(g, true)
	}
	out.Privileges = append(out.Privileges, s.Privileges...)
	return out, nil
}

func pick(cur, next string, explicit bool) string {
	if next != "" && (cur == "" || explicit) {
		return next
	}
	return cur
}

func union(a, b []string) []string {
	for _, x := range b {
		if !slices.Contains(a, x) {
			a = append(a, x)
		}
	}
	return a
}

// checkParams rejects unknown inputs, missing required ones and values of the
// wrong type.
func checkParams(t Template, f FolderSpec) error {
	known := map[string]ParamDef{}
	for _, d := range t.Params {
		known[d.Name] = d
	}
	for name, v := range f.Params {
		d, ok := known[name]
		switch {
		case !ok:
			names := make([]string, len(t.Params))
			for i, d := range t.Params {
				names[i] = d.Name
			}
			return fmt.Errorf("folder %q: template %s has no input %q (inputs: %s)", f.Name, t.ID, name, strings.Join(names, ", "))
		case len(v) > MaxParamBytes:
			return fmt.Errorf("folder %q: input %s is too long", f.Name, name)
		case d.Type == ParamGroup && v != "":
			if _, err := naming.Parse(v); err != nil {
				return fmt.Errorf("folder %q: input %s is not a group name: %w", f.Name, name, err)
			}
		}
	}
	for _, d := range t.Params {
		if d.Required && f.Params[d.Name] == "" {
			return fmt.Errorf("folder %q: template %s needs input %s", f.Name, t.ID, d.Name)
		}
	}
	return nil
}
