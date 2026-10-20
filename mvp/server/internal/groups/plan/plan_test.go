package plan

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func mustParse(t *testing.T, s string) *Spec {
	t.Helper()
	spec, err := Parse(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name, in, wantErr string
	}{
		{"empty", "", "empty"},
		{"unknown key", "folders:\n  - name: a\n    templat: x\n", "templat"},
		{"two documents", "folders:\n  - name: a\n---\nfolders:\n  - name: b\n", "more than one"},
		{"grant is not a list", "privileges:\n  - object: folder:a\n    grant: {stem_admin: nobody}\n", "list of holders"},
		{"grant is not a mapping", "privileges:\n  - object: folder:a\n    grant: [x]\n", "mapping"},
		{"ok", "folders:\n  - name: a\ngroups:\n  - name: a:g\n    members: {add: [1, \"group:a:h\"]}\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.in))
			if (err == nil) != (tc.wantErr == "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
	if _, err := Parse(strings.NewReader(strings.Repeat("#", MaxFile+1))); err == nil || !strings.Contains(err.Error(), "MiB") {
		t.Errorf("an oversized plan: %v", err)
	}
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name, in, wantErr string
	}{
		{"bad folder name", "folders:\n  - name: \"a b\"\n", "not a valid name"},
		{"root group", "groups:\n  - name: g\n", "lives in a folder"},
		{"duplicate", "folders:\n  - name: a\n  - name: A\n", "already listed"},
		{"bad type", "groups:\n  - name: a:g\n    type: wheel\n", "group or role"},
		{"bad member", "groups:\n  - name: a:g\n    members: {add: [\"x\"]}\n", "identity:<id> or group:<name>"},
		{"zero identity", "groups:\n  - name: a:g\n    members: {remove: [0]}\n", "identity:<id>"},
		{"composite with one factor", "groups:\n  - name: a:g\n    composite: {op: union, factors: [a:x]}\n", "at least two"},
		{"complement of three", "groups:\n  - name: a:g\n    composite: {op: complement, factors: [a:x, a:y, a:z]}\n", "exactly two"},
		{"bad op", "groups:\n  - name: a:g\n    composite: {op: xor, factors: [a:x, a:y]}\n", "union, intersection or complement"},
		{"composite with members", "groups:\n  - name: a:g\n    composite: {op: union, factors: [a:x, a:y]}\n    members: {add: [1]}\n", "no direct members"},
		{"bad object", "privileges:\n  - object: attr:a\n    grant: {read: [everyone]}\n", "folder:<name> or group:<name>"},
		{"unknown privilege", "privileges:\n  - object: folder:a\n    grant: {godmode: [everyone]}\n", "not a privilege"},
		{"group privilege on a folder, self", "privileges:\n  - object: folder:a\n    grant: {read: [everyone]}\n", "group privilege"},
		{"scope on a group", "privileges:\n  - object: group:a:g\n    grant: {read: [everyone], scope: sub}\n", "only a folder's privileges are inherited"},
		{"bad scope", "privileges:\n  - object: folder:a\n    grant: {stem_admin: [everyone], scope: all}\n", "self, one or sub"},
		{"no holders", "privileges:\n  - object: folder:a\n    grant: {stem_admin: []}\n", "no holders"},
		{"bad holder", "privileges:\n  - object: folder:a\n    grant: {stem_admin: [bob]}\n", "identity:<id>, group:<name> or everyone"},
		{"group privilege inherited", "privileges:\n  - object: folder:a\n    grant: {read: [everyone], scope: sub}\n", ""},
		{"valid", "folders:\n  - name: a\ngroups:\n  - name: a:g\n    members: {add: [1, group:a:h]}\nprivileges:\n  - object: folder:a\n    grant: {stem_admin: [\"identity:3\"], scope: one}\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := mustParse(t, tc.in).Validate()
			if (err == nil) != (tc.wantErr == "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestPrivTable_MatchesPrivs(t *testing.T) {
	for typ, list := range map[privs.ObjectType][]string{privs.Group: groupPrivs, privs.Folder: folderPrivs, privs.AttrDef: attrPrivs} {
		var want []string
		for _, p := range privs.All() {
			if privs.ObjectOf(p) == typ {
				want = append(want, string(p))
			}
		}
		if !reflect.DeepEqual(sorted(want), sorted(list)) {
			t.Errorf("%s privileges: plan has %v, privs has %v", typ, list, want)
		}
		if got := appliesTo(string(typ)); got != typ.AppliesTo() {
			t.Errorf("appliesTo(%s) = %q, privs says %q", typ, got, typ.AppliesTo())
		}
		for _, p := range list {
			if privObject(p) != string(typ) {
				t.Errorf("privObject(%s) = %q", p, privObject(p))
			}
		}
	}
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

// TestTemplate_ApplicationMatchesDeploymentGuide pins the expansion of the
// application template to the structure of the Deployment Guide (design §3.15):
// security and service folders, service:ref and service:policy below it, the
// admin group, and foo_user = foo_user_allow minus foo_user_deny with the
// manual exceptions group nested in allow.
func TestTemplate_ApplicationMatchesDeploymentGuide(t *testing.T) {
	spec := mustParse(t, `
folders:
  - name: app:foo
    template: application
    params: {admins: "org:it:staff:iam", global_deny: "ref:iam:global_deny"}
`)
	got, err := Expand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	var folders []string
	for _, f := range got.Folders {
		folders = append(folders, f.Name)
	}
	wantFolders := []string{"app:foo", "app:foo:security", "app:foo:service", "app:foo:service:ref", "app:foo:service:policy"}
	if !reflect.DeepEqual(folders, wantFolders) {
		t.Errorf("folders = %v, want %v", folders, wantFolders)
	}
	type g struct {
		composite string
		add       []string
	}
	want := map[string]g{
		"app:foo:security:fooAdmin":                    {add: []string{"group:org:it:staff:iam"}},
		"app:foo:service:policy:foo_user":              {composite: "complement app:foo:service:policy:foo_user_allow app:foo:service:policy:foo_user_deny"},
		"app:foo:service:policy:foo_user_allow":        {add: []string{"group:app:foo:service:policy:foo_user_allow_manual"}},
		"app:foo:service:policy:foo_user_allow_manual": {},
		"app:foo:service:policy:foo_user_deny":         {add: []string{"group:ref:iam:global_deny"}},
	}
	if len(got.Groups) != len(want) {
		t.Errorf("%d groups, want %d", len(got.Groups), len(want))
	}
	for _, gs := range got.Groups {
		w, ok := want[gs.Name]
		if !ok {
			t.Errorf("unexpected group %s", gs.Name)
			continue
		}
		comp := ""
		if gs.Composite != nil {
			comp = gs.Composite.Op + " " + strings.Join(gs.Composite.Factors, " ")
		}
		if comp != w.composite || !reflect.DeepEqual(gs.Members.Add, w.add) {
			t.Errorf("%s = composite %q add %v, want composite %q add %v", gs.Name, comp, gs.Members.Add, w.composite, w.add)
		}
	}
	if len(got.Privileges) != 1 || got.Privileges[0].Object != "folder:app:foo" || got.Privileges[0].Grant.Scope != "sub" ||
		!reflect.DeepEqual(got.Privileges[0].Grant.Privileges, map[string][]string{
			"stem_admin": {"group:app:foo:security:fooAdmin"}, "admin": {"group:app:foo:security:fooAdmin"}}) {
		t.Errorf("privileges = %+v", got.Privileges)
	}
	// without the optional inputs there is nothing nested in admin or deny
	bare, err := Expand(mustParse(t, "folders:\n  - name: app:foo\n    template: application\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, gs := range bare.Groups {
		if strings.HasSuffix(gs.Name, "fooAdmin") || strings.HasSuffix(gs.Name, "_deny") {
			if len(gs.Members.Add) != 0 {
				t.Errorf("%s has members %v", gs.Name, gs.Members.Add)
			}
		}
	}
}

func TestExpand(t *testing.T) {
	for _, tc := range []struct {
		name, in, wantErr string
	}{
		{"unknown template", "folders:\n  - name: a:b\n    template: nope\n", "no template"},
		{"unknown input", "folders:\n  - name: a:b\n    template: application\n    params: {admin: x}\n", "no input"},
		{"input of the wrong type", "folders:\n  - name: a:b\n    template: application\n    params: {admins: \"not a name!\"}\n", "not a group name"},
		{"params without a template", "folders:\n  - name: a:b\n    params: {admins: x}\n", "need a template"},
		{"bad folder name", "folders:\n  - name: \"a b\"\n    template: application\n", "not a valid name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Expand(mustParse(t, tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestExpand_MergesWhatThePlanSaysItself(t *testing.T) {
	got, err := Expand(mustParse(t, `
folders:
  - name: app:foo
    display_name: Foo
    template: application
groups:
  - name: app:foo:security:fooadmin
    description: mine
    members: {add: [7]}
`))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, g := range got.Groups {
		if strings.EqualFold(g.Name, "app:foo:security:fooAdmin") {
			n++
			if g.Description != "mine" || !reflect.DeepEqual(g.Members.Add, []string{"7"}) {
				t.Errorf("merged group = %+v", g)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d entries for the admin group, want 1", n)
	}
	if got.Folders[0].DisplayName != "Foo" {
		t.Errorf("folder = %+v", got.Folders[0])
	}
}

// live builds a state with the named folders, groups and members.
func live() *Live {
	l := NewLive()
	l.AddFolder(LiveFolder{ID: "f-root", Name: ""})
	l.AddFolder(LiveFolder{ID: "f-app", Name: "app"})
	l.AddGroup(LiveGroup{ID: "g-team", Name: "app:team", Type: "group", Definition: "basic"})
	l.AddGroup(LiveGroup{ID: "g-staff", Name: "app:staff", Type: "group", Definition: "basic"})
	l.Members["g-team"] = map[string]bool{"identity:1": true, "identity:2": true, "group:app:staff": true}
	return l
}

func TestCompute(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     []string // kind name detail
		wantSame int
		wantErr  string
	}{
		{name: "nothing to do", wantSame: 5, in: `
folders: [{name: app}]
groups:
  - name: app:team
    members: {add: [1, "identity:2", "group:app:staff"]}
`},
		{name: "new folder, group and members", wantSame: 1, in: `
folders:
  - {name: app}
  - {name: app:new}
groups:
  - name: app:new:g
    members: {add: [5]}
`, want: []string{"folder.create app:new", "group.create app:new:g", "member.add app:new:g identity:5"}},
		{name: "add and remove against live members", wantSame: 3, in: `
groups:
  - name: app:team
    members: {add: [1, 3], remove: [2, 9]}
`, want: []string{"member.add app:team identity:3", "member.remove app:team identity:2"}},
		{name: "case-insensitive names and a repeated member", wantSame: 1, in: `
groups:
  - name: APP:Team
    members: {add: [3, "identity:3"]}
`, want: []string{"member.add APP:Team identity:3"}},
		{name: "parents before children, composites after factors", in: `
folders:
  - {name: app:a:b}
  - {name: app:a}
groups:
  - name: app:a:both
    composite: {op: union, factors: [app:a:x, app:a:y]}
  - name: app:a:y
  - name: app:a:x
`, want: []string{"folder.create app:a", "folder.create app:a:b", "group.create app:a:y", "group.create app:a:x",
			"group.create app:a:both composite union of app:a:x, app:a:y"}},
		{name: "privilege rows: self and inherited", in: `
privileges:
  - object: folder:app
    grant: {stem_admin: ["group:app:staff"], scope: sub}
`, want: []string{"privilege.grant folder:app stem_admin to group:app:staff", "privilege.grant folder:app stem_admin to group:app:staff (inherited by folders, scope sub)"}},
		{name: "group privilege on a folder is only inherited", in: `
privileges:
  - object: folder:app
    grant: {read: [everyone], scope: one}
`, want: []string{"privilege.grant folder:app read to everyone (inherited by groups, scope one)"}},
		{name: "missing parent", in: "folders:\n  - {name: nope:child}\n", wantErr: `parent folder "nope" does not exist`},
		{name: "missing folder of a group", in: "groups:\n  - {name: nope:g}\n", wantErr: `its folder "nope" does not exist`},
		{name: "missing factor", in: "groups:\n  - name: app:c\n    composite: {op: union, factors: [app:team, app:ghost]}\n", wantErr: "factor app:ghost does not exist"},
		{name: "missing member group", in: "groups:\n  - name: app:team\n    members: {add: [\"group:app:ghost\"]}\n", wantErr: "member group app:ghost"},
		{name: "own member", in: "groups:\n  - name: app:team\n    members: {add: [\"group:app:team\"]}\n", wantErr: "its own member"},
		{name: "added and removed", in: "groups:\n  - name: app:team\n    members: {add: [3], remove: [3]}\n", wantErr: "both added and removed"},
		{name: "missing holder", in: "privileges:\n  - object: folder:app\n    grant: {stem_admin: [\"group:app:ghost\"]}\n", wantErr: "holder group app:ghost"},
		{name: "missing object", in: "privileges:\n  - object: group:app:ghost\n    grant: {admin: [everyone]}\n", wantErr: "app:ghost: it does not exist"},
		{name: "composite cycle", in: "groups:\n  - {name: app:p, composite: {op: union, factors: [app:q, app:team]}}\n  - {name: app:q, composite: {op: union, factors: [app:p, app:team]}}\n", wantErr: "depend on each other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := mustParse(t, tc.in)
			if err := spec.Validate(); err != nil {
				t.Fatal(err)
			}
			p, err := Compute(spec, live())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, a := range p.Actions {
				got = append(got, strings.TrimSpace(a.Kind+" "+a.Name+" "+a.Detail))
			}
			if !reflect.DeepEqual(got, tc.want) && !(len(got) == 0 && len(tc.want) == 0) {
				t.Errorf("actions:\n got %q\nwant %q", got, tc.want)
			}
			if tc.wantSame != 0 && p.Unchanged != tc.wantSame {
				t.Errorf("unchanged = %d, want %d", p.Unchanged, tc.wantSame)
			}
		})
	}
}

func TestCompute_ExistingPrivilegeRowsAreNotGrantedAgain(t *testing.T) {
	l := live()
	l.Privs["f-app"] = []LivePriv{
		{Privilege: "stem_admin", HolderType: "group", HolderID: "g-staff", AppliesTo: "self", Scope: "self"},
		{Privilege: "stem_admin", HolderType: "group", HolderID: "g-staff", AppliesTo: "folders", Scope: "sub"},
		{Privilege: "create", HolderType: "identity", HolderID: "4", AppliesTo: "self", Scope: "self"},
	}
	spec := mustParse(t, `
privileges:
  - object: folder:app
    grant: {stem_admin: ["group:app:staff"], create: ["identity:4", "identity:5"], scope: sub}
`)
	p, err := Compute(spec, l)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range p.Actions {
		got = append(got, a.Detail)
	}
	want := []string{"create to identity:4 (inherited by folders, scope sub)", "create to identity:5", "create to identity:5 (inherited by folders, scope sub)"}
	if !reflect.DeepEqual(got, want) || p.Unchanged != 3 {
		t.Errorf("got %q (unchanged %d), want %q (3)", got, p.Unchanged, want)
	}
}

func TestIdempotencyKey(t *testing.T) {
	id1, id2 := int64(1), int64(2)
	a := idempotencyKey("g", []batchAdd{{Identity: &id1}, {Identity: &id2}}, []string{"7"}, "")
	b := idempotencyKey("g", []batchAdd{{Identity: &id2}, {Identity: &id1}}, []string{"7"}, "")
	if a != b {
		t.Error("the key depends on the order of the operations")
	}
	for name, other := range map[string]string{
		"group":   idempotencyKey("h", []batchAdd{{Identity: &id1}, {Identity: &id2}}, []string{"7"}, ""),
		"members": idempotencyKey("g", []batchAdd{{Identity: &id1}}, []string{"7"}, ""),
		"remove":  idempotencyKey("g", []batchAdd{{Identity: &id1}, {Identity: &id2}}, []string{"8"}, ""),
		"run":     idempotencyKey("g", []batchAdd{{Identity: &id1}, {Identity: &id2}}, []string{"7"}, "again"),
		"kind":    idempotencyKey("g", []batchAdd{{Group: "1"}, {Identity: &id2}}, []string{"7"}, ""),
	} {
		if other == a {
			t.Errorf("the key does not depend on the %s", name)
		}
	}
	if !strings.HasPrefix(a, "plan-") || len(a) != 45 {
		t.Errorf("key %q", a)
	}
}

func TestRoundTrip_MarshalParse(t *testing.T) {
	in := mustParse(t, `
folders:
  - {name: app, display_name: App}
groups:
  - name: app:g
    type: role
    members: {add: [1, "group:app:h"], remove: [2]}
  - name: app:c
    composite: {op: complement, factors: [app:g, app:h]}
privileges:
  - object: folder:app
    grant: {stem_admin: ["group:app:h"], create: [everyone], scope: sub}
  - object: group:app:g
    grant: {admin: ["identity:1"]}
`)
	b, err := Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip changed the plan:\n%s", b)
	}
}

func golden(t *testing.T, name string, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) // #nosec G304 -- a fixed path under testdata
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s differs from its golden file (go test -update rewrites it):\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func TestRender_Golden(t *testing.T) {
	spec := mustParse(t, `
folders:
  - {name: app}
  - name: app:foo
    template: application
    params: {admins: "app:staff"}
groups:
  - name: app:team
    members: {add: [1, 3, "group:app:foo:service:policy:foo_user_allow_manual"], remove: [2]}
`)
	spec, err := Expand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := Compute(spec, live())
	if err != nil {
		t.Fatal(err)
	}
	imp := &Impact{Added: 2, Removed: 1, Simulated: 2, Skipped: 1, Chunks: 1, Groups: []ImpactGroup{
		{ID: "g-team", Name: "app:team", Targeted: true, Before: 2, After: 3, Added: 2, Removed: 1},
		{ID: "g-staff", Name: "app:staff", Before: 4, After: 5, Added: 1}}}
	var b bytes.Buffer
	if err := Render(&b, p, imp); err != nil {
		t.Fatal(err)
	}
	golden(t, "plan_with_impact", b.String())

	b.Reset()
	if err := Render(&b, &Plan{Unchanged: 7}, nil); err != nil {
		t.Fatal(err)
	}
	golden(t, "plan_empty", b.String())

	// a plan with only existing groups: impact, no skipped changes
	b.Reset()
	one, err := Compute(mustParse(t, "groups:\n  - name: app:team\n    members: {add: [3]}\n"), live())
	if err != nil {
		t.Fatal(err)
	}
	if err := Render(&b, one, &Impact{Added: 1, Simulated: 1, Chunks: 3, Truncated: true,
		Groups: []ImpactGroup{{Name: "app:team\x1b[31m", Targeted: true, Before: 3, After: 4, Added: 1}}}); err != nil {
		t.Fatal(err)
	}
	golden(t, "plan_chunked", b.String())
}

func TestAPIError(t *testing.T) {
	e := &APIError{Status: 409, Code: "name_taken", Message: "app:x exists\x1b[0m"}
	if got := e.Error(); got != "the server answered 409 name_taken: app:x exists[0m" {
		t.Errorf("Error() = %q", got)
	}
	var ae *APIError
	if !errors.As(error(e), &ae) {
		t.Error("not an APIError")
	}
}
