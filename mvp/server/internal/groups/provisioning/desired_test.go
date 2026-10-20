package provisioning

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func TestTemplates(t *testing.T) {
	long := strings.Repeat("x", 80)
	g := GroupData{ID: "g1", Name: "dept:eng:Admins", Extension: "Admins", DisplayName: "Dept : Eng : Admins", Folder: "dept:eng",
		Meta: map[string]string{"scope": "global"}}
	cases := []struct {
		name, tpl, want string
	}{
		{"name", `{{.Name}}`, "dept:eng:Admins"},
		{"lower and replace", `{{.Name | replace ":" "-" | lower}}`, "dept-eng-admins"},
		{"upper", `{{upper .Extension}}`, "ADMINS"},
		{"meta", `{{.Meta.scope}}-{{.Extension}}`, "global-Admins"},
		{"ldapEscape", `{{ldapEscape "Smith, John+#1"}}`, `Smith\, John\+#1`},
		{"ldapEscape edges", `{{ldapEscape " #x "}}`, `\ #x\ `},
		{"split is not in the set", `{{split "a b" " "}}`, ""},
		{"truncateHash short", `{{truncateHash 64 .Extension}}`, "Admins"},
		{"truncateHash long", `{{truncateHash 20 "` + long + `"}}`, strings.Repeat("x", 11) + "-" + hashOf(long)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tp, err := ParseTemplate("t", c.tpl)
			if c.want == "" { // a function outside the set
				if err == nil {
					t.Fatal("a template naming a function outside the set was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := tp.Render(g)
			if err != nil || got != c.want {
				t.Errorf("= %q, %v; want %q", got, err, c.want)
			}
		})
	}

	t.Run("join of a list", func(t *testing.T) {
		tp, err := ParseTemplate("t", `{{join "," .List}}`)
		if err != nil {
			t.Fatal(err)
		}
		got, err := tp.Render(struct{ List []string }{[]string{"a", "b"}})
		if err != nil || got != "a,b" {
			t.Errorf("= %q, %v", got, err)
		}
	})

	for name, tpl := range map[string]string{
		"no os access":       `{{call .X}}`,
		"unknown function":   `{{exec "ls"}}`,
		"unknown field":      `{{.Nope}}`,
		"missing meta key":   `{{.Meta.absent}}`,
		"bad truncate width": `{{truncateHash 2 .Name}}`,
		"control character":  "a\x01b",
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			tp, err := ParseTemplate("t", tpl)
			if err != nil {
				return
			}
			if got, err := tp.Render(g); err == nil {
				t.Errorf("%q ran and gave %q", tpl, got)
			}
		})
	}
	if _, err := ParseTemplate("t", strings.Repeat("a", maxTemplateBytes+1)); err == nil {
		t.Error("an oversize template was accepted")
	}
	tp, _ := ParseTemplate("t", `{{range $i := .Many}}{{$i}}{{end}}`)
	if _, err := tp.Render(struct{ Many []string }{strings.Split(strings.Repeat("0123456789,", 600), ",")}); err == nil {
		t.Error("an oversize output was accepted")
	}
	if got := TemplateFuncs(); len(got) != 6 {
		t.Errorf("function set = %v, want the six of the design", got)
	}
}

func hashOf(s string) string {
	out, _ := TruncateHash(12, s) // 3 characters and the hash
	return out[len(out)-8:]
}

func TestEscapeDN(t *testing.T) {
	for in, want := range map[string]string{
		"plain":   "plain",
		"a,b":     `a\,b`,
		`a"b\c`:   `a\"b\\c`,
		"a=b;c<d": `a\=b\;c\<d`,
		"#lead":   `\#lead`,
		" lead":   `\ lead`,
		"trail ":  `trail\ `,
		"nul\x00": `nul\00`,
		"ünï":     "ünï",
	} {
		if got := EscapeDN(in); got != want {
			t.Errorf("EscapeDN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormMember(t *testing.T) {
	for _, c := range []struct{ a, b string }{
		{"UID=Alice, OU=People ,DC=Example,dc=com", "uid=alice,ou=people,dc=example,dc=com"},
		{" U0 ", "u0"},
		{"user@Example.com", "user@example.com"},
	} {
		if NormMember(c.a) != NormMember(c.b) {
			t.Errorf("%q and %q should be one member", c.a, c.b)
		}
	}
	if NormMember("uid=a,dc=x") == NormMember("uid=b,dc=x") {
		t.Error("different members compare equal")
	}
}

// Marks are inherited dynamically: a sub mark on a folder covers everything below
// it, one covers only its own groups, include=false cuts a subtree or a group
// out, and the nearest mark wins.
func TestDesired_MarkInheritance(t *testing.T) {
	x := newHarness(t, 3)
	a := x.folder(x.root, "a")
	b := x.folder(a, "b")
	c := x.folder(b, "c")
	other := x.folder(x.root, "other")
	gA, gB, gC, gOther, gRoot := x.group(a, "ga"), x.group(b, "gb"), x.group(c, "gc"), x.group(other, "go"), x.group(x.root, "gr")
	p, _ := x.prov("p", `{}`)

	covered := func() map[string]string {
		out := map[string]string{}
		x.read(func(tx *store.TenantTx) error {
			prov, _ := tx.Provisioner(p.ID)
			cc, err := ParseCommon(prov.Config)
			if err != nil {
				t.Fatal(err)
			}
			d, err := Compute(tx, prov, cc, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, dg := range d.ByGroup {
				out[dg.NativeName] = dg.Why
			}
			return nil
		})
		return out
	}
	names := func(m map[string]string) string {
		var out []string
		for _, n := range []string{"gr", "a:ga", "a:b:gb", "a:b:c:gc", "other:go"} {
			if _, ok := m[n]; ok {
				out = append(out, n)
			}
		}
		return strings.Join(out, " ")
	}
	if got := names(covered()); got != "" {
		t.Fatalf("with no marks %q are provisioned", got)
	}

	x.mark(p.ID, MarkInput{ObjectType: "folder", ObjectID: string(a), Scope: "sub", Include: true})
	if got := names(covered()); got != "a:ga a:b:gb a:b:c:gc" {
		t.Errorf("sub mark on a: %q", got)
	}
	x.mark(p.ID, MarkInput{ObjectType: "folder", ObjectID: string(b), Scope: "sub", Include: false})
	if got := names(covered()); got != "a:ga" {
		t.Errorf("a sub opt-out on a:b: %q", got)
	}
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(gC), Include: true})
	if got := names(covered()); got != "a:ga a:b:c:gc" {
		t.Errorf("a group mark inside an opted-out subtree: %q", got)
	}
	x.mark(p.ID, MarkInput{ObjectType: "folder", ObjectID: string(b), Scope: "sub", Include: true})
	x.mark(p.ID, MarkInput{ObjectType: "group", ObjectID: string(gB), Include: false})
	if got := names(covered()); got != "a:ga a:b:c:gc" {
		t.Errorf("a group opt-out: %q", got)
	}
	if why := covered()["a:b:c:gc"]; why != "group mark" {
		t.Errorf("gc is covered by %q, want its own mark", why)
	}
	// scope one covers only the folder's own groups
	x.must(func(e model.Env) error {
		for _, m := range []struct{ t, id string }{{"folder", string(a)}, {"folder", string(b)}, {"group", string(gB)}, {"group", string(gC)}} {
			if err := x.svc.RemoveMark(e.Tx, x.now, "t", p.ID, m.t, m.id); err != nil {
				return err
			}
		}
		return nil
	})
	x.mark(p.ID, MarkInput{ObjectType: "folder", ObjectID: string(a), Scope: "one", Include: true})
	if got := names(covered()); got != "a:ga" {
		t.Errorf("scope one: %q", got)
	}
	x.mark(p.ID, MarkInput{ObjectType: "folder", ObjectID: string(x.root), Scope: "sub", Include: true})
	if got := names(covered()); got != "gr a:ga a:b:gb a:b:c:gc other:go" {
		t.Errorf("sub on the root: %q", got)
	}
	// marks are never copied onto groups
	x.read(func(tx *store.TenantTx) error {
		ms, _ := tx.ProvMarks(p.ID)
		for _, m := range ms {
			if m.ObjectType == "group" {
				t.Errorf("a group mark %s was created by inheritance", m.ObjectID)
			}
		}
		return nil
	})
	_, _ = gA, gOther
	_ = gRoot
}

func TestDesired_MembersAccountsAndConflicts(t *testing.T) {
	x := newHarness(t, 4)
	a, b := x.folder(x.root, "a"), x.folder(x.root, "b")
	g1, g2 := x.group(a, "eng"), x.group(b, "eng")
	solo := x.group(x.root, "solo")
	for _, i := range []int{0, 1, 2} {
		x.add(solo, x.idents[i])
	}
	// u2 loses its account in the target system
	x.must(func(e model.Env) error {
		accts, err := e.Tx.IdentityAccounts(x.idents[2])
		if err != nil {
			return err
		}
		return e.Tx.DisableAccount(accts[0].ID)
	})
	p, f := x.provWith("p", `{}`, map[string]any{"group_name": "{{.Extension}}"})
	x.mark(p.ID, MarkInput{ObjectType: "folder", ObjectID: string(x.root), Scope: "sub", Include: true})
	x.setMode(p.ID, store.ProvModeActive)

	var d *Desired
	x.read(func(tx *store.TenantTx) error {
		prov, _ := tx.Provisioner(p.ID)
		cc, _ := ParseCommon(prov.Config)
		var err error
		d, err = Compute(tx, prov, cc, nil)
		return err
	})
	dg := d.ByGroup[string(solo)]
	if dg == nil || strings.Join(dg.Members, ",") != "u0,u1" || len(dg.Unmapped) != 1 || dg.Unmapped[0] != x.idents[2] {
		t.Fatalf("solo = %+v, want members u0,u1 and u2 reported as unmapped", dg)
	}
	if len(d.Conflicts) != 1 || d.Conflicts[0].Name != "eng" || strings.Join(d.Conflicts[0].Groups, ",") != min(string(g1), string(g2))+","+max(string(g1), string(g2)) {
		t.Fatalf("conflicts = %+v", d.Conflicts)
	}
	if d.ByGroup[string(g1)] != nil || d.ByGroup[string(g2)] != nil {
		t.Error("a group whose target name collides is still provisioned")
	}

	// a sync provisions solo and leaves the colliding pair alone
	rep := x.full(p.ID)
	if rep.Summary.Unmapped != 1 || len(rep.Summary.Conflicts) != 1 {
		t.Errorf("summary = %+v", rep.Summary)
	}
	if got := f.names(); strings.Join(got, ",") != "solo" {
		t.Errorf("target groups = %v, want only solo", got)
	}

	// a disabled group is the empty set
	status := store.GroupDisabled
	x.must(func(e model.Env) error {
		_, err := e.UpdateGroup(solo, model.UpdateGroupInput{Status: &status})
		return err
	})
	x.full(p.ID)
	if got := f.members("solo"); len(got) != 0 {
		t.Errorf("a disabled group has members %v on the target", got)
	}
	if _, ok := f.groups["solo"]; !ok {
		t.Error("a disabled group is deleted instead of emptied")
	}

	// a template that fails keeps one group out and says why
	p2, _ := x.provWith("p2", `{}`, map[string]any{"group_name": "{{.Nope}}"})
	x.mark(p2.ID, MarkInput{ObjectType: "group", ObjectID: string(solo), Include: true})
	x.read(func(tx *store.TenantTx) error {
		prov, _ := tx.Provisioner(p2.ID)
		cc, _ := ParseCommon(prov.Config)
		d, err := Compute(tx, prov, cc, nil)
		if err != nil || len(d.ByGroup) != 0 || d.Errors[string(solo)] == "" {
			t.Errorf("desired = %+v, %v; want a template error for solo", d, err)
		}
		return nil
	})
}
