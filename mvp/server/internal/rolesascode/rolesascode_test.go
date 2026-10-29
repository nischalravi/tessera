package rolesascode_test

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/rolesascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The world is the tiny fixture in tenant B (see internal/roles/roles_test.go): alice and carol are in
// Engineering, bob in Finance, dave is terminated.

type world struct {
	t   *testing.T
	f   *storetest.Fixture
	pat roles.Actor
	now time.Time
	opt rolesascode.Options
}

func newWorld(t *testing.T) *world {
	t.Helper()
	f := storetest.TwoTenants(t)
	w := &world{t: t, f: f, now: storetest.Now, opt: rolesascode.Options{Tenant: f.B.Slug}}
	w.tx(func(c *store.TenantTx) error {
		pu := &store.PlatformUser{DisplayName: "Pat", CreatedAt: w.now}
		if err := c.InsertPlatformUser(pu); err != nil {
			return err
		}
		w.pat = roles.Actor{UserID: pu.ID, Display: "Pat"}
		return nil
	})
	return w
}

func (w *world) tx(fn func(c *store.TenantTx) error) {
	w.t.Helper()
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, fn); err != nil {
		w.t.Fatal(err)
	}
}

// ent is the system:name of a fixture group.
func (w *world) ent(xid string) string {
	w.t.Helper()
	var out string
	w.tx(func(c *store.TenantTx) error {
		gs, err := c.Groups()
		if err != nil {
			return err
		}
		for _, g := range gs {
			if w.f.B.IDs["group:"+xid] == g.ID {
				out = g.System + ":" + g.Name
			}
		}
		return nil
	})
	if out == "" {
		w.t.Fatalf("no group %s", xid)
	}
	return out
}

func (w *world) gid(xid string) int64 { return w.f.B.IDs["group:"+xid] }

func (w *world) export() policybundle.Files {
	w.t.Helper()
	var files policybundle.Files
	w.tx(func(c *store.TenantTx) (err error) { files, err = rolesascode.Export(c, w.f.B.Slug); return })
	return files
}

func (w *world) plan(files policybundle.Files) (*rolesascode.Plan, error) {
	var p *rolesascode.Plan
	var err error
	w.tx(func(c *store.TenantTx) error { p, err = rolesascode.Build(c, files, w.opt, w.now); return nil })
	return p, err
}

func (w *world) apply(files policybundle.Files, want string) (*rolesascode.Plan, error) {
	var p *rolesascode.Plan
	var err error
	w.tx(func(c *store.TenantTx) error {
		p, err = rolesascode.Apply(c, files, w.opt, rolesascode.Ref{Commit: "abc123"}, want, w.pat, w.now)
		return nil // the caller's transaction commits whatever the writers did; a real caller returns the error
	})
	return p, err
}

func code(err error) string {
	var e *roles.Error
	if errors.As(err, &e) {
		return e.Code
	}
	var inv *rolesascode.InvalidError
	if errors.As(err, &inv) {
		cs := []string{}
		for _, d := range inv.Diags {
			cs = append(cs, d.Code)
		}
		return "invalid_bundle:" + strings.Join(cs, ",")
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return ""
}

func (w *world) engSpec() roles.Spec {
	return roles.Spec{Name: "Engineer", Description: "Day-one engineering access", Risk: "medium", Requestable: true,
		Birthright:   &roles.Rule{Department: []string{"Engineering"}, Type: []string{"human"}},
		Entitlements: []int64{w.gid("okta:eng"), w.gid("okta:platform")}}
}

func (w *world) create(s roles.Spec) *roles.Result {
	w.t.Helper()
	var res *roles.Result
	w.tx(func(c *store.TenantTx) (err error) { res, err = roles.Create(c, s, w.pat, false, w.now); return })
	return res
}

func bundle(tenant, manage string, roleYAML map[string]string, cedar map[string]string) policybundle.Files {
	f := policybundle.Files{"tessera.yaml": []byte("schema: tessera.repo/v1\ntenant: " + tenant + "\nmanage:\n  roles: " + manage + "\n")}
	for k, v := range roleYAML {
		f["roles/"+k+".yaml"] = []byte(v)
	}
	for k, v := range cedar {
		f["birthright/"+k+".cedar"] = []byte(v)
	}
	return f
}

func TestRoundTrip(t *testing.T) {
	w := newWorld(t)
	owner := w.f.B.IDs["carol"]
	s := w.engSpec()
	s.OwnerIdentityID = &owner
	w.create(s)
	w.create(roles.Spec{Name: "Payments clerk (read only)", Risk: "low", Entitlements: []int64{w.gid("okta:payments-clerks")}})

	files := w.export()
	for _, p := range []string{"tessera.yaml", "roles/engineer.yaml", "roles/payments-clerk-read-only.yaml", "birthright/engineer.cedar"} {
		if files[p] == nil {
			t.Fatalf("export has no %s; has %v", p, keys(files))
		}
	}
	if files["birthright/payments-clerk-read-only.cedar"] != nil {
		t.Error("a role with no rule got a birthright file")
	}
	if _, diags := policybundle.Load(files, nil); len(diags) > 0 {
		t.Fatalf("the export does not load: %v\n%s", diags, files["birthright/engineer.cedar"])
	}

	// planning the export against the state it came from changes nothing
	p, err := w.plan(files)
	if err != nil {
		t.Fatal(err)
	}
	if p.Unchanged != 2 || p.Created+p.Updated != 0 || p.Steps != 0 {
		t.Fatalf("round trip plan = %+v", p)
	}
	// applying it writes no version and no role, and exporting again gives the same bytes
	if _, err := w.apply(files, p.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	if again := w.export(); !reflect.DeepEqual(again, files) {
		t.Errorf("export is not stable:\n%v\n%v", keys(files), keys(again))
	}
	w.tx(func(c *store.TenantTx) error {
		r, err := c.BusinessRoleByKey("engineer")
		if err != nil || r.Version != 1 {
			t.Errorf("engineer = %+v, %v; want version 1", r, err)
		}
		return nil
	})
}

// A role granting a group whose name has a space exports to a bundle that loads and plans back as unchanged
// (issue #729: "workday:AP Clerk" was refused as a reference).
func TestRoundTripGroupNameWithSpace(t *testing.T) {
	w := newWorld(t)
	var gid int64
	w.tx(func(c *store.TenantTx) error {
		if err := c.UpsertGroup(&store.Group{TenantID: w.f.B.ID, System: "workday", ExternalID: "ap-clerk", Name: "AP Clerk", Kind: "group"}); err != nil {
			return err
		}
		g, err := c.GroupByXID("workday", "ap-clerk")
		if err == nil {
			gid = g.ID
		}
		return err
	})
	w.create(roles.Spec{Name: "Finance operations", Risk: "high", Entitlements: []int64{gid, w.gid("okta:payments-clerks")}})
	files := w.export()
	if _, diags := policybundle.Load(files, nil); len(diags) > 0 {
		t.Fatalf("the export does not load: %v\n%s", diags, files["roles/finance-operations.yaml"])
	}
	p, err := w.plan(files)
	if err != nil {
		t.Fatal(err)
	}
	if p.Unchanged != 1 || p.Created+p.Updated != 0 || p.Steps != 0 {
		t.Fatalf("round trip plan = %+v", p)
	}
}

func keys(f policybundle.Files) []string {
	var out []string
	for k := range f {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// A bundle's plan for a new role is the plan the UI path shows for the same change, and applying it saves what
// the UI would, with the repository change as the policy_ref of the version.
func TestPlanMatchesUIChange(t *testing.T) {
	w := newWorld(t)
	spec := w.engSpec()
	var ui *roles.Result
	w.tx(func(c *store.TenantTx) (err error) { ui, err = roles.Create(c, spec, w.pat, true, w.now); return })

	files := bundle(w.f.B.Slug, "partial", map[string]string{"engineer": `schema: tessera.role/v1
key: engineer
name: Engineer
description: Day-one engineering access
risk: medium
requestable: true
entitlements: [` + w.ent("okta:eng") + `, ` + w.ent("okta:platform") + `]
`}, map[string]string{"engineer": `@id("engineer-birthright")
@role("engineer")
permit (principal is Tessera::Identity, action == Tessera::Action::"birthright", resource == Tessera::Role::"engineer")
when { principal.status == "active" && principal has department && ["Engineering"].contains(principal.department)
       && ["human"].contains(principal.type) };
`})
	p, err := w.plan(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Roles) != 1 || p.Roles[0].Action != "create" || p.Created != 1 {
		t.Fatalf("plan = %+v", p)
	}
	got := p.Roles[0]
	if got.Adds != ui.Plan.Adds || got.Members != ui.Plan.Members || got.Removes != ui.Plan.Removes || got.Missing != ui.Plan.Missing {
		t.Errorf("bundle plan %+v differs from the UI plan %+v", got, ui.Plan)
	}
	want := append([]roles.Step(nil), ui.Plan.Steps...)
	for i := range want {
		want[i].RoleID = ""
	}
	if !reflect.DeepEqual(got.Steps, want) {
		t.Errorf("steps differ:\nbundle %+v\nUI     %+v", got.Steps, want)
	}
	// planning twice is the same plan (the digest does not depend on the id a new role would get)
	if p2, _ := w.plan(files); p2 == nil || p2.PlanSHA256 != p.PlanSHA256 || len(p.PlanSHA256) != 64 {
		t.Errorf("plan digest not stable: %v", p2)
	}
	w.tx(func(c *store.TenantTx) error {
		if rs, _ := c.BusinessRoles(); len(rs) != 0 {
			t.Errorf("a plan saved %d roles", len(rs))
		}
		return nil
	})

	if _, err := w.apply(files, p.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	w.tx(func(c *store.TenantTx) error {
		r, err := c.BusinessRoleByKey("engineer")
		if err != nil {
			t.Fatal(err)
		}
		if r.Name != "Engineer" || r.Version != 1 || r.Status != store.RoleActive {
			t.Errorf("role = %+v", r)
		}
		vs, err := c.RoleVersions(r.ID)
		if err != nil || len(vs) != 1 || vs[0].PolicyRef == nil {
			t.Fatalf("versions = %v, %v", vs, err)
		}
		if ref := *vs[0].PolicyRef; !strings.Contains(ref, `"commit":"abc123"`) || !strings.Contains(ref, `"path":"roles/engineer.yaml"`) ||
			!strings.Contains(ref, `"bundle_sha256":"`+p.BundleSHA256+`"`) {
			t.Errorf("policy_ref = %s", ref)
		}
		evs, err := c.AuditLog(10)
		if err != nil {
			t.Fatal(err)
		}
		seen := false
		for _, e := range evs {
			seen = seen || e.Action == "policy.roles.applied"
		}
		if !seen {
			t.Errorf("no policy.roles.applied event in %v", evs)
		}
		return nil
	})
	// a second apply of the same bundle is a plan of no changes
	if p2, err := w.plan(files); err != nil || p2.Unchanged != 1 || p2.Steps != 0 {
		t.Errorf("after apply: %+v, %v", p2, err)
	}
}

// An update through a bundle shows the plan roles.Update shows for the same spec.
func TestUpdatePlanMatchesUI(t *testing.T) {
	w := newWorld(t)
	base := w.engSpec()
	base.Key = "engineer"
	res := w.create(base)

	next := base
	next.Entitlements = []int64{w.gid("okta:eng"), w.gid("okta:platform"), w.gid("okta:payments-clerks")}
	var ui *roles.Result
	w.tx(func(c *store.TenantTx) (err error) {
		ui, err = roles.Update(c, res.Role.ID, 1, next, w.pat, true, w.now)
		return
	})

	files := w.export()
	var doc policybundle.Role
	if err := yaml.Unmarshal(files["roles/engineer.yaml"], &doc); err != nil {
		t.Fatal(err)
	}
	doc.Entitlements = append(doc.Entitlements, w.ent("okta:payments-clerks"))
	b, _ := yaml.Marshal(doc)
	files["roles/engineer.yaml"] = b

	p, err := w.plan(files)
	if err != nil {
		t.Fatal(err)
	}
	if p.Updated != 1 || p.Roles[0].Action != "update" || p.Roles[0].RoleID != res.Role.ID {
		t.Fatalf("plan = %+v", p)
	}
	if !reflect.DeepEqual(p.Roles[0].Steps, ui.Plan.Steps) || p.Roles[0].Adds != ui.Plan.Adds {
		t.Errorf("bundle steps %+v\nUI steps     %+v", p.Roles[0].Steps, ui.Plan.Steps)
	}
	if _, err := w.apply(files, p.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	w.tx(func(c *store.TenantTx) error {
		r, _ := c.BusinessRoleByKey("engineer")
		vs, _ := c.RoleVersions(r.ID)
		if r.Version != 2 || len(vs) != 2 || vs[0].PolicyRef == nil || vs[1].PolicyRef != nil {
			t.Errorf("role v%d, versions %v: want v2 with a policy_ref on the new version only", r.Version, vs)
		}
		return nil
	})
}

func TestApplyRefusesAStalePlan(t *testing.T) {
	w := newWorld(t)
	w.create(w.engSpec())
	files := w.export()
	var doc policybundle.Role
	if err := yaml.Unmarshal(files["roles/engineer.yaml"], &doc); err != nil {
		t.Fatal(err)
	}
	doc.Risk = "high"
	files["roles/engineer.yaml"], _ = yaml.Marshal(doc)
	p, err := w.plan(files)
	if err != nil {
		t.Fatal(err)
	}
	var err2 error
	w.tx(func(c *store.TenantTx) error {
		_, err2 = rolesascode.Apply(c, files, w.opt, rolesascode.Ref{Commit: "c1"}, strings.Repeat("0", 64), w.pat, w.now)
		return nil
	})
	if code(err2) != "stale_plan" {
		t.Fatalf("apply with a wrong plan digest = %v; want stale_plan", err2)
	}
	w.tx(func(c *store.TenantTx) error {
		if r, _ := c.BusinessRoleByKey("engineer"); r.Risk != "medium" || r.Version != 1 {
			t.Errorf("a refused apply changed the role: %+v", r)
		}
		return nil
	})
	// the bundle is part of the plan: another bundle, or the same one after the state moved, is not the approved plan
	other := policybundle.Files{}
	for k, v := range files {
		other[k] = v
	}
	other["roles/engineer.yaml"] = []byte(strings.Replace(string(files["roles/engineer.yaml"]), "risk: high", "risk: low", 1))
	if _, err := w.apply(other, p.PlanSHA256); code(err) != "stale_plan" {
		t.Errorf("apply of another bundle with the approved digest = %v; want stale_plan", err)
	}
	if _, err := w.apply(files, p.PlanSHA256); err != nil {
		t.Fatalf("apply of the planned bundle: %v", err)
	}
	if _, err := w.apply(files, p.PlanSHA256); code(err) != "stale_plan" {
		t.Errorf("a second apply of the same plan = %v; want stale_plan (the role moved on)", err)
	}
}

func TestPlanTooLargeAndDeletionGuard(t *testing.T) {
	w := newWorld(t)
	base := w.engSpec()
	base.Key = "engineer"
	w.create(base)

	files := w.export()
	var doc policybundle.Role
	if err := yaml.Unmarshal(files["roles/engineer.yaml"], &doc); err != nil {
		t.Fatal(err)
	}
	// more grants than the ceiling
	doc.Entitlements = append(doc.Entitlements, w.ent("okta:payments-clerks"), w.ent("okta:payments-approvers"))
	files["roles/engineer.yaml"], _ = yaml.Marshal(doc)
	w.opt.MaxSteps = 1
	if _, err := w.plan(files); code(err) != "plan_too_large" {
		t.Errorf("MaxSteps 1: %v; want plan_too_large", err)
	}
	if _, err := w.apply(files, strings.Repeat("0", 64)); code(err) != "plan_too_large" {
		t.Errorf("apply over the ceiling: %v; want plan_too_large", err)
	}
	w.opt.MaxSteps = 0
	if _, err := w.plan(files); err != nil {
		t.Fatalf("under the default ceiling: %v", err)
	}

	// removing an entitlement removes members' grants; a deletion guard that allows none refuses it
	files = w.export()
	if err := yaml.Unmarshal(files["roles/engineer.yaml"], &doc); err != nil {
		t.Fatal(err)
	}
	doc.Entitlements = []string{w.ent("okta:eng")}
	files["roles/engineer.yaml"], _ = yaml.Marshal(doc)
	p, err := w.plan(files)
	if err != nil || p.Removes == 0 {
		t.Fatalf("plan = %+v, %v; want removals", p, err)
	}
	zero := 0
	w.tx(func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: deleteguard.CatMembers, MaxCount: &zero, WindowMinutes: 60,
			Mode: deleteguard.ModeHoldExcess}, nil, w.now)
	})
	if _, err := w.plan(files); code(err) != "deletion_guard" {
		t.Errorf("with a guard of 0: %v; want deletion_guard", err)
	}
	if _, err := w.apply(files, p.PlanSHA256); code(err) != "deletion_guard" {
		t.Errorf("apply with a guard of 0: %v; want deletion_guard", err)
	}
}

func TestInvalidBundles(t *testing.T) {
	w := newWorld(t)
	w.create(w.engSpec())
	role := func(key, extra string) string {
		return "schema: tessera.role/v1\nkey: " + key + "\nname: " + key + "\nrisk: low\nentitlements: [" + w.ent("okta:eng") + "]\n" + extra
	}
	cedar := func(body string) string {
		return `@id("r-b") @role("r")
permit (principal is Tessera::Identity, action == Tessera::Action::"birthright", resource == Tessera::Role::"r")
when { ` + body + ` };
`
	}
	cases := []struct {
		name  string
		files policybundle.Files
		want  string
	}{
		{"another tenant's slug", bundle("globex", "partial", map[string]string{"r": role("r", "")}, nil), "tenant_mismatch"},
		{"full mode", bundle(w.f.B.Slug, "full", map[string]string{"r": role("r", "")}, nil), "unsupported_mode"},
		{"unknown group", bundle(w.f.B.Slug, "partial", map[string]string{"r": strings.Replace(role("r", ""), w.ent("okta:eng"), "okta:no-such-group", 1)}, nil), "unknown_entitlement"},
		{"unknown owner", bundle(w.f.B.Slug, "partial", map[string]string{"r": role("r", "owner: nobody\n")}, nil), "unknown_owner"},
		{"name used by a role with another key", bundle(w.f.B.Slug, "partial", map[string]string{"r": strings.Replace(role("r", ""), "name: r", "name: Engineer", 1)}, nil), "name_taken"},
		{"or in a rule", bundle(w.f.B.Slug, "partial", map[string]string{"r": role("r", "")},
			map[string]string{"r": cedar(`principal.status == "active" && principal has department && principal has title && (["a"].contains(principal.department) || ["b"].contains(principal.title))`)}), "unsupported_birthright"},
		{"attrs in a rule", bundle(w.f.B.Slug, "partial", map[string]string{"r": role("r", "")},
			map[string]string{"r": cedar(`principal.status == "active" && principal.attrs has cost_center && principal.attrs.cost_center == "4410"`)}), "unsupported_birthright"},
		{"no status test", bundle(w.f.B.Slug, "partial", map[string]string{"r": role("r", "")},
			map[string]string{"r": cedar(`principal has department && ["a"].contains(principal.department)`)}), "unsupported_birthright"},
		{"no conditions", bundle(w.f.B.Slug, "partial", map[string]string{"r": role("r", "")},
			map[string]string{"r": cedar(`principal.status == "active"`)}), "empty_birthright"},
		{"unknown identity type", bundle(w.f.B.Slug, "partial", map[string]string{"r": role("r", "")},
			map[string]string{"r": cedar(`principal.status == "active" && ["robot"].contains(principal.type)`)}), "invalid_rule"},
		{"unknown attribute policy", bundle(w.f.B.Slug, "partial", map[string]string{"r": role("r", "")},
			map[string]string{"r": strings.Replace(cedar(`principal.status == "active"`), `@role("r")`, `@role("r") @abac("nope")`, 1)}), "unknown_abac_policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := w.plan(tc.files)
			if got := code(err); !strings.Contains(got, tc.want) {
				t.Errorf("code = %q; want it to include %q (%v)", got, tc.want, err)
			}
		})
	}
}

// The attribute policy a rule names survives export and plan.
func TestBirthrightNamingAnAttributePolicy(t *testing.T) {
	w := newWorld(t)
	var pid string
	w.tx(func(c *store.TenantTx) error {
		p := &store.AbacPolicy{ID: "p1", Name: "Cost centre 4410", Condition: `{"attr":"identity.department","op":"eq","value":"Engineering"}`,
			Status: store.AbacActive, Version: 1, CreatedAt: w.now, UpdatedAt: w.now}
		pid = p.ID
		return c.InsertAbacPolicy(p)
	})
	s := w.engSpec()
	s.Birthright = &roles.Rule{Department: []string{"Engineering"}, Policy: pid}
	w.create(s)
	files := w.export()
	if c := string(files["birthright/engineer.cedar"]); !strings.Contains(c, `@abac("Cost centre 4410")`) {
		t.Fatalf("export lost the attribute policy:\n%s", c)
	}
	p, err := w.plan(files)
	if err != nil || p.Unchanged != 1 {
		t.Fatalf("round trip plan = %+v, %v", p, err)
	}
}

func TestBundleDigestIsContentAndPath(t *testing.T) {
	a := policybundle.Files{"a": []byte("xy"), "b": []byte("z")}
	b := policybundle.Files{"a": []byte("x"), "b": []byte("yz")}
	if rolesascode.Digest(a) == rolesascode.Digest(b) {
		t.Error("shifting a byte between files left the digest unchanged")
	}
	if rolesascode.Digest(a) != rolesascode.Digest(policybundle.Files{"b": []byte("z"), "a": []byte("xy")}) {
		t.Error("the digest depends on map order")
	}
}
