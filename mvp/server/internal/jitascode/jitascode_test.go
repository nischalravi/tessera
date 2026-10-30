package jitascode_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/jitascode"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The world is the tiny fixture in tenant B: alice is in okta:eng, bob in okta:payments-clerks and
// okta:payments-approvers, carol in okta:platform and okta:eng; aws:ProdAdmin is requestable.

type world struct {
	t   *testing.T
	f   *storetest.Fixture
	pat roles.Actor
	now time.Time
	opt jitascode.Options
}

func newWorld(t *testing.T) *world {
	t.Helper()
	f := storetest.TwoTenants(t)
	w := &world{t: t, f: f, now: storetest.Now, opt: jitascode.Options{Tenant: f.B.Slug}}
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
		for _, g := range gs {
			if w.f.B.IDs["group:"+xid] == g.ID {
				out = g.System + ":" + g.Name
			}
		}
		return err
	})
	if out == "" {
		w.t.Fatalf("no group %s", xid)
	}
	return out
}

func (w *world) export() policybundle.Files {
	w.t.Helper()
	var files policybundle.Files
	w.tx(func(c *store.TenantTx) (err error) { files, err = jitascode.Export(c, w.f.B.Slug); return })
	return files
}

func (w *world) plan(files policybundle.Files) (*jitascode.Plan, error) {
	var p *jitascode.Plan
	var err error
	w.tx(func(c *store.TenantTx) error { p, err = jitascode.Build(c, files, w.opt); return nil })
	return p, err
}

func (w *world) apply(files policybundle.Files, want string) (*jitascode.Plan, error) {
	var p *jitascode.Plan
	var err error
	w.tx(func(c *store.TenantTx) error {
		p, err = jitascode.Apply(c, files, w.opt, jitascode.Ref{Commit: "abc123"}, want, w.pat, w.now)
		return nil // the caller's transaction commits whatever the writers did; a real caller returns the error
	})
	return p, err
}

// applyPlanned plans and applies a bundle as the approver would.
func (w *world) applyPlanned(files policybundle.Files) *jitascode.Plan {
	w.t.Helper()
	p, err := w.plan(files)
	if err != nil {
		w.t.Fatalf("plan: %v", err)
	}
	if _, err := w.apply(files, p.PlanSHA256); err != nil {
		w.t.Fatalf("apply: %v", err)
	}
	return p
}

func code(err error) string {
	var e *roles.Error
	if errors.As(err, &e) {
		return e.Code
	}
	var inv *jitascode.InvalidError
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

func list(l ...string) string { return "[" + strings.Join(l, ", ") + "]" }

// rule is a jit/<key>.yaml document.
func rule(key string, principals, entitlements, approvers []string, hours int, extra string) string {
	s := "schema: tessera.jit/v1\nkey: " + key + "\nprincipals: " + list(principals...) + "\nentitlements: " + list(entitlements...) +
		"\nmax_hours: " + string(rune('0'+hours/10)) + string(rune('0'+hours%10)) + "\n"
	if approvers != nil {
		s += "approvers: " + list(approvers...) + "\n"
	}
	return s + extra
}

func bundle(tenant, mode, enforce string, rules map[string]string) policybundle.Files {
	cfg := "schema: tessera.repo/v1\ntenant: " + tenant + "\n"
	if mode != "" {
		cfg += "manage:\n  jit: " + mode + "\n"
	}
	if enforce != "" {
		cfg += "jit_enforce: " + enforce + "\n"
	}
	f := policybundle.Files{"tessera.yaml": []byte(cfg)}
	for k, v := range rules {
		f["jit/"+k+".yaml"] = []byte(v)
	}
	return f
}

func (w *world) baseline() policybundle.Files {
	return bundle(w.f.B.Slug, "partial", "true", map[string]string{
		"prod-admin": rule("prod-admin", []string{w.ent("okta:eng")}, []string{w.ent("aws:ProdAdmin")},
			[]string{w.ent("okta:platform")}, 4, "min_approvals: 1\nstep_up: true\n"),
	})
}

func TestPlanApplyExportRoundTrip(t *testing.T) {
	w := newWorld(t)
	files := w.baseline()
	p, err := w.plan(files)
	if err != nil {
		t.Fatal(err)
	}
	if p.Created != 1 || p.Steps != 4 || p.Enforcement.Current || !p.Enforcement.Wanted || len(p.PlanSHA256) != 64 {
		t.Fatalf("plan = %+v", p)
	}
	// a plan writes nothing
	w.tx(func(c *store.TenantTx) error {
		if es, err := c.JITEligibilities(); err != nil || len(es) != 0 {
			t.Errorf("a plan saved %v, %v", es, err)
		}
		if s, err := c.JITSettings(); err != nil || s.Enabled {
			t.Errorf("a plan turned enforcement on: %v, %v", s, err)
		}
		return nil
	})
	// a stale or wrong digest does not apply
	if _, err := w.apply(files, strings.Repeat("0", 64)); code(err) != "stale_plan" {
		t.Fatalf("apply with another digest: %v; want stale_plan", err)
	}
	if _, err := w.apply(files, p.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	w.tx(func(c *store.TenantTx) error {
		e, err := c.JITEligibilityByKey("prod-admin")
		if err != nil || e.MaxHours != 4 || e.MinApprovals != 1 || !e.StepUp || len(e.Principals) != 1 || len(e.Entitlements) != 1 || len(e.Approvers) != 1 {
			t.Fatalf("rule = %+v, %v", e, err)
		}
		vs, err := c.JITEligibilityVersions(e.ID)
		if err != nil || len(vs) != 1 || vs[0].PolicyRef == nil || !strings.Contains(*vs[0].PolicyRef, `"commit":"abc123"`) ||
			!strings.Contains(*vs[0].PolicyRef, `"path":"jit/prod-admin.yaml"`) {
			t.Errorf("versions = %v, %v; want one with the commit and path as its policy_ref", vs, err)
		}
		if s, err := c.JITSettings(); err != nil || !s.Enabled {
			t.Errorf("settings = %v, %v; want enforcement on", s, err)
		}
		return nil
	})
	// the plan was made against the old state: it is stale now
	if _, err := w.apply(files, p.PlanSHA256); code(err) != "stale_plan" {
		t.Errorf("a plan applied twice: %v", err)
	}
	// export, then plan the export: no changes (the round trip)
	exp := w.export()
	if exp["jit/prod-admin.yaml"] == nil || !strings.Contains(string(exp["tessera.yaml"]), "jit_enforce: true") {
		t.Fatalf("export = %v", exp)
	}
	again, err := w.plan(exp)
	if err != nil {
		t.Fatal(err)
	}
	if again.Unchanged != 1 || again.Created+again.Updated+again.Retired != 0 || again.Steps != 0 || again.Enforcement.Current != again.Enforcement.Wanted {
		t.Fatalf("round trip plan = %+v", again)
	}
	// a change plans as an update that names what moved
	changed := w.baseline()
	changed["jit/prod-admin.yaml"] = []byte(rule("prod-admin", []string{w.ent("okta:eng")}, []string{w.ent("aws:ProdAdmin")},
		[]string{w.ent("okta:platform"), w.ent("okta:payments-approvers")}, 2, "min_approvals: 1\nstep_up: true\n"))
	up, err := w.plan(changed)
	if err != nil || up.Updated != 1 || up.Rules[0].GroupsAdded != 1 || up.Rules[0].GroupsRemoved != 0 || up.Rules[0].Version != 2 {
		t.Fatalf("update plan = %+v, %v", up, err)
	}
}

// A group whose name has a space is a valid reference, and a rule naming one round-trips (lesson of issue #729).
func TestGroupNameWithSpace(t *testing.T) {
	w := newWorld(t)
	w.tx(func(c *store.TenantTx) error {
		return c.UpsertGroup(&store.Group{TenantID: w.f.B.ID, System: "workday", ExternalID: "ap-clerk", Name: "AP Clerk", Kind: "group"})
	})
	files := bundle(w.f.B.Slug, "partial", "", map[string]string{
		"ap": rule("ap", []string{w.ent("okta:eng")}, []string{"workday:AP Clerk"}, nil, 8, ""),
	})
	w.applyPlanned(files)
	exp := w.export()
	if !strings.Contains(string(exp["jit/ap.yaml"]), "workday:AP Clerk") {
		t.Fatalf("export = %s", exp["jit/ap.yaml"])
	}
	p, err := w.plan(exp)
	if err != nil || p.Unchanged != 1 || p.Steps != 0 {
		t.Fatalf("round trip plan = %+v, %v", p, err)
	}
}

func TestInvalidBundles(t *testing.T) {
	w := newWorld(t)
	eng, prod := w.ent("okta:eng"), w.ent("aws:ProdAdmin")
	ok := rule("r", []string{eng}, []string{prod}, nil, 4, "")
	cases := []struct {
		name  string
		files policybundle.Files
		want  string
	}{
		{"another tenant's slug", bundle("globex", "partial", "", map[string]string{"r": ok}), "tenant_mismatch"},
		{"jit not managed", bundle(w.f.B.Slug, "", "", map[string]string{"r": ok}), "not_managed"},
		{"unknown principal group", bundle(w.f.B.Slug, "partial", "", map[string]string{"r": rule("r", []string{"okta:nope"}, []string{prod}, nil, 4, "")}), "unknown_group"},
		{"another tenant's group name", bundle(w.f.B.Slug, "partial", "", map[string]string{"r": rule("r", []string{eng}, []string{"nowhere:ProdAdmin"}, nil, 4, "")}), "unknown_group"},
		{"more than 72 hours", bundle(w.f.B.Slug, "partial", "", map[string]string{"r": rule("r", []string{eng}, []string{prod}, nil, 73, "")}), "invalid_max_hours"},
		{"two approvals", bundle(w.f.B.Slug, "partial", "", map[string]string{"r": rule("r", []string{eng}, []string{prod}, []string{w.ent("okta:platform"), w.ent("okta:payments-clerks")}, 4, "min_approvals: 2\n")}), "unsupported_min_approvals"},
		{"no principals", bundle(w.f.B.Slug, "partial", "", map[string]string{"r": rule("r", nil, []string{prod}, nil, 4, "")}), "invalid_principals"},
		{"an unknown field", bundle(w.f.B.Slug, "partial", "", map[string]string{"r": ok + "elevate: true\n"}), "invalid"},
		{"a Cedar file under jit/", func() policybundle.Files {
			f := bundle(w.f.B.Slug, "partial", "", map[string]string{"r": ok})
			f["jit/extra.cedar"] = []byte(`@id("x") forbid (principal, action == Tessera::Action::"jit_request", resource);`)
			return f
		}(), "unexpected_file"},
		{"a Cedar file for a jit_request policy", func() policybundle.Files {
			f := bundle(w.f.B.Slug, "partial", "", map[string]string{"r": ok})
			f["birthright/x.cedar"] = []byte(`@id("x") @role("r") permit (principal, action == Tessera::Action::"jit_request", resource);`)
			return f
		}(), "invalid_bundle"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := w.plan(tc.files)
			got := code(err)
			if tc.want == "invalid_bundle" {
				if !strings.HasPrefix(got, "invalid_bundle:") {
					t.Fatalf("err = %v; want an invalid bundle", err)
				}
			} else if !strings.Contains(got, tc.want) {
				t.Fatalf("err = %v; want %s", got, tc.want)
			}
			if _, err := w.apply(tc.files, strings.Repeat("0", 64)); err == nil {
				t.Error("an invalid bundle applied")
			}
		})
	}
	w.tx(func(c *store.TenantTx) error {
		if es, err := c.JITEligibilities(); err != nil || len(es) != 0 {
			t.Errorf("an invalid bundle saved %v, %v", es, err)
		}
		return nil
	})
}

func TestFullModeRetiresAndGuards(t *testing.T) {
	w := newWorld(t)
	eng, prod, dev := w.ent("okta:eng"), w.ent("aws:ProdAdmin"), w.ent("aws:DevAdmin")
	both := bundle(w.f.B.Slug, "partial", "", map[string]string{
		"a": rule("a", []string{eng}, []string{prod}, nil, 4, ""),
		"b": rule("b", []string{eng}, []string{dev}, nil, 4, ""),
	})
	w.applyPlanned(both)
	// partial leaves a rule absent from the bundle alone
	onlyA := bundle(w.f.B.Slug, "partial", "", map[string]string{"a": rule("a", []string{eng}, []string{prod}, nil, 4, "")})
	if p, err := w.plan(onlyA); err != nil || p.Retired != 0 || p.Unchanged != 1 || p.ActiveAfter != 2 {
		t.Fatalf("partial plan = %+v, %v", p, err)
	}
	// full retires it (never deletes) and says what it removes
	full := bundle(w.f.B.Slug, "full", "", map[string]string{"a": rule("a", []string{eng}, []string{prod}, nil, 4, "")})
	p, err := w.plan(full)
	if err != nil || p.Retired != 1 || p.Removes != 3 || p.ActiveAfter != 1 {
		t.Fatalf("full plan = %+v, %v", p, err)
	}
	// a deletion guard that allows none refuses it outright, at plan and at apply
	zero := 0
	w.tx(func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: deleteguard.CatMembers, MaxCount: &zero, WindowMinutes: 60,
			Mode: deleteguard.ModeHoldExcess}, nil, w.now)
	})
	if _, err := w.plan(full); code(err) != "deletion_guard" {
		t.Errorf("with a guard of 0: %v; want deletion_guard", err)
	}
	if _, err := w.apply(full, p.PlanSHA256); code(err) != "deletion_guard" {
		t.Errorf("apply with a guard of 0: %v; want deletion_guard", err)
	}
	w.tx(func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: deleteguard.CatMembers, WindowMinutes: 60, Mode: deleteguard.ModeOff}, nil, w.now)
	})
	w.applyPlanned(full)
	w.tx(func(c *store.TenantTx) error {
		e, err := c.JITEligibilityByKey("b")
		if err != nil || e.Status != store.JITEligibilityRetired || e.Version != 2 || len(e.Principals) != 0 {
			t.Errorf("retired rule = %+v, %v; want retired at version 2 and kept", e, err)
		}
		if vs, err := c.JITEligibilityVersions(e.ID); err != nil || len(vs) != 2 {
			t.Errorf("versions = %v, %v; want both kept", vs, err)
		}
		return nil
	})
	// the export holds only the active rule; naming the retired one again reactivates it as version 3
	if exp := w.export(); exp["jit/b.yaml"] != nil || exp["jit/a.yaml"] == nil {
		t.Errorf("export after retire = %v", exp)
	}
	if p, err := w.plan(both); err != nil || p.Updated != 1 || p.Rules[1].Version != 3 {
		t.Errorf("reactivation plan = %+v, %v", p, err)
	}
}

func TestStepCeiling(t *testing.T) {
	w := newWorld(t)
	files := w.baseline()
	w.opt.MaxSteps = 3 // the rule is 4 writes
	if _, err := w.plan(files); code(err) != "plan_too_large" {
		t.Errorf("MaxSteps 3: %v; want plan_too_large", err)
	}
	if _, err := w.apply(files, strings.Repeat("0", 64)); code(err) != "plan_too_large" {
		t.Errorf("apply over the ceiling: %v; want plan_too_large", err)
	}
	w.opt.MaxSteps = 4
	if _, err := w.plan(files); err != nil {
		t.Errorf("at the ceiling: %v", err)
	}
}

// Enforcement with no active rule warns; turning it off again is a plan like any other.
func TestEnforcementSwitch(t *testing.T) {
	w := newWorld(t)
	on := bundle(w.f.B.Slug, "partial", "true", nil)
	p, err := w.plan(on)
	if err != nil || !p.Enforcement.Wanted || len(p.Warnings) < 2 {
		t.Fatalf("plan = %+v, %v; want warnings that every request is denied", p, err)
	}
	w.applyPlanned(on)
	if p, err := w.plan(bundle(w.f.B.Slug, "partial", "", nil)); err != nil || !p.Enforcement.Current || !p.Enforcement.Wanted {
		t.Errorf("a bundle that does not say leaves enforcement alone: %+v, %v", p, err)
	}
	off := bundle(w.f.B.Slug, "partial", "false", nil)
	w.applyPlanned(off)
	w.tx(func(c *store.TenantTx) error {
		if ok, err := jit.Enforced(c); err != nil || ok {
			t.Errorf("Enforced = %v, %v; want off", ok, err)
		}
		return nil
	})
}
