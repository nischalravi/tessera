package agentscopeascode_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agentscope"
	"github.com/nischalravi/tessera/mvp/server/internal/agentscopeascode"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

type world struct {
	t   *testing.T
	f   *storetest.Fixture
	pat roles.Actor
	now time.Time
	opt agentscopeascode.Options
}

// newWorld is tenant B with two discovered agents (entra:hb, and blueprint bp-1 on entra:linked) and tenant A with
// one (entra:only-a) that B's bundles must not be able to name.
func newWorld(t *testing.T) *world {
	t.Helper()
	f := storetest.TwoTenants(t)
	w := &world{t: t, f: f, now: storetest.Now, opt: agentscopeascode.Options{Tenant: f.B.Slug}}
	w.tx(func(c *store.TenantTx) error {
		pu := &store.PlatformUser{DisplayName: "Pat", CreatedAt: w.now}
		if err := c.InsertPlatformUser(pu); err != nil {
			return err
		}
		w.pat = roles.Actor{UserID: pu.ID, Display: "Pat"}
		for _, ext := range []string{"hb", "linked"} {
			if err := c.UpsertAgentProfile(&store.AgentProfile{Source: "entra", ExternalID: ext, IdentityID: f.B.IDs["alice"], Kind: "agent"}, w.now); err != nil {
				return err
			}
		}
		return c.UpsertAgentLink(&store.AgentLink{Source: "entra", ExternalID: "linked", BlueprintAppID: "bp-1"})
	})
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.UpsertAgentProfile(&store.AgentProfile{Source: "entra", ExternalID: "only-a", IdentityID: f.A.IDs["alice"], Kind: "agent"}, w.now)
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) tx(fn func(c *store.TenantTx) error) {
	w.t.Helper()
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, fn); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) plan(files policybundle.Files) (*agentscopeascode.Plan, error) {
	var p *agentscopeascode.Plan
	var err error
	w.tx(func(c *store.TenantTx) error { p, err = agentscopeascode.Build(c, files, w.opt); return nil })
	return p, err
}

func (w *world) apply(files policybundle.Files, want string) error {
	var err error
	w.tx(func(c *store.TenantTx) error {
		_, err = agentscopeascode.Apply(c, files, w.opt, agentscopeascode.Ref{Commit: "abc123"}, want, w.pat, w.now)
		return nil // a real caller returns the error and the transaction rolls back
	})
	return err
}

func (w *world) applyPlanned(files policybundle.Files) *agentscopeascode.Plan {
	w.t.Helper()
	p, err := w.plan(files)
	if err != nil {
		w.t.Fatalf("plan: %v", err)
	}
	if err := w.apply(files, p.PlanSHA256); err != nil {
		w.t.Fatalf("apply: %v", err)
	}
	return p
}

func (w *world) export() policybundle.Files {
	w.t.Helper()
	var files policybundle.Files
	w.tx(func(c *store.TenantTx) (err error) { files, err = agentscopeascode.Export(c, w.f.B.Slug); return })
	return files
}

func code(err error) string {
	var e *roles.Error
	if errors.As(err, &e) {
		return e.Code
	}
	var inv *agentscopeascode.InvalidError
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

func scope(key, agent, actions string, extra string) string {
	return "schema: tessera.agentscope/v1\nkey: " + key + "\nname: Scope " + key + "\nagent:\n" + agent +
		"allow:\n  actions: " + actions + "\n  resources:\n    - systems: [aws]\n      tags_any: [support]\n" + extra
}

const hb = "  source: entra\n  external_id: hb\n"

func bundle(tenant, mode string, scopes map[string]string) policybundle.Files {
	cfg := "schema: tessera.repo/v1\ntenant: " + tenant + "\n"
	if mode != "" {
		cfg += "manage:\n  agents: " + mode + "\n"
	}
	f := policybundle.Files{"tessera.yaml": []byte(cfg)}
	for k, v := range scopes {
		f["agents/"+k+".yaml"] = []byte(v)
	}
	return f
}

func (w *world) baseline() policybundle.Files {
	return bundle(w.f.B.Slug, "partial", map[string]string{"hb": scope("hb", hb, "[read]", "")})
}

// Round trip: what is applied exports to files that plan as no change, with the repository change recorded.
func TestPlanApplyExportRoundTrip(t *testing.T) {
	w := newWorld(t)
	files := w.baseline()
	p, err := w.plan(files)
	if err != nil || p.Created != 1 || p.Steps != 1 || p.Removes != 0 || p.Scopes[0].Action != "create" || p.Scopes[0].Agent != "entra:hb" ||
		!p.Scopes[0].OwnerCeiling || len(p.PlanSHA256) != 64 {
		t.Fatalf("plan = %+v, %v", p, err)
	}
	if err := w.apply(files, strings.Repeat("0", 64)); code(err) != "stale_plan" {
		t.Errorf("apply of another plan: %v; want stale_plan", err)
	}
	var noCommit error
	w.tx(func(c *store.TenantTx) error {
		_, noCommit = agentscopeascode.Apply(c, files, w.opt, agentscopeascode.Ref{}, p.PlanSHA256, w.pat, w.now)
		return nil
	})
	if code(noCommit) != "invalid_commit" {
		t.Errorf("apply without a commit: %v", noCommit)
	}
	if err := w.apply(files, p.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	w.tx(func(c *store.TenantTx) error {
		s, err := c.AgentScopeByKey("hb")
		if err != nil || s.Status != store.AgentScopeActive || s.Version != 1 || s.Name != "Scope hb" {
			t.Fatalf("scope = %+v, %v", s, err)
		}
		vs, err := c.AgentScopeVersions(s.ID)
		if err != nil || len(vs) != 1 || vs[0].PolicyRef == nil || !strings.Contains(*vs[0].PolicyRef, `"commit":"abc123"`) ||
			!strings.Contains(*vs[0].PolicyRef, `"path":"agents/hb.yaml"`) ||
			!strings.Contains(*vs[0].PolicyRef, `"bundle_sha256":"`+agentscopeascode.Digest(files)+`"`) || vs[0].Actor != "Pat" {
			t.Errorf("versions = %+v, %v", vs, err)
		}
		return nil
	})
	if p2, err := w.plan(files); err != nil || p2.Unchanged != 1 || p2.Steps != 0 || p2.Scopes[0].Action != "unchanged" {
		t.Errorf("the same bundle again = %+v, %v; want no change", p2, err)
	}
	exp := w.export()
	if exp["agents/hb.yaml"] == nil || !strings.Contains(string(exp["tessera.yaml"]), "agents: partial") {
		t.Fatalf("export = %v", exp)
	}
	if p3, err := w.plan(exp); err != nil || p3.Steps != 0 || p3.Created+p3.Updated+p3.Retired != 0 {
		t.Errorf("plan of the export = %+v, %v; want no change", p3, err)
	}
	// the files come back in canonical form, and differently written files that mean the same are no change either
	same := bundle(w.f.B.Slug, "partial", map[string]string{"hb": scope("hb", hb, "[read]", "severity: high\nowner_ceiling: true\n")})
	if p4, err := w.plan(same); err != nil || p4.Steps != 0 {
		t.Errorf("an equivalent file = %+v, %v; want no change", p4, err)
	}
	// tenant A got nothing
	err = w.f.DB.ReadTenant(context.Background(), w.f.A.ID, func(c *store.TenantTx) error {
		if ss, err := c.AgentScopes(); err != nil || len(ss) != 0 {
			t.Errorf("tenant A got %v, %v", ss, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUpdateWritesAVersion(t *testing.T) {
	w := newWorld(t)
	w.applyPlanned(w.baseline())
	changed := bundle(w.f.B.Slug, "partial", map[string]string{"hb": scope("hb", hb, "[read, write]", "owner_ceiling: false\n")})
	p, err := w.plan(changed)
	if err != nil || p.Updated != 1 || p.Scopes[0].Action != "update" || p.Scopes[0].OwnerCeiling || len(p.Warnings) != 1 ||
		!strings.Contains(p.Warnings[0], "owner_ceiling: false") {
		t.Fatalf("plan = %+v, %v; want an update with a warning about the owner ceiling", p, err)
	}
	w.applyPlanned(changed)
	w.tx(func(c *store.TenantTx) error {
		s, _ := c.AgentScopeByKey("hb")
		vs, _ := c.AgentScopeVersions(s.ID)
		if s.Version != 2 || len(vs) != 2 || vs[0].Version != 2 {
			t.Errorf("scope = %+v, versions = %+v", s, vs)
		}
		return nil
	})
}

// A bundle names agents the tenant has discovered; another tenant's agent looks like none.
func TestSelectors(t *testing.T) {
	w := newWorld(t)
	blueprint := "  blueprint: bp-1\n"
	if p, err := w.plan(bundle(w.f.B.Slug, "partial", map[string]string{"bp": scope("bp", blueprint, "[read]", "")})); err != nil || p.Scopes[0].Agent != "blueprint:bp-1" {
		t.Errorf("a blueprint of this tenant: %+v, %v", p, err)
	}
	for name, tc := range map[string]struct{ agent, want string }{
		"another tenant's agent": {"  source: entra\n  external_id: only-a\n", "unknown_agent"},
		"an agent nobody knows":  {"  source: entra\n  external_id: ghost\n", "unknown_agent"},
		"the wrong source":       {"  source: okta\n  external_id: hb\n", "unknown_agent"},
		"an unknown blueprint":   {"  blueprint: bp-9\n", "unknown_blueprint"},
	} {
		t.Run(name, func(t *testing.T) {
			files := bundle(w.f.B.Slug, "partial", map[string]string{"x": scope("x", tc.agent, "[read]", "")})
			if _, err := w.plan(files); !strings.Contains(code(err), tc.want) {
				t.Errorf("plan = %q; want %s", code(err), tc.want)
			}
			if err := w.apply(files, strings.Repeat("0", 64)); err == nil {
				t.Error("apply succeeded")
			}
		})
	}
}

func TestRefusals(t *testing.T) {
	w := newWorld(t)
	with := func(path, text string) policybundle.Files {
		f := w.baseline()
		f[path] = []byte(text)
		return f
	}
	good := scope("hb", hb, "[read]", "")
	for name, tc := range map[string]struct {
		files policybundle.Files
		want  string
	}{
		"unknown field":       {with("agents/hb.yaml", good+"extra: 1\n"), "invalid_document"},
		"duplicate key":       {with("agents/hb.yaml", good+"name: again\n"), "invalid_document"},
		"anchor":              {with("agents/hb.yaml", strings.Replace(good, "key: hb", "key: &k hb", 1)), "invalid_document"},
		"two documents":       {with("agents/hb.yaml", good+"---\n"+good), "invalid_document"},
		"wrong schema":        {with("agents/hb.yaml", strings.Replace(good, "agentscope/v1", "agentscope/v2", 1)), "invalid_schema"},
		"path is not the key": {bundle(w.f.B.Slug, "partial", map[string]string{"other": good}), "path_key_mismatch"},
		"a cedar file":        {with("agents/x.cedar", `@id("x") @agent("entra:hb") permit (principal, action == Tessera::Action::"reach", resource);`), "cedar_scope_unsupported"},
		"unknown class":       {with("agents/hb.yaml", strings.Replace(good, "[read]", "[read, root]", 1)), "invalid_actions"},
		"no class":            {with("agents/hb.yaml", strings.Replace(good, "[read]", "[]", 1)), "invalid_actions"},
		"a class of everything": {with("agents/hb.yaml", strings.Replace(good, "    - systems: [aws]\n      tags_any: [support]\n", "    - {}\n", 1)),
			"invalid_resources"},
		"no resources":        {with("agents/hb.yaml", strings.Replace(good, "  resources:\n    - systems: [aws]\n      tags_any: [support]\n", "  resources: []\n", 1)), "invalid_resources"},
		"bad severity":        {with("agents/hb.yaml", good+"severity: urgent\n"), "invalid_severity"},
		"wrong tenant":        {bundle("globex", "partial", map[string]string{"hb": good}), "tenant_mismatch"},
		"not managed":         {bundle(w.f.B.Slug, "", map[string]string{"hb": good}), "not_managed"},
		"too large":           {with("agents/big.yaml", strings.Repeat("a", 300<<10)), "too_large"},
		"a stray file":        {with("agents/readme.txt", "hi"), "unexpected_file"},
		"two scopes, one key": {bundle(w.f.B.Slug, "partial", map[string]string{"hb": good, "hb2": good}), "duplicate_key"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := w.plan(tc.files); !strings.Contains(code(err), tc.want) {
				t.Errorf("plan = %q; want %s", code(err), tc.want)
			}
			if err := w.apply(tc.files, strings.Repeat("0", 64)); err == nil {
				t.Error("apply of an invalid bundle succeeded")
			}
		})
	}
}

func TestFullModeRetiresAndGuards(t *testing.T) {
	w := newWorld(t)
	linked := "  source: entra\n  external_id: linked\n"
	two := bundle(w.f.B.Slug, "partial", map[string]string{"hb": scope("hb", hb, "[read]", ""), "linked": scope("linked", linked, "[read]", "")})
	w.applyPlanned(two)
	partial := bundle(w.f.B.Slug, "partial", map[string]string{"hb": scope("hb", hb, "[read]", "")})
	if p, err := w.plan(partial); err != nil || p.Retired != 0 {
		t.Fatalf("partial plan = %+v, %v; want nothing retired", p, err)
	}
	full := bundle(w.f.B.Slug, "full", map[string]string{"hb": scope("hb", hb, "[read]", "")})
	p, err := w.plan(full)
	if err != nil || p.Retired != 1 || p.Removes != 1 || p.Steps != 1 || p.Scopes[1].Key != "linked" || p.Scopes[1].Action != "retire" {
		t.Fatalf("full plan = %+v, %v; want linked retired", p, err)
	}
	zero := 0
	w.tx(func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: deleteguard.CatMembers, MaxCount: &zero, WindowMinutes: 60,
			Mode: deleteguard.ModeHoldExcess}, nil, w.now)
	})
	if _, err := w.plan(full); code(err) != "deletion_guard" {
		t.Errorf("with a guard of 0: %v; want deletion_guard", err)
	}
	if err := w.apply(full, p.PlanSHA256); code(err) != "deletion_guard" {
		t.Errorf("apply with a guard of 0: %v; want deletion_guard", err)
	}
	w.tx(func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: deleteguard.CatMembers, WindowMinutes: 60, Mode: deleteguard.ModeOff}, nil, w.now)
	})
	w.applyPlanned(full)
	w.tx(func(c *store.TenantTx) error {
		for k, want := range map[string]string{"linked": store.AgentScopeRetired, "hb": store.AgentScopeActive} {
			if s, err := c.AgentScopeByKey(k); err != nil || s.Status != want {
				t.Errorf("scope %s = %+v, %v; want %s", k, s, err, want)
			}
		}
		s, _ := c.AgentScopeByKey("linked")
		if vs, _ := c.AgentScopeVersions(s.ID); len(vs) != 2 || vs[0].PolicyRef != nil {
			t.Errorf("versions of the retired scope = %+v", vs)
		}
		return nil
	})
	if exp := w.export(); exp["agents/linked.yaml"] != nil || exp["agents/hb.yaml"] == nil {
		t.Errorf("export after retire = %v", exp)
	}
	if _, err := w.plan(two); !strings.Contains(code(err), "scope_retired") {
		t.Errorf("naming a retired scope: %v; want scope_retired", err)
	}
}

func TestStepCeilingAndStalePlan(t *testing.T) {
	w := newWorld(t)
	linked := "  source: entra\n  external_id: linked\n"
	files := bundle(w.f.B.Slug, "partial", map[string]string{"hb": scope("hb", hb, "[read]", ""), "linked": scope("linked", linked, "[read]", "")})
	w.opt.MaxSteps = 1
	if _, err := w.plan(files); code(err) != "plan_too_large" {
		t.Errorf("MaxSteps 1: %v; want plan_too_large", err)
	}
	if err := w.apply(files, strings.Repeat("0", 64)); code(err) != "plan_too_large" {
		t.Errorf("apply over the ceiling: %v; want plan_too_large", err)
	}
	w.opt.MaxSteps = 2
	p, err := w.plan(files)
	if err != nil {
		t.Fatalf("at the ceiling: %v", err)
	}
	// the state moves after the plan: the apply of the approved plan is refused
	w.applyPlanned(w.baseline())
	if err := w.apply(files, p.PlanSHA256); code(err) != "stale_plan" {
		t.Errorf("apply of a moved plan: %v; want stale_plan", err)
	}
}

// The scopes the apply wrote are the ones the invariant reads back.
func TestAppliedScopeReadsBackAsADocument(t *testing.T) {
	w := newWorld(t)
	w.applyPlanned(w.baseline())
	w.tx(func(c *store.TenantTx) error {
		s, _ := c.AgentScopeByKey("hb")
		d, err := agentscope.FromJSON(s.Doc)
		if err != nil || d.Key != "hb" || d.Agent.ExternalID != "hb" || !d.Permits("read", "aws", nil, []string{"support"}) || d.Permits("write", "aws", nil, []string{"support"}) {
			t.Errorf("stored document = %+v, %v", d, err)
		}
		return nil
	})
}
