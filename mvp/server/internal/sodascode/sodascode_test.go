package sodascode_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/sodascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

type world struct {
	t   *testing.T
	f   *storetest.Fixture
	pat roles.Actor
	now time.Time
	opt sodascode.Options
}

func newWorld(t *testing.T) *world {
	t.Helper()
	f := storetest.TwoTenants(t)
	w := &world{t: t, f: f, now: storetest.Now, opt: sodascode.Options{Tenant: f.B.Slug}}
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

func (w *world) plan(files policybundle.Files) (*sodascode.Plan, error) {
	var p *sodascode.Plan
	var err error
	w.tx(func(c *store.TenantTx) error { p, err = sodascode.Build(c, files, w.opt); return nil })
	return p, err
}

func (w *world) apply(files policybundle.Files, want string) (*sodascode.Plan, error) {
	var p *sodascode.Plan
	var err error
	w.tx(func(c *store.TenantTx) error {
		p, err = sodascode.Apply(c, files, w.opt, sodascode.Ref{Commit: "abc123"}, want, w.pat, w.now)
		return nil // the caller's transaction commits whatever the writers did; a real caller returns the error
	})
	return p, err
}

func (w *world) applyPlanned(files policybundle.Files) *sodascode.Plan {
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

func (w *world) export() policybundle.Files {
	w.t.Helper()
	var files policybundle.Files
	w.tx(func(c *store.TenantTx) (err error) { files, err = sodascode.Export(c, w.f.B.Slug); return })
	return files
}

func code(err error) string {
	var e *roles.Error
	if errors.As(err, &e) {
		return e.Code
	}
	var inv *sodascode.InvalidError
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

// ruleset is a sod/<key>.yaml document with names that hold spaces; the functions are payments:create and
// payments:approve and the one risk needs both.
func ruleset(key string, risks string) string {
	return `schema: tessera.sod/v1
ruleset:
  key: ` + key + `
  name: Payments controls ` + key + `
  description: Who may create and approve a payment
  enabled: true
functions:
  - key: create
    name: Create a payment
    selectors:
      - name_pattern: "payments:create*"
  - key: approve
    name: Approve a payment
    selectors:
      - name_pattern: "payments:approve*"
      - system: "Core Banking"
        name_pattern: "wire approve"
risks:
` + risks
}

const payRisk = `  - key: pay-create-approve
    name: Create and approve a payment
    priority: high
    functions: [create, approve]
    subjects:
      identity_types: [human]
    remediation: [revoke, mitigate]
`

func bundle(tenant, mode string, rulesets map[string]string) policybundle.Files {
	cfg := "schema: tessera.repo/v1\ntenant: " + tenant + "\n"
	if mode != "" {
		cfg += "manage:\n  sod: " + mode + "\n"
	}
	f := policybundle.Files{"tessera.yaml": []byte(cfg)}
	for k, v := range rulesets {
		f["sod/"+k+".yaml"] = []byte(v)
	}
	return f
}

func (w *world) baseline() policybundle.Files {
	return bundle(w.f.B.Slug, "partial", map[string]string{"payments": ruleset("payments", payRisk)})
}

// compiled is the risks a tenant checks, with the ids and versions left out: the same risks find the same violations.
func compiled(t *testing.T, db *store.DB, tid interface{ String() string }, run func(fn func(c *store.TenantTx) error) error) string {
	t.Helper()
	var out []map[string]any
	err := run(func(c *store.TenantTx) error {
		rs, err := sod.Compile(c)
		for _, r := range rs {
			var fns []any
			for _, f := range r.Functions {
				fns = append(fns, map[string]any{"key": f.Key, "name": f.Name, "selectors": f.Selectors})
			}
			out = append(out, map[string]any{"key": r.Key, "name": r.Name, "priority": r.Priority, "ruleset": r.Ruleset.Key,
				"functions": fns, "subjects": r.Subjects, "remediation": r.Remediation})
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// Round trip: what is applied exports to files that plan as no change, and applying the export to another tenant
// compiles to the same risks, so the same violations.
func TestPlanApplyExportRoundTrip(t *testing.T) {
	w := newWorld(t)
	files := w.baseline()
	p, err := w.plan(files)
	if err != nil || p.Created != 4 || p.Steps != 4 || p.Removes != 0 || p.Rulesets[0].Action != "create" || len(p.PlanSHA256) != 64 {
		t.Fatalf("plan = %+v, %v", p, err)
	}
	// apply refuses a plan that is not the approved one, and a missing commit
	if _, err := w.apply(files, strings.Repeat("0", 64)); code(err) != "stale_plan" {
		t.Errorf("apply of another plan: %v; want stale_plan", err)
	}
	var noCommit error
	w.tx(func(c *store.TenantTx) error {
		_, noCommit = sodascode.Apply(c, files, w.opt, sodascode.Ref{}, p.PlanSHA256, w.pat, w.now)
		return nil
	})
	if code(noCommit) != "invalid_commit" {
		t.Errorf("apply without a commit: %v", noCommit)
	}
	if _, err := w.apply(files, p.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	w.tx(func(c *store.TenantTx) error {
		rs, err := c.SodRulesetByKey("payments")
		if err != nil || rs.Name != "Payments controls payments" {
			t.Fatalf("ruleset = %+v, %v", rs, err)
		}
		refs, err := c.SodPolicyRefs()
		if err != nil || len(refs) != 1 || refs[0].RulesetID != rs.ID || refs[0].RulesetVersion != rs.Version ||
			!strings.Contains(refs[0].PolicyRef, `"commit":"abc123"`) || !strings.Contains(refs[0].PolicyRef, `"path":"sod/payments.yaml"`) ||
			!strings.Contains(refs[0].PolicyRef, `"bundle_sha256":"`+sodascode.Digest(files)+`"`) {
			t.Errorf("policy refs = %+v, %v", refs, err)
		}
		return nil
	})
	if p2, err := w.plan(files); err != nil || p2.Unchanged != 3 || p2.Steps != 0 || p2.Rulesets[0].Action != "unchanged" {
		t.Errorf("the same bundle again = %+v, %v; want no change", p2, err)
	}

	exp := w.export()
	if exp["sod/payments.yaml"] == nil || !strings.Contains(string(exp["tessera.yaml"]), "sod: partial") {
		t.Fatalf("export = %v", exp)
	}
	if p3, err := w.plan(exp); err != nil || p3.Steps != 0 || p3.Created+p3.Updated+p3.Retired != 0 {
		t.Errorf("plan of the export = %+v, %v; want no change", p3, err)
	}

	// the export, applied to the other tenant, compiles to the same risks
	var forA policybundle.Files
	w.tx(func(c *store.TenantTx) (err error) { forA, err = sodascode.Export(c, w.f.A.Slug); return })
	optA := sodascode.Options{Tenant: w.f.A.Slug}
	err = w.f.DB.InTenant(context.Background(), w.f.A.ID, func(c *store.TenantTx) error {
		pa, err := sodascode.Build(c, forA, optA)
		if err != nil {
			return err
		}
		_, err = sodascode.Apply(c, forA, optA, sodascode.Ref{Commit: "def456"}, pa.PlanSHA256, roles.Actor{Display: "Pat"}, w.now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	inB := compiled(t, w.f.DB, nil, func(fn func(c *store.TenantTx) error) error {
		return w.f.DB.ReadTenant(context.Background(), w.f.B.ID, fn)
	})
	inA := compiled(t, w.f.DB, nil, func(fn func(c *store.TenantTx) error) error {
		return w.f.DB.ReadTenant(context.Background(), w.f.A.ID, fn)
	})
	if inA != inB || !strings.Contains(inB, "pay-create-approve") || !strings.Contains(inB, "Core Banking") {
		t.Errorf("risks differ after the round trip:\nB %s\nA %s", inB, inA)
	}
}

// An update changes what the bundle says and nothing else; a ruleset made in the UI is adopted by the first apply.
func TestUpdateAndAdopt(t *testing.T) {
	w := newWorld(t)
	w.tx(func(c *store.TenantTx) error {
		b, err := sod.ParseYAML([]byte(ruleset("payments", payRisk)))
		if err != nil {
			return err
		}
		_, err = (&sod.Writer{Tx: c, By: sod.Actor{Display: "ui"}, Now: w.now, Quiet: true}).Import(b, sod.ImportOptions{})
		return err
	})
	p, err := w.plan(w.baseline())
	if err != nil || p.Steps != 0 || len(p.Rulesets) != 1 || !p.Rulesets[0].Adopt || len(p.Warnings) != 1 {
		t.Fatalf("plan over a UI ruleset = %+v, %v; want an adoption and no writes", p, err)
	}
	w.applyPlanned(w.baseline())
	w.tx(func(c *store.TenantTx) error {
		if refs, err := c.SodPolicyRefs(); err != nil || len(refs) != 1 {
			t.Errorf("an adopted ruleset has refs %v, %v; want one", refs, err)
		}
		return nil
	})
	changed := strings.Replace(payRisk, "priority: high", "priority: critical", 1)
	files := bundle(w.f.B.Slug, "partial", map[string]string{"payments": ruleset("payments", changed)})
	p, err = w.plan(files)
	if err != nil || p.Updated != 1 || p.Created != 0 || p.Rulesets[0].Action != "update" || p.Rulesets[0].Updated[0] != "risk pay-create-approve" {
		t.Fatalf("plan = %+v, %v", p, err)
	}
	w.applyPlanned(files)
	w.tx(func(c *store.TenantTx) error {
		if r, err := c.SodRiskByKey("pay-create-approve"); err != nil || r.Priority != "critical" || r.Version != 2 {
			t.Errorf("risk = %+v, %v", r, err)
		}
		return nil
	})
}

func TestInvalidBundles(t *testing.T) {
	w := newWorld(t)
	good := w.baseline()
	with := func(path, text string) policybundle.Files {
		f := policybundle.Files{}
		for k, v := range good {
			f[k] = v
		}
		f[path] = []byte(text)
		return f
	}
	two := func(a, b string) policybundle.Files {
		return bundle(w.f.B.Slug, "partial", map[string]string{"a": ruleset("a", a), "b": ruleset("b", b)})
	}
	otherRisk := strings.Replace(payRisk, "pay-create-approve", "other", 1)
	for name, tc := range map[string]struct {
		files policybundle.Files
		want  string
	}{
		"unknown field":                 {with("sod/payments.yaml", ruleset("payments", payRisk)+"extra: 1\n"), "invalid"},
		"unknown risk field":            {with("sod/payments.yaml", ruleset("payments", strings.Replace(payRisk, "priority: high", "priority: high\n    cedar: permit(principal,action,resource);", 1))), "invalid"},
		"two documents":                 {with("sod/payments.yaml", ruleset("payments", payRisk)+"---\nschema: tessera.sod/v1\n"), "invalid"},
		"a cedar file":                  {with("sod/payments.cedar", "permit(principal, action, resource);"), "unexpected_file"},
		"wrong schema":                  {with("sod/payments.yaml", strings.Replace(ruleset("payments", payRisk), "tessera.sod/v1", "tessera.sod/v2", 1)), "invalid_schema"},
		"path is not the key":           {bundle(w.f.B.Slug, "partial", map[string]string{"other": ruleset("payments", payRisk)}), "path_key_mismatch"},
		"bad priority":                  {with("sod/payments.yaml", ruleset("payments", strings.Replace(payRisk, "priority: high", "priority: urgent", 1))), "invalid_priority"},
		"one function":                  {with("sod/payments.yaml", ruleset("payments", strings.Replace(payRisk, "[create, approve]", "[create]", 1))), "invalid_functions"},
		"unknown function":              {with("sod/payments.yaml", ruleset("payments", strings.Replace(payRisk, "[create, approve]", "[create, nope]", 1))), "invalid_functions"},
		"bad identity type":             {with("sod/payments.yaml", ruleset("payments", strings.Replace(payRisk, "[human]", "[robot]", 1))), "invalid_subjects"},
		"condition outside the grammar": {with("sod/payments.yaml", ruleset("payments", strings.Replace(payRisk, "identity_types: [human]", "condition: {exec: rm}", 1))), "invalid_subjects"},
		"bad remediation":               {with("sod/payments.yaml", ruleset("payments", strings.Replace(payRisk, "[revoke, mitigate]", "[delete]", 1))), "invalid_remediation"},
		"unknown owner":                 {with("sod/payments.yaml", ruleset("payments", payRisk+"    owner: nobody@nowhere\n")), "owner_not_found"},
		"wrong tenant":                  {bundle("globex", "partial", map[string]string{"payments": ruleset("payments", payRisk)}), "tenant_mismatch"},
		"not managed":                   {bundle(w.f.B.Slug, "", map[string]string{"payments": ruleset("payments", payRisk)}), "not_managed"},
		"a risk in two files":           {two(payRisk, payRisk), "duplicate_key"},
		"the same function twice":       {two(payRisk, otherRisk), ""},
		"conflicting functions": {bundle(w.f.B.Slug, "partial", map[string]string{"a": ruleset("a", payRisk),
			"b": strings.Replace(ruleset("b", otherRisk), "payments:create*", "payments:make*", 1)}), "conflicting_function"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := w.plan(tc.files)
			got := code(err)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("plan = %v; want none", err)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("plan = %q; want %s", got, tc.want)
			}
			if _, err := w.apply(tc.files, strings.Repeat("0", 64)); err == nil {
				t.Error("apply of an invalid bundle succeeded")
			}
		})
	}
}

// Names hold spaces everywhere they appear; a function shared by two rulesets is written once.
func TestNamesWithSpacesAndSharedFunctions(t *testing.T) {
	w := newWorld(t)
	files := bundle(w.f.B.Slug, "partial", map[string]string{
		"a": ruleset("a", payRisk),
		"b": ruleset("b", strings.Replace(payRisk, "pay-create-approve", "second risk", 1)),
	})
	// risk keys are keys, not names: a key with a space is refused with its own code
	if _, err := w.plan(files); !strings.Contains(code(err), "invalid_key") {
		t.Errorf("a key with a space: %v; want invalid_key", err)
	}
	files = bundle(w.f.B.Slug, "partial", map[string]string{
		"a": ruleset("a", payRisk),
		"b": strings.Replace(ruleset("b", strings.Replace(payRisk, "pay-create-approve", "second", 1)), "name: Create and approve a payment", "name: Create and approve", 1),
	})
	p, err := w.plan(files)
	if err != nil || p.Created != 6 { // 2 rulesets, 2 functions once, 2 risks
		t.Fatalf("plan = %+v, %v", p, err)
	}
	w.applyPlanned(files)
	w.tx(func(c *store.TenantTx) error {
		f, err := c.SodFunctionByKey("approve")
		if err != nil || f.Version != 1 || !strings.Contains(f.Selectors, "Core Banking") || !strings.Contains(f.Selectors, "wire approve") {
			t.Errorf("function = %+v, %v", f, err)
		}
		return nil
	})
}

func TestFullModeRetiresAndGuards(t *testing.T) {
	w := newWorld(t)
	extra := `  - key: extra
    name: Another risk
    priority: low
    functions: [create, approve]
`
	two := bundle(w.f.B.Slug, "partial", map[string]string{"payments": ruleset("payments", payRisk+extra), "ledger": ruleset("ledger", strings.Replace(extra, "extra", "ledger-risk", 1)+"")})
	two["sod/ledger.yaml"] = []byte(strings.Replace(string(two["sod/ledger.yaml"]), "name: Another risk", "name: Ledger risk", 1))
	w.applyPlanned(two)
	// a ruleset made outside the repository is never retired by an apply
	w.tx(func(c *store.TenantTx) error {
		return c.InsertSodRuleset(&store.SodRuleset{ID: "ui-rs", Key: "ui", Name: "From the UI", Enabled: true,
			Status: store.SodActive, Version: 1, CreatedAt: w.now, UpdatedAt: w.now})
	})

	onlyPay := ruleset("payments", payRisk+extra)
	partial := bundle(w.f.B.Slug, "partial", map[string]string{"payments": onlyPay})
	if p, err := w.plan(partial); err != nil || p.Retired != 0 {
		t.Fatalf("partial plan = %+v, %v; want nothing retired", p, err)
	}
	// full retires the risk the ruleset no longer lists and the repository's ruleset the bundle drops, not the UI's
	full := bundle(w.f.B.Slug, "full", map[string]string{"payments": ruleset("payments", payRisk)})
	p, err := w.plan(full)
	if err != nil || p.Retired != 3 || p.Removes != 3 || p.Steps != 3 {
		t.Fatalf("full plan = %+v, %v; want extra, ledger-risk and ledger retired", p, err)
	}
	for _, r := range p.Rulesets {
		if r.Key == "ui" {
			t.Errorf("the UI's ruleset is in the plan: %+v", r)
		}
	}
	// a guard that allows none refuses it outright, at plan and at apply
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
		for k, want := range map[string]string{"extra": store.SodRetired, "ledger-risk": store.SodRetired, "pay-create-approve": store.SodActive} {
			if r, err := c.SodRiskByKey(k); err != nil || r.Status != want {
				t.Errorf("risk %s = %+v, %v; want %s", k, r, err, want)
			}
		}
		for k, want := range map[string]string{"ledger": store.SodRetired, "ui": store.SodActive, "payments": store.SodActive} {
			if r, err := c.SodRulesetByKey(k); err != nil || r.Status != want {
				t.Errorf("ruleset %s = %+v, %v; want %s", k, r, err, want)
			}
		}
		return nil
	})
	// the export holds only what is active; a retired key cannot be reused by a bundle
	if exp := w.export(); exp["sod/ledger.yaml"] != nil || exp["sod/payments.yaml"] == nil || strings.Contains(string(exp["sod/payments.yaml"]), "extra") {
		t.Errorf("export after retire = %v", exp)
	}
	if _, err := w.plan(two); !strings.Contains(code(err), "ruleset_retired") {
		t.Errorf("naming a retired ruleset: %v; want ruleset_retired", err)
	}
}

func TestStepCeiling(t *testing.T) {
	w := newWorld(t)
	files := w.baseline() // ruleset, two functions, risk: 4 writes
	w.opt.MaxSteps = 3
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

// A plan that moved since it was approved is refused, and a failed apply writes nothing the caller would commit.
func TestStalePlan(t *testing.T) {
	w := newWorld(t)
	files := w.baseline()
	p, err := w.plan(files)
	if err != nil {
		t.Fatal(err)
	}
	w.applyPlanned(bundle(w.f.B.Slug, "partial", map[string]string{"payments": ruleset("payments", strings.Replace(payRisk, "high", "low", 1))}))
	if _, err := w.apply(files, p.PlanSHA256); code(err) != "stale_plan" {
		t.Errorf("apply of a moved plan: %v; want stale_plan", err)
	}
}
