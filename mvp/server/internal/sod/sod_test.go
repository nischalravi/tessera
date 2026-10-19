package sod_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

func writer(c *store.TenantTx) *sod.Writer {
	return &sod.Writer{Tx: c, By: sod.Actor{UserID: uuid.Nil, Display: "tester"}, Now: testkit.Now}
}

func code(err error) string {
	var rf *sod.Refusal
	if errors.As(err, &rf) {
		return rf.Code
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

func pat(p string) []sod.Selector { return []sod.Selector{{NamePattern: p}} }

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, s string
		want       bool
	}{
		{"payments:create", "payments:create", true},
		{"payments:*", "payments:approve", true},
		{"*", "", true},
		{"*:approve", "payments:approve", true},
		{"pay*ts:cr*e", "payments:create", true},
		{"payments:create", "payments:create2", false},
		{"payments:\\*", "payments:*", true},
		{"payments:\\*", "payments:x", false},
		{"a*b*c", "aXbYcZ", false},
		{"a*b*c", "aXbYbc", true},
		{"", "", true},
		{"", "x", false},
	} {
		if got := sod.Match(tc.pattern, tc.s); got != tc.want {
			t.Errorf("Match(%q, %q) = %v", tc.pattern, tc.s, got)
		}
	}
	if !sod.Match(sod.EscapePattern(`a*b\c`), `a*b\c`) || sod.Match(sod.EscapePattern("a*"), "ab") {
		t.Error("EscapePattern does not match only itself")
	}
}

func TestFunctionRiskRulesetLifecycleAndVersions(t *testing.T) {
	st, _ := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		w := writer(c)
		fa, err := w.CreateFunction(sod.FunctionInput{Name: "Create payments", Selectors: pat("payments:create")})
		if err != nil {
			return err
		}
		fb, err := w.CreateFunction(sod.FunctionInput{Name: "Approve payments", Selectors: pat("payments:approve")})
		if err != nil {
			return err
		}
		if fa.Key != "create-payments" {
			t.Errorf("key = %q", fa.Key)
		}
		rs, err := w.CreateRuleset(sod.RulesetInput{Name: "Finance", Enabled: true})
		if err != nil {
			return err
		}
		in := sod.RiskInput{Name: "Pay own invoice", Priority: "high", RulesetID: rs.ID, FunctionIDs: []string{fa.ID, fb.ID}}
		for name, mut := range map[string]func(*sod.RiskInput){
			"one function":  func(r *sod.RiskInput) { r.FunctionIDs = r.FunctionIDs[:1] },
			"same function": func(r *sod.RiskInput) { r.FunctionIDs = []string{fa.ID, fa.ID} },
			"bad priority":  func(r *sod.RiskInput) { r.Priority = "urgent" },
			"no function":   func(r *sod.RiskInput) { r.FunctionIDs = []string{fa.ID, "nope"} },
			"no ruleset":    func(r *sod.RiskInput) { r.RulesetID = "nope" },
			"bad subjects":  func(r *sod.RiskInput) { r.Subjects = sod.Subjects{IdentityTypes: []string{"alien"}} },
		} {
			bad := in
			mut(&bad)
			if _, err := w.CreateRisk(bad); err == nil || !strings.HasPrefix(code(err), "invalid_") && code(err) != "function_not_found" && code(err) != "ruleset_not_found" {
				t.Errorf("%s: err = %v", name, err)
			}
		}
		r, err := w.CreateRisk(in)
		if err != nil {
			return err
		}
		if _, err := w.CreateRisk(in); code(err) != "name_taken" {
			t.Errorf("duplicate risk: %v", err)
		}
		if _, err := w.RetireFunction(fa.ID, "x"); code(err) != "function_in_use" {
			t.Errorf("retire used function: %v", err)
		}
		if _, err := w.RetireRuleset(rs.ID, "x"); code(err) != "ruleset_not_empty" {
			t.Errorf("retire non-empty ruleset: %v", err)
		}
		// stale version, then a good update
		in.Priority = "critical"
		if _, err := w.UpdateRisk(r.ID, 7, in); code(err) != "version_conflict" {
			t.Errorf("stale update: %v", err)
		}
		r2, err := w.UpdateRisk(r.ID, 1, in)
		if err != nil || r2.Version != 2 {
			t.Fatalf("update: %v %v", r2, err)
		}
		vs, err := c.SodVersions(store.SodKindRisk, r.ID)
		if err != nil || len(vs) != 2 || vs[0].Version != 2 {
			t.Errorf("risk versions = %v, %v", vs, err)
		}
		// the ruleset's history follows what is in it: created, risk added, risk changed
		rvs, err := c.SodVersions(store.SodKindRuleset, rs.ID)
		if err != nil || len(rvs) != 3 || !strings.Contains(rvs[0].Snapshot, `"critical"`) {
			t.Errorf("ruleset versions = %d, %v", len(rvs), err)
		}
		// disabling bumps the version; a retired function cannot be used again
		cur, _ := c.SodRuleset(rs.ID)
		off, err := w.UpdateRuleset(rs.ID, cur.Version, sod.RulesetInput{Name: "Finance", Enabled: false})
		if err != nil || off.Enabled {
			t.Fatalf("disable: %v", err)
		}
		if risks, err := sod.Compile(c); err != nil || len(risks) != 0 {
			t.Errorf("a disabled ruleset compiled %d risks (%v)", len(risks), err)
		}
		if _, err := w.UpdateRuleset(rs.ID, cur.Version, sod.RulesetInput{Name: "Finance", Enabled: true}); code(err) != "version_conflict" {
			t.Errorf("stale ruleset update: %v", err)
		}
		if _, err := w.RetireRisk(r.ID, "obsolete"); err != nil {
			return err
		}
		if _, err := w.RetireFunction(fa.ID, "obsolete"); err != nil {
			return err
		}
		if _, err := w.RetireRuleset(rs.ID, "obsolete"); err != nil {
			return err
		}
		if _, err := w.UpdateFunction(fa.ID, 2, sod.FunctionInput{Name: "x", Selectors: pat("x")}); code(err) != "function_retired" {
			t.Errorf("update retired: %v", err)
		}
		return nil
	})
}

func TestSelectorValidation(t *testing.T) {
	st, ids := testkit.Tiny(t)
	pid := ids["alice"] // an identity id, not a permission id: must not pass as an entitlement
	testkit.Write(t, st, func(c *store.TenantTx) error {
		w := writer(c)
		perms, err := c.Permissions()
		if err != nil {
			return err
		}
		eid := perms[0].ID
		for name, sels := range map[string][]sod.Selector{
			"none":                nil,
			"both":                {{System: "aws", EntitlementID: &eid, NamePattern: "x"}},
			"neither":             {{System: "aws"}},
			"id needs system":     {{EntitlementID: &eid}},
			"attribute no value":  {{NamePattern: "x", Attribute: "tag"}},
			"unknown attribute":   {{NamePattern: "x", Attribute: "colour", Value: "red"}},
			"privileged value":    {{NamePattern: "x", Attribute: "privileged", Value: "maybe"}},
			"wrong system":        {{System: "not-" + perms[0].System, EntitlementID: &eid}},
			"unknown entitlement": {{System: "aws", EntitlementID: func() *int64 { n := int64(pid) + 99999; return &n }()}},
		} {
			if _, err := w.CreateFunction(sod.FunctionInput{Name: "f " + name, Selectors: sels}); code(err) != "invalid_selectors" {
				t.Errorf("%s: %v", name, err)
			}
		}
		if _, err := w.CreateFunction(sod.FunctionInput{Name: "ok", Selectors: []sod.Selector{{System: perms[0].System, EntitlementID: &eid}}}); err != nil {
			t.Errorf("a valid entitlement selector: %v", err)
		}
		return nil
	})
}

func TestYAMLRoundTripImportAndPrune(t *testing.T) {
	st, _ := testkit.Tiny(t)
	env := "prod"
	_ = env
	doc := `schema: tessera.sod/v1
ruleset:
  key: finance
  name: Finance
  enabled: true
functions:
  - key: create
    name: Create payments
    selectors:
      - {system: workday, name_pattern: "payments:create", attribute: environment, value: prod}
  - key: approve
    name: Approve payments
    description: Approve what was created
    selectors:
      - {name_pattern: "payments:approve"}
risks:
  - key: pay-own
    name: Pay own invoice
    priority: high
    business_process: Procure to pay
    functions: [create, approve]
    subjects:
      identity_types: [human]
      condition: {attr: identity.department, op: eq, value: Finance}
`
	var exported string
	testkit.Write(t, st, func(c *store.TenantTx) error {
		w := writer(c)
		b, err := sod.ParseYAML([]byte(doc))
		if err != nil {
			return err
		}
		dry, err := w.Import(b, sod.ImportOptions{DryRun: true})
		if err != nil || len(dry.Created) != 4 {
			t.Fatalf("dry run: %+v %v", dry, err)
		}
		if n, _ := c.CountSodRulesets(); n != 0 {
			t.Fatal("a dry run wrote")
		}
		res, err := w.Import(b, sod.ImportOptions{})
		if err != nil || len(res.Created) != 4 {
			t.Fatalf("import: %+v %v", res, err)
		}
		again, err := w.Import(b, sod.ImportOptions{})
		if err != nil || len(again.Created)+len(again.Updated) != 0 || len(again.Same) != 3 {
			t.Fatalf("re-import should change nothing: %+v %v", again, err)
		}
		rs, _ := c.SodRulesetByKey("finance")
		if rs.Version != 2 { // created, then one version for the whole import
			t.Errorf("ruleset version = %d", rs.Version)
		}
		out, err := sod.BundleOf(c, rs)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(out.Risks[0].Subjects.IdentityTypes, []string{"human"}) || out.Risks[0].BusinessProcess != "Procure to pay" {
			t.Errorf("bundle risk = %+v", out.Risks[0])
		}
		y, err := out.MarshalYAML()
		if err != nil {
			return err
		}
		exported = string(y)
		// the exported file imports back to the same state
		b2, err := sod.ParseYAML(y)
		if err != nil {
			return err
		}
		same, err := w.Import(b2, sod.ImportOptions{})
		if err != nil || len(same.Same) != 3 {
			t.Errorf("round trip changed things: %+v %v", same, err)
		}
		// a changed priority is an update; dropping the risk with prune retires it
		b2.Risks[0].Priority = "low"
		up, err := w.Import(b2, sod.ImportOptions{})
		if err != nil || len(up.Updated) != 1 {
			t.Errorf("update: %+v %v", up, err)
		}
		b2.Risks = nil
		if _, err := w.Import(b2, sod.ImportOptions{}); err != nil {
			t.Errorf("import without risks: %v", err)
		}
		if r, _ := c.SodRiskByKey("pay-own"); r.Status != store.SodActive {
			t.Error("risk retired without prune")
		}
		pr, err := w.Import(b2, sod.ImportOptions{Prune: true})
		if err != nil || len(pr.Retired) != 1 {
			t.Errorf("prune: %+v %v", pr, err)
		}
		return nil
	})
	if !strings.Contains(exported, "name_pattern: payments:create") || !strings.Contains(exported, "schema: tessera.sod/v1") {
		t.Errorf("export:\n%s", exported)
	}
}

func TestParseYAMLRefusals(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":         "",
		"unknown field": "ruleset: {key: a, name: A, colour: red}\n",
		"two documents": "ruleset: {key: a, name: A}\n---\nruleset: {key: b, name: B}\n",
		"wrong schema":  "schema: other/v9\nruleset: {key: a, name: A}\n",
		"not yaml":      "ruleset: [",
	} {
		if _, err := sod.ParseYAML([]byte(doc)); code(err) != "invalid_document" {
			t.Errorf("%s: %v", name, err)
		}
	}
	st, _ := testkit.Tiny(t)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		w := writer(c)
		for name, doc := range map[string]string{
			"unknown function": "ruleset: {key: a, name: A}\nrisks: [{key: r, name: R, priority: high, functions: [x, y]}]\n",
			"bad priority":     "ruleset: {key: a, name: A}\nfunctions: [{key: x, name: X, selectors: [{name_pattern: q}]}, {key: y, name: Y, selectors: [{name_pattern: q}]}]\nrisks: [{key: r, name: R, priority: huge, functions: [x, y]}]\n",
			"one function":     "ruleset: {key: a, name: A}\nfunctions: [{key: x, name: X, selectors: [{name_pattern: q}]}]\nrisks: [{key: r, name: R, priority: high, functions: [x]}]\n",
			"unknown owner":    "ruleset: {key: a, name: A}\nfunctions: [{key: x, name: X, owner: nobody, selectors: [{name_pattern: q}]}]\n",
			"bad key":          "ruleset: {key: 'a b', name: A}\n",
		} {
			b, err := sod.ParseYAML([]byte(doc))
			if err != nil {
				t.Errorf("%s: parse: %v", name, err)
				continue
			}
			if _, err := w.Import(b, sod.ImportOptions{}); err == nil || strings.HasPrefix(code(err), "other") {
				t.Errorf("%s: import: %v", name, err)
			}
		}
		if n, _ := c.CountSodRulesets(); n != 0 {
			t.Error("a refused import wrote a ruleset")
		}
		return nil
	})
}
