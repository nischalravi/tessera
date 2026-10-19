package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func jsonMap(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("not json: %s", body)
	}
	return m
}

func TestSodAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	viewer := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	call := func(l authtest.Login, method, path, body string, want int) map[string]any {
		t.Helper()
		rec := reqDo(h, l, method, path, body)
		if rec.Code != want {
			t.Fatalf("%s %s: %d (want %d) %s", method, path, rec.Code, want, rec.Body)
		}
		if strings.HasPrefix(rec.Body.String(), "{") {
			return jsonMap(t, rec.Body.String())
		}
		return nil
	}
	count := func(m map[string]any) int { return int(m["total"].(float64)) }

	// a tenant with no stored ruleset is checked against its policy files
	if m := call(viewer, "GET", "/api/sod/rulesets", "", 200); m["legacy"] != true {
		t.Errorf("fresh tenant is not legacy: %v", m)
	}
	legacy := call(viewer, "GET", "/api/sod/violations", "", 200)
	if count(legacy) == 0 {
		t.Fatal("the fixture has no SoD violation (bob holds both payments halves)")
	}
	// only policy admins write
	for _, l := range []authtest.Login{viewer} {
		call(l, "POST", "/api/sod/functions", `{"name":"x","selectors":[{"name_pattern":"x"}]}`, 403)
		call(l, "POST", "/api/sod/import-legacy", `{}`, 403)
	}

	// the one-time import keeps the findings
	dry := call(admin, "POST", "/api/sod/import-legacy", `{"dry_run":true}`, 200)
	if dry["dry_run"] != true || len(dry["created"].([]any)) == 0 {
		t.Errorf("dry run: %v", dry)
	}
	call(viewer, "GET", "/api/sod/rulesets", "", 200)
	call(admin, "POST", "/api/sod/import-legacy", `{}`, 200)
	if m := call(viewer, "GET", "/api/sod/rulesets", "", 200); m["legacy"] != false || len(m["rulesets"].([]any)) != 1 {
		t.Errorf("after import: %v", m)
	}
	if after := call(viewer, "GET", "/api/sod/violations", "", 200); count(after) != count(legacy) {
		t.Errorf("import changed the findings: %d -> %d", count(legacy), count(after))
	}
	call(admin, "POST", "/api/sod/import-legacy", `{}`, 200) // idempotent
	if m := call(viewer, "GET", "/api/policies?x=1", "", 200); m != nil {
		t.Log("policies is a list")
	}

	// functions, a risk, a ruleset of our own
	fa := call(admin, "POST", "/api/sod/functions", `{"name":"Read customer data","selectors":[{"name_pattern":"s3:GetObject"},{"name_pattern":"payments:create"}],"note":"v1"}`, 201)
	fb := call(admin, "POST", "/api/sod/functions", `{"name":"Approve payments","selectors":[{"system":"workday","name_pattern":"payments:approve"}]}`, 201)
	call(admin, "POST", "/api/sod/functions", `{"name":"Approve payments","selectors":[{"name_pattern":"x"}]}`, 409)
	call(admin, "POST", "/api/sod/functions", `{"name":"Bad","selectors":[{"name_pattern":"x","attribute":"tag"}]}`, 422)
	rs := call(admin, "POST", "/api/sod/rulesets", `{"name":"Data and money","enabled":true}`, 201)
	riskBody := fmt.Sprintf(`{"name":"Read data and approve","priority":"critical","business_process":"Procure to pay","ruleset_id":%q,"function_ids":[%q,%q]}`,
		rs["id"], fa["id"], fb["id"])
	call(admin, "POST", "/api/sod/risks", strings.Replace(riskBody, `"priority":"critical"`, `"priority":"urgent"`, 1), 422)
	risk := call(admin, "POST", "/api/sod/risks", riskBody, 201)
	if rs2 := call(viewer, "GET", "/api/sod/rulesets/"+rs["id"].(string), "", 200); rs2["version"].(float64) != 2 || rs2["risks"].(float64) != 1 {
		t.Errorf("ruleset after adding a risk: %v", rs2)
	}
	// violations with filters
	for q, want := range map[string]int{
		"?priority=critical": -1, "?priority=low": 0, "?risk=" + risk["key"].(string): -1, "?ruleset=" + rs["key"].(string): -1,
		"?system=workday": -1, "?system=github": 0, "?business_process=procure+to+pay": -1, "?business_process=hr": 0,
		fmt.Sprintf("?identity=%d", f.B.IDs["bob"]): -1, "?identity=nobody-here": 0,
	} {
		m := call(viewer, "GET", "/api/sod/violations"+q, "", 200)
		if (want == 0) != (count(m) == 0) {
			t.Errorf("%s: total %d", q, count(m))
		}
	}
	call(viewer, "GET", "/api/sod/violations?priority=urgent", "", 422)

	// simulate: a request that completes a conflict warns before it is submitted
	if rec := reqDo(h, admin, "PUT", fmt.Sprintf("/api/catalog/items/%d", f.B.IDs["group:okta:payments-approvers"]),
		`{"requestable":true,"risk":"high"}`); rec.Code != 200 {
		t.Fatalf("catalog: %d %s", rec.Code, rec.Body)
	}
	cat := call(viewer, "GET", "/api/catalog", "", 200)
	var itemID string
	for _, it := range cat["items"].([]any) {
		m := it.(map[string]any)
		if g := m["group"].(map[string]any); int64(g["id"].(float64)) == f.B.IDs["group:okta:payments-approvers"] && m["id"] != nil {
			itemID = m["id"].(string)
		}
	}
	if itemID == "" {
		t.Fatal("approvers item not in the catalog")
	}
	nBefore := count(call(viewer, "GET", "/api/sod/violations?risk="+risk["key"].(string), "", 200))
	body := fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":[%q]}`, f.B.IDs["alice"], itemID)
	sim := call(viewer, "POST", "/api/sod/simulate", body, 200)
	trig, _ := sim["would_trigger"].([]any)
	if len(trig) != 1 || sim["highest_priority"] != "critical" || trig[0].(map[string]any)["risk_key"] != risk["key"] {
		t.Errorf("simulate: %v", sim)
	}
	call(viewer, "POST", "/api/sod/simulate", fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":[%q]}`, f.B.IDs["bob"], itemID), 403) // not for others
	call(viewer, "POST", "/api/sod/simulate", `{"beneficiary_ids":[],"catalog_item_ids":[]}`, 422)
	call(admin, "POST", "/api/sod/simulate", fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":[%q]}`, f.B.IDs["alice"], itemID), 200)
	if after := call(viewer, "GET", "/api/sod/violations?risk="+risk["key"].(string), "", 200); count(after) != nBefore {
		t.Error("simulate changed state")
	}

	// version history, YAML export and import back
	fnv := call(admin, "PUT", "/api/sod/functions/"+fa["id"].(string),
		`{"version":1,"name":"Read customer data","selectors":[{"name_pattern":"s3:*"},{"name_pattern":"payments:create"}],"note":"widen"}`, 200)
	if fnv["version"].(float64) != 2 || len(fnv["versions"].([]any)) != 2 {
		t.Errorf("function versions: %v", fnv)
	}
	call(admin, "PUT", "/api/sod/functions/"+fa["id"].(string), `{"version":1,"name":"x","selectors":[{"name_pattern":"s3:*"}]}`, 409)
	exp := call(viewer, "GET", "/api/sod/rulesets/"+rs["id"].(string)+"/export", "", 200)
	y := exp["yaml"].(string)
	if !strings.Contains(y, "name_pattern: s3:*") || !strings.Contains(y, "business_process: Procure to pay") {
		t.Errorf("export:\n%s", y)
	}
	yb, _ := json.Marshal(map[string]any{"yaml": y, "dry_run": true})
	if res := call(admin, "POST", "/api/sod/rulesets/import", string(yb), 200); len(res["created"].([]any))+len(res["updated"].([]any)) != 0 {
		t.Errorf("re-importing the export changes things: %v", res)
	}
	bad, _ := json.Marshal(map[string]any{"yaml": "ruleset: {key: a, name: A, nope: 1}"})
	call(admin, "POST", "/api/sod/rulesets/import", string(bad), 422)

	// retire and disable
	call(admin, "POST", "/api/sod/functions/"+fa["id"].(string)+"/retire", `{"reason":"x"}`, 409)
	call(admin, "PUT", "/api/sod/rulesets/"+rs["id"].(string), `{"version":3,"name":"Data and money","enabled":false}`, 200)
	if after := call(viewer, "GET", "/api/sod/violations?ruleset="+rs["key"].(string), "", 200); count(after) != 0 {
		t.Error("a disabled ruleset still reports")
	}
	call(admin, "POST", "/api/sod/risks/"+risk["id"].(string)+"/retire", `{"reason":"done"}`, 200)

	// every change left its audit event
	acts := reqAuditActions(t, f, f.B.ID)
	for _, a := range []string{"sod.function.create", "sod.function.update", "sod.risk.create", "sod.risk.retire", "sod.ruleset.create",
		"sod.ruleset.import", "sod.ruleset.disable"} {
		if acts[a] == 0 {
			t.Errorf("no %s audit event (have %v)", a, acts)
		}
	}
}

// Tenant A's ids answer exactly like missing ones in tenant B, and A's
// functions cannot be named in B's risks.
func TestSodAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	var aFn, aRs, aRisk string
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		aFn, aRs, aRisk = "fn-a", "rs-a", "rk-a"
		if err := c.InsertSodFunction(&store.SodFunction{ID: aFn, Key: "fn", Name: "Fn " + storetest.Sentinel, Selectors: `[{"name_pattern":"x"}]`,
			Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.InsertSodRuleset(&store.SodRuleset{ID: aRs, Key: "rs", Name: "Rs " + storetest.Sentinel, Enabled: true,
			Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		return c.InsertSodRisk(&store.SodRisk{ID: aRisk, Key: "rk", Name: "Risk " + storetest.Sentinel, Priority: "high", RulesetID: aRs,
			Subjects: "{}", Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	}); err != nil {
		t.Fatal(err)
	}
	const missing = "00000000-0000-4000-8000-00000000dead"
	before := storetest.Dump(t, f.DB, f.A.ID)
	for _, c := range []struct{ method, kind, suffix, body string }{
		{"GET", "functions", "", ""}, {"GET", "risks", "", ""}, {"GET", "rulesets", "", ""}, {"GET", "rulesets", "/export", ""},
		{"PUT", "functions", "", `{"version":1,"name":"x","selectors":[{"name_pattern":"x"}]}`},
		{"POST", "functions", "/retire", `{"reason":"x"}`}, {"POST", "risks", "/retire", `{"reason":"x"}`},
		{"POST", "rulesets", "/retire", `{"reason":"x"}`}, {"PUT", "rulesets", "", `{"version":1,"name":"x"}`},
		{"PUT", "risks", "", `{"version":1,"name":"x","priority":"low"}`},
	} {
		ids := map[string]string{"functions": aFn, "risks": aRisk, "rulesets": aRs}
		cross := reqDo(h, admin, c.method, "/api/sod/"+c.kind+"/"+ids[c.kind]+c.suffix, c.body)
		gone := reqDo(h, admin, c.method, "/api/sod/"+c.kind+"/"+missing+c.suffix, c.body)
		if cross.Code != 404 || cross.Body.String() != gone.Body.String() || leaks(cross.Body.String()) {
			t.Errorf("%s %s%s: %d %s (missing: %d %s)", c.method, c.kind, c.suffix, cross.Code, cross.Body, gone.Code, gone.Body)
		}
	}
	// B's own ruleset and function, then a risk naming A's function or A's ruleset
	rs := jsonMap(t, reqDo(h, admin, "POST", "/api/sod/rulesets", `{"name":"B rules"}`).Body.String())
	fn := jsonMap(t, reqDo(h, admin, "POST", "/api/sod/functions", `{"name":"B fn","selectors":[{"name_pattern":"x"}]}`).Body.String())
	for name, body := range map[string]string{
		"A's function": fmt.Sprintf(`{"name":"r","priority":"low","ruleset_id":%q,"function_ids":[%q,%q]}`, rs["id"], fn["id"], aFn),
		"A's ruleset":  fmt.Sprintf(`{"name":"r","priority":"low","ruleset_id":%q,"function_ids":[%q,%q]}`, aRs, fn["id"], fn["id"]),
	} {
		rec := reqDo(h, admin, "POST", "/api/sod/risks", body)
		if rec.Code != 422 && rec.Code != 404 {
			t.Errorf("risk naming %s: %d %s", name, rec.Code, rec.Body)
		}
	}
	for _, path := range []string{"/api/sod/functions", "/api/sod/risks", "/api/sod/rulesets", "/api/sod/violations"} {
		if rec := reqDo(h, admin, "GET", path, ""); rec.Code != 200 || leaks(rec.Body.String()) {
			t.Errorf("%s: %d, leaks A's data", path, rec.Code)
		}
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("calls made as tenant B changed tenant A")
	}
}
