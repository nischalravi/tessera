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

func TestSodMitigationAPI_Flow(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin1 := reqLogin(t, f, "pa1@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	admin2 := reqLogin(t, f, "pa2@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	operator := reqLogin(t, f, "op@b.example", []auth.Role{auth.RoleOperator}, "")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice") // the risk owner
	viewer := reqLogin(t, f, "v@b.example", []auth.Role{auth.RoleViewer}, "")
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
	num := func(m map[string]any, k string) int { return int(m[k].(float64)) }

	// the legacy policies become a stored risk; its owner is alice, and it offers every option
	call(admin1, "POST", "/api/sod/import-legacy", `{}`, 200)
	risks := call(viewer, "GET", "/api/sod/risks", "", 200)["risks"].([]any)
	risk := risks[0].(map[string]any)
	riskID := risk["id"].(string)
	var fnIDs []string
	for _, fn := range risk["functions"].([]any) {
		fnIDs = append(fnIDs, fn.(map[string]any)["id"].(string))
	}
	fj, _ := json.Marshal(fnIDs)
	updateRisk := func(version int, remediation string) {
		t.Helper()
		call(admin1, "PUT", "/api/sod/risks/"+riskID, fmt.Sprintf(`{"version":%d,"name":%q,"priority":"high","ruleset_id":%q,"function_ids":%s,"owner_id":%d,"remediation":%s}`,
			version, risk["name"], risk["ruleset"].(map[string]any)["id"], fj, f.B.IDs["alice"], remediation), 200)
	}
	updateRisk(1, `[]`)
	if r := call(viewer, "GET", "/api/sod/risks/"+riskID, "", 200); len(r["remediation"].([]any)) != 4 {
		t.Errorf("default remediation: %v", r["remediation"])
	}
	bob := f.B.IDs["bob"]
	open := func() int { return num(call(viewer, "GET", "/api/sod/violations", "", 200), "open") }
	total := func() int { return num(call(viewer, "GET", "/api/sod/violations", "", 200), "total") }
	n0 := open()
	if n0 == 0 {
		t.Fatal("no open violation to mitigate")
	}
	policyViolations := func() int {
		rec := reqDo(h, viewer, "GET", "/api/violations", "")
		var vs []any
		_ = json.Unmarshal(rec.Body.Bytes(), &vs)
		return len(vs)
	}
	pv0 := policyViolations()

	// the control library: only sod.manage writes
	ctlBody := fmt.Sprintf(`{"name":"Monthly payments review","description":"d","owner_id":%d,"type":"detective","frequency":"monthly","evidence_requirement":"signed report"}`, f.B.IDs["alice"])
	call(operator, "POST", "/api/sod/controls", ctlBody, 403)
	call(admin1, "POST", "/api/sod/controls", strings.Replace(ctlBody, "detective", "magic", 1), 422)
	ctl := call(admin1, "POST", "/api/sod/controls", ctlBody, 201)
	call(admin1, "POST", "/api/sod/controls", ctlBody, 409)
	if c := call(viewer, "GET", "/api/sod/controls/"+ctl["id"].(string), "", 200); c["type"] != "detective" {
		t.Errorf("control: %v", c)
	}
	call(admin1, "PUT", "/api/sod/controls/"+ctl["id"].(string), strings.Replace(ctlBody, `"name"`, fmt.Sprintf(`"version":1,"name"`), 1), 200)

	// request: needs sod.mitigate, an end date, a control; a viewer cannot
	end := "2026-11-20" // the fixture clock is 2026-10-08
	req := func(l authtest.Login, ends string, want int) map[string]any {
		return call(l, "POST", "/api/sod/mitigations", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"kind":"control","control_id":%q,"justification":"reviewed monthly","ends_at":%q,"evidence":["SEC-12"]}`,
			riskID, bob, ctl["id"], ends), want)
	}
	req(viewer, end, 403)
	req(operator, "", 422)
	req(operator, "2025-01-01", 422)
	req(operator, "2030-01-01", 422)
	call(operator, "POST", "/api/sod/mitigations", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"kind":"control","control_id":%q,"justification":"x","ends_at":%q}`, riskID, f.B.IDs["carol"], ctl["id"], end), 409) // no violation
	m := req(operator, end, 201)
	mid := m["id"].(string)
	req(operator, end, 409) // already pending
	if open() != n0 {
		t.Error("a pending request must not close the violation")
	}
	// four-eyes: the requester cannot decide it, a viewer cannot, another admin can
	call(operator, "POST", "/api/sod/mitigations/"+mid+"/approve", `{}`, 403) // operators lack sod.approve
	call(viewer, "POST", "/api/sod/mitigations/"+mid+"/approve", `{}`, 403)
	// a decider with no linked identity is refused (#446)
	unlinked := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ul@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	if rec := reqDo(h, unlinked, "POST", "/api/sod/mitigations/"+mid+"/approve", `{}`); rec.Code != 403 || !strings.Contains(rec.Body.String(), `"decider_unlinked"`) {
		t.Errorf("unlinked decider: %d %s", rec.Code, rec.Body)
	}
	call(admin2, "POST", "/api/sod/mitigations/"+mid+"/reject", `{}`, 422) // a note is required
	m = call(admin2, "POST", "/api/sod/mitigations/"+mid+"/approve", `{"note":"fine"}`, 200)
	if m["status"] != "active" {
		t.Fatalf("approved: %v", m)
	}
	// the violation leaves the open counts everywhere, and stays visible in the report
	if open() != n0-1 || total() != n0 || policyViolations() != pv0-1 {
		t.Errorf("counts: open %d (was %d), total %d, policy violations %d (was %d)", open(), n0, total(), policyViolations(), pv0)
	}
	vs := call(viewer, "GET", "/api/sod/violations?status=mitigated", "", 200)["violations"].([]any)
	if len(vs) != 1 || !strings.HasPrefix(vs[0].(map[string]any)["mitigation"].(map[string]any)["label"].(string), "Mitigated until 2026-11-20") {
		t.Errorf("mitigated report: %v", vs)
	}
	if ms := call(viewer, "GET", "/api/sod/mitigations?expiring_within_days=60", "", 200)["mitigations"].([]any); len(ms) != 1 {
		t.Errorf("expiring soon: %v", ms)
	}
	if ms := call(viewer, "GET", "/api/sod/mitigations?expiring_within_days=5", "", 200)["mitigations"].([]any); len(ms) != 0 {
		t.Errorf("not expiring in 5 days: %v", ms)
	}
	// early revoke: not by the requester or a viewer; by the risk owner
	call(viewer, "POST", "/api/sod/mitigations/"+mid+"/revoke", `{"reason":"x"}`, 403)
	call(operator, "POST", "/api/sod/mitigations/"+mid+"/revoke", `{"reason":"x"}`, 403)
	call(alice, "POST", "/api/sod/mitigations/"+mid+"/revoke", `{"reason":""}`, 422)
	call(alice, "POST", "/api/sod/mitigations/"+mid+"/revoke", `{"reason":"the control stopped"}`, 200)
	if open() != n0 || policyViolations() != pv0 {
		t.Error("a revoked mitigation did not reopen the violation")
	}
	call(alice, "POST", "/api/sod/mitigations/"+mid+"/revoke", `{"reason":"again"}`, 409)

	// remediation options are enforced: with only revoke and escalate, mitigate and accept are refused
	updateRisk(2, `["revoke","escalate"]`)
	req(operator, end, 409)
	call(operator, "POST", "/api/sod/mitigations", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"kind":"accept","justification":"x","ends_at":%q}`, riskID, bob, end), 409)
	call(operator, "POST", "/api/sod/violations/escalate", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"note":"decide please"}`, riskID, bob), 201)
	call(viewer, "POST", "/api/sod/violations/escalate", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"note":"x"}`, riskID, bob), 403)
	// revoke goes through the revoke path: a dry run shows the effect, the grant must be one of the violation's
	vio := call(viewer, "GET", "/api/sod/violations", "", 200)["violations"].([]any)[0].(map[string]any)
	edge := vio["edges"].([]any)[0].([]any)
	var edgeID int64
	g := call(viewer, "GET", fmt.Sprintf("/api/identities/%d", bob), "", 200)["grants"].([]any)
	for _, x := range g {
		gm := x.(map[string]any)
		if gm["src"] == edge[0] && gm["dst"] == edge[1] {
			edgeID = int64(gm["edge_id"].(float64))
		}
	}
	if edgeID == 0 {
		t.Fatal("no grant behind the violation")
	}
	dry := call(viewer, "POST", "/api/sod/violations/revoke", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"edge_id":%d,"dry_run":true}`, riskID, bob, edgeID), 200)
	if dry["dry_run"] != true {
		t.Errorf("dry run: %v", dry)
	}
	call(viewer, "POST", "/api/sod/violations/revoke", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"edge_id":%d}`, riskID, bob, edgeID), 403)
	call(admin1, "POST", "/api/sod/violations/revoke", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"edge_id":%d,"dry_run":true}`, riskID, bob, f.B.IDs["edge:1"]), 409)
	updateRisk(3, `["mitigate","accept","escalate"]`)
	call(admin1, "POST", "/api/sod/violations/revoke", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"edge_id":%d,"dry_run":true}`, riskID, bob, edgeID), 409) // revoke not offered
	updateRisk(4, `[]`)
	applied := call(admin1, "POST", "/api/sod/violations/revoke", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"edge_id":%d}`, riskID, bob, edgeID), 200)
	if applied["applied"] != true || open() >= n0 {
		t.Errorf("revoke: %v, open %d", applied, open())
	}

	// every step is in the audit ledger and so in its export
	acts := reqAuditActions(t, f, f.B.ID)
	for _, a := range []string{"sod.control.create", "sod.control.update", "sod.mitigation.request", "sod.mitigation.approve", "sod.mitigation.revoke",
		"sod.violation.escalate", "grant.revoke"} {
		if acts[a] == 0 {
			t.Errorf("no %s audit event (have %v)", a, acts)
		}
	}
	exp := reqDo(h, reqLogin(t, f, "au@b.example", []auth.Role{auth.RoleAuditor}, ""), "GET", "/api/audit/export", "")
	if exp.Code != 200 || !strings.Contains(exp.Body.String(), "sod.mitigation.approve") {
		t.Errorf("the audit export lacks the mitigation approval: %d", exp.Code)
	}
}

func TestSodMitigationAPI_FourEyesAndReviews(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	viewer := reqLogin(t, f, "v@b.example", []auth.Role{auth.RoleViewer}, "")
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
	call(admin, "POST", "/api/sod/import-legacy", `{}`, 200)
	riskID := call(viewer, "GET", "/api/sod/risks", "", 200)["risks"].([]any)[0].(map[string]any)["id"].(string)
	m := call(admin, "POST", "/api/sod/mitigations", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"kind":"accept","justification":"business need","ends_at":"2026-12-01"}`,
		riskID, f.B.IDs["bob"]), 201)
	// the requester cannot approve their own request, even holding sod.approve
	call(admin, "POST", "/api/sod/mitigations/"+m["id"].(string)+"/approve", `{}`, 403)
	call(admin, "POST", "/api/sod/mitigations/"+m["id"].(string)+"/cancel", `{}`, 200)
	// the review context lists the SoD risk behind a grant of the campaign
	camp := f.B.IDs["campaign"]
	ctx := call(viewer, "GET", fmt.Sprintf("/api/sod/review-context?campaign_id=%d", camp), "", 200)
	if _, ok := ctx["items"]; !ok {
		t.Errorf("review context: %v", ctx)
	}
	call(viewer, "GET", "/api/sod/review-context?campaign_id=999999", "", 404)
}

// Tenant A's controls and mitigations answer like missing ones in tenant B.
func TestSodMitigationAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	var aCtl, aMit, aRisk string
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "a user", CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		uid := u.ID.String()
		aCtl, aMit, aRisk = "ctl-a", "mit-a", "rk-a"
		if err := c.InsertSodRuleset(&store.SodRuleset{ID: "rs-a", Key: "rs", Name: "Rs", Enabled: true, Status: store.SodActive, Version: 1,
			CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.InsertSodRisk(&store.SodRisk{ID: aRisk, Key: "rk", Name: "Risk " + storetest.Sentinel, Priority: "high", RulesetID: "rs-a", Subjects: "{}",
			Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		owner := f.A.IDs["alice"]
		if err := c.InsertSodControl(&store.SodControl{ID: aCtl, Name: "Control " + storetest.Sentinel, OwnerID: &owner, Type: "detective", Frequency: "daily",
			Status: store.SodActive, Version: 1, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		return c.InsertSodMitigation(&store.SodMitigation{ID: aMit, RiskID: aRisk, IdentityID: owner, Kind: store.MitigationControl, ControlID: &aCtl,
			Justification: "j " + storetest.Sentinel, Evidence: "[]", Status: store.MitigationActive, EndsAt: storetest.Now.AddDate(0, 1, 0),
			RequestedBy: uid, RequestedAt: storetest.Now})
	}); err != nil {
		t.Fatal(err)
	}
	const missing = "00000000-0000-4000-8000-00000000dead"
	before := storetest.Dump(t, f.DB, f.A.ID)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/sod/controls/%s", ""}, {"PUT", "/api/sod/controls/%s", `{"version":1,"name":"x","type":"detective","frequency":"daily","owner_id":1}`},
		{"POST", "/api/sod/controls/%s/retire", `{"reason":"x"}`},
		{"POST", "/api/sod/mitigations/%s/approve", `{}`}, {"POST", "/api/sod/mitigations/%s/reject", `{"note":"x"}`},
		{"POST", "/api/sod/mitigations/%s/cancel", `{}`}, {"POST", "/api/sod/mitigations/%s/revoke", `{"reason":"x"}`},
	} {
		id := aCtl
		if strings.Contains(c.path, "mitigations") {
			id = aMit
		}
		cross := reqDo(h, admin, c.method, fmt.Sprintf(c.path, id), c.body)
		gone := reqDo(h, admin, c.method, fmt.Sprintf(c.path, missing), c.body)
		if cross.Code != 404 || cross.Body.String() != gone.Body.String() || leaks(cross.Body.String()) {
			t.Errorf("%s %s: %d %s (missing: %d %s)", c.method, c.path, cross.Code, cross.Body, gone.Code, gone.Body)
		}
	}
	// B cannot request against A's risk or escalate it
	for _, body := range []string{
		fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"kind":"accept","justification":"x","ends_at":"2026-12-01"}`, aRisk, f.B.IDs["bob"]),
	} {
		if rec := reqDo(h, admin, "POST", "/api/sod/mitigations", body); rec.Code != 404 {
			t.Errorf("mitigating A's risk: %d %s", rec.Code, rec.Body)
		}
	}
	if rec := reqDo(h, admin, "POST", "/api/sod/violations/escalate", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"note":"x"}`, aRisk, f.B.IDs["bob"])); rec.Code != 404 {
		t.Errorf("escalating A's risk: %d %s", rec.Code, rec.Body)
	}
	for _, path := range []string{"/api/sod/controls", "/api/sod/mitigations", "/api/sod/risks", "/api/sod/violations"} {
		if rec := reqDo(h, admin, "GET", path, ""); rec.Code != 200 || leaks(rec.Body.String()) {
			t.Errorf("%s: %d, leaks A's data", path, rec.Code)
		}
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("calls made as tenant B changed tenant A")
	}
}
