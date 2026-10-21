package api

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Ruleset-level remediation (issue #298): who may set it, how risks and
// violations inherit it, and where an escalation goes.
func TestSodRemediationAPI_RulesetOptionsAndEscalation(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	operator := reqLogin(t, f, "op@b.example", []auth.Role{auth.RoleOperator}, "")
	viewer := reqLogin(t, f, "v@b.example", []auth.Role{auth.RoleViewer}, "")
	carolUser := reqLogin(t, f, "carol@b.example", []auth.Role{auth.RoleViewer}, "carol")
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, staleAuth, storetest.Now)
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
	risk := call(viewer, "GET", "/api/sod/risks", "", 200)["risks"].([]any)[0].(map[string]any)
	riskID, rsID := risk["id"].(string), risk["ruleset"].(map[string]any)["id"].(string)
	bob, carol := f.B.IDs["bob"], f.B.IDs["carol"]
	path := "/api/sod/rulesets/" + rsID + "/remediation"

	// nothing configured: every option, the risk owner (none here) is the target
	if got := strs(risk["remediation"]); len(got) != 4 || risk["remediation_source"] != "default" {
		t.Errorf("default: %v %v", got, risk["remediation_source"])
	}

	// permissions: sod.manage and a fresh phishing-resistant sign-in
	body := fmt.Sprintf(`{"options":["revoke","escalate"],"escalate_to_id":%d}`, carol)
	call(viewer, "PUT", path, body, 403)
	call(operator, "PUT", path, body, 403)
	if rec := reqDo(h, stale, "PUT", path, body); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %s", rec.Code, rec.Body)
	}
	call(admin, "PUT", "/api/sod/rulesets/nope/remediation", body, 404)
	call(admin, "PUT", path, `{"options":["ignore"]}`, 422)
	call(admin, "PUT", path, `{"options":["revoke"],"escalate_to_id":999999}`, 422)
	call(admin, "PUT", path, `{"options":["revoke"],"surprise":1}`, 422)

	rs := call(admin, "PUT", path, body, 200)
	if got := strs(rs["remediation"]); !slices.Equal(got, []string{"revoke", "escalate"}) || rs["escalate_to"].(map[string]any)["name"] == nil {
		t.Errorf("ruleset view: %v", rs)
	}
	// the risk inherits it, and so does every violation of it
	r := call(viewer, "GET", "/api/sod/risks/"+riskID, "", 200)
	if got := strs(r["remediation"]); !slices.Equal(got, []string{"revoke", "escalate"}) || r["remediation_source"] != "ruleset" {
		t.Errorf("risk view: %v %v", r["remediation"], r["remediation_source"])
	}
	vs := call(viewer, "GET", "/api/sod/violations", "", 200)["violations"].([]any)
	if len(vs) == 0 {
		t.Fatal("no violation")
	}
	for _, v := range vs {
		vm := v.(map[string]any)
		if !slices.Equal(strs(vm["remediation"]), []string{"revoke", "escalate"}) || vm["escalate_to"].(map[string]any)["id"].(float64) != float64(carol) {
			t.Errorf("violation view: %v", vm)
		}
	}
	// mitigate and accept are refused, escalate goes to carol and lands in her inbox
	call(operator, "POST", "/api/sod/mitigations", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"kind":"accept","justification":"x","ends_at":"2026-11-20"}`, riskID, bob), 409)
	esc := call(operator, "POST", "/api/sod/violations/escalate", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"note":"decide please"}`, riskID, bob), 201)
	if esc["routed_to"].(map[string]any)["id"].(float64) != float64(carol) {
		t.Errorf("routed to %v", esc["routed_to"])
	}
	rec := reqDo(h, carolUser, "GET", "/api/notifications", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "SoD violation escalated") {
		t.Errorf("carol's inbox: %d %s", rec.Code, rec.Body)
	}
	// a risk's own options win over the ruleset's
	fj, _ := json.Marshal(func() []string {
		var ids []string
		for _, fn := range risk["functions"].([]any) {
			ids = append(ids, fn.(map[string]any)["id"].(string))
		}
		return ids
	}())
	call(admin, "PUT", "/api/sod/risks/"+riskID, fmt.Sprintf(`{"version":1,"name":%q,"priority":"high","ruleset_id":%q,"function_ids":%s,"remediation":["accept"]}`,
		risk["name"], rsID, fj), 200)
	r = call(viewer, "GET", "/api/sod/risks/"+riskID, "", 200)
	if !slices.Equal(strs(r["remediation"]), []string{"accept"}) || r["remediation_source"] != "risk" {
		t.Errorf("own options: %v %v", r["remediation"], r["remediation_source"])
	}
	// clearing the ruleset's options offers all four again
	call(admin, "PUT", path, `{}`, 200)

	acts := reqAuditActions(t, f, f.B.ID)
	if acts["sod.ruleset.remediation"] != 2 || acts["sod.violation.escalate"] != 1 {
		t.Errorf("audit: %v", acts)
	}
}

// An accepted risk re-opens at its end date through the durable queue (issue #298).
func TestSodRemediationAPI_AcceptanceExpiresThroughTheQueue(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	admin1 := reqLogin(t, f, "pa1@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	admin2 := reqLogin(t, f, "pa2@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
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
	call(admin1, "POST", "/api/sod/import-legacy", `{}`, 200)
	riskID := call(viewer, "GET", "/api/sod/risks", "", 200)["risks"].([]any)[0].(map[string]any)["id"].(string)
	open := func() int { return int(call(viewer, "GET", "/api/sod/violations", "", 200)["open"].(float64)) }
	n0 := open()
	expireJobs := func() []*store.QueueJob {
		var out []*store.QueueJob
		if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
			var err error
			out, err = c.QueueJobs(store.QueueJobFilter{Kind: jobs.SoDMitigationExpire, Limit: 50})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}

	m := call(admin1, "POST", "/api/sod/mitigations", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"kind":"accept","justification":"business need","ends_at":"2026-11-20"}`,
		riskID, f.B.IDs["bob"]), 201)
	mid := m["id"].(string)
	if len(expireJobs()) != 0 {
		t.Fatal("a job was queued before the acceptance was approved")
	}
	call(admin2, "POST", "/api/sod/mitigations/"+mid+"/reject", `{"note":"no"}`, 200)
	if len(expireJobs()) != 0 {
		t.Fatal("a job was queued by a rejection")
	}
	m = call(admin1, "POST", "/api/sod/mitigations", fmt.Sprintf(`{"risk_id":%q,"identity_id":%d,"kind":"accept","justification":"business need","ends_at":"2026-11-20"}`,
		riskID, f.B.IDs["bob"]), 201)
	mid = m["id"].(string)
	call(admin2, "POST", "/api/sod/mitigations/"+mid+"/approve", `{}`, 200)
	js := expireJobs()
	if len(js) != 1 || js[0].IdempotencyKey == nil || *js[0].IdempotencyKey != "sod-expire:"+mid || js[0].Status != store.QueueQueued ||
		!strings.Contains(js[0].Payload, mid) {
		t.Fatalf("queued jobs: %+v", js)
	}
	end := time.Date(2026, 11, 20, 23, 59, 59, 0, time.UTC) // a date-only end runs to the end of that day
	if !js[0].RunAt.Equal(end) {
		t.Errorf("the job runs at %v, want the end date %v", js[0].RunAt, end)
	}
	if open() != n0-1 {
		t.Fatalf("approving did not cover the violation: open %d, was %d", open(), n0)
	}

	// before the end date the job does nothing; after it, the violation is open again
	job := queue.Job{Tenant: f.B.ID, Kind: jobs.SoDMitigationExpire, Payload: js[0].Payload}
	if res, err := srv.queueSoDExpire(context.Background(), job); err != nil || res != nil {
		t.Fatalf("early run: %v %v", res, err)
	}
	later := newIsolationServerWith(f, func(c *Config) { c.Clock = timeutil.Frozen(end.Add(time.Hour)) })
	res, err := later.queueSoDExpire(context.Background(), job)
	if err != nil || res == nil {
		t.Fatalf("due run: %v %v", res, err)
	}
	if res, err := later.queueSoDExpire(context.Background(), job); err != nil || res != nil {
		t.Errorf("a retry of a finished job: %v %v", res, err)
	}
	got := call(viewer, "GET", "/api/sod/mitigations?status=expired", "", 200)["mitigations"].([]any)
	if len(got) != 1 {
		t.Errorf("expired mitigations: %v", got)
	}
	if acts := reqAuditActions(t, f, f.B.ID); acts["sod.mitigation.expire"] != 1 || acts["sod.mitigation.approve"] != 1 {
		t.Errorf("audit: %v", acts)
	}
	// a malformed payload is not retried
	if _, err := srv.queueSoDExpire(context.Background(), queue.Job{Tenant: f.B.ID, Payload: `{}`}); err == nil {
		t.Error("an empty payload was accepted")
	}
}
