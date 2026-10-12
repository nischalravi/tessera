package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/rotation"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// rotAPI is the rotation API over tenant B of the two-tenant fixture, with the
// engine that runs its jobs.
type rotAPI struct {
	t   *testing.T
	f   *storetest.Fixture
	srv *Server
	h   http.Handler
	eng *rotation.Engine
}

func newRotAPI(t *testing.T) *rotAPI {
	t.Helper()
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	a := &rotAPI{t: t, f: f, srv: srv, h: asAdmin(t, srv, f.DB, f.B.ID, storetest.Now).Handler()}
	a.eng = &rotation.Engine{DB: f.DB, Service: srv.rotation, Clock: timeutil.Frozen(storetest.Now),
		Factory: &rotation.Factory{Sealer: srv.cfg.Sealer, AllowFake: true, Now: timeutil.Frozen(storetest.Now)}}
	return a
}

// call sends a request and decodes the JSON answer (an object or an array).
func (a *rotAPI) call(method, path, body string, want int) (any, string) {
	a.t.Helper()
	rec := serveOnce(a.h, method, path, body)
	if rec.Code != want {
		a.t.Fatalf("%s %s: %d %.400s, want %d", method, path, rec.Code, rec.Body.String(), want)
	}
	var v any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			a.t.Fatalf("%s %s: not JSON: %v", method, path, err)
		}
	}
	return v, rec.Body.String()
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func arr(v any) []any          { l, _ := v.([]any); return l }

func (a *rotAPI) actions() []string {
	a.t.Helper()
	var out []string
	if err := a.f.DB.ReadTenant(context.Background(), a.f.B.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditLog(-1)
		for i := len(evs) - 1; i >= 0; i-- {
			out = append(out, evs[i].Action)
		}
		return err
	}); err != nil {
		a.t.Fatal(err)
	}
	return out
}

func (a *rotAPI) runEngine(n int) {
	a.t.Helper()
	for i := 0; i < n; i++ {
		if _, err := a.eng.RunTenant(context.Background(), a.f.B.ID); err != nil {
			a.t.Fatal(err)
		}
	}
}

// TestRotationAPI_EndToEnd drives the whole feature through HTTP: adapters
// and a policy, a plan, rotate now, the worker running the job to
// completion, and a vendor-compromised bulk run.
func TestRotationAPI_EndToEnd(t *testing.T) {
	a := newRotAPI(t)
	secret := a.f.B.IDs["secret"]
	const vaultToken = "s.apiTestVaultToken0123456789"

	// adapters: the credential is accepted, sealed, and never shown again
	_, raw := a.call("PUT", "/api/rotation/adapters/vault-prod", `{"type":"vault","config":{"address":"https://vault.example"},"credential":{"token":"`+vaultToken+`"}}`, 201)
	if strings.Contains(raw, vaultToken) {
		t.Error("the PUT response echoes the credential")
	}
	v, raw := a.call("GET", "/api/rotation/adapters", "", 200)
	if strings.Contains(raw, vaultToken) {
		t.Error("the adapter list returns the credential")
	}
	var vault map[string]any
	for _, x := range arr(obj(v)["adapters"]) {
		if obj(x)["name"] == "vault-prod" {
			vault = obj(x)
		}
	}
	if vault == nil || vault["credential_set"] != true || obj(vault["config"])["address"] != "https://vault.example" {
		t.Errorf("vault adapter %v", vault)
	}
	if !slices.Contains(toStrings(arr(obj(v)["types"])), "fake") {
		t.Error("the simulated adapter should be offered in a server that allows it")
	}
	a.call("PUT", "/api/rotation/adapters/vault-prod", `{"name":"other","type":"vault"}`, 422) // name mismatch
	a.call("PUT", "/api/rotation/adapters/sim", `{"type":"fake"}`, 201)
	a.call("PUT", "/api/rotation/adapters/sim", `{"type":"fake","unknown":1}`, 422) // strict bodies

	// a policy, replacing the fixture's policy for the same kind
	a.call("PUT", "/api/rotation/policies", `{"kind":"access_key","max_age_days":90,"grace_hours":0,"adapter":"sim","destination":"sim","dest_path":"kv/{system}/{name}"}`, 200)
	a.call("PUT", "/api/rotation/policies", `{"kind":"access_key","max_age_days":0}`, 422)
	pols, _ := a.call("GET", "/api/rotation/policies", "", 200)
	if n := len(arr(pols)); n != 1 {
		t.Errorf("%d policies", n)
	}

	// plan: a dry run
	plan, _ := a.call("POST", "/api/rotation/plan", fmt.Sprintf(`{"secret_ids":[%d]}`, secret), 200)
	item := obj(arr(plan)[0])
	if item["action"] != "in_flight" { // the fixture already has a pending job for this secret
		t.Fatalf("plan item %v", item)
	}
	a.call("POST", "/api/rotation/jobs", fmt.Sprintf(`{"secret_id":%d}`, secret), 409)
	a.call("POST", "/api/rotation/jobs/"+a.f.B.Refs["rot:job"]+"/retry", `{}`, 409) // not failed
	a.call("POST", "/api/rotation/jobs/"+a.f.B.Refs["rot:job"]+"/cancel", `{}`, 200)
	plan, _ = a.call("POST", "/api/rotation/plan", fmt.Sprintf(`{"secret_ids":[%d]}`, secret), 200)
	item = obj(arr(plan)[0])
	if item["action"] != "rotate" || item["adapter"] != "sim" || len(arr(item["steps"])) < 5 {
		t.Fatalf("plan item %v", item)
	}
	a.call("POST", "/api/rotation/plan", `{"secret_ids":[987654321]}`, 404)

	// rotate now
	job, _ := a.call("POST", "/api/rotation/jobs", fmt.Sprintf(`{"secret_id":%d}`, secret), 201)
	id := obj(job)["id"].(string)
	if obj(job)["state"] != "pending" {
		t.Errorf("new job %v", job)
	}
	a.call("POST", "/api/rotation/jobs", `{"secret_id":0}`, 422)
	list, _ := a.call("GET", "/api/rotation/jobs?state=pending", "", 200)
	if n := len(arr(list)); n != 1 {
		t.Errorf("%d pending jobs", n)
	}
	a.call("GET", "/api/rotation/jobs?state=bogus", "", 422)
	a.call("GET", "/api/rotation/jobs?secret_id=x", "", 422)
	a.call("GET", "/api/rotation/jobs?limit=0", "", 422)

	// the worker runs it: create + hand over, disable, verify, delete
	a.runEngine(5)
	job, _ = a.call("GET", "/api/rotation/jobs/"+id, "", 200)
	j := obj(job)
	if j["state"] != "old_deleted" || j["new_ref"] == nil || j["completed_at"] == nil {
		t.Fatalf("job after the worker ran: %v", j)
	}
	ver := obj(j["verification"])
	if ver["verdict"] != "ok" || ver["old_age_days"] == nil || ver["last_used_known"] != true {
		t.Errorf("verification %v", ver)
	}
	steps := arr(j["steps"])
	if len(steps) != 5 || obj(steps[4])["status"] != "done" {
		t.Errorf("steps %v", steps)
	}
	ov, _ := a.call("GET", "/api/rotation/overview", "", 200)
	row := obj(arr(ov)[0])
	for _, r := range arr(ov) {
		if obj(r)["secret_id"] == float64(secret) {
			row = obj(r)
		}
	}
	if obj(row["last_job"])["state"] != "old_deleted" || row["active_job"] != nil {
		t.Errorf("overview row %v", row)
	}

	// a bulk vendor-compromised run: plan (dry run), then execute with the plan's hash
	bp, _ := a.call("POST", "/api/rotation/bulk/plan", `{"system":"aws"}`, 200)
	hash := obj(bp)["plan_hash"].(string)
	if obj(obj(bp)["counts"])["rotate"] != float64(1) {
		t.Errorf("bulk plan %v", bp)
	}
	a.call("POST", "/api/rotation/bulk/plan", `{"system":"no-such-system"}`, 404)
	a.call("POST", "/api/rotation/bulk", `{"system":"aws","reason":"Vendor breach notice","plan_hash":"stale"}`, 409)
	a.call("POST", "/api/rotation/bulk", `{"system":"aws","reason":"short","plan_hash":"`+hash+`"}`, 422)
	run, _ := a.call("POST", "/api/rotation/bulk", `{"system":"aws","reason":"Vendor breach notice","plan_hash":"`+hash+`"}`, 201)
	bulkID := obj(run)["id"].(string)
	if len(arr(obj(run)["jobs"])) != 1 {
		t.Errorf("bulk run %v", run)
	}
	a.runEngine(5)
	run, _ = a.call("GET", "/api/rotation/bulk/"+bulkID, "", 200)
	if obj(obj(run)["progress"])["old_deleted"] != float64(1) {
		t.Errorf("bulk progress %v", obj(run)["progress"])
	}
	byBulk, _ := a.call("GET", "/api/rotation/jobs?bulk_id="+bulkID, "", 200)
	if len(arr(byBulk)) != 1 || obj(arr(byBulk)[0])["origin"] != "vendor_compromise" {
		t.Errorf("jobs of the bulk run %v", byBulk)
	}
	bulks, _ := a.call("GET", "/api/rotation/bulk", "", 200)
	if len(arr(bulks)) != 2 { // the fixture's and this one
		t.Errorf("%d bulk runs", len(arr(bulks)))
	}

	// every change is in the audit ledger, committed with the change
	got := a.actions()
	for _, want := range []string{"rotation.adapter.created", "rotation.policy.updated", "rotation.job.queued", "rotation.job.cancelled",
		"rotation.job.created", "rotation.job.handed_over", "rotation.job.old_disabled", "rotation.job.verified", "rotation.completed",
		"rotation.bulk.executed", "rotation.owner_notified"} {
		if !slices.Contains(got, want) {
			t.Errorf("audit lacks %s", want)
		}
	}
	var ledger string
	_ = a.f.DB.ReadTenant(context.Background(), a.f.B.ID, func(c *store.TenantTx) error {
		evs, _ := c.AuditLog(-1)
		for _, e := range evs {
			ledger += e.Action + " " + string(e.Detail) + "\n"
		}
		return nil
	})
	if strings.Contains(ledger, vaultToken) {
		t.Error("the adapter credential is in the audit ledger")
	}
}

func toStrings(l []any) []string {
	var out []string
	for _, v := range l {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// Rotation changes need secrets.rotate (policy_admin) and a fresh phishing-
// resistant sign-in; reading needs only graph.read.
func TestRotationAPI_PermissionsAndStepUp(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	h := srv.Handler()
	stale := authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}
	admin := authtest.User{Email: "rot-admin@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}
	staleLogin := signIn(t, f.DB, f.B.ID, admin, stale, storetest.Now)
	fresh := signIn(t, f.DB, f.B.ID, authtest.User{Email: "rot-admin2@b.example", Roles: admin.Roles}, authtest.Phr, storetest.Now)
	tenantAdmin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "rot-ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "rot-viewer@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	mutations := []struct{ method, path, body string }{
		{"PUT", "/api/rotation/adapters/sim", `{"type":"fake"}`},
		{"DELETE", "/api/rotation/adapters/sim", ``},
		{"PUT", "/api/rotation/policies", `{"kind":"pat","max_age_days":30}`},
		{"DELETE", "/api/rotation/policies/" + f.B.Refs["rot:policy"], ``},
		{"POST", "/api/rotation/jobs", `{"secret_id":1}`},
		{"POST", "/api/rotation/jobs/" + f.B.Refs["rot:job"] + "/retry", `{}`},
		{"POST", "/api/rotation/jobs/" + f.B.Refs["rot:job"] + "/cancel", `{}`},
		{"POST", "/api/rotation/bulk", `{"system":"aws","reason":"a long enough reason","plan_hash":"x"}`},
	}
	for _, m := range mutations {
		name := m.method + " " + m.path
		if rec := serve(h, authed(staleLogin, m.method, m.path, m.body)); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
			t.Errorf("%s with a 20-minute-old sign-in: %d %.200s", name, rec.Code, rec.Body.String())
		}
		for who, l := range map[string]authtest.Login{"tenant admin": tenantAdmin, "viewer": viewer} {
			if rec := serve(h, authed(l, m.method, m.path, m.body)); rec.Code != 403 {
				t.Errorf("%s as %s: %d, want 403", name, who, rec.Code)
			}
		}
		if rec := serve(h, authed(fresh, m.method, m.path, m.body)); rec.Code == 401 || rec.Code == 403 {
			t.Errorf("%s with a fresh sign-in: %d %.200s", name, rec.Code, rec.Body.String())
		}
	}
	for _, p := range []string{"/api/rotation/overview", "/api/rotation/adapters", "/api/rotation/policies", "/api/rotation/jobs", "/api/rotation/bulk"} {
		if rec := serve(h, authed(viewer, "GET", p, "")); rec.Code != 200 {
			t.Errorf("viewer GET %s: %d", p, rec.Code)
		}
	}
	for _, tc := range []struct{ path, body string }{{"/api/rotation/plan", `{}`}, {"/api/rotation/bulk/plan", `{"system":"aws"}`}} {
		if rec := serve(h, authed(viewer, "POST", tc.path, tc.body)); rec.Code != 200 {
			t.Errorf("viewer POST %s (a dry run): %d %.200s", tc.path, rec.Code, rec.Body.String())
		}
	}
}

// Plans are dry runs: they fail closed like a read when their http.request event cannot be written.
func TestRotationAPI_PlansAreAuditedReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	for _, rt := range srv.Routes() {
		if rt.Method == "POST" && (rt.Pattern == "/api/rotation/plan" || rt.Pattern == "/api/rotation/bulk/plan") {
			if rt.Write {
				t.Errorf("%s runs in a write transaction", rt.Pattern)
			}
		}
	}
}

// Every rotation route is documented in /api/rotation/openapi.json.
func TestRotationOpenAPI_CoversRoutes(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/rotation/openapi.json", nil)
	signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now).Apply(req)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, rt := range srv.Routes() {
		if !strings.HasPrefix(rt.Pattern, "/api/rotation") || rt.Pattern == "/api/rotation/openapi.json" {
			continue
		}
		n++
		if doc.Paths[rt.Pattern][strings.ToLower(rt.Method)] == nil {
			t.Errorf("%s %s is not documented", rt.Method, rt.Pattern)
		}
	}
	if n != 17 {
		t.Errorf("%d rotation routes registered, want 17", n)
	}
}

// A leaver's secret is rotated through the rotation service when a policy
// covers it (the JML rotate_secret step), and its rotation time is left to the job.
func TestRotationAPI_LeaverSecretsAreRotated(t *testing.T) {
	a := newRotAPI(t)
	secret := a.f.B.IDs["secret"]
	a.call("PUT", "/api/rotation/adapters/sim", `{"type":"fake"}`, 201)
	a.call("PUT", "/api/rotation/policies", `{"kind":"access_key","max_age_days":90,"grace_hours":72,"adapter":"sim","destination":"sim","dest_path":"kv/{name}"}`, 200)
	a.call("POST", "/api/rotation/jobs/"+a.f.B.Refs["rot:job"]+"/cancel", `{}`, 200) // free the fixture secret
	// dave owns the svc-etl service account that holds the secret
	var ev int64
	if err := a.f.DB.InTenant(context.Background(), a.f.B.ID, func(c *store.TenantTx) error {
		dave := a.f.B.IDs["dave"]
		var err error
		ev, err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: "rot-leaver", Type: "leaver", IdentityID: &dave, EffectiveAt: storetest.Now, Status: "pending"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	a.call("POST", fmt.Sprintf("/api/hris/events/%d/execute", ev), `{}`, 200)
	jobs, _ := a.call("GET", fmt.Sprintf("/api/rotation/jobs?secret_id=%d&state=pending", secret), "", 200)
	if len(arr(jobs)) != 1 {
		t.Fatalf("jobs %v", jobs)
	}
	j := obj(arr(jobs)[0])
	if j["origin"] != "jml" || j["grace_hours"] != float64(0) {
		t.Errorf("job %v: a leaver's credential is rotated at once", j)
	}
	if err := a.f.DB.ReadTenant(context.Background(), a.f.B.ID, func(c *store.TenantTx) error {
		s, err := c.SecretByID(secret)
		if err == nil && s.LastRotatedAt != nil {
			t.Errorf("the rotation time was stamped (%v) although the rotation has not run", s.LastRotatedAt)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
