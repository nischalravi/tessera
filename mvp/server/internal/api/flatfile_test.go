package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

const ffMapping = `{"name":"HR app","owner":"hr@example.com",
 "accounts":{"account_id":"UserID","username":"Login","email":"Mail","identity_id":"EmpNo","status":"State"},
 "entitlements":{"account_id":"UserID","entitlement":"Role","name":"RoleName","privileged":"Admin"}}`

const (
	ffAccounts = "UserID,Login,Mail,EmpNo,State\nu1,alice.a,alice@t.example,,active\nu2,bob.b,,bob,active\nu3,carol.c,,,active\n"
	ffEnts     = "UserID,Role,RoleName,Admin\nu1,invoice:create,Create,no\nu1,invoice:approve,Approve,yes\nu2,invoice:create,Create,no\n"
)

type ffEnv struct {
	t       *testing.T
	f       *storetest.Fixture
	h       http.Handler
	admin   authtest.Login // tenant_admin: mappings
	pa      authtest.Login // policy_admin: uploads, close tasks
	op      authtest.Login // operator: uploads
	viewer  authtest.Login
	staleTA authtest.Login // tenant_admin whose sign-in is too old for step-up
	stalePA authtest.Login
}

func newFFEnv(t *testing.T) *ffEnv {
	t.Helper()
	f := storetest.TwoTenants(t)
	user := func(role auth.Role, ctx authtest.Ctx) authtest.Login {
		return signIn(t, f.DB, f.B.ID, authtest.User{Email: fmt.Sprintf("%s-%d@b.example", role, ctx.AuthTime.Unix()), Roles: []auth.Role{role}}, ctx, storetest.Now)
	}
	old := authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}
	return &ffEnv{t: t, f: f, h: newIsolationServer(f).Handler(),
		admin: user(auth.RoleTenantAdmin, authtest.Phr), pa: user(auth.RolePolicyAdmin, authtest.Phr),
		op: user(auth.RoleOperator, authtest.Phr), viewer: user(auth.RoleViewer, authtest.Phr),
		staleTA: user(auth.RoleTenantAdmin, old), stalePA: user(auth.RolePolicyAdmin, old)}
}

func (e *ffEnv) do(l authtest.Login, method, path, ctype, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	l.Apply(req)
	return serve(e.h, req)
}

func (e *ffEnv) json(l authtest.Login, method, path, body string) *httptest.ResponseRecorder {
	return e.do(l, method, path, "application/json", body)
}

func (e *ffEnv) upload(l authtest.Login, system, kind, csv string) *httptest.ResponseRecorder {
	return e.do(l, "POST", "/api/flatfile/apps/"+system+"/uploads?kind="+kind+"&filename=file.csv", "text/csv", csv)
}

func ffDecode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("%d %s: %v", rec.Code, rec.Body, err)
	}
	return m
}

func (e *ffEnv) setup() {
	e.t.Helper()
	if rec := e.json(e.admin, "PUT", "/api/flatfile/apps/hr-app/mapping", ffMapping); rec.Code != 201 {
		e.t.Fatalf("mapping: %d %s", rec.Code, rec.Body)
	}
}

func upMap(m map[string]any) map[string]any { return m["upload"].(map[string]any) }

func TestFlatfileAPI_MappingUploadHistoryAndTasks(t *testing.T) {
	e := newFFEnv(t)
	e.setup()
	// the mapping is saved, listed, and replaced by a second PUT (200)
	rec := e.json(e.viewer, "GET", "/api/flatfile/apps", "")
	apps := ffDecode(t, rec)["apps"].([]any)
	if rec.Code != 200 || len(apps) != 1 || apps[0].(map[string]any)["system"] != "hr-app" {
		t.Fatalf("apps: %d %s", rec.Code, rec.Body)
	}
	if rec := e.json(e.admin, "PUT", "/api/flatfile/apps/hr-app/mapping", ffMapping); rec.Code != 200 {
		t.Errorf("second PUT: %d %s", rec.Code, rec.Body)
	}

	// upload accounts and entitlements
	rec = e.upload(e.op, "hr-app", "accounts", ffAccounts)
	if rec.Code != 201 || upMap(ffDecode(t, rec))["added"] != float64(3) || upMap(ffDecode(t, rec))["status"] != "applied" {
		t.Fatalf("accounts upload: %d %s", rec.Code, rec.Body)
	}
	if rec = e.upload(e.pa, "hr-app", "entitlements", ffEnts); rec.Code != 201 {
		t.Fatalf("entitlements upload: %d %s", rec.Code, rec.Body)
	}
	// a re-upload with changes: delta and history
	rec = e.upload(e.pa, "hr-app", "accounts", "UserID,Login,Mail,EmpNo,State\nu1,alice.a,alice@t.example,,active\nu2,bob.renamed,,bob,active\nu4,dan.d,,,active\n")
	up := upMap(ffDecode(t, rec))
	if rec.Code != 201 || up["added"] != float64(1) || up["removed"] != float64(0) || up["held"] != float64(1) || up["changed"] != float64(1) || up["unchanged"] != float64(1) {
		t.Fatalf("re-upload: %d %s", rec.Code, rec.Body)
	}
	rec = e.json(e.viewer, "GET", "/api/flatfile/uploads?system=hr-app", "")
	ups := ffDecode(t, rec)["uploads"].([]any)
	if rec.Code != 200 || len(ups) < 3 {
		t.Fatalf("history: %d %s", rec.Code, rec.Body)
	}
	detail := ffDecode(t, e.json(e.viewer, "GET", "/api/flatfile/uploads/"+up["id"].(string), ""))
	if ch := detail["changes"].([]any); len(ch) < 3 || detail["status"] != "applied" {
		t.Errorf("upload detail = %v", detail)
	}

	// a leaver revoke on an imported entitlement: a task, listed
	var edgeID int64
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error {
		a, err := c.AccountByXID("hr-app", "u2")
		if err != nil {
			return err
		}
		edges, err := c.EdgesFrom(graph.Key("account", a.ID))
		if err != nil || len(edges) != 1 {
			return fmt.Errorf("u2 edges %v %v", edges, err)
		}
		edgeID = edges[0].ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rec = e.json(e.pa, "POST", "/api/least-privilege/revoke", fmt.Sprintf(`{"edge_id":%d,"dry_run":false}`, edgeID))
	if rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	rec = e.json(e.viewer, "GET", "/api/flatfile/tasks?status=open", "")
	tasks := ffDecode(t, rec)["tasks"].([]any)
	if rec.Code != 200 || len(tasks) != 1 {
		t.Fatalf("tasks: %d %s", rec.Code, rec.Body)
	}
	task := tasks[0].(map[string]any)
	if task["kind"] != "remove_entitlement" || task["entitlement"] != "invoice:create" || task["trigger"] != "revoke" || task["status"] != "open" ||
		!strings.Contains(task["instruction"].(string), "by hand") {
		t.Errorf("task = %v", task)
	}

	// close by hand: reason required, step-up required, then it is closed
	path := "/api/flatfile/tasks/" + task["id"].(string) + "/close"
	if rec := e.json(e.pa, "POST", path, `{"reason":"short"}`); rec.Code != 422 {
		t.Errorf("short reason: %d %s", rec.Code, rec.Body)
	}
	if rec := e.json(e.stalePA, "POST", path, `{"reason":"removed in the console"}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %s", rec.Code, rec.Body)
	}
	if rec := e.json(e.op, "POST", path, `{"reason":"removed in the console"}`); rec.Code != 403 {
		t.Errorf("operator closing: %d", rec.Code)
	}
	rec = e.json(e.pa, "POST", path, `{"reason":"removed in the console on the 9th"}`)
	if rec.Code != 200 || ffDecode(t, rec)["task"].(map[string]any)["status"] != "closed" {
		t.Fatalf("close: %d %s", rec.Code, rec.Body)
	}
	if rec := e.json(e.pa, "POST", path, `{"reason":"removed in the console on the 9th"}`); rec.Code != 409 {
		t.Errorf("close twice: %d %s", rec.Code, rec.Body)
	}
	if rec := e.json(e.pa, "POST", "/api/flatfile/tasks/not-an-id/close", `{"reason":"removed in the console"}`); rec.Code != 404 {
		t.Errorf("bad task id: %d", rec.Code)
	}
	if rec := e.json(e.viewer, "GET", "/api/flatfile/tasks?status=bogus", ""); rec.Code != 422 {
		t.Errorf("bad status filter: %d", rec.Code)
	}

	// audit: mapping, uploads, task state changes
	got := auditActions(t, e.f, e.f.B.ID)
	for action, min := range map[string]int{"flatfile.mapping_saved": 2, "flatfile.upload": 3, "flatfile.task_created": 1, "flatfile.task_closed": 1} {
		if got[action] < min {
			t.Errorf("audit %s = %d, want at least %d (%v)", action, got[action], min, got)
		}
	}
}

func TestFlatfileAPI_RejectedUploadIsReportedPerRowAndKept(t *testing.T) {
	e := newFFEnv(t)
	e.setup()
	rec := e.upload(e.pa, "hr-app", "accounts", "UserID,Login,Mail,EmpNo,State\nu1,a,bad-email,,\n,b,,,\nu3,c,,,maybe\nu4,short\n")
	if rec.Code != 422 {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	up := upMap(ffDecode(t, rec))
	errs := up["errors"].([]any)
	var codes []string
	for _, x := range errs {
		m := x.(map[string]any)
		codes = append(codes, fmt.Sprintf("%v:%v:%v", m["row"], m["column"], m["code"]))
	}
	if want := "1:Mail:invalid_email 2:UserID:required 3:State:invalid_status 4::column_count"; strings.Join(codes, " ") != want {
		t.Errorf("errors = %v, want %s", codes, want)
	}
	if up["status"] != "rejected" || up["rows_rejected"] != float64(4) {
		t.Errorf("upload = %v", up)
	}
	// the rejected attempt is in the history, with its errors, and changed no account
	hist := ffDecode(t, e.json(e.viewer, "GET", "/api/flatfile/uploads", ""))["uploads"].([]any)
	if len(hist) != 1 || hist[0].(map[string]any)["status"] != "rejected" {
		t.Errorf("history = %v", hist)
	}
	d := ffDecode(t, e.json(e.viewer, "GET", "/api/flatfile/uploads/"+up["id"].(string), ""))
	if len(d["errors"].([]any)) != 4 {
		t.Errorf("stored errors = %v", d["errors"])
	}
	if got := auditActions(t, e.f, e.f.B.ID); got["flatfile.upload"] != 1 {
		t.Errorf("audit = %v", got)
	}
}

func TestFlatfileAPI_FileLimitsAndBadInput(t *testing.T) {
	e := newFFEnv(t)
	e.setup()
	// over the file limit but under the request limit: rejected and recorded
	big := "UserID,Login\n" + strings.Repeat("u,n\n", (flatfile.MaxBytes/4)+10)
	rec := e.upload(e.pa, "hr-app", "accounts", big)
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "file_too_large") {
		t.Errorf("oversized file: %d %.200s", rec.Code, rec.Body)
	}
	// over the request body limit: refused before the handler
	huge := strings.Repeat("x", int(DefaultMaxBodyBytes)+1)
	if rec := e.upload(e.pa, "hr-app", "accounts", huge); rec.Code != 413 {
		t.Errorf("huge body: %d", rec.Code)
	}
	// not UTF-8
	rec = e.upload(e.pa, "hr-app", "accounts", "UserID,Login,Mail,EmpNo,State\nu1,caf\xe9,,,\n")
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "not_utf8") {
		t.Errorf("bad encoding: %d %.200s", rec.Code, rec.Body)
	}
	for name, tc := range map[string]struct {
		path, ctype string
		code        int
	}{
		"no kind":          {"/api/flatfile/apps/hr-app/uploads", "text/csv", 422},
		"bad kind":         {"/api/flatfile/apps/hr-app/uploads?kind=groups", "text/csv", 422},
		"json body":        {"/api/flatfile/apps/hr-app/uploads?kind=accounts", "application/json", 415},
		"form body":        {"/api/flatfile/apps/hr-app/uploads?kind=accounts", "application/x-www-form-urlencoded", 415},
		"unknown app":      {"/api/flatfile/apps/other/uploads?kind=accounts", "text/csv", 404},
		"bad system name":  {"/api/flatfile/apps/HR_APP/uploads?kind=accounts", "text/csv", 404},
		"long filename":    {"/api/flatfile/apps/hr-app/uploads?kind=accounts&filename=" + strings.Repeat("a", 300), "text/csv", 422},
		"unlabelled is ok": {"/api/flatfile/apps/hr-app/uploads?kind=accounts", "", 422}, // taken as CSV; an empty file has no header
	} {
		if rec := e.do(e.pa, "POST", tc.path, tc.ctype, ""); rec.Code != tc.code {
			t.Errorf("%s: %d %.200s, want %d", name, rec.Code, rec.Body, tc.code)
		}
	}
	// the filename is stored safe: path stripped, formula prefix neutralised
	rec = e.do(e.pa, "POST", "/api/flatfile/apps/hr-app/uploads?kind=accounts&filename=..%2F..%2F-evil.csv", "text/csv", ffAccounts)
	if rec.Code != 201 || upMap(ffDecode(t, rec))["filename"] != "'-evil.csv" {
		t.Errorf("filename: %d %.300s", rec.Code, rec.Body)
	}
}

func TestFlatfileAPI_Permissions(t *testing.T) {
	e := newFFEnv(t)
	for name, tc := range map[string]struct {
		l    authtest.Login
		code int
	}{
		"tenant admin":        {e.admin, 201},
		"policy admin":        {e.pa, 403},
		"operator":            {e.op, 403},
		"viewer":              {e.viewer, 403},
		"tenant admin, stale": {e.staleTA, 401},
	} {
		if rec := e.json(tc.l, "PUT", "/api/flatfile/apps/hr-app/mapping", ffMapping); rec.Code != tc.code {
			t.Errorf("PUT mapping as %s: %d %.200s, want %d", name, rec.Code, rec.Body, tc.code)
		}
	}
	if rec := serveOnce(e.h, "PUT", "/api/flatfile/apps/hr-app/mapping", ffMapping); rec.Code != 401 {
		t.Errorf("PUT mapping without a session: %d", rec.Code)
	}
	for name, tc := range map[string]struct {
		l    authtest.Login
		code int
	}{
		"operator": {e.op, 201}, "policy admin": {e.pa, 201}, "tenant admin": {e.admin, 403}, "viewer": {e.viewer, 403},
	} {
		if rec := e.upload(tc.l, "hr-app", "accounts", ffAccounts); rec.Code != tc.code {
			t.Errorf("upload as %s: %d %.200s, want %d", name, rec.Code, rec.Body, tc.code)
		}
	}
}

func TestFlatfileAPI_MappingValidationAndSystemConflicts(t *testing.T) {
	e := newFFEnv(t)
	for name, tc := range map[string]struct {
		system, body string
		code         int
	}{
		"missing username": {"app-1", `{"name":"x","accounts":{"account_id":"id"}}`, 422},
		"unknown field":    {"app-1", `{"name":"x","accounts":{"account_id":"id","username":"u"},"admin":true}`, 422},
		"no body":          {"app-1", ``, 422},
		"bad system":       {"App_1", ffMapping, 404},
		"another source":   {"okta", ffMapping, 409},
		"platform system":  {"tessera", ffMapping, 409},
		"ok":               {"app-1", `{"name":"x","accounts":{"account_id":"id","username":"u"}}`, 201},
	} {
		if rec := e.json(e.admin, "PUT", "/api/flatfile/apps/"+tc.system+"/mapping", tc.body); rec.Code != tc.code {
			t.Errorf("%s: %d %.200s, want %d", name, rec.Code, rec.Body, tc.code)
		}
	}
	// a system a connection feeds is taken
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error {
		conns, err := c.Connections()
		if err != nil || len(conns) == 0 {
			return fmt.Errorf("fixture connections %v %v", conns, err)
		}
		if rec := e.json(e.admin, "PUT", "/api/flatfile/apps/"+conns[0].System+"/mapping", ffMapping); rec.Code != 409 {
			t.Errorf("connection's system: %d %.200s", rec.Code, rec.Body)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Tenant B never sees or touches tenant A's flat-file data, and A's upload id
// is indistinguishable from a missing one.
func TestFlatfileAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	login := func(tenant storetest.Tenant, role auth.Role) authtest.Login {
		return signIn(t, f.DB, tenant.ID, authtest.User{Email: fmt.Sprintf("%s@%s.example", role, tenant.Slug), Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
	}
	aAdmin, aPA, bPA, bAdmin := login(f.A, auth.RoleTenantAdmin), login(f.A, auth.RolePolicyAdmin), login(f.B, auth.RolePolicyAdmin), login(f.B, auth.RoleTenantAdmin)
	do := func(l authtest.Login, method, path, ctype, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", ctype)
		l.Apply(req)
		return serve(h, req)
	}
	// A has an app with an upload and a task-worthy account; B has nothing
	if rec := do(aAdmin, "PUT", "/api/flatfile/apps/hr-app/mapping", "application/json", ffMapping); rec.Code != 201 {
		t.Fatalf("A mapping: %d %s", rec.Code, rec.Body)
	}
	rec := do(aPA, "POST", "/api/flatfile/apps/hr-app/uploads?kind=accounts", "text/csv", strings.Replace(ffAccounts, "alice@t.example", "alice."+strings.ToLower(storetest.Sentinel)+"@t.example", 1))
	if rec.Code != 201 {
		t.Fatalf("A upload: %d %s", rec.Code, rec.Body)
	}
	aUpload := upMap(ffDecode(t, rec))["id"].(string)

	if rec := do(bPA, "POST", "/api/flatfile/apps/hr-app/uploads?kind=accounts", "text/csv", ffAccounts); rec.Code != 404 {
		t.Errorf("B uploading to A's app: %d %s", rec.Code, rec.Body)
	}
	missing := do(bPA, "GET", "/api/flatfile/uploads/00000000-0000-4000-8000-00000000dead", "application/json", "")
	cross := do(bPA, "GET", "/api/flatfile/uploads/"+aUpload, "application/json", "")
	if cross.Code != 404 || cross.Code != missing.Code || cross.Body.String() != missing.Body.String() {
		t.Errorf("A's upload id for B: %d %s, missing: %d %s", cross.Code, cross.Body, missing.Code, missing.Body)
	}
	for _, p := range []string{"/api/flatfile/apps", "/api/flatfile/uploads", "/api/flatfile/uploads?system=hr-app", "/api/flatfile/tasks"} {
		rec := do(bPA, "GET", p, "application/json", "")
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "hr-app") || strings.Contains(rec.Body.String(), aUpload) || leaks(rec.Body.String()) {
			t.Errorf("GET %s as B: %d %.300s", p, rec.Code, rec.Body)
		}
	}
	// B saves its own mapping under the same system name: A's is untouched
	if rec := do(bAdmin, "PUT", "/api/flatfile/apps/hr-app/mapping", "application/json", `{"name":"B's","accounts":{"account_id":"id","username":"u"}}`); rec.Code != 201 {
		t.Errorf("B mapping: %d %s", rec.Code, rec.Body)
	}
	apps := ffDecode(t, do(aAdmin, "GET", "/api/flatfile/apps", "application/json", ""))["apps"].([]any)
	if len(apps) != 1 || apps[0].(map[string]any)["name"] != "HR app" {
		t.Errorf("A's apps after B's PUT = %v", apps)
	}
	// B closing A's task id: not found (a UUID that is not B's)
	if rec := do(bPA, "POST", "/api/flatfile/tasks/00000000-0000-4000-8000-00000000dead/close", "application/json", `{"reason":"cleaning up the list"}`); rec.Code != 404 {
		t.Errorf("close unknown task: %d", rec.Code)
	}
}

func ffAccountsN(from, to int) string {
	var b strings.Builder
	b.WriteString("UserID,Login,Mail,EmpNo,State\n")
	for i := from; i <= to; i++ {
		fmt.Fprintf(&b, "x%02d,user%02d,,,active\n", i, i)
	}
	return b.String()
}

// A truncated upload is held by the deletion guard: the answer and the history say so (#470), the second
// uploader who extends the hold may not release it, and a corrected feed withdraws the held drops (#467).
func TestFlatfileAPI_HeldRemovalsAreReportedAndEveryUploaderIsRefused(t *testing.T) {
	e := newFFEnv(t)
	e.setup()
	both := func(email string) authtest.Login {
		return signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: email, Roles: []auth.Role{auth.RoleTenantAdmin, auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)
	}
	first, second := both("first@b.example"), both("second@b.example")
	if rec := e.upload(first, "hr-app", "accounts", ffAccountsN(1, 20)); rec.Code != 201 {
		t.Fatalf("first upload: %d %s", rec.Code, rec.Body)
	}
	rec := e.upload(first, "hr-app", "accounts", ffAccountsN(1, 10))
	out := ffDecode(t, rec)
	up := upMap(out)
	if rec.Code != 201 || out["status"] != "held" || out["applied"] != float64(0) || out["held"] != float64(10) || out["hold_id"] == "" ||
		up["removed"] != float64(0) || up["held"] != float64(10) || up["hold_id"] != out["hold_id"] {
		t.Fatalf("truncated upload: %d %s", rec.Code, rec.Body)
	}
	holdID := out["hold_id"].(string)
	// the history says the same
	hist := ffDecode(t, e.json(e.viewer, "GET", "/api/flatfile/uploads/"+up["id"].(string), ""))
	if upMap(map[string]any{"upload": hist})["removed"] != float64(0) {
		t.Errorf("history removed = %v", hist["removed"])
	}
	// a second admin uploads a further truncated file: his removals join the hold
	out = ffDecode(t, e.upload(second, "hr-app", "accounts", ffAccountsN(1, 1)))
	if out["hold_id"] != holdID || out["held"] != float64(9) {
		t.Fatalf("second upload: %v", out)
	}
	approve := "/api/admin/deletion-holds/" + holdID + "/approve"
	for name, l := range map[string]authtest.Login{"first uploader": first, "second uploader": second} {
		if rec := e.json(l, "POST", approve, ""); rec.Code != 403 || ffDecode(t, rec)["error"] != "same_actor" {
			t.Errorf("%s released the hold: %d %s", name, rec.Code, rec.Body)
		}
	}
	// a third admin may
	if rec := e.json(e.admin, "POST", approve, ""); rec.Code != 200 {
		t.Fatalf("a third admin: %d %s", rec.Code, rec.Body)
	}
}

// A corrected feed withdraws the drops an earlier truncated upload had held: releasing the old hold then
// disables nobody.
func TestFlatfileAPI_ACorrectedFeedWithdrawsHeldRemovals(t *testing.T) {
	e := newFFEnv(t)
	e.setup()
	if rec := e.upload(e.pa, "hr-app", "accounts", ffAccountsN(1, 20)); rec.Code != 201 {
		t.Fatalf("first upload: %d %s", rec.Code, rec.Body)
	}
	holdID, _ := ffDecode(t, e.upload(e.pa, "hr-app", "accounts", ffAccountsN(1, 10)))["hold_id"].(string)
	if holdID == "" {
		t.Fatal("the truncated upload was not held")
	}
	approve := "/api/admin/deletion-holds/" + holdID + "/approve"
	// the feed is corrected: every account is listed again, so the hold has nothing left to release
	if rec := e.upload(e.pa, "hr-app", "accounts", ffAccountsN(1, 20)); rec.Code != 201 {
		t.Fatalf("corrected upload: %d %s", rec.Code, rec.Body)
	}
	if rec := e.json(e.admin, "POST", approve, ""); rec.Code != 409 {
		t.Errorf("release after the correction: %d %s", rec.Code, rec.Body)
	}
	if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		a, err := tx.AccountByXID("hr-app", "x05")
		if err == nil && a.Status != "active" {
			t.Errorf("a re-listed account is %s", a.Status)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
