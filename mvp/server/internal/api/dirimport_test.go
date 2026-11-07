package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

const (
	diPeople   = "email,name,department,title,manager_email\nnew.one@t.example,New One,Finance,Analyst,\nnew.two@t.example,New Two,Finance,Lead,new.one@t.example\n"
	diAccounts = "account_id,username,email,identity_id,status\na1,new.one,new.one@t.example,,active\na2,new.two,,,active\n"
	diEnts     = "name,external_id,kind,privileged,description\nInvoice approvers,inv-app,group,yes,Approves invoices\nInvoice readers,inv-read,group,no,\n"
)

func (e *ffEnv) imp(l authtest.Login, verb, target, system, csv string) *httptest.ResponseRecorder {
	return e.do(l, "POST", "/api/directory/imports/"+verb+"?target="+target+"&system="+system+"&name=HR+spreadsheet&filename=file.csv", "text/csv", csv)
}

func TestDirectoryImportAPI_RBACAndStepUp(t *testing.T) {
	e := newFFEnv(t)
	cases := map[string]struct {
		l           authtest.Login
		plan, apply int
	}{
		"viewer":              {e.viewer, 403, 403},
		"operator":            {e.op, 403, 403},
		"policy admin":        {e.pa, 403, 403},
		"tenant admin":        {e.admin, 200, 201},
		"tenant admin, stale": {e.staleTA, 200, 401},
	}
	for name, c := range cases {
		if rec := e.imp(c.l, "plan", "people", "hr-sheet", diPeople); rec.Code != c.plan {
			t.Errorf("%s: plan %d, want %d: %s", name, rec.Code, c.plan, rec.Body)
		}
		sys := "hr-" + strings.ReplaceAll(name, " ", "-")
		sys = strings.ReplaceAll(sys, ",", "")
		rec := e.imp(c.l, "apply", "people", sys, diPeople)
		if rec.Code != c.apply {
			t.Errorf("%s: apply %d, want %d: %s", name, rec.Code, c.apply, rec.Body)
		}
		if c.apply == 401 && !strings.Contains(rec.Body.String(), "step_up_required") {
			t.Errorf("%s: apply answered %s, want step_up_required", name, rec.Body)
		}
	}
	// the tenant admin's apply is audited with its domain event
	if got := auditActions(t, e.f, e.f.B.ID)["directory.import"]; got != 1 {
		t.Errorf("directory.import events = %d, want 1", got)
	}
	// sources need only graph.read
	if rec := e.json(e.viewer, "GET", "/api/directory/imports/sources", ""); rec.Code != 200 {
		t.Errorf("sources as viewer: %d %s", rec.Code, rec.Body)
	}
}

func TestDirectoryImportAPI_PlanChangesNothing(t *testing.T) {
	e := newFFEnv(t)
	for _, target := range []string{"people", "accounts", "entitlements"} {
		csv := map[string]string{"people": diPeople, "accounts": diAccounts, "entitlements": diEnts}[target]
		rec := e.imp(e.admin, "plan", target, "hr-sheet", csv)
		pl := ffDecode(t, rec)["plan"].(map[string]any)
		if rec.Code != 200 || pl["added"] != float64(2) || pl["removed"] != float64(0) || pl["error_count"] != float64(0) {
			t.Fatalf("%s plan: %d %s", target, rec.Code, rec.Body)
		}
	}
	src := ffDecode(t, e.json(e.viewer, "GET", "/api/directory/imports/sources", ""))["sources"].([]any)
	if len(src) != 0 {
		t.Errorf("a plan created sources: %v", src)
	}
	if rec := e.json(e.viewer, "GET", "/api/flatfile/apps", ""); strings.Contains(rec.Body.String(), "hr-sheet") {
		t.Errorf("a plan saved a mapping: %s", rec.Body)
	}
	if got := auditActions(t, e.f, e.f.B.ID); got["directory.import"] != 0 || got["flatfile.upload"] != 0 {
		t.Errorf("a plan wrote domain events: %v", got)
	}
}

func TestDirectoryImportAPI_ApplyAllTargetsAndRemoval(t *testing.T) {
	e := newFFEnv(t)
	for target, csv := range map[string]string{"people": diPeople, "accounts": diAccounts, "entitlements": diEnts} {
		rec := e.imp(e.admin, "apply", target, "hr-sheet", csv)
		out := ffDecode(t, rec)
		if rec.Code != 201 || out["status"] != "applied" || out["plan"].(map[string]any)["added"] != float64(2) {
			t.Fatalf("%s apply: %d %s", target, rec.Code, rec.Body)
		}
	}
	src := ffDecode(t, e.json(e.viewer, "GET", "/api/directory/imports/sources", ""))["sources"].([]any)[0].(map[string]any)
	if src["system"] != "hr-sheet" || src["people"] != float64(2) || src["accounts"] != float64(2) || src["entitlements"] != float64(2) {
		t.Errorf("source = %v", src)
	}
	// the people are in the directory, the manager reference resolved
	rec := e.json(e.viewer, "GET", "/api/identities", "")
	if !strings.Contains(rec.Body.String(), "New Two") {
		t.Errorf("identities lack the imported person: %.300s", rec.Body)
	}
	// the same file again changes nothing
	out := ffDecode(t, e.imp(e.admin, "plan", "people", "hr-sheet", diPeople))["plan"].(map[string]any)
	if out["added"] != float64(0) || out["changed"] != float64(0) || out["unchanged"] != float64(2) {
		t.Errorf("replan = %v", out)
	}
	// a changed cell is a change, a dropped row a removal; the guard's view comes with it
	next := "email,name,department,title,manager_email\nnew.one@t.example,New One,Legal,Analyst,\n"
	out = ffDecode(t, e.imp(e.admin, "plan", "people", "hr-sheet", next))["plan"].(map[string]any)
	if out["changed"] != float64(1) || out["removed"] != float64(1) || out["guard"] == nil {
		t.Errorf("plan of a shorter file = %v", out)
	}
	rec = e.imp(e.admin, "apply", "people", "hr-sheet", next)
	res := ffDecode(t, rec)
	if rec.Code != 201 || (res["status"] != "applied" && res["status"] != "held" && res["status"] != "partially_applied") {
		t.Fatalf("apply of a shorter file: %d %s", rec.Code, rec.Body)
	}
	// a removal is only of what this source imported: Alice (another source's person) is untouched
	_, other := someoneElse(t, e)
	rec = e.imp(e.admin, "apply", "people", "hr-sheet", "email,name\n"+other+",Takeover\n")
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "owned_by_other_source") && !strings.Contains(rec.Body.String(), "email_in_use") {
		t.Errorf("taking over another source's person: %d %s", rec.Code, rec.Body)
	}
	// every apply and the refused one are in the ledger
	got := auditActions(t, e.f, e.f.B.ID)
	if got["directory.import"] < 5 {
		t.Errorf("directory.import events = %d, want at least 5 (%v)", got["directory.import"], got)
	}
}

func TestDirectoryImportAPI_InputLimitsAndSafety(t *testing.T) {
	e := newFFEnv(t)
	bad := func(name, csv, ctype string, status int, code string) {
		t.Helper()
		rec := e.do(e.admin, "POST", "/api/directory/imports/plan?target=people&system=hr-sheet", ctype, csv)
		if rec.Code != status || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%s: %d %.300s, want %d %s", name, rec.Code, rec.Body, status, code)
		}
	}
	rows := strings.Repeat("a@t.example,A\n", 10001)
	bad("too many rows", "email,name\n"+rows, "text/csv", 200, "too_many_rows")
	bad("too large", "email,name\n"+strings.Repeat("x", 5<<20), "text/csv", 200, "file_too_large")
	bad("binary", "email,name\n\x00\x01\x02", "text/csv", 200, "not_utf8")
	bad("not utf-8", "email,name\n\xff\xfe,x\n", "text/csv", 200, "not_utf8")
	bad("no data rows is a plan of nothing", "email,name\n", "text/csv", 200, `"rows":0`)
	bad("missing required column", "email\na@t.example\n", "text/csv", 200, "missing_column")
	bad("json is not a file", `{"a":1}`, "application/json", 415, "")
	bad("formula in a key", "email,name\n=cmd|' /C calc'!A0,X\n", "text/csv", 200, "formula_prefix")
	// the cap of a bigger body than the limit is the limit: the request is refused, not read
	rec := e.do(e.admin, "POST", "/api/directory/imports/plan?target=people&system=hr-sheet", "text/csv", strings.Repeat("x", 6<<20))
	if rec.Code != 413 {
		t.Errorf("6 MiB body: %d, want 413", rec.Code)
	}
	// a text cell that starts like a formula is stored neutralised, never as a formula
	rec = e.imp(e.admin, "apply", "people", "hr-sheet", "email,name\nf@t.example,=1+1\n")
	if rec.Code != 201 {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	if rec = e.json(e.viewer, "GET", "/api/identities", ""); strings.Contains(rec.Body.String(), `"=1+1"`) || !strings.Contains(rec.Body.String(), "'=1+1") {
		t.Errorf("a formula name was stored as typed: %.400s", rec.Body)
	}
	// a system name is a slug, a connector's system is never written to
	for sys, want := range map[string]int{"Bad Name": 422, "okta": 409, "tessera": 409} {
		if rec := e.imp(e.admin, "plan", "accounts", strings.ReplaceAll(sys, " ", "%20"), diAccounts); rec.Code != want {
			t.Errorf("system %q: %d %s, want %d", sys, rec.Code, rec.Body, want)
		}
	}
	if rec := e.imp(e.admin, "plan", "groups", "hr-sheet", diPeople); rec.Code != 422 {
		t.Errorf("unknown target: %d", rec.Code)
	}
}

func TestDirectoryImportAPI_FormsAndLookup(t *testing.T) {
	e := newFFEnv(t)
	put := func(l authtest.Login, body string) *httptest.ResponseRecorder {
		return e.json(l, "PUT", "/api/directory/manual/records", body)
	}
	create := `{"target":"people","system":"hr-sheet","name":"HR spreadsheet","fields":{"email":"form.one@t.example","name":"Form One","title":"Intern"}}`
	if rec := put(e.pa, create); rec.Code != 403 {
		t.Errorf("policy admin: %d", rec.Code)
	}
	if rec := put(e.staleTA, create); rec.Code != 401 {
		t.Errorf("stale sign-in: %d", rec.Code)
	}
	if rec := put(e.admin, create); rec.Code != 200 || ffDecode(t, rec)["status"] != "applied" {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	// editing replaces the row of the same key and keeps the rest of the source
	if rec := put(e.admin, `{"target":"people","system":"hr-sheet","fields":{"email":"form.one@t.example","name":"Form One","title":"Engineer"}}`); rec.Code != 200 ||
		ffDecode(t, rec)["plan"].(map[string]any)["changed"] != float64(1) {
		t.Fatalf("edit: %d %s", rec.Code, rec.Body)
	}
	if rec := put(e.admin, `{"target":"accounts","system":"hr-sheet","name":"HR spreadsheet","fields":{"account_id":"f1","username":"form.one"}}`); rec.Code != 200 {
		t.Fatalf("account: %d %s", rec.Code, rec.Body)
	}
	if rec := put(e.admin, `{"target":"entitlements","system":"hr-sheet","fields":{"name":"Intern group","privileged":"no"}}`); rec.Code != 200 {
		t.Fatalf("entitlement: %d %s", rec.Code, rec.Body)
	}
	// a connector's system is refused, an unknown field and a bad value are 422
	otherID, otherEmail := someoneElse(t, e)
	for body, want := range map[string]int{
		`{"target":"accounts","system":"okta","fields":{"account_id":"x","username":"x"}}`:                  409,
		`{"target":"people","system":"hr-sheet","fields":{"email":"x","name":"X"}}`:                         422,
		`{"target":"people","system":"hr-sheet","fields":{"email":"y@t.example","name":"Y","salary":"1"}}`:  422,
		`{"target":"people","system":"hr-sheet","fields":{}}`:                                               422,
		`{"target":"people","system":"hr-sheet","fields":{"email":"` + otherEmail + `","name":"Takeover"}}`: 422,
	} {
		if rec := put(e.admin, body); rec.Code != want {
			t.Errorf("%s: %d %.200s, want %d", body, rec.Code, rec.Body, want)
		}
	}
	// the lookup: a manual person is managed and carries its fields; a connector's person is not
	var manualID int64
	for _, row := range decodeList(t, e.json(e.viewer, "GET", "/api/identities", "")) {
		if row["email"] == "form.one@t.example" {
			manualID = int64(row["id"].(float64))
		}
	}
	if manualID == 0 {
		t.Fatal("the manual person was not found")
	}
	m := ffDecode(t, e.json(e.viewer, "GET", fmt.Sprintf("/api/directory/manual/lookup?target=people&id=%d", manualID), ""))
	if m["managed"] != true || m["system"] != "hr-sheet" || m["fields"].(map[string]any)["title"] != "Engineer" {
		t.Errorf("manual lookup = %v", m)
	}
	o := ffDecode(t, e.json(e.viewer, "GET", fmt.Sprintf("/api/directory/manual/lookup?target=people&id=%d", otherID), ""))
	if o["managed"] != false {
		t.Errorf("connector lookup = %v", o)
	}
	if rec := e.json(e.viewer, "GET", "/api/directory/manual/lookup?target=people&id=99999999", ""); rec.Code != 404 {
		t.Errorf("unknown id: %d", rec.Code)
	}
}

// Tenant B never sees or edits tenant A's manual sources, and A's identity id is a missing one for B.
func TestDirectoryImportAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	login := func(tenant storetest.Tenant, role auth.Role) authtest.Login {
		return signIn(t, f.DB, tenant.ID, authtest.User{Email: fmt.Sprintf("%s@%s.example", role, tenant.Slug), Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
	}
	aAdmin, bAdmin := login(f.A, auth.RoleTenantAdmin), login(f.B, auth.RoleTenantAdmin)
	do := func(l authtest.Login, method, path, ctype, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", ctype)
		l.Apply(req)
		return serve(h, req)
	}
	csv := "email,name\n" + strings.ToLower(storetest.Sentinel) + "@a.example,Sentinel Person\n"
	if rec := do(aAdmin, "POST", "/api/directory/imports/apply?target=people&system=hr-sheet", "text/csv", csv); rec.Code != 201 {
		t.Fatalf("A apply: %d %s", rec.Code, rec.Body)
	}
	rec := do(bAdmin, "GET", "/api/directory/imports/sources", "application/json", "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "hr-sheet") || leaks(rec.Body.String()) {
		t.Errorf("B sources: %d %.300s", rec.Code, rec.Body)
	}
	// B's plan of the same file sees no baseline, and its apply leaves A's snapshot alone
	pl := ffDecode(t, do(bAdmin, "POST", "/api/directory/imports/plan?target=people&system=hr-sheet", "text/csv", csv))["plan"].(map[string]any)
	if pl["added"] != float64(1) {
		t.Errorf("B plan = %v", pl)
	}
	if rec := do(bAdmin, "POST", "/api/directory/imports/apply?target=people&system=hr-sheet", "text/csv", "email,name\nb.only@b.example,B Only\n"); rec.Code != 201 {
		t.Fatalf("B apply: %d %s", rec.Code, rec.Body)
	}
	var aID int64
	for _, row := range decodeList(t, do(aAdmin, "GET", "/api/identities", "application/json", "")) {
		if strings.Contains(fmt.Sprint(row["email"]), strings.ToLower(storetest.Sentinel)) {
			aID = int64(row["id"].(float64))
		}
	}
	if aID == 0 {
		t.Fatal("A's imported person not found")
	}
	if rec := do(bAdmin, "GET", fmt.Sprintf("/api/directory/manual/lookup?target=people&id=%d", aID), "application/json", ""); rec.Code == 200 && strings.Contains(rec.Body.String(), `"managed":true`) {
		t.Errorf("B looked up A's manual person: %s", rec.Body)
	}
	a := ffDecode(t, do(aAdmin, "GET", "/api/directory/imports/sources", "application/json", ""))["sources"].([]any)
	if len(a) != 1 || a[0].(map[string]any)["people"] != float64(1) {
		t.Errorf("A sources after B's apply = %v", a)
	}
}

func decodeList(t *testing.T, rec *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("%d %.200s: %v", rec.Code, rec.Body, err)
	}
	return rows
}

// someoneElse is a person another source put in the directory: an id and an email.
func someoneElse(t *testing.T, e *ffEnv) (int64, string) {
	t.Helper()
	for _, row := range decodeList(t, e.json(e.viewer, "GET", "/api/identities", "")) {
		if em, ok := row["email"].(string); ok && em != "" {
			return int64(row["id"].(float64)), em
		}
	}
	t.Fatal("the fixture has no identity with an email")
	return 0, ""
}

// Security review of #915: a system a configured connector writes to without a connection row (the test
// server's "tiny") is refused by the plan, the apply and the form, before its first sync has put data there.
func TestDirectoryImportAPI_RefusesAConfiguredConnectorsSystem(t *testing.T) {
	e := newFFEnv(t)
	for _, verb := range []string{"plan", "apply"} {
		if rec := e.imp(e.admin, verb, "accounts", "tiny", diAccounts); rec.Code != 409 || !strings.Contains(rec.Body.String(), "a connector feeds the system tiny") {
			t.Errorf("%s: %d %s, want 409", verb, rec.Code, rec.Body)
		}
	}
	if rec := e.json(e.admin, "PUT", "/api/directory/manual/records", `{"target":"accounts","system":"tiny","fields":{"account_id":"x1","username":"x"}}`); rec.Code != 409 {
		t.Errorf("form: %d %s, want 409", rec.Code, rec.Body)
	}
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error {
		if _, err := c.FlatMapping("tiny"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a refused import saved a mapping for tiny: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
