package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The configurable settings of issue #298: step-up per action, the SoD page,
// review types, user preferences and organization settings. Who may read and
// change each, validation at the boundary, tenant scoping, and that the server
// enforces what was configured.

type settingsEnv struct {
	t    *testing.T
	f    *storetest.Fixture
	h    http.Handler
	call func(l authtest.Login, method, path, body string, want int) map[string]any
}

func newSettingsEnv(t *testing.T) *settingsEnv {
	t.Helper()
	f := storetest.TwoTenants(t)
	e := &settingsEnv{t: t, f: f, h: newIsolationServerWith(f, func(c *Config) {
		c.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	}).Handler()}
	e.call = func(l authtest.Login, method, path, body string, want int) map[string]any {
		t.Helper()
		rec := reqDo(e.h, l, method, path, body)
		if rec.Code != want {
			t.Fatalf("%s %s: %d (want %d) %s", method, path, rec.Code, want, rec.Body)
		}
		if strings.HasPrefix(rec.Body.String(), "{") {
			return jsonMap(t, rec.Body.String())
		}
		return nil
	}
	return e
}

func TestStepUpPolicyAPI(t *testing.T) {
	e := newSettingsEnv(t)
	tenantAdmin := reqLogin(t, e.f, "ta@b.example", []auth.Role{auth.RoleTenantAdmin}, "")
	policyAdmin := reqLogin(t, e.f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	staleAdmin := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "ta-stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, staleAuth, storetest.Now)
	aging := authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-3 * time.Minute)}
	alice := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "alice@b.example", Roles: []auth.Role{auth.RoleViewer}}, aging, storetest.Now)
	adminA := signInA(t, e.f, auth.RoleTenantAdmin)

	// reading: admin.read; the actions come with the code's floor
	e.call(alice, "GET", "/api/stepup-policy", "", 403)
	pol := e.call(tenantAdmin, "GET", "/api/stepup-policy", "", 200)
	if pol["version"].(float64) != 0 || pol["allow_weaker"] != false {
		t.Errorf("defaults: %v", pol)
	}
	var catalogManage, requestsCreate map[string]any
	for _, a := range pol["actions"].([]any) {
		m := a.(map[string]any)
		switch m["action"] {
		case "catalog.manage":
			catalogManage = m
		case "requests.create":
			requestsCreate = m
		case "auth.self":
			t.Errorf("%v is not an action", m["action"])
		}
	}
	if catalogManage == nil || catalogManage["floor"] == nil || catalogManage["policy"] != nil {
		t.Errorf("catalog.manage: %v", catalogManage)
	}
	if requestsCreate == nil || requestsCreate["unguarded"] != true {
		t.Errorf("requests.create: %v", requestsCreate)
	}

	put := func(l authtest.Login, ver int, entries string, want int) map[string]any {
		t.Helper()
		return e.call(l, "PUT", "/api/stepup-policy", fmt.Sprintf(`{"version":%d,"entries":{%s}}`, ver, entries), want)
	}
	// changing: admin.change.request, a fresh sign-in; nobody else
	put(policyAdmin, 0, "", 403)
	put(alice, 0, "", 403)
	if rec := reqDo(e.h, staleAdmin, "PUT", "/api/stepup-policy", `{}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %s", rec.Code, rec.Body)
	}
	// the floor: today's requirement can be made stricter, never weaker
	weaker := put(tenantAdmin, 0, fmt.Sprintf(`"sod.manage":{"acr":%q,"max_age_s":300}`, auth.ACRAAL2), 422)
	if weaker["error"] != "weaker_than_required" {
		t.Errorf("weaker acr: %v", weaker)
	}
	put(tenantAdmin, 0, fmt.Sprintf(`"sod.manage":{"acr":%q,"max_age_s":3000}`, auth.ACRPhr), 422)
	put(tenantAdmin, 0, fmt.Sprintf(`"nope.nothing":{"acr":%q,"max_age_s":300}`, auth.ACRPhr), 422)
	put(tenantAdmin, 0, fmt.Sprintf(`"requests.create":{"acr":%q,"max_age_s":300}`, auth.ACRAAL1), 422)
	put(tenantAdmin, 0, fmt.Sprintf(`"requests.create":{"acr":%q,"max_age_s":5}`, auth.ACRPhr), 422)
	put(tenantAdmin, 3, "", 409)
	e.call(tenantAdmin, "PUT", "/api/stepup-policy", `{"version":0,"entries":{},"surprise":1}`, 422)

	// an action with no step-up today: a session 3 minutes old acts until the tenant asks for more
	submit := func() int {
		return reqDo(e.h, alice, "POST", "/api/requests", `{"beneficiary_ids":[],"catalog_item_ids":[]}`).Code
	}
	if c := submit(); c != 422 {
		t.Fatalf("before the policy a request is validated: %d", c)
	}
	got := put(tenantAdmin, 0, fmt.Sprintf(`"requests.create":{"acr":%q,"max_age_s":120}`, auth.ACRPhr), 200)
	if got["version"].(float64) != 1 {
		t.Errorf("saved: %v", got)
	}
	rec := reqDo(e.h, alice, "POST", "/api/requests", `{"beneficiary_ids":[],"catalog_item_ids":[]}`)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") || !strings.Contains(rec.Body.String(), `"max_age":120`) {
		t.Errorf("after the policy: %d %s", rec.Code, rec.Body)
	}
	// reads of the same permission are not step-up'd, and a fresh sign-in passes
	e.call(alice, "GET", "/api/request-settings", "", 200)
	fresh := reqLogin(t, e.f, "alice2@b.example", []auth.Role{auth.RoleViewer}, "")
	if rec := reqDo(e.h, fresh, "POST", "/api/requests", `{"beneficiary_ids":[],"catalog_item_ids":[]}`); rec.Code != 422 {
		t.Errorf("a fresh sign-in: %d %s", rec.Code, rec.Body)
	}

	// a stricter entry on a guarded action tightens it; the floor itself is untouched
	put(tenantAdmin, 1, fmt.Sprintf(`"requests.create":{"acr":%q,"max_age_s":120},"catalog.manage":{"acr":%q,"max_age_s":120}`, auth.ACRPhr, auth.ACRPhr), 200)
	view := e.call(tenantAdmin, "GET", "/api/stepup-policy", "", 200)
	for _, a := range view["actions"].([]any) {
		m := a.(map[string]any)
		if m["action"] == "catalog.manage" {
			if m["effective"].(map[string]any)["max_age_s"].(float64) != 120 || m["floor"].(map[string]any)["max_age_s"].(float64) != 900 {
				t.Errorf("catalog.manage after: %v", m)
			}
		}
	}
	// removing an entry returns to the code's own requirement
	put(tenantAdmin, 2, "", 200)
	if c := reqDo(e.h, alice, "POST", "/api/requests", `{"beneficiary_ids":[],"catalog_item_ids":[]}`).Code; c != 422 {
		t.Errorf("after clearing the policy: %d", c)
	}

	// one tenant's policy never reaches another's
	put(tenantAdmin, 3, fmt.Sprintf(`"requests.create":{"acr":%q,"max_age_s":120}`, auth.ACRPhr), 200)
	if v := e.call(adminA, "GET", "/api/stepup-policy", "", 200); v["version"].(float64) != 0 {
		t.Errorf("A sees B's policy: %v", v["version"])
	}
}

func TestSodViewAPI(t *testing.T) {
	e := newSettingsEnv(t)
	admin := reqLogin(t, e.f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	operator := reqLogin(t, e.f, "op@b.example", []auth.Role{auth.RoleOperator}, "")
	viewer := reqLogin(t, e.f, "v@b.example", []auth.Role{auth.RoleViewer}, "")
	adminA := signInA(t, e.f, auth.RolePolicyAdmin)

	def := e.call(viewer, "GET", "/api/sod/view-settings", "", 200)
	if def["version"].(float64) != 0 || len(def["columns"].([]any)) != 6 || len(def["filters"].([]any)) != 6 || def["can_manage"] != false {
		t.Errorf("defaults: %v", def)
	}
	put := func(l authtest.Login, ver int, cols, filters string, want int) map[string]any {
		return e.call(l, "PUT", "/api/sod/view-settings", fmt.Sprintf(`{"version":%d,"columns":%s,"filters":%s}`, ver, cols, filters), want)
	}
	put(viewer, 0, `["risk"]`, `[]`, 403)
	put(operator, 0, `["risk"]`, `[]`, 403)
	stale := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, staleAuth, storetest.Now)
	if rec := reqDo(e.h, stale, "PUT", "/api/sod/view-settings", `{}`); rec.Code != 401 {
		t.Errorf("stale: %d", rec.Code)
	}
	put(admin, 0, `["risk","payroll"]`, `[]`, 422)
	put(admin, 0, `[]`, `[]`, 422)
	put(admin, 0, `["risk"]`, `["colour"]`, 422)
	put(admin, 4, `["risk"]`, `[]`, 409)
	got := put(admin, 0, `["mitigating_control","risk","risk"]`, `["ruleset"]`, 200)
	cols := got["columns"].([]any)
	if got["version"].(float64) != 1 || len(cols) != 2 || cols[0] != "risk" || cols[1] != "mitigating_control" {
		t.Errorf("saved (canonical order, no repeats): %v", got)
	}
	if v := e.call(viewer, "GET", "/api/sod/view-settings", "", 200); len(v["filters"].([]any)) != 1 || v["filters"].([]any)[0] != "ruleset" {
		t.Errorf("a reviewer reads it: %v", v)
	}
	if v := e.call(adminA, "GET", "/api/sod/view-settings", "", 200); v["version"].(float64) != 0 {
		t.Errorf("A sees B's configuration: %v", v)
	}
}

func TestPreferencesAPI(t *testing.T) {
	e := newSettingsEnv(t)
	alice := reqLogin(t, e.f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	bob := reqLogin(t, e.f, "bob@b.example", []auth.Role{auth.RoleViewer}, "bob")
	adminA := signInA(t, e.f, auth.RoleViewer)

	def := e.call(alice, "GET", "/api/me/preferences", "", 200)
	if def["time_zone"] != "" || def["date_format"] != "" || len(def["landing_pages"].([]any)) == 0 || len(def["date_formats"].([]any)) != 4 {
		t.Errorf("defaults: %v", def)
	}
	put := func(l authtest.Login, body string, want int) map[string]any {
		return e.call(l, "PUT", "/api/me/preferences", body, want)
	}
	for _, bad := range []string{
		`{"time_zone":"Mars/Olympus","date_format":"","locale":"","landing_page":""}`,
		`{"time_zone":"Local","date_format":"","locale":"","landing_page":""}`,
		`{"time_zone":"../etc/passwd","date_format":"","locale":"","landing_page":""}`,
		`{"time_zone":"","date_format":"dd-mm","locale":"","landing_page":""}`,
		`{"time_zone":"","date_format":"","locale":"xx-YY","landing_page":""}`,
		`{"time_zone":"","date_format":"","locale":"","landing_page":"https://evil.example/"}`,
		`{"time_zone":"","date_format":"","locale":"","landing_page":"//evil.example"}`,
		`{"time_zone":"","date_format":"","locale":"","landing_page":"/admin/users"}`,
		`{"unknown":1}`,
	} {
		put(alice, bad, 422)
	}
	got := put(alice, `{"time_zone":"Europe/Berlin","date_format":"dmy","locale":"de-DE","landing_page":"/inbox"}`, 200)
	if got["time_zone"] != "Europe/Berlin" || got["landing_page"] != "/inbox" {
		t.Errorf("saved: %v", got)
	}
	// each user has their own; there is no way to name another
	if v := e.call(bob, "GET", "/api/me/preferences", "", 200); v["time_zone"] != "" || v["landing_page"] != "" {
		t.Errorf("bob sees alice's: %v", v)
	}
	if v := e.call(alice, "GET", "/api/me/preferences", "", 200); v["date_format"] != "dmy" || v["locale"] != "de-DE" {
		t.Errorf("alice's: %v", v)
	}
	if v := e.call(adminA, "GET", "/api/me/preferences", "", 200); v["time_zone"] != "" {
		t.Errorf("another tenant's user sees them: %v", v)
	}
	// clearing returns to the defaults
	put(alice, `{"time_zone":"","date_format":"","locale":"","landing_page":""}`, 200)
	if v := e.call(alice, "GET", "/api/me/preferences", "", 200); v["time_zone"] != "" || v["landing_page"] != "" {
		t.Errorf("cleared: %v", v)
	}
	// an unauthenticated caller has none
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/me/preferences", nil))
	if rec.Code != 401 {
		t.Errorf("anonymous: %d", rec.Code)
	}
}

func TestReviewTypesAPI(t *testing.T) {
	e := newSettingsEnv(t)
	admin := reqLogin(t, e.f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	viewer := reqLogin(t, e.f, "v@b.example", []auth.Role{auth.RoleViewer}, "")
	adminA := signInA(t, e.f, auth.RolePolicyAdmin)
	carol, bob := e.f.B.IDs["carol"], e.f.B.IDs["bob"]

	list := e.call(viewer, "GET", "/api/review-types", "", 200)
	types := list["types"].([]any)
	if len(types) != 6 {
		t.Fatalf("types: %v", list)
	}
	first := types[0].(map[string]any)
	if first["type"] != "user_manager" || first["enabled"] != true || first["on_incomplete"] != "revoke" || first["version"].(float64) != 0 {
		t.Errorf("a type's defaults: %v", first)
	}
	put := func(l authtest.Login, typ string, body string, want int) map[string]any {
		return e.call(l, "PUT", "/api/review-types/"+typ, body, want)
	}
	body := func(ver int, extra string) string {
		return fmt.Sprintf(`{"version":%d,"enabled":true,"reviewer_source":"owner","on_incomplete":"revoke","escalation_days":7%s}`, ver, extra)
	}
	put(viewer, "application_owner", body(0, ""), 403)
	stale := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, staleAuth, storetest.Now)
	if rec := reqDo(e.h, stale, "PUT", "/api/review-types/application_owner", `{}`); rec.Code != 401 {
		t.Errorf("stale: %d", rec.Code)
	}
	put(admin, "friends", body(0, ""), 404)
	put(admin, "application_owner", strings.Replace(body(0, ""), `"owner"`, `"anyone"`, 1), 422)
	put(admin, "application_owner", strings.Replace(body(0, ""), `"owner"`, `"fixed"`, 1), 422)     // needs a reviewer
	put(admin, "application_owner", strings.Replace(body(0, ""), `"revoke"`, `"escalate"`, 1), 422) // needs a fallback
	put(admin, "application_owner", strings.Replace(body(0, ""), `"revoke"`, `"ignore"`, 1), 422)   // unknown outcome
	put(admin, "application_owner", body(0, `,"fallback_reviewer_id":999999`), 422)                 // unknown person
	put(admin, "application_owner", strings.Replace(body(0, ""), `"escalation_days":7`, `"escalation_days":0`, 1), 422)
	put(admin, "application_owner", body(2, ""), 409)
	got := put(admin, "application_owner", strings.Replace(body(0, fmt.Sprintf(`,"fallback_reviewer_id":%d`, carol)), `"revoke"`, `"escalate"`, 1), 200)
	if got["on_incomplete"] != "escalate" || got["fallback_reviewer_person"] == nil || got["version"].(float64) != 1 {
		t.Errorf("saved: %v", got)
	}
	put(admin, "role_owner", strings.Replace(body(0, fmt.Sprintf(`,"reviewer_id":%d`, bob)), `"owner"`, `"fixed"`, 1), 200)

	// a schedule runs as a type; a disabled type cannot be chosen
	sched := func(extra string, want int) map[string]any {
		return e.call(admin, "POST", "/api/reviews/schedules",
			fmt.Sprintf(`{"name":"Owners","recurrence":"quarterly","first_run_at":"2026-11-01T00:00:00Z"%s}`, extra), want)
	}
	s := sched(`,"review_type":"application_owner"`, 201)
	if s["review_type"] != "application_owner" {
		t.Errorf("schedule type: %v", s)
	}
	sched(`,"review_type":"friends"`, 422)
	put(admin, "service_account", strings.Replace(body(0, ""), `"enabled":true`, `"enabled":false`, 1), 200)
	sched(`,"review_type":"service_account"`, 422)
	plain := sched("", 201)
	if plain["review_type"] != nil {
		t.Errorf("an untyped schedule: %v", plain["review_type"])
	}
	list = e.call(viewer, "GET", "/api/review-types", "", 200)
	for _, ty := range list["types"].([]any) {
		m := ty.(map[string]any)
		if m["type"] == "application_owner" && m["schedules"].(float64) != 1 {
			t.Errorf("schedule count: %v", m)
		}
	}
	if v := e.call(adminA, "GET", "/api/review-types", "", 200); v["types"].([]any)[1].(map[string]any)["version"].(float64) != 0 {
		t.Errorf("A sees B's settings: %v", v)
	}
}

func TestOrgSettingsAPI(t *testing.T) {
	e := newSettingsEnv(t)
	admin := reqLogin(t, e.f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	operator := reqLogin(t, e.f, "op@b.example", []auth.Role{auth.RoleOperator}, "")
	alice := reqLogin(t, e.f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	adminA := signInA(t, e.f, auth.RolePolicyAdmin)
	carol := e.f.B.IDs["carol"]

	// alice's organization
	ident := e.call(alice, "GET", fmt.Sprintf("/api/identities/%d", e.f.B.IDs["alice"]), "", 200)
	var org string
	for _, o := range e.callList(alice, "/api/orgs") {
		if o["kind"] == "department" && ident["department"] == o["name"] {
			org = o["id"].(string)
		}
	}
	if org == "" {
		t.Fatalf("no organization for alice's department %v", ident["department"])
	}
	path := "/api/orgs/" + org + "/settings"

	def := e.call(alice, "GET", path, "", 200)
	if def["version"].(float64) != 0 || len(def["owner_ids"].([]any)) != 0 {
		t.Errorf("defaults: %v", def)
	}
	if d := e.call(alice, "GET", "/api/orgs/"+org, "", 200); d["owners_source"] != "derived" {
		t.Errorf("before: %v", d["owners_source"])
	}
	put := func(l authtest.Login, body string, want int) map[string]any {
		return e.call(l, "PUT", path, body, want)
	}
	put(alice, `{"version":0,"owner_ids":[],"policies":{}}`, 403)
	put(operator, `{"version":0,"owner_ids":[],"policies":{}}`, 403)
	e.call(admin, "GET", "/api/orgs/dept-ffffffffff/settings", "", 404)
	e.call(admin, "GET", "/api/orgs/nonsense/settings", "", 404)
	for _, bad := range []string{
		`{"version":0,"owner_ids":[999999],"policies":{}}`,
		fmt.Sprintf(`{"version":0,"owner_ids":[%d,%d],"policies":{}}`, carol, carol),
		`{"version":0,"owner_ids":[],"policies":{"default_stages":["manager","manager"]}}`,
		`{"version":0,"owner_ids":[],"policies":{"default_stages":["boss"]}}`,
		`{"version":0,"owner_ids":[],"policies":{"default_escalate_hours":24}}`,
		`{"version":0,"owner_ids":[],"policies":{"justification_required":false}}`,
		`{"version":0,"owner_ids":[],"policies":{"default_hours":48,"max_hours":24}}`,
		`{"version":0,"owner_ids":[],"policies":{"max_hours":-1}}`,
		`{"version":0,"owner_ids":[],"policies":{"justification_min_length":0}}`,
	} {
		put(admin, bad, 422)
	}
	put(admin, `{"version":3,"owner_ids":[],"policies":{}}`, 409)
	got := put(admin, fmt.Sprintf(`{"version":0,"owner_ids":[%d],"policies":{"default_stages":["manager","decider"],"justification_min_length":40,"max_hours":8}}`, carol), 200)
	if got["version"].(float64) != 1 || len(got["owners"].([]any)) != 1 {
		t.Errorf("saved: %v", got)
	}
	if d := e.call(alice, "GET", "/api/orgs/"+org, "", 200); d["owners_source"] != "assigned" || d["owners"].([]any)[0].(map[string]any)["id"].(float64) != float64(carol) {
		t.Errorf("assigned owner not shown: %v %v", d["owners_source"], d["owners"])
	}

	// the organization's overrides are enforced on a request for its people
	e.call(admin, "PUT", fmt.Sprintf("/api/catalog/items/%d", e.f.B.IDs["group:okta:platform"]), `{"requestable":true,"risk":"low"}`, 200)
	itemID := e.call(alice, "GET", "/api/catalog", "", 200)["items"].([]any)[0].(map[string]any)["id"].(string)
	submit := func(extra string, want int) map[string]any {
		return e.call(alice, "POST", "/api/requests", fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":[%q],%s}`, e.f.B.IDs["alice"], itemID, extra), want)
	}
	submit(`"justification":"for the Atlas project","duration_hours":4`, 422) // 21 characters, the organization wants 40
	submit(`"justification":"for the Atlas project, as agreed with the platform lead","duration_hours":12`, 422)
	ok := submit(`"justification":"for the Atlas project, as agreed with the platform lead","duration_hours":4`, 201)
	// with no approval policy on the item, the organization's default workflow routes it: manager first
	line := ok["lines"].([]any)[0].(map[string]any)
	detail := e.call(alice, "GET", "/api/requests/"+line["id"].(string), "", 200)
	if st := fmt.Sprint(detail["stages"]); !strings.Contains(st, "manager") {
		t.Errorf("default workflow not applied: %v", st)
	}

	// clearing returns to the tenant's own settings
	put(admin, `{"version":1,"owner_ids":[],"policies":{}}`, 200)
	submit(`"justification":"for the Atlas project","duration_hours":12`, 409) // past the justification and duration checks: only the open duplicate refuses it
	if d := e.call(alice, "GET", "/api/orgs/"+org, "", 200); d["owners_source"] != "derived" {
		t.Errorf("after clearing: %v", d["owners_source"])
	}
	if v := e.call(adminA, "GET", "/api/orgs/"+org+"/settings", "", 200); v["version"].(float64) != 0 || len(v["owner_ids"].([]any)) != 0 {
		t.Errorf("A sees B's organization settings: %v", v)
	}
}

func TestOrgHierarchySourceAPI(t *testing.T) {
	e := newSettingsEnv(t)
	admin := reqLogin(t, e.f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	viewer := reqLogin(t, e.f, "v@b.example", []auth.Role{auth.RoleViewer}, "")
	adminA := signInA(t, e.f, auth.RolePolicyAdmin)

	def := e.call(viewer, "GET", "/api/org-hierarchy-source", "", 200)
	if def["source"] != "hr_department" || def["system"] != nil || def["version"].(float64) != 0 {
		t.Errorf("defaults: %v", def)
	}
	put := func(l authtest.Login, body string, want int) map[string]any {
		return e.call(l, "PUT", "/api/org-hierarchy-source", body, want)
	}
	put(viewer, `{"version":0,"source":"hr_department"}`, 403)
	put(admin, `{"version":0,"source":"magic"}`, 422)
	put(admin, `{"version":0,"source":"hr_department","system":"nowhere"}`, 422)
	put(admin, `{"version":2,"source":"hr_department"}`, 409)
	if v := e.call(adminA, "GET", "/api/org-hierarchy-source", "", 200); v["system"] != nil {
		t.Errorf("A sees B's source: %v", v)
	}
}

// callList GETs a JSON array.
func (e *settingsEnv) callList(l authtest.Login, path string) []map[string]any {
	e.t.Helper()
	rec := reqDo(e.h, l, "GET", path, "")
	if rec.Code != 200 {
		e.t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body)
	}
	return jsonList(e.t, rec.Body.String())
}

func jsonList(t *testing.T, body string) []map[string]any {
	t.Helper()
	var l []map[string]any
	if err := json.Unmarshal([]byte(body), &l); err != nil {
		t.Fatalf("not a json list: %s", body)
	}
	return l
}
