package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Tenant request settings (issue #298): who reads and changes them, and that
// the server enforces them on submit whatever the client sends.
func TestRequestSettingsAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	admin := reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	operator := reqLogin(t, f, "op@b.example", []auth.Role{auth.RoleOperator}, "")
	alice := reqLogin(t, f, "alice@b.example", []auth.Role{auth.RoleViewer}, "alice")
	carol := reqLogin(t, f, "carol@b.example", []auth.Role{auth.RoleViewer}, "carol") // alice's manager
	stale := signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, staleAuth, storetest.Now)
	adminA := signInA(t, f, auth.RolePolicyAdmin)
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
	put := func(l authtest.Login, ver int, patch string, want int) map[string]any {
		t.Helper()
		base := `"justification_required":true,"justification_min_length":1,"attachments_allowed":false,"history_visibility":"readers","for_others":"permission"`
		if patch != "" {
			for _, kv := range strings.Split(patch, ";") {
				k := strings.SplitN(kv, ":", 2)[0]
				i := strings.Index(base, k)
				if i < 0 {
					base += "," + kv
					continue
				}
				j := strings.Index(base[i:], ",")
				if j < 0 {
					j = len(base) - i
				}
				base = base[:i] + kv + base[i+j:]
			}
		}
		return call(l, "PUT", "/api/request-settings", fmt.Sprintf(`{"version":%d,%s}`, ver, base), want)
	}

	// everyone who can request reads them; before any save they are the defaults
	def := call(alice, "GET", "/api/request-settings", "", 200)
	if def["version"].(float64) != 0 || def["justification_required"] != true || def["for_others"] != "permission" ||
		def["history_visibility"] != "readers" || def["can_manage"] != false || def["attachments_allowed"] != false {
		t.Errorf("defaults: %v", def)
	}

	// changing them: catalog.manage and a fresh sign-in; the body is validated
	put(alice, 0, "", 403)
	put(operator, 0, "", 403)
	if rec := reqDo(h, stale, "PUT", "/api/request-settings", `{}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %s", rec.Code, rec.Body)
	}
	put(admin, 0, `"justification_min_length":0`, 422)
	put(admin, 0, `"for_others":"friends"`, 422)
	put(admin, 0, `"history_visibility":"all"`, 422)
	put(admin, 0, `"default_hours":48;"max_hours":24`, 422)
	put(admin, 5, "", 409) // not the version that was read
	call(admin, "PUT", "/api/request-settings", `{"version":0,"surprise":true}`, 422)

	// the item the requests below ask for, and a person to ask for
	call(admin, "PUT", fmt.Sprintf("/api/catalog/items/%d", f.B.IDs["group:okta:platform"]), `{"requestable":true,"risk":"low"}`, 200)
	items := call(alice, "GET", "/api/catalog", "", 200)["items"].([]any)
	itemID := items[0].(map[string]any)["id"].(string)
	submit := func(l authtest.Login, who, extra string, want int) map[string]any {
		t.Helper()
		return call(l, "POST", "/api/requests", fmt.Sprintf(`{"beneficiary_ids":[%d],"catalog_item_ids":[%q],%s}`, f.B.IDs[who], itemID, extra), want)
	}

	// justification: the minimum length is enforced by the server
	put(admin, 0, `"justification_min_length":25`, 200)
	submit(alice, "alice", `"justification":"too short"`, 422)
	if got := call(alice, "GET", "/api/request-settings", "", 200); got["version"].(float64) != 1 || got["justification_min_length"].(float64) != 25 {
		t.Errorf("after a save: %v", got)
	}
	// durations: a maximum is a limit, and without one a request has to name a duration
	put(admin, 1, `"justification_min_length":5;"max_hours":10`, 200)
	submit(alice, "alice", `"justification":"for the Atlas project"`, 422)
	submit(alice, "alice", `"justification":"for the Atlas project","duration_hours":11`, 422)
	// attachments: off, then on
	submit(alice, "alice", `"justification":"for the Atlas project","duration_hours":8,"attachments":["SEC-1"]`, 422)
	put(admin, 2, `"justification_min_length":5;"max_hours":10;"attachments_allowed":true`, 200)
	// for others: nobody means nobody, even for a holder of the permission
	put(admin, 3, `"justification_min_length":5;"max_hours":10;"attachments_allowed":true;"for_others":"nobody"`, 200)
	submit(admin, "bob", `"justification":"for the Atlas project","duration_hours":8`, 403)
	// managers: carol (alice's manager, no special permission) may; a peer may not
	put(admin, 4, `"justification_min_length":5;"max_hours":10;"attachments_allowed":true;"for_others":"managers"`, 200)
	if got := call(carol, "GET", "/api/catalog", "", 200); got["can_request_for_others"] != true {
		t.Errorf("the catalog hides the managers policy: %v", got["can_request_for_others"])
	}
	submit(alice, "bob", `"justification":"for the Atlas project","duration_hours":8`, 403)
	ok := submit(carol, "alice", `"justification":"for the Atlas project","duration_hours":8,"attachments":["SEC-1"]`, 201)
	if len(ok["lines"].([]any)) != 1 {
		t.Errorf("manager's request: %v", ok)
	}

	// history visibility: an auditor reads others' requests unless the tenant restricts it
	auditor := reqLogin(t, f, "au@b.example", []auth.Role{auth.RoleAuditor}, "")
	lineID := ok["lines"].([]any)[0].(map[string]any)["id"].(string)
	call(auditor, "GET", "/api/requests/"+lineID, "", 200)
	call(auditor, "GET", "/api/requests?scope=all", "", 200)
	put(admin, 5, `"justification_min_length":5;"max_hours":10;"attachments_allowed":true;"for_others":"managers";"history_visibility":"involved"`, 200)
	call(auditor, "GET", "/api/requests/"+lineID, "", 404)
	call(auditor, "GET", "/api/requests?scope=all", "", 403)
	call(alice, "GET", "/api/requests/"+lineID, "", 200) // the beneficiary
	call(carol, "GET", "/api/requests/"+lineID, "", 200) // the requester
	call(admin, "GET", "/api/requests/"+lineID, "", 200) // deciders

	// the settings are the tenant's: tenant A is untouched, and sees defaults
	rec := reqDo(h, adminA, "GET", "/api/request-settings", "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), `"history_visibility":"involved"`) || !strings.Contains(rec.Body.String(), `"version":0`) {
		t.Errorf("tenant A: %d %s", rec.Code, rec.Body)
	}

	// every change is in the audit ledger, with the values it replaced
	acts := reqAuditActions(t, f, f.B.ID)
	if acts["request.settings.update"] != 6 {
		t.Errorf("settings audit events = %d, want 6 (%v)", acts["request.settings.update"], acts)
	}
}
