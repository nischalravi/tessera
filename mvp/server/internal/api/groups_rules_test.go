package api

import (
	"fmt"
	"strings"
	"testing"
)

// Group rules over the API (issue #56, GR-13): saving needs the privileges the
// rule will use, a veto answers the request it refuses, and the email gate is
// closed until a tenant admin opens it.

func TestRulesAPI_SaveNeedsPrivilegesOnWhatItTouches(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	gb, gc := e.admin.group(app, "b"), e.admin.group(app, "c")
	bob := e.user("bob", "bob")
	e.grant("/api/groups/"+gb, "admin", "bob", "")
	add := fmt.Sprintf(`{"name":"copy","trigger":"membership.direct.added","action":"add_to_group","params":{"group":%q}}`, gc)

	// bob administers the owner but not the group the action changes
	denied(t, bob, "POST", "/api/groups/"+gb+"/rules", add, "admin")
	e.grant("/api/groups/"+gc, "admin", "bob", "")
	rule := bob.call("POST", "/api/groups/"+gb+"/rules", add, 201)
	if rule["updated_by"] == "" || rule["scope"] != "self" || rule["enabled"] != true {
		t.Errorf("rule = %v", rule)
	}
	// changing it needs the same: take the privilege away and bob cannot save again
	rows := e.admin.call("GET", "/api/groups/"+gc+"/privileges", "", 200)["items"].([]any)
	e.admin.call("DELETE", "/api/groups/"+gc+"/privileges/"+rows[0].(map[string]any)["id"].(string), "", 200)
	denied(t, bob, "PUT", "/api/groups/"+gb+"/rules/"+rule["id"].(string), add, "admin")
	// but he may still delete it: that takes authority away
	bob.call("DELETE", "/api/groups/"+gb+"/rules/"+rule["id"].(string), "", 200)
	if items := bob.call("GET", "/api/groups/"+gb+"/rules", "", 200)["items"].([]any); len(items) != 0 {
		t.Errorf("rules after delete = %v", items)
	}
	// another owner's rule is not found through this owner
	other := e.admin.call("POST", "/api/groups/"+gc+"/rules", `{"trigger":"membership.direct.added","action":"no_self_add"}`, 201)["id"].(string)
	bob.call("DELETE", "/api/groups/"+gb+"/rules/"+other, "", 404)
	e.admin.call("DELETE", "/api/groups/"+gc+"/rules/"+other, "", 200)
	e.admin.call("DELETE", "/api/groups/"+gc+"/rules/"+other, "", 404)
}

func TestRulesAPI_VetoAnswersTheRefusedRequest(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	ga, gb := e.admin.group(app, "a"), e.admin.group(app, "b")
	bob := e.user("bob", "bob")
	e.grant("/api/groups/"+gb, "update", "bob", "")
	rule := e.admin.call("POST", "/api/groups/"+gb+"/rules",
		fmt.Sprintf(`{"name":"b needs a","trigger":"membership.direct.added","action":"require_member_of","params":{"group":%q}}`, ga), 201)
	if rule["veto"] != true {
		t.Errorf("rule = %v", rule)
	}
	member := fmt.Sprintf(`{"identity":%d}`, e.ident("carol"))
	rec := bob.do("POST", "/api/groups/"+gb+"/members", member)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"error":"vetoed"`) || !strings.Contains(rec.Body.String(), rule["id"].(string)) {
		t.Fatalf("vetoed add = %d %s", rec.Code, rec.Body.String())
	}
	if m := e.admin.call("GET", "/api/groups/"+gb+"/members?filter=direct", "", 200); m["total"] != float64(0) {
		t.Errorf("members after a veto = %v", m)
	}
	e.admin.call("POST", "/api/groups/"+ga+"/members", member, 201)
	bob.call("POST", "/api/groups/"+gb+"/members", member, 201)
}

func TestRulesAPI_EmailGateAndValidation(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	g := e.admin.group(app, "g")
	notify := `{"trigger":"membership.direct.added","action":"notify","params":{"subject":"hi","message":"you joined {group}"}}`
	if got := e.admin.call("GET", "/api/groups/rules/settings", "", 200); got["email_enabled"] != false {
		t.Errorf("default settings = %v", got)
	}
	if rec := e.admin.do("POST", "/api/groups/"+g+"/rules", notify); rec.Code != 409 || !strings.Contains(rec.Body.String(), "email_rules_disabled") {
		t.Errorf("an email rule with the gate closed = %d %s", rec.Code, rec.Body.String())
	}
	e.admin.call("PUT", "/api/groups/rules/settings", `{"email_enabled":true}`, 200)
	e.admin.call("POST", "/api/groups/"+g+"/rules", notify, 201)
	if got := e.admin.call("GET", "/api/groups/rules/settings", "", 200); got["email_enabled"] != true {
		t.Errorf("settings = %v", got)
	}

	for name, body := range map[string]string{
		"unknown trigger":  `{"trigger":"membership.sideways","action":"no_self_add"}`,
		"a script":         `{"trigger":"membership.direct.added","action":"run_script","params":{"code":"1"}}`,
		"unknown field":    `{"trigger":"membership.direct.added","action":"no_self_add","code":"x"}`,
		"a later action":   `{"trigger":"membership.direct.added","action":"open_inbox_task"}`,
		"veto no message":  `{"trigger":"membership.direct.added","action":"veto"}`,
		"a stray param":    `{"trigger":"membership.direct.added","action":"no_self_add","params":{"message":"x"}}`,
		"group id invalid": `{"trigger":"membership.direct.added","action":"require_member_of","params":{"group":"app:a"}}`,
	} {
		if rec := e.admin.do("POST", "/api/groups/"+g+"/rules", body); rec.Code != 422 && rec.Code != 400 {
			t.Errorf("%s = %d %.120s, want 400 or 422", name, rec.Code, rec.Body.String())
		}
	}
	// no outbound client in this server: a webhook rule cannot be saved
	if rec := e.admin.do("POST", "/api/groups/"+g+"/rules", `{"trigger":"membership.direct.added","action":"webhook","params":{"url":"https://hooks.example/x"}}`); rec.Code != 409 ||
		!strings.Contains(rec.Body.String(), "webhooks_unavailable") {
		t.Errorf("a webhook rule with no client = %d %s", rec.Code, rec.Body.String())
	}
	// a folder's rules end with the folder
	empty := e.admin.folder(app, "empty")
	e.admin.call("POST", "/api/groups/folders/"+empty+"/rules", `{"scope":"one","trigger":"membership.direct.added","action":"one_group_only"}`, 201)
	e.admin.call("DELETE", "/api/groups/folders/"+empty, "", 200)
	e.admin.call("GET", "/api/groups/folders/"+empty+"/rules", "", 404)
}
