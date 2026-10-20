package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Group privileges (issue #47, GR-4): every group route asks the folder's or
// group's privilege, a caller's privileges come from the identity its platform
// user is linked to, and listings show only what the caller may view.

// privEnv is tenant B's server with a tenant_admin client and a way to sign in
// other users, each linked to one of the fixture's identities.
type privEnv struct {
	t     *testing.T
	f     *storetest.Fixture
	srv   *Server
	admin grpClient
	n     int
}

func newPrivEnv(t *testing.T) *privEnv {
	t.Helper()
	f := storetest.TwoTenants(t)
	srv := newIsolationServer(f)
	e := &privEnv{t: t, f: f, srv: srv}
	e.admin = e.as("admin", []auth.Role{auth.RoleTenantAdmin}, nil)
	return e
}

// as signs in a user with the roles, linked to the identity if given.
func (e *privEnv) as(name string, roles []auth.Role, identity *int64) grpClient {
	e.t.Helper()
	l := signIn(e.t, e.f.DB, e.f.B.ID, authtest.User{Email: name + "@b.example", Roles: roles, IdentityID: identity}, authtest.Phr, storetest.Now)
	return grpClient{client{e.t, l.Handler(e.srv.Handler())}}
}

func (e *privEnv) user(name string, identity string) grpClient {
	id := e.f.B.IDs[identity]
	return e.as(name, []auth.Role{auth.RoleOperator}, &id)
}

func (e *privEnv) ident(name string) int64 { return e.f.B.IDs[name] }

// grant makes the admin grant privilege to an identity on an object path
// ("/api/groups/{id}" or "/api/groups/folders/{id}"), and returns the row id.
func (e *privEnv) grant(object, privilege string, identity string, extra string) string {
	e.t.Helper()
	body := fmt.Sprintf(`{"privilege":%q,"holder_type":"identity","identity":%d%s}`, privilege, e.ident(identity), extra)
	return e.admin.call("POST", object+"/privileges", body, 201)["id"].(string)
}

// denied checks a 403 privilege_required answer for the privilege.
func denied(t *testing.T, c grpClient, method, path, body, privilege string) {
	t.Helper()
	rec := c.do(method, path, body)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusForbidden || out["error"] != "privilege_required" || (privilege != "" && out["privilege"] != privilege) {
		t.Errorf("%s %s = %d %.200s, want 403 privilege_required (%s)", method, path, rec.Code, rec.Body.String(), privilege)
	}
}

// TestGroupsRoutesRequirePrivilege is the authorization test of every group
// route: a signed-in user whose roles reach the route but who holds no
// privilege on the folder or group gets 403, and so does a user without the
// route's permission. The table must name every registered /api/groups route.
func TestGroupsRoutesRequirePrivilege(t *testing.T) {
	e := newPrivEnv(t)
	root := e.admin.folder("", "root0")
	app := e.admin.folder(root, "app")
	app2 := e.admin.folder(root, "app2")
	g := e.admin.group(app, "g")
	f1 := e.admin.group(app, "factor1")
	priv := e.grant("/api/groups/"+g, "update", "bob", "")
	fpriv := e.grant("/api/groups/folders/"+app, "create", "bob", "")
	other := "00000000-0000-4000-8000-00000000d00d"
	// the attribute framework (GR-7): a definition with two names and two actions, an assignment, and a row on the definition
	ad := e.admin.call("POST", "/api/groups/attr-defs", `{"folder":"`+app+`","extension":"tags","value_type":"string","multi_valued":true,`+
		`"multi_assign":true,"assign_to":["group","folder","identity"]}`, 201)["id"].(string)
	nm := e.admin.call("POST", "/api/groups/attr-names", `{"def":"`+ad+`","extension":"n"}`, 201)["id"].(string)
	nm2 := e.admin.call("POST", "/api/groups/attr-names", `{"def":"`+ad+`","extension":"m"}`, 201)["id"].(string)
	act2 := e.admin.call("POST", "/api/groups/attr-defs/"+ad+"/actions", `{"name":"extra"}`, 201)["id"].(string)
	asg := e.admin.call("POST", "/api/groups/attr-assignments", `{"name":"`+nm+`","owner_type":"group","owner":"`+g+`","values":["a"]}`, 201)["id"].(string)
	apriv := e.grant("/api/groups/attr-defs/"+ad, "attr_view", "bob", "")
	rb := `{"name":"n","trigger":"membership.direct.added","action":"no_self_add"}`
	grule := e.admin.call("POST", "/api/groups/"+g+"/rules", rb, 201)["id"].(string)
	frule := e.admin.call("POST", "/api/groups/folders/"+app+"/rules", rb, 201)["id"].(string)

	// policy groups (GR-9): a file for a new group in app that refers to g
	polFile := func(group, ref string) string {
		cedar := `permit (principal, action == Tessera::Action::"member", resource == Tessera::Group::"` + group + `") when { principal in Tessera::Group::"` + ref + `" };`
		b, _ := json.Marshal(map[string]any{"files": []map[string]string{{"path": "groups/p.cedar", "cedar": cedar}}, "origin": "repo", "commit": "c1"})
		return string(b)
	}
	polBody := polFile("root0:app:pol1", "root0:app:g")

	type routeCase struct {
		method, pattern, path, body string
		privilege                   string // the privilege the first check asks; "" when the route is role-gated only
	}
	cases := []routeCase{
		{"GET", "/api/groups/folders/{id}", "/api/groups/folders/" + app, "", "stem_view"},
		{"POST", "/api/groups/folders", "/api/groups/folders", `{"parent":"` + app + `","extension":"x"}`, "create"},
		{"PATCH", "/api/groups/folders/{id}", "/api/groups/folders/" + app, `{"description":"x"}`, "stem_admin"},
		{"DELETE", "/api/groups/folders/{id}", "/api/groups/folders/" + app, "", "stem_admin"},
		{"POST", "/api/groups/folders/{id}/move", "/api/groups/folders/" + app + "/move", `{"parent":"` + app2 + `"}`, "stem_admin"},
		{"POST", "/api/groups/folders/{id}/copy", "/api/groups/folders/" + app + "/copy", `{"parent":"` + app2 + `"}`, "stem_admin"},
		{"POST", "/api/groups", "/api/groups", `{"folder":"` + app + `","extension":"x"}`, "create"},
		{"GET", "/api/groups/{id}", "/api/groups/" + g, "", "view"},
		{"PATCH", "/api/groups/{id}", "/api/groups/" + g, `{"description":"x"}`, "admin"},
		{"DELETE", "/api/groups/{id}", "/api/groups/" + g, "", "admin"},
		{"POST", "/api/groups/{id}/move", "/api/groups/" + g + "/move", `{"folder":"` + app2 + `"}`, "admin"},
		{"POST", "/api/groups/{id}/copy", "/api/groups/" + g + "/copy", `{"folder":"` + app2 + `"}`, "read"},
		{"POST", "/api/groups/{id}/restore", "/api/groups/" + g + "/restore", "", "admin"},
		{"GET", "/api/groups/{id}/members", "/api/groups/" + g + "/members", "", "read"},
		{"POST", "/api/groups/{id}/members", "/api/groups/" + g + "/members", fmt.Sprintf(`{"identity":%d}`, e.ident("carol")), "update"},
		{"GET", "/api/groups/{id}/members/{member}", "/api/groups/" + g + "/members/1", "", "read"},
		{"GET", "/api/groups/{id}/members/{member}", "/api/groups/" + g + "/members/1?trace=true", "", "read"},
		{"POST", "/api/groups/{id}/members:batch", "/api/groups/" + g + "/members:batch", fmt.Sprintf(`{"add":[{"identity":%d}]}`, e.ident("carol")), "update"},
		{"POST", "/api/groups:simulate", "/api/groups:simulate", fmt.Sprintf(`{"changes":[{"kind":"add_member","group":%q,"identity":%d}]}`, g, e.ident("carol")), "update"},
		{"DELETE", "/api/groups/{id}/members/{member}", "/api/groups/" + g + "/members/" + fmt.Sprint(e.ident("carol")), "", "update"},
		{"POST", "/api/groups/{id}/convert-to-composite", "/api/groups/" + g + "/convert-to-composite", `{"op":"union","factors":["` + f1 + `"]}`, "admin"},
		{"PUT", "/api/groups/{id}/composite", "/api/groups/" + g + "/composite", `{"op":"union","factors":["` + f1 + `"]}`, "admin"},
		{"GET", "/api/groups/folders/{id}/privileges", "/api/groups/folders/" + app + "/privileges", "", "stem_admin"},
		{"POST", "/api/groups/folders/{id}/privileges", "/api/groups/folders/" + app + "/privileges", `{"privilege":"stem_view","holder_type":"everyone"}`, "stem_admin"},
		{"GET", "/api/groups/folders/{id}/privileges/effective", "/api/groups/folders/" + app + "/privileges/effective", "", "stem_view"},
		{"DELETE", "/api/groups/folders/{id}/privileges/{privilege_id}", "/api/groups/folders/" + app + "/privileges/" + fpriv, "", "stem_admin"},
		{"GET", "/api/groups/{id}/privileges", "/api/groups/" + g + "/privileges", "", "admin"},
		{"POST", "/api/groups/{id}/privileges", "/api/groups/" + g + "/privileges", `{"privilege":"view","holder_type":"everyone"}`, "admin"},
		{"GET", "/api/groups/{id}/privileges/effective", "/api/groups/" + g + "/privileges/effective", "", "view"},
		{"DELETE", "/api/groups/{id}/privileges/{privilege_id}", "/api/groups/" + g + "/privileges/" + priv, "", "admin"},
		// rules: admin on the owner (stem_admin on a folder)
		{"GET", "/api/groups/folders/{id}/rules", "/api/groups/folders/" + app + "/rules", "", "stem_admin"},
		{"POST", "/api/groups/folders/{id}/rules", "/api/groups/folders/" + app + "/rules", rb, "stem_admin"},
		{"PUT", "/api/groups/folders/{id}/rules/{rule_id}", "/api/groups/folders/" + app + "/rules/" + frule, rb, "stem_admin"},
		{"DELETE", "/api/groups/folders/{id}/rules/{rule_id}", "/api/groups/folders/" + app + "/rules/" + frule, "", "stem_admin"},
		{"GET", "/api/groups/{id}/rules", "/api/groups/" + g + "/rules", "", "admin"},
		{"POST", "/api/groups/{id}/rules", "/api/groups/" + g + "/rules", rb, "admin"},
		{"PUT", "/api/groups/{id}/rules/{rule_id}", "/api/groups/" + g + "/rules/" + grule, rb, "admin"},
		{"DELETE", "/api/groups/{id}/rules/{rule_id}", "/api/groups/" + g + "/rules/" + grule, "", "admin"},
		{"GET", "/api/groups/rules/settings", "/api/groups/rules/settings", "", ""},
		{"PUT", "/api/groups/rules/settings", "/api/groups/rules/settings", `{"email_enabled":false}`, ""},
		// another identity's privileges need admin on the object, not view
		{"GET", "/api/groups/{id}/privileges/effective", "/api/groups/" + g + "/privileges/effective?identity=" + fmt.Sprint(e.ident("bob")), "", "admin"},
		// attribute definitions, names, actions and assignments (GR-7)
		{"POST", "/api/groups/attr-defs", "/api/groups/attr-defs", `{"folder":"` + app + `","extension":"x","assign_to":["group"]}`, "create"},
		{"GET", "/api/groups/attr-defs/{id}", "/api/groups/attr-defs/" + ad, "", "attr_view"},
		{"PATCH", "/api/groups/attr-defs/{id}", "/api/groups/attr-defs/" + ad, `{"description":"x"}`, "attr_admin"},
		{"DELETE", "/api/groups/attr-defs/{id}", "/api/groups/attr-defs/" + ad, "", "attr_admin"},
		{"GET", "/api/groups/attr-defs/{id}/actions", "/api/groups/attr-defs/" + ad + "/actions", "", "attr_view"},
		{"POST", "/api/groups/attr-defs/{id}/actions", "/api/groups/attr-defs/" + ad + "/actions", `{"name":"more"}`, "attr_admin"},
		{"DELETE", "/api/groups/attr-defs/{id}/actions/{action_id}", "/api/groups/attr-defs/" + ad + "/actions/" + act2, "", "attr_admin"},
		{"PUT", "/api/groups/attr-defs/{id}/actions/{action_id}/implies", "/api/groups/attr-defs/" + ad + "/actions/" + act2 + "/implies", `{"implies":[]}`, "attr_admin"},
		{"GET", "/api/groups/attr-defs/{id}/privileges", "/api/groups/attr-defs/" + ad + "/privileges", "", "attr_admin"},
		{"POST", "/api/groups/attr-defs/{id}/privileges", "/api/groups/attr-defs/" + ad + "/privileges", `{"privilege":"attr_view","holder_type":"everyone"}`, "attr_admin"},
		{"GET", "/api/groups/attr-defs/{id}/privileges/effective", "/api/groups/attr-defs/" + ad + "/privileges/effective", "", "attr_view"},
		{"GET", "/api/groups/attr-defs/{id}/privileges/effective", "/api/groups/attr-defs/" + ad + "/privileges/effective?identity=" + fmt.Sprint(e.ident("bob")), "", "attr_admin"},
		{"DELETE", "/api/groups/attr-defs/{id}/privileges/{privilege_id}", "/api/groups/attr-defs/" + ad + "/privileges/" + apriv, "", "attr_admin"},
		{"POST", "/api/groups/attr-names", "/api/groups/attr-names", `{"def":"` + ad + `","extension":"y"}`, "attr_admin"},
		{"GET", "/api/groups/attr-names/{id}", "/api/groups/attr-names/" + nm, "", "attr_view"},
		{"PATCH", "/api/groups/attr-names/{id}", "/api/groups/attr-names/" + nm, `{"description":"x"}`, "attr_admin"},
		{"DELETE", "/api/groups/attr-names/{id}", "/api/groups/attr-names/" + nm2, "", "attr_admin"},
		{"PUT", "/api/groups/attr-names/{id}/implies", "/api/groups/attr-names/" + nm + "/implies", `{"implies":["` + nm2 + `"]}`, "attr_admin"},
		{"POST", "/api/groups/attr-assignments", "/api/groups/attr-assignments", `{"name":"` + nm + `","owner_type":"group","owner":"` + g + `","values":["b"]}`, "attr_update"},
		{"GET", "/api/groups/attr-assignments/{id}", "/api/groups/attr-assignments/" + asg, "", "attr_read"},
		{"PATCH", "/api/groups/attr-assignments/{id}", "/api/groups/attr-assignments/" + asg, `{"disabled_at":null}`, "attr_update"},
		{"DELETE", "/api/groups/attr-assignments/{id}", "/api/groups/attr-assignments/" + asg, "", "attr_update"},
		{"PUT", "/api/groups/attr-assignments/{id}/values", "/api/groups/attr-assignments/" + asg + "/values", `{"values":["c"]}`, "attr_update"},
		{"GET", "/api/groups/{id}/object-types", "/api/groups/" + g + "/object-types", "", "view"},
		{"PUT", "/api/groups/{id}/object-types", "/api/groups/" + g + "/object-types", `{"types":["ref"]}`, "group_attr_update"},
		{"GET", "/api/groups/folders/{id}/object-types", "/api/groups/folders/" + app + "/object-types", "", "stem_view"},
		{"PUT", "/api/groups/folders/{id}/object-types", "/api/groups/folders/" + app + "/object-types", `{"types":["app"]}`, "stem_attr_update"},
		// policy groups as code (GR-9)
		{"POST", "/api/groups/policy/validate", "/api/groups/policy/validate", polBody, "read"},
		{"POST", "/api/groups/policy/diff", "/api/groups/policy/diff", polBody, "read"},
		{"POST", "/api/groups/policy/apply", "/api/groups/policy/apply", polBody, "create"},
		{"POST", "/api/groups/policy/reindex", "/api/groups/policy/reindex", "", ""},
		{"GET", "/api/groups/{id}/policy", "/api/groups/" + g + "/policy", "", "read"},
		// tenant-wide maintenance and settings: groups.admin
		{"GET", "/api/groups/pit/digests", "/api/groups/pit/digests", "", ""},
		{"GET", "/api/groups/pit/verify", "/api/groups/pit/verify", "", ""},
		{"POST", "/api/groups/pit/rebuild", "/api/groups/pit/rebuild", "", ""},
		{"POST", "/api/groups/engine/verify", "/api/groups/engine/verify", "", ""},
		{"GET", "/api/groups/engine/ops/{seq}", "/api/groups/engine/ops/1", "", ""},
		{"GET", "/api/groups/privileges/settings", "/api/groups/privileges/settings", "", ""},
		{"PUT", "/api/groups/privileges/settings", "/api/groups/privileges/settings", `{"everyone_allowed":[],"defaults":[]}`, ""},
		{"PUT", "/api/groups/users/{id}/identity", "/api/groups/users/" + other + "/identity", `{"identity_id":null}`, ""},
	}
	// the listings are gated too, by filtering: the table below names them so none is forgotten
	listings := []routeCase{{"GET", "/api/groups/folders", "", "", ""}, {"GET", "/api/groups/native", "", "", ""},
		// GR-5: what an identity belongs to, and the read-only SCIM server, show only what the caller may read
		// (the SCIM routes answer in SCIM's error format: TestSCIM_PrivilegeAndAuth checks their 403s)
		{"GET", "/api/identities/{identity_id}/groups", "", "", ""}, {"GET", "/scim/v2/Groups", "", "", ""},
		{"GET", "/scim/v2/Groups/{id}", "", "", ""}, {"GET", "/scim/v2/Users", "", "", ""}, {"GET", "/scim/v2/Users/{id}", "", "", ""},
		{"GET", "/scim/v2/ServiceProviderConfig", "", "", ""}, {"GET", "/scim/v2/ResourceTypes", "", "", ""},
		// the description of these routes is for every signed-in user
		{"GET", "/api/openapi/groups.json", "", "", ""},

		{"GET", "/api/groups/attr-defs", "", "", ""}, {"GET", "/api/groups/attr-names", "", "", ""},
		{"GET", "/api/groups/attr-assignments", "", "", ""}, {"GET", "/api/groups/services", "", "", ""},
		{"GET", "/api/groups/object-types", "", "", ""}}
	// every registered group route is in the table
	have := map[string]bool{}
	for _, c := range append(slices.Clone(cases), listings...) {
		have[c.method+" "+c.pattern] = true
	}
	for _, rt := range e.srv.Routes() {
		isGroups := strings.HasPrefix(rt.Pattern, "/api/groups") || strings.HasPrefix(rt.Pattern, "/scim/v2/") ||
			rt.Pattern == "/api/openapi/groups.json" ||
			(strings.HasPrefix(rt.Pattern, "/api/identities/") && strings.HasSuffix(rt.Pattern, "/groups"))
		if !isGroups || (rt.Method == "GET" && rt.Pattern == "/api/groups") {
			continue // GET /api/groups lists the connected-system groups
		}
		if !have[rt.Method+" "+rt.Pattern] {
			t.Errorf("%s %s has no authorization case", rt.Method, rt.Pattern)
		}
	}
	nobody := e.user("nobody", "alice") // operator: reaches every route, holds no privilege
	for _, c := range cases {
		t.Run("no privilege "+c.method+" "+c.pattern, func(t *testing.T) {
			if c.privilege == "" {
				if rec := nobody.do(c.method, c.path, c.body); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"forbidden"`) {
					t.Errorf("%s %s = %d %.200s, want 403 forbidden", c.method, c.path, rec.Code, rec.Body.String())
				}
				return
			}
			denied(t, nobody, c.method, c.path, c.body, c.privilege)
		})
	}
	// the listings answer 200 and show nothing
	for _, p := range []string{"/api/groups/folders", "/api/groups/native", "/api/groups/attr-defs", "/api/groups/attr-names",
		"/api/groups/attr-assignments", "/api/groups/services"} {
		if items := nobody.call("GET", p, "", 200)["items"].([]any); len(items) != 0 {
			t.Errorf("%s shows %d items to a user without view", p, len(items))
		}
	}
	// the object type vocabulary is public to anyone who reaches the groups routes
	nobody.call("GET", "/api/groups/object-types", "", 200)
	// a user without the route's permission: viewer holds groups.read only
	viewer := e.as("viewer", []auth.Role{auth.RoleViewer}, nil)
	for _, c := range cases {
		if c.method == "GET" && !strings.Contains(c.pattern, "pit") && !strings.Contains(c.pattern, "engine") &&
			!strings.Contains(c.pattern, "settings") {
			continue
		}
		if c.pattern == "/api/groups/policy/validate" || c.pattern == "/api/groups/policy/diff" {
			continue // POST, but reads: groups.read reaches them
		}
		if rec := viewer.do(c.method, c.path, c.body); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"forbidden"`) {
			t.Errorf("viewer %s %s = %d %.100s, want 403 forbidden", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	// the same requests from the tenant admin are not refused for want of a privilege
	for _, c := range cases {
		if c.method == "DELETE" || c.method == "PUT" || strings.Contains(c.pattern, "move") || strings.Contains(c.pattern, "restore") ||
			strings.Contains(c.pattern, "composite") || c.pattern == "/api/groups/{id}/copy" {
			continue
		}
		if rec := e.admin.do(c.method, c.path, c.body); rec.Code == http.StatusForbidden {
			t.Errorf("tenant_admin %s %s = 403 %.100s", c.method, c.path, rec.Body.String())
		}
	}
}

// TestPrivs_GrantsGiveAccess: privileges granted over the API give exactly
// what the implication table says, and a creator administers what they make.
func TestPrivs_GrantsGiveAccess(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	g := e.admin.group(app, "g")
	bob := e.user("bob", "bob")
	alice := e.user("alice", "alice")

	denied(t, bob, "GET", "/api/groups/"+g, "", "view")
	e.grant("/api/groups/"+g, "update", "bob", "")
	bob.call("GET", "/api/groups/"+g, "", 200) // update implies view
	denied(t, bob, "GET", "/api/groups/"+g+"/members", "", "read")
	bob.call("POST", "/api/groups/"+g+"/members", fmt.Sprintf(`{"identity":%d}`, e.ident("carol")), 201)
	denied(t, bob, "PATCH", "/api/groups/"+g, `{"description":"x"}`, "admin")

	// a member group is added with update on the parent and read on the child
	g2 := e.admin.group(app, "g2")
	denied(t, bob, "POST", "/api/groups/"+g+"/members", `{"group":"`+g2+`"}`, "read")
	e.grant("/api/groups/"+g2, "read", "bob", "")
	bob.call("POST", "/api/groups/"+g+"/members", `{"group":"`+g2+`"}`, 201)

	// optin and optout: a member may add and remove themselves
	e.grant("/api/groups/"+g, "optin", "alice", "")
	denied(t, alice, "POST", "/api/groups/"+g+"/members", fmt.Sprintf(`{"identity":%d}`, e.ident("bob")), "update") // not herself
	alice.call("POST", "/api/groups/"+g+"/members", fmt.Sprintf(`{"identity":%d}`, e.ident("alice")), 201)
	denied(t, alice, "DELETE", fmt.Sprintf("/api/groups/%s/members/%d", g, e.ident("alice")), "", "optout")
	e.grant("/api/groups/"+g, "optout", "alice", "")
	alice.call("DELETE", fmt.Sprintf("/api/groups/%s/members/%d", g, e.ident("alice")), "", 200)

	// create on a folder: the creator administers what they create
	denied(t, alice, "POST", "/api/groups", `{"folder":"`+app+`","extension":"mine"}`, "create")
	e.grant("/api/groups/folders/"+app, "create", "alice", "")
	mine := alice.call("POST", "/api/groups", `{"folder":"`+app+`","extension":"mine"}`, 201)["id"].(string)
	alice.call("PATCH", "/api/groups/"+mine, `{"description":"mine"}`, 200)
	rows := alice.call("GET", "/api/groups/"+mine+"/privileges", "", 200)["items"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["source"] != "creator_default" || rows[0].(map[string]any)["privilege"] != "admin" {
		t.Errorf("the creator's rows = %v", rows)
	}
	sub := alice.call("POST", "/api/groups/folders", `{"parent":"`+app+`","extension":"sub"}`, 201)["id"].(string)
	alice.call("PATCH", "/api/groups/folders/"+sub, `{"description":"mine"}`, 200) // stem_admin of what they created
	denied(t, alice, "PATCH", "/api/groups/folders/"+app, `{"description":"x"}`, "stem_admin")

	// move needs admin on the group and create on the destination
	dest := e.admin.folder("", "dest")
	denied(t, alice, "POST", "/api/groups/"+mine+"/move", `{"folder":"`+dest+`"}`, "create")
	e.grant("/api/groups/folders/"+dest, "create", "alice", "")
	alice.call("POST", "/api/groups/"+mine+"/move", `{"folder":"`+dest+`"}`, 200)
	// a copy needs read on the source
	denied(t, bob, "POST", "/api/groups/"+g2+"/copy", `{"folder":"`+dest+`"}`, "create")

	// revoking takes the access away; a row of another object is not revocable through this one
	row := e.grant("/api/groups/"+g2, "admin", "bob", "")
	bob.call("PATCH", "/api/groups/"+g2, `{"description":"x"}`, 200)
	e.admin.call("DELETE", "/api/groups/"+g+"/privileges/"+row, "", 404)
	e.admin.call("DELETE", "/api/groups/"+g2+"/privileges/"+row, "", 200)
	denied(t, bob, "PATCH", "/api/groups/"+g2, `{"description":"y"}`, "admin")
	e.admin.call("DELETE", "/api/groups/"+g2+"/privileges/"+row, "", 404)

	// a grant is idempotent
	again := e.admin.do("POST", "/api/groups/"+g+"/privileges", fmt.Sprintf(`{"privilege":"update","holder_type":"identity","identity":%d}`, e.ident("bob")))
	if again.Code != 200 {
		t.Errorf("repeating a grant = %d, want 200", again.Code)
	}
}

// TestPrivs_InheritedThroughTheAPI: a folder row with applies_to groups and a
// scope reaches the groups below, one level or all of them.
func TestPrivs_InheritedThroughTheAPI(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	foo := e.admin.folder(app, "foo")
	g1, g2 := e.admin.group(app, "g1"), e.admin.group(foo, "g2")
	bob := e.user("bob", "bob")
	row := e.grant("/api/groups/folders/"+app, "read", "bob", `,"applies_to":"groups","scope":"one"`)
	bob.call("GET", "/api/groups/"+g1+"/members", "", 200)
	denied(t, bob, "GET", "/api/groups/"+g2+"/members", "", "read")
	e.admin.call("DELETE", "/api/groups/folders/"+app+"/privileges/"+row, "", 200)
	e.grant("/api/groups/folders/"+app, "read", "bob", `,"applies_to":"groups","scope":"sub"`)
	bob.call("GET", "/api/groups/"+g2+"/members", "", 200)
	// stem_admin on a folder administers everything below
	e.grant("/api/groups/folders/"+foo, "stem_admin", "bob", "")
	bob.call("PATCH", "/api/groups/"+g2, `{"description":"x"}`, 200)
	denied(t, bob, "PATCH", "/api/groups/"+g1, `{"description":"x"}`, "admin")
	// refused grants
	for name, body := range map[string]string{
		"a group privilege on a folder":  `{"privilege":"view","holder_type":"everyone"}`,
		"a bad holder":                   `{"privilege":"stem_view","holder_type":"robot"}`,
		"an identity holder without one": `{"privilege":"stem_view","holder_type":"identity"}`,
		"inherited without a scope":      `{"privilege":"read","holder_type":"everyone","applies_to":"groups","scope":"self"}`,
		"unknown field":                  `{"privilege":"stem_view","holder_type":"everyone","x":1}`,
	} {
		if rec := e.admin.do("POST", "/api/groups/folders/"+app+"/privileges", body); rec.Code != 422 {
			t.Errorf("%s = %d %.100s, want 422", name, rec.Code, rec.Body.String())
		}
	}
	if rec := e.admin.do("POST", "/api/groups/folders/"+app+"/privileges", fmt.Sprintf(`{"privilege":"stem_view","holder_type":"identity","identity":%d}`, 987654)); rec.Code != 404 {
		t.Errorf("unknown identity holder = %d", rec.Code)
	}
}

func TestPrivs_EveryoneNeedsTenantAdminOverTheAPI(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	g := e.admin.group(app, "g")
	bob, carol := e.user("bob", "bob"), e.user("carol", "carol")
	e.grant("/api/groups/"+g, "admin", "bob", "") // bob administers the group, but is not a tenant admin
	body := `{"privilege":"view","holder_type":"everyone"}`
	rec := bob.do("POST", "/api/groups/"+g+"/privileges", body)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "everyone_requires_tenant_admin") {
		t.Errorf("group admin grants view to everyone = %d %s", rec.Code, rec.Body.String())
	}
	denied(t, carol, "GET", "/api/groups/"+g, "", "view")
	e.admin.call("POST", "/api/groups/"+g+"/privileges", body, 201)
	carol.call("GET", "/api/groups/"+g, "", 200)
	// the policy refuses a privilege it does not allow
	if rec := e.admin.do("POST", "/api/groups/"+g+"/privileges", `{"privilege":"admin","holder_type":"everyone"}`); rec.Code != 422 {
		t.Errorf("everyone admin = %d %s", rec.Code, rec.Body.String())
	}
	// default privileges: new groups are viewable by everyone once the tenant says so
	e.admin.call("PUT", "/api/groups/privileges/settings", `{"everyone_allowed":["view","read"],"defaults":[{"object_type":"group","privilege":"view"}]}`, 200)
	g2 := e.admin.group(app, "g2")
	carol.call("GET", "/api/groups/"+g2, "", 200)
	got := e.admin.call("GET", "/api/groups/privileges/settings", "", 200)
	if d := got["defaults"].([]any); len(d) != 1 {
		t.Errorf("settings = %v", got)
	}
	if rec := e.admin.do("PUT", "/api/groups/privileges/settings", `{"everyone_allowed":["admin"],"defaults":[]}`); rec.Code != 422 {
		t.Errorf("a policy that allows admin = %d", rec.Code)
	}
}

// TestPrivs_ViewFiltersBrowseAndSearch: lists and searches show only what the
// caller may view (GRP-7387); a page counts visible rows.
func TestPrivs_ViewFiltersBrowseAndSearch(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	hr := e.admin.folder("", "hr")
	var seen, hidden []string
	for i := 0; i < 6; i++ {
		seen = append(seen, e.admin.group(app, fmt.Sprintf("team%d", i)))
		hidden = append(hidden, e.admin.group(hr, fmt.Sprintf("team%d", i)))
	}
	bob := e.user("bob", "bob")
	// view on app's groups by inheritance; stem_view on the app folder only
	e.grant("/api/groups/folders/"+app, "view", "bob", `,"applies_to":"groups","scope":"one"`)
	e.grant("/api/groups/folders/"+app, "stem_view", "bob", "")
	names := func(c grpClient, path string) []string {
		var out []string
		for _, it := range c.call("GET", path, "", 200)["items"].([]any) {
			out = append(out, it.(map[string]any)["name"].(string))
		}
		return out
	}
	got := names(bob, "/api/groups/native?limit=500")
	if len(got) != 6 {
		t.Fatalf("bob lists %v, want the six groups of app", got)
	}
	for _, n := range got {
		if !strings.HasPrefix(n, "app:") {
			t.Errorf("bob sees %s", n)
		}
	}
	// search is filtered too: "team" matches twelve groups, bob may see six
	if got := names(bob, "/api/groups/native?q=team&limit=500"); len(got) != 6 {
		t.Errorf("search shows %v", got)
	}
	// a page counts visible rows: the hr groups interleave by name but never take a slot
	page1 := names(bob, "/api/groups/native?q=team&limit=4")
	page2 := names(bob, "/api/groups/native?q=team&limit=4&offset=4")
	if len(page1) != 4 || len(page2) != 2 || slices.Contains(page1, page2[0]) {
		t.Errorf("pages = %v, %v", page1, page2)
	}
	// folders: bob sees app (and the root he has no view on is hidden)
	if got := names(bob, "/api/groups/folders?limit=500"); !slices.Equal(got, []string{"app"}) {
		t.Errorf("bob's folders = %v", got)
	}
	// a hidden group is refused by id, a hidden folder's listing is empty
	denied(t, bob, "GET", "/api/groups/"+hidden[0], "", "view")
	if n := len(bob.call("GET", "/api/groups/native?folder="+hr, "", 200)["items"].([]any)); n != 0 {
		t.Errorf("bob lists %d groups of hr", n)
	}
	// the platform roles see more: the tenant admin all, the auditor all, the viewer only if the tenant allows
	if n := len(names(e.admin, "/api/groups/native?limit=500")); n != 12 {
		t.Errorf("tenant_admin lists %d groups", n)
	}
	auditor := e.as("auditor", []auth.Role{auth.RoleAuditor}, nil)
	if n := len(names(auditor, "/api/groups/native?limit=500")); n != 12 {
		t.Errorf("auditor lists %d groups", n)
	}
	// the auditor holds read, but not groups.write
	auditor.call("GET", "/api/groups/"+hidden[0]+"/members", "", 200)
	if rec := auditor.do("PATCH", "/api/groups/"+hidden[0], `{"description":"x"}`); rec.Code != 403 {
		t.Errorf("auditor edits = %d", rec.Code)
	}
	viewer := e.as("viewer", []auth.Role{auth.RoleViewer}, nil)
	if n := len(names(viewer, "/api/groups/native?limit=500")); n != 0 {
		t.Errorf("viewer lists %d groups before the tenant allows it", n)
	}
	if err := e.f.DB.InSystem(context.Background(), "test", func(s *store.SystemTx) error {
		return s.SetTenantSettings(e.f.B.ID, `{"groups_viewer_can_view":true}`)
	}); err != nil {
		t.Fatal(err)
	}
	viewer = e.as("viewer2", []auth.Role{auth.RoleViewer}, nil)
	if n := len(names(viewer, "/api/groups/native?limit=500")); n != 12 {
		t.Errorf("viewer lists %d groups after the tenant allows it", n)
	}
	viewer.call("GET", "/api/groups/"+seen[0], "", 200)
	if rec := viewer.do("PATCH", "/api/groups/"+seen[0], `{"description":"x"}`); rec.Code != 403 {
		t.Errorf("viewer edits = %d", rec.Code)
	}
}

func TestPrivs_EffectiveRoute(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	g := e.admin.group(app, "g")
	g2 := e.admin.group(app, "ops")
	e.admin.call("POST", "/api/groups/"+g2+"/members", fmt.Sprintf(`{"identity":%d}`, e.ident("bob")), 201)
	e.grant("/api/groups/"+g, "update", "bob", "")
	e.admin.call("POST", "/api/groups/"+g+"/privileges", fmt.Sprintf(`{"privilege":"admin","holder_type":"group","group":%q}`, g2), 201)
	e.grant("/api/groups/folders/"+app, "read", "bob", `,"applies_to":"groups","scope":"sub"`)
	paths := func(c grpClient, path, priv string) []any {
		for _, p := range c.call("GET", path, "", 200)["privileges"].([]any) {
			if m := p.(map[string]any); m["privilege"] == priv {
				return m["paths"].([]any)
			}
		}
		t.Fatalf("no %s in %s", priv, path)
		return nil
	}
	bobID := e.ident("bob")
	// the admin reads another identity's privileges: update has two paths (its own row, and admin through ops)
	got := paths(e.admin, fmt.Sprintf("/api/groups/%s/privileges/effective?identity=%d", g, bobID), "update")
	if len(got) != 2 {
		t.Fatalf("update paths = %v", got)
	}
	kinds := []string{got[0].(map[string]any)["kind"].(string), got[1].(map[string]any)["kind"].(string)}
	slices.Sort(kinds)
	if !slices.Equal(kinds, []string{"group", "identity"}) {
		t.Errorf("kinds = %v", kinds)
	}
	for _, p := range got {
		if txt := p.(map[string]any)["text"].(string); !strings.Contains(txt, "holds UPDATE on `app:g`") {
			t.Errorf("text = %q", txt)
		}
	}
	// the caller's own privileges need only view
	bob := e.user("bob", "bob")
	if n := len(paths(bob, "/api/groups/"+g+"/privileges/effective", "read")); n != 2 {
		t.Errorf("bob's own read paths = %d, want 2 (admin through ops, inherited read)", n)
	}
	// but another identity's need admin: bob holds admin through ops
	bob.call("GET", fmt.Sprintf("/api/groups/%s/privileges/effective?identity=%d", g, e.ident("carol")), "", 200)
	carol := e.user("carol", "carol")
	denied(t, carol, "GET", fmt.Sprintf("/api/groups/%s/privileges/effective?identity=%d", g, bobID), "", "admin")
	if rec := e.admin.do("GET", "/api/groups/"+g+"/privileges/effective?identity=999999", ""); rec.Code != 404 {
		t.Errorf("unknown identity = %d", rec.Code)
	}
	if rec := e.admin.do("GET", "/api/groups/"+g+"/privileges/effective?identity=x", ""); rec.Code != 422 {
		t.Errorf("bad identity = %d", rec.Code)
	}
}

// TestPrivs_PlatformUserIdentityLink: group privileges come from the identity a
// platform user is linked to; linking is a tenant admin's act and is audited.
func TestPrivs_PlatformUserIdentityLink(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	g := e.admin.group(app, "g")
	e.grant("/api/groups/"+g, "admin", "bob", "")
	// dave is a platform user with no identity link
	l := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "dave@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, storetest.Now)
	dave := grpClient{client{t, l.Handler(e.srv.Handler())}}
	denied(t, dave, "GET", "/api/groups/"+g, "", "view")
	path := "/api/groups/users/" + l.UserID.String() + "/identity"
	denied2 := func(c grpClient) {
		t.Helper()
		if rec := c.do("PUT", path, fmt.Sprintf(`{"identity_id":%d}`, e.ident("bob"))); rec.Code != 403 {
			t.Errorf("link by a non-admin = %d", rec.Code)
		}
	}
	denied2(dave)
	e.admin.call("PUT", path, fmt.Sprintf(`{"identity_id":%d}`, e.ident("bob")), 200)
	dave.call("PATCH", "/api/groups/"+g, `{"description":"linked"}`, 200) // dave now holds bob's privileges
	// an identity of another tenant, an unknown user and a bad body
	if rec := e.admin.do("PUT", path, fmt.Sprintf(`{"identity_id":%d}`, e.f.A.IDs["alice"])); rec.Code != 404 {
		t.Errorf("link to A's identity = %d", rec.Code)
	}
	if rec := e.admin.do("PUT", "/api/groups/users/00000000-0000-4000-8000-00000000d00d/identity", `{"identity_id":null}`); rec.Code != 404 {
		t.Errorf("unknown user = %d", rec.Code)
	}
	if rec := e.admin.do("PUT", path, `{"identity_id":0}`); rec.Code != 422 {
		t.Errorf("identity 0 = %d", rec.Code)
	}
	// removing an existing link needs a second admin (#357), and it ends dave's sessions
	e.admin.call("PUT", path, `{"identity_id":null}`, 202)
	dave.call("PATCH", "/api/groups/"+g, `{"description":"still linked"}`, 200)
	e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil).call("PUT", path, `{"identity_id":null}`, 200)
	if rec := dave.do("PATCH", "/api/groups/"+g, `{"description":"unlinked"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("dave's session after the unlink = %d, want 401", rec.Code)
	}
	dave = grpClient{client{t, signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "dave@b.example", Roles: []auth.Role{auth.RoleOperator}},
		authtest.Phr, storetest.Now).Handler(e.srv.Handler())}}
	denied(t, dave, "PATCH", "/api/groups/"+g, `{"description":"unlinked"}`, "admin")
	err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		for action, want := range map[string]int{"groups.user.identity_linked": 1, "groups.user.identity_unlinked": 1,
			"groups.privilege.granted": 1} {
			evs, err := tx.AuditEvents(store.AuditFilter{Action: action})
			if err != nil {
				return err
			}
			if len(evs) != want {
				t.Errorf("%s audit events = %d, want %d", action, len(evs), want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestPrivs_TenantIsolation: another tenant's privilege rows, folders and
// groups look nonexistent, and privileges do not cross tenants.
func TestPrivs_TenantIsolation(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := grpClient{client{t, isolationServer(t, f, f.A.ID).Handler()}}
	b := grpClient{client{t, isolationServer(t, f, f.B.ID).Handler()}}
	af := a.folder("", "app")
	ag := a.group(af, "g")
	row := a.call("POST", "/api/groups/"+ag+"/privileges", fmt.Sprintf(`{"privilege":"view","holder_type":"identity","identity":%d}`, f.A.IDs["alice"]), 201)["id"].(string)
	for _, tc := range [][3]string{
		{"GET", "/api/groups/" + ag + "/privileges", ""},
		{"POST", "/api/groups/" + ag + "/privileges", `{"privilege":"view","holder_type":"everyone"}`},
		{"DELETE", "/api/groups/" + ag + "/privileges/" + row, ""},
		{"GET", "/api/groups/" + ag + "/privileges/effective", ""},
		{"GET", "/api/groups/folders/" + af + "/privileges", ""},
		{"POST", "/api/groups/folders/" + af + "/privileges", `{"privilege":"stem_view","holder_type":"everyone"}`},
	} {
		if rec := b.do(tc[0], tc[1], tc[2]); rec.Code != 404 {
			t.Errorf("B %s %s = %d %.100s, want 404", tc[0], tc[1], rec.Code, rec.Body.String())
		}
	}
	// B cannot name A's identity or group as a holder
	bf := b.folder("", "app")
	if rec := b.do("POST", "/api/groups/folders/"+bf+"/privileges", fmt.Sprintf(`{"privilege":"stem_view","holder_type":"identity","identity":%d}`, f.A.IDs["alice"])); rec.Code != 404 && rec.Code != 201 {
		t.Errorf("B names A's identity id = %d", rec.Code)
	}
	if rec := b.do("POST", "/api/groups/folders/"+bf+"/privileges", fmt.Sprintf(`{"privilege":"stem_view","holder_type":"group","group":%q}`, ag)); rec.Code != 404 {
		t.Errorf("B names A's group = %d", rec.Code)
	}
	if got := a.call("GET", "/api/groups/"+ag+"/privileges", "", 200)["items"].([]any); len(got) != 1 {
		t.Errorf("A's rows after B's attempts = %v", got)
	}
}

// TestPrivs_IdentityLinkFourEyes (#357): the user-identity link feeds the
// inactive-identity sign-in block and every self check, so one admin cannot
// lift a termination or a self check by changing it.
func TestPrivs_IdentityLinkFourEyes(t *testing.T) {
	e := newPrivEnv(t)
	h := e.srv.Handler()
	login := func(name string, roles []auth.Role, identity *int64) authtest.Login {
		return signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: name + "@b.example", Roles: roles, IdentityID: identity}, authtest.Phr, storetest.Now)
	}
	put := func(by authtest.Login, user authtest.Login, body string) (int, string) {
		t.Helper()
		rec := corrDo(h, by, "PUT", "/api/groups/users/"+user.UserID.String()+"/identity", body)
		return rec.Code, rec.Body.String()
	}
	want := func(name string, code int, body string, status int, errCode string) {
		t.Helper()
		if code != status || (errCode != "" && !strings.Contains(body, `"`+errCode+`"`)) {
			t.Errorf("%s: %d %s, want %d %s", name, code, body, status, errCode)
		}
	}
	linkOf := func(user authtest.Login) *int64 {
		t.Helper()
		var id *int64
		if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error {
			u, err := c.PlatformUser(user.UserID)
			if err == nil {
				id = u.IdentityID
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	setStatus := func(identity int64, status string) {
		t.Helper()
		if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error {
			return c.SetIdentityStatus(identity, status)
		}); err != nil {
			t.Fatal(err)
		}
	}
	admins := []auth.Role{auth.RoleTenantAdmin}
	bob, carol, dave := e.ident("bob"), e.ident("carol"), e.ident("dave")
	a1 := login("a1", admins, &bob)
	a2 := login("a2", admins, nil)

	// nobody changes their own link, even to drop it before approving their own request
	code, body := put(a1, a1, `{"identity_id":null}`)
	want("own link", code, body, 403, "self_link_not_allowed")
	if l := linkOf(a1); l == nil || *l != bob {
		t.Fatalf("a1's link changed: %v", l)
	}

	// a user is linked only to an active identity
	setStatus(dave, "terminated")
	fresh := login("fresh", []auth.Role{auth.RoleOperator}, nil)
	code, body = put(a1, fresh, fmt.Sprintf(`{"identity_id":%d}`, dave))
	want("link to a terminated identity", code, body, 409, "identity_not_active")

	// a terminated or disabled person's link stays, so sign-in stays blocked
	for _, st := range []string{"terminated", "disabled"} {
		setStatus(carol, "active")
		pat := login("pat-"+st, []auth.Role{auth.RolePolicyAdmin}, &carol)
		setStatus(carol, st)
		for _, by := range []authtest.Login{a1, a2} {
			code, body = put(by, pat, `{"identity_id":null}`)
			want(st+": unlink", code, body, 409, "identity_inactive")
			code, body = put(by, pat, fmt.Sprintf(`{"identity_id":%d}`, bob))
			want(st+": relink", code, body, 409, "identity_inactive")
		}
		if l := linkOf(pat); l == nil || *l != carol {
			t.Errorf("%s: the link changed: %v", st, l)
		}
		if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error {
			u, err := c.PlatformUser(pat.UserID)
			if err != nil {
				return err
			}
			if off, err := auth.IdentityInactive(c, u); err != nil || !off {
				t.Errorf("%s: IdentityInactive = %v, %v", st, off, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	setStatus(carol, "active")

	// changing an existing link takes two admins
	vic := login("vic", []auth.Role{auth.RoleOperator}, &bob)
	code, body = put(a1, vic, `{"identity_id":null}`)
	want("first admin's unlink", code, body, 202, "pending_second_admin")
	code, body = put(a1, vic, `{"identity_id":null}`)
	want("same admin again", code, body, 403, "four_eyes_required")
	if l := linkOf(vic); l == nil || *l != bob {
		t.Fatalf("one admin changed the link: %v", l)
	}
	if rec := corrDo(h, vic, "GET", "/api/connectors", ""); rec.Code != 200 {
		t.Fatalf("vic's session before the change: %d", rec.Code)
	}
	// a different change by the second admin replaces the request; it is theirs now
	code, body = put(a2, vic, fmt.Sprintf(`{"identity_id":%d}`, carol))
	want("second admin's different change", code, body, 202, "pending_second_admin")
	code, body = put(a2, vic, fmt.Sprintf(`{"identity_id":%d}`, carol))
	want("second admin again", code, body, 403, "four_eyes_required")
	// the first admin confirms it
	code, body = put(a1, vic, fmt.Sprintf(`{"identity_id":%d}`, carol))
	want("confirmed", code, body, 200, "")
	if l := linkOf(vic); l == nil || *l != carol {
		t.Fatalf("the confirmed change was not applied: %v", l)
	}
	if rec := corrDo(h, vic, "GET", "/api/connectors", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("vic's session after the change: %d, want 401", rec.Code)
	}
	// the request was consumed: the next change starts over
	code, body = put(a2, vic, `{"identity_id":null}`)
	want("next change", code, body, 202, "pending_second_admin")

	got := auditActions(t, e.f, e.f.B.ID)
	if got["groups.user.identity_change_requested"] != 3 || got["groups.user.identity_linked"] != 1 || got["groups.user.identity_unlinked"] != 0 {
		t.Errorf("audit actions %v", got)
	}
}
