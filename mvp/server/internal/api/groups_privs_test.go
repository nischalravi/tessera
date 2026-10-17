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
		// another identity's privileges need admin on the object, not view
		{"GET", "/api/groups/{id}/privileges/effective", "/api/groups/" + g + "/privileges/effective?identity=" + fmt.Sprint(e.ident("bob")), "", "admin"},
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
		{"GET", "/api/openapi/groups.json", "", "", ""}}
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
	for _, p := range []string{"/api/groups/folders", "/api/groups/native"} {
		if items := nobody.call("GET", p, "", 200)["items"].([]any); len(items) != 0 {
			t.Errorf("%s shows %d items to a user without view", p, len(items))
		}
	}
	// a user without the route's permission: viewer holds groups.read only
	viewer := e.as("viewer", []auth.Role{auth.RoleViewer}, nil)
	for _, c := range cases {
		if c.method == "GET" && !strings.Contains(c.pattern, "pit") && !strings.Contains(c.pattern, "engine") &&
			!strings.Contains(c.pattern, "settings") {
			continue
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
	e.admin.call("PUT", path, `{"identity_id":null}`, 200)
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
