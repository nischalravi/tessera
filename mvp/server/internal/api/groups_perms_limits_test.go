package api

import (
	"net/http"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// A limit that cannot compile is refused on write (422 invalid_limit) and leaves
// nothing behind, on create and on a values change.
func TestGroupsPermissionsAPI_JunkLimitRefused(t *testing.T) {
	c, _ := newGrp(t)
	app := c.folder("", "app")
	role := c.group(app, "payroll")
	perm := c.attrDef(app, "perms", `"attr_type":"perm","multi_assign":true,"assign_to":["group"]`)
	ledger := c.attrName(perm, "ledger")
	c.call("POST", "/api/groups/attr-defs/"+perm+"/actions", `{"name":"read"}`, 201)
	lim := c.attrDef(app, "limits", `"attr_type":"limit","value_type":"string","multi_valued":true,"assign_to":["assignment"]`)
	ip, bogus := c.attrName(lim, "ipOnNetwork"), c.attrName(lim, "bogus")
	granted := c.call("POST", "/api/groups/attr-assignments", `{"name":"`+ledger+`","action":"read","owner_type":"group","owner":"`+role+`","disallowed":true}`, 201)["id"].(string)

	on := `"owner_type":"assignment","owner":"` + granted + `"`
	if got := c.call("POST", "/api/groups/attr-assignments", `{"name":"`+bogus+`",`+on+`,"values":["x"]}`, 422); got["code"] != "invalid_limit" && got["error"] != "invalid_limit" {
		t.Errorf("unknown limit name: %v", got)
	}
	c.call("POST", "/api/groups/attr-assignments", `{"name":"`+ip+`",`+on+`,"values":["not-a-cidr"]}`, 422)
	if rp := c.call("GET", "/api/groups/"+role+"/permissions", "", 200)["permissions"].([]any); len(rp) != 1 || len(rp[0].(map[string]any)["limits"].([]any)) != 0 {
		t.Errorf("a refused limit was stored: %v", rp)
	}
	good := c.call("POST", "/api/groups/attr-assignments", `{"name":"`+ip+`",`+on+`,"values":["10.0.0.0/8"]}`, 201)["id"].(string)
	c.call("PUT", "/api/groups/attr-assignments/"+good+"/values", `{"values":["nope"]}`, 422)
	c.call("PUT", "/api/groups/attr-assignments/"+good+"/values", `{"values":["192.168.0.0/16"]}`, 200)
}

// Importing permissions is for tenant_admin: a role without the route's
// permission gets 403 (the handler also refuses a caller that is not tenant_admin).
func TestGroupsPermissionsAPI_ImportNeedsTenantAdmin(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	body := `{"permissions":[]}`
	for _, role := range []auth.Role{auth.RolePolicyAdmin, auth.RoleOperator, auth.RoleAuditor} {
		u := signIn(t, f.DB, f.B.ID, authtest.User{Email: string(role) + "@b.example", Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
		if rec := serve(h, authed(u, "POST", "/api/groups/permissions/import", body)); rec.Code != http.StatusForbidden {
			t.Errorf("%s import = %d, want 403: %s", role, rec.Code, rec.Body.String())
		}
	}
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	if rec := serve(h, authed(admin, "POST", "/api/groups/permissions/import", body)); rec.Code != http.StatusOK {
		t.Errorf("tenant_admin import = %d: %s", rec.Code, rec.Body.String())
	}
}
