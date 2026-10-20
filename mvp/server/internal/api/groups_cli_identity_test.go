package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// A DPoP-token principal (tessera-cli) gets the identity and Groups viewer view
// of its user, as a browser session does (issue #389); the token's scopes still
// cap what it may do, and an unlinked user gets nothing extra.
func TestGroupsPrivilegesThroughDPoPToken(t *testing.T) {
	e := newOAuthEnv(t)
	admin := grpClient{client{t, signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "root@b.example",
		Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now).Handler(e.h)}}
	pat := e.f.B.IDs["bob"]
	folder := admin.folder("", "cli")
	admin.call("POST", "/api/groups/folders/"+folder+"/privileges",
		fmt.Sprintf(`{"privilege":"stem_admin","holder_type":"identity","identity":%d}`, pat), 201)
	admin.folder("", "other") // a folder Pat holds nothing on

	list := func(c cliTokens) []string {
		rec := e.call(c, "GET", "/api/groups/folders?q=&limit=500", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("list folders: %d %s", rec.Code, rec.Body)
		}
		var out []string
		for _, it := range body(rec)["items"].([]any) {
			out = append(out, it.(map[string]any)["name"].(string))
		}
		return out
	}
	create := `{"folder":"` + folder + `","extension":"made"}`
	linked := authtest.User{Email: "pat@b.example", Roles: []auth.Role{auth.RoleOperator}, IdentityID: &pat}

	t.Run("a linked user sees and plans in the folder", func(t *testing.T) {
		c := e.signInCLIUser("tenant-b", linked, "tessera:read tessera:write")
		if got := list(c); len(got) != 1 || got[0] != "cli" {
			t.Errorf("folders = %v, want [cli]", got)
		}
		plan := policyReq(map[string]string{"groups/cli/p.cedar": policyCedar("cli:p", `principal has department && principal.department == "x"`, "")}, "", "", false)
		if rec := e.call(c, "POST", "/api/groups/policy/diff", plan); rec.Code != http.StatusOK {
			t.Errorf("plan in the folder: %d %s", rec.Code, rec.Body)
		}
		if rec := e.call(c, "POST", "/api/groups", create); rec.Code != http.StatusCreated {
			t.Errorf("create in the folder: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("the scope still caps what the token may do", func(t *testing.T) {
		c := e.signInCLIUser("tenant-b", linked, "tessera:read")
		if got := list(c); len(got) != 1 || got[0] != "cli" {
			t.Errorf("folders = %v, want [cli]", got)
		}
		rec := e.call(c, "POST", "/api/groups", `{"folder":"`+folder+`","extension":"nope"}`)
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "privilege_required") {
			t.Errorf("write with a read-only scope: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("an unlinked user sees nothing", func(t *testing.T) {
		c := e.signInCLIUser("tenant-b", authtest.User{Email: "nolink@b.example", Roles: []auth.Role{auth.RoleOperator}}, "tessera:read tessera:write")
		if got := list(c); len(got) != 0 {
			t.Errorf("folders = %v, want none", got)
		}
		if rec := e.call(c, "POST", "/api/groups", create); rec.Code != http.StatusForbidden {
			t.Errorf("create without an identity: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("a deactivated identity gets no session", func(t *testing.T) {
		c := e.signInCLIUser("tenant-b", linked, "tessera:read tessera:write")
		if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
			return tx.SetIdentityStatus(pat, "inactive")
		}); err != nil {
			t.Fatal(err)
		}
		if rec := e.call(c, "GET", "/api/groups/folders?q=&limit=500", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("deactivated identity: %d %s", rec.Code, rec.Body)
		}
	})
}
