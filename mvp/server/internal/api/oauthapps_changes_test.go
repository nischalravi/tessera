package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps/oauthfake"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Detected changes of OAuth apps and their containment over the API (issue #474).
func TestOAuthAppChangesAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := containServer(t, f)
	entra := &oauthfake.Entra{}
	es := httptest.NewServer(entra)
	t.Cleanup(es.Close)
	entra.BaseURL = es.URL
	entra.SPs = []*oauthfake.EntraSP{{ID: "sp-graph", AppID: "graph", Name: "Graph", Roles: map[string]string{"role-dir": "Directory.ReadWrite.All"}},
		{ID: "sp-gain", AppID: "app-gainsight", Name: "Gainsight"}}
	entra.Delegated = []*oauthfake.EntraDelegated{{ID: "d1", ClientSP: "sp-gain", ConsentType: "AllPrincipals", Scope: "User.Read"}}
	entra.Apps = []*oauthfake.EntraApplication{{ID: "obj-gain", AppID: "app-gainsight",
		Secrets: []oauthfake.EntraKey{{ID: "key-1", Name: "prod"}}}}
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		id := store.NewID()
		if err := c.InsertConnection(&store.Connection{ID: id, Name: "entra", ConnectorType: "entra", System: "entra", Role: "account_source",
			CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		return srv.containment.PutCredential(c, id, containment.CredentialInput{Token: oauthfake.Token, BaseURL: es.URL}, "admin", storetest.Now)
	})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	user := func(email string, role auth.Role) authtest.Login {
		return signIn(t, f.DB, f.A.ID, authtest.User{Email: email, Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
	}
	pa, ta, viewer := user("pa@a.example", auth.RolePolicyAdmin), user("ta@a.example", auth.RoleTenantAdmin), user("v@a.example", auth.RoleViewer)
	paB := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)

	type listOut struct {
		Apps    []oauthAppView
		Changes []oauthChangeView
		Summary map[string]int
	}
	if rec := corrDo(h, ta, "POST", "/api/oauth-apps/sync", `{"provider":"entra"}`); rec.Code != 200 {
		t.Fatalf("sync: %d %s", rec.Code, rec.Body)
	}
	if l := oaDecode[listOut](t, corrDo(h, viewer, "GET", "/api/oauth-apps", "").Body.String()); len(l.Changes) != 0 || l.Summary["open_changes"] != 0 {
		t.Fatalf("the baseline sync reported changes: %+v", l.Changes)
	}

	// Storm-0940: a secret and a permission are added to the app
	entra.With(func() {
		entra.Apps[0].Secrets = append(entra.Apps[0].Secrets, oauthfake.EntraKey{ID: "key-2", Name: "backdoor"})
		entra.Roles = append(entra.Roles, &oauthfake.EntraRole{ID: "ra1", ClientSP: "sp-gain", Resource: "sp-graph", RoleID: "role-dir"})
	})
	if rec := corrDo(h, ta, "POST", "/api/oauth-apps/sync", `{"provider":"entra"}`); rec.Code != 200 {
		t.Fatalf("sync: %d %s", rec.Code, rec.Body)
	}
	rec := corrDo(h, viewer, "GET", "/api/oauth-apps", "")
	l := oaDecode[listOut](t, rec.Body.String())
	if rec.Code != 200 || len(l.Changes) != 2 || l.Summary["open_changes"] != 2 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	var credChange, grantChange oauthChangeView
	for _, c := range l.Changes {
		if c.CredentialID != "" {
			credChange = c
		}
		if c.GrantID != "" {
			grantChange = c
		}
	}
	if credChange.Kind != "credential_added" || !strings.Contains(credChange.Summary, "backdoor") || credChange.App != "Gainsight" ||
		grantChange.Kind != "permission_granted" {
		t.Fatalf("changes: %+v", l.Changes)
	}
	appID := credChange.AppID
	rec = corrDo(h, viewer, "GET", "/api/oauth-apps/"+appID, "")
	detail := oaDecode[struct {
		Credentials []oauthCredentialView
		Changes     []oauthChangeView
	}](t, rec.Body.String())
	if rec.Code != 200 || len(detail.Credentials) != 2 || len(detail.Changes) != 2 {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body)
	}
	// the secret's value is never part of a response
	if strings.Contains(rec.Body.String(), oauthfake.Token) {
		t.Error("the response carries the provider token")
	}

	rm := "/api/oauth-apps/" + appID + "/credentials/" + credChange.CredentialID + "/remove"
	body := `{"reason":"Storm-0940 response, secret was not ours"}`
	if rec = corrDo(h, ta, "POST", rm, body); rec.Code != 403 { // a tenant admin may not revoke (oauthapps.revoke is policy admin)
		t.Errorf("remove as tenant admin: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, pa, "POST", rm, `{"reason":"short"}`); rec.Code != 422 && rec.Code != 400 {
		t.Errorf("short reason: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, paB, "POST", rm, body); rec.Code != 404 {
		t.Errorf("another tenant: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, pa, "POST", "/api/oauth-apps/"+appID+"/credentials/nope/remove", body); rec.Code != 404 {
		t.Errorf("unknown credential: %d %s", rec.Code, rec.Body)
	}
	entra.Refuse.Store(true)
	if rec = corrDo(h, pa, "POST", rm, body); rec.Code != 502 || !strings.Contains(rec.Body.String(), "oauth_credential_failed") {
		t.Errorf("provider refuses: %d %s", rec.Code, rec.Body)
	}
	entra.Refuse.Store(false)
	rec = corrDo(h, pa, "POST", rm, body)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"outcome":"removed"`) {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	if len(entra.Apps[0].Secrets) != 1 {
		t.Errorf("provider secrets = %+v", entra.Apps[0].Secrets)
	}
	if rec = corrDo(h, pa, "POST", rm, body); rec.Code != 404 {
		t.Errorf("remove twice: %d %s", rec.Code, rec.Body)
	}

	// the permission: revoke it with the grant revoke; the change closes with it
	rec = corrDo(h, pa, "POST", "/api/oauth-apps/"+appID+"/grants/"+grantChange.GrantID+"/revoke", `{"reason":"permission was not ours"}`)
	if rec.Code != 200 {
		t.Fatalf("revoke grant: %d %s", rec.Code, rec.Body)
	}
	if l = oaDecode[listOut](t, corrDo(h, viewer, "GET", "/api/oauth-apps", "").Body.String()); len(l.Changes) != 0 {
		t.Errorf("open changes after containment = %+v", l.Changes)
	}

	// an owner change is acknowledged by a person
	entra.With(func() {
		entra.Apps[0].Owners = []oauthfake.EntraOwner{{ID: "u-mallory", UPN: "mallory@evil.example"}}
	})
	corrDo(h, ta, "POST", "/api/oauth-apps/sync", `{"provider":"entra"}`)
	l = oaDecode[listOut](t, corrDo(h, viewer, "GET", "/api/oauth-apps", "").Body.String())
	if len(l.Changes) != 1 || l.Changes[0].Kind != "owner_changed" {
		t.Fatalf("owner change: %+v", l.Changes)
	}
	res := "/api/oauth-apps/" + appID + "/changes/" + l.Changes[0].ID + "/resolve"
	if rec = corrDo(h, viewer, "POST", res, `{"note":"ok"}`); rec.Code != 403 {
		t.Errorf("resolve as viewer: %d", rec.Code)
	}
	if rec = corrDo(h, paB, "POST", res, `{"note":"ok"}`); rec.Code != 404 {
		t.Errorf("resolve in another tenant: %d", rec.Code)
	}
	if rec = corrDo(h, ta, "POST", res, `{"note":"`+strings.Repeat("x", 501)+`"}`); rec.Code != 422 && rec.Code != 400 {
		t.Errorf("long note: %d", rec.Code)
	}
	if rec = corrDo(h, ta, "POST", res, `{"note":"new owner is our admin"}`); rec.Code != 200 {
		t.Fatalf("resolve: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, ta, "POST", res, `{}`); rec.Code != 409 {
		t.Errorf("resolve twice: %d", rec.Code)
	}
	if l = oaDecode[listOut](t, corrDo(h, viewer, "GET", "/api/oauth-apps", "").Body.String()); len(l.Changes) != 0 {
		t.Errorf("open changes = %+v", l.Changes)
	}
}
