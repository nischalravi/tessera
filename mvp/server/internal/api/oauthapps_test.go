package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps/oauthfake"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// newOAuthRig is a server with tenant A connected to a fake Google and a fake
// Salesforce, holding a Drift app with users at each.
func newOAuthRig(t *testing.T) (*storetest.Fixture, *Server, *oauthfake.Google, *oauthfake.Salesforce) {
	t.Helper()
	f := storetest.TwoTenants(t)
	srv := containServer(t, f)
	g, sf := &oauthfake.Google{}, &oauthfake.Salesforce{}
	gs, ss := httptest.NewServer(g), httptest.NewServer(sf)
	t.Cleanup(gs.Close)
	t.Cleanup(ss.Close)
	g.Users = []*oauthfake.GoogleUser{
		{ID: "g1", Email: "alice@a.example", Tokens: []oauthfake.GoogleToken{{ClientID: "drift.google", DisplayText: "Salesloft Drift", Scopes: []string{"https://mail.google.com/"}}}},
		{ID: "g2", Email: "bob@a.example", Tokens: []oauthfake.GoogleToken{{ClientID: "drift.google", DisplayText: "Salesloft Drift", Scopes: []string{"https://mail.google.com/"}},
			{ClientID: "cal.google", DisplayText: "Calendar", Scopes: []string{"openid"}}}},
	}
	sf.Tokens = []*oauthfake.SalesforceToken{{ID: oauthfake.ID("00Xa", 1), AppName: "Salesloft Drift", AppID: oauthfake.ID("0Aa", 1),
		UserID: "005A", Username: "alice@a.example", Scopes: "api refresh_token"}}
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		for name, url := range map[string]string{"google": gs.URL, "salesforce": ss.URL} {
			id := store.NewID()
			if err := c.InsertConnection(&store.Connection{ID: id, Name: name, ConnectorType: name, System: name, Role: "account_source",
				CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
				return err
			}
			if err := srv.containment.PutCredential(c, id, containment.CredentialInput{Token: oauthfake.Token, BaseURL: url}, "admin", storetest.Now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, srv, g, sf
}

func oaDecode[T any](t *testing.T, body string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return v
}

func TestOAuthAppsAPI(t *testing.T) {
	f, srv, google, sf := newOAuthRig(t)
	h := srv.Handler()
	user := func(email string, role auth.Role) authtest.Login {
		return signIn(t, f.DB, f.A.ID, authtest.User{Email: email, Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
	}
	pa1, pa2 := user("pa1@a.example", auth.RolePolicyAdmin), user("pa2@a.example", auth.RolePolicyAdmin)
	ta, viewer, auditor := user("ta@a.example", auth.RoleTenantAdmin), user("v@a.example", auth.RoleViewer), user("au@a.example", auth.RoleAuditor)
	stale := signIn(t, f.DB, f.A.ID, authtest.User{Email: "stale@a.example", Roles: []auth.Role{auth.RolePolicyAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	paB := signIn(t, f.DB, f.B.ID, authtest.User{Email: "pa@b.example", Roles: []auth.Role{auth.RolePolicyAdmin}}, authtest.Phr, storetest.Now)

	// nothing synced yet
	rec := corrDo(h, viewer, "GET", "/api/oauth-apps", "")
	if rec.Code != 200 || len(oaDecode[struct{ Apps []oauthAppView }](t, rec.Body.String()).Apps) != 0 {
		t.Fatalf("empty list: %d %s", rec.Code, rec.Body)
	}

	// sync: manage permission only (a tenant admin may, a viewer and an auditor may not)
	for _, l := range []authtest.Login{viewer, auditor} {
		if rec = corrDo(h, l, "POST", "/api/oauth-apps/sync", ""); rec.Code != 403 {
			t.Errorf("sync as viewer or auditor: %d", rec.Code)
		}
	}
	if rec = corrDo(h, ta, "POST", "/api/oauth-apps/sync", `{"provider":"nope"}`); rec.Code != 422 {
		t.Errorf("bad provider: %d %s", rec.Code, rec.Body)
	}
	rec = corrDo(h, ta, "POST", "/api/oauth-apps/sync", "")
	rep := oaDecode[oauthapps.SyncReport](t, rec.Body.String())
	if rec.Code != 200 || len(rep.Providers) != 4 || rep.Providers[0].Status != "ok" || rep.Providers[2].Status != "ok" ||
		rep.Providers[1].Status != "skipped" || rep.Providers[3].Status != "skipped" {
		t.Fatalf("sync: %d %s", rec.Code, rec.Body)
	}

	// list, filters and validation
	type listOut struct {
		Apps    []oauthAppView
		Summary map[string]int
		Sync    []map[string]any
	}
	rec = corrDo(h, viewer, "GET", "/api/oauth-apps", "")
	l := oaDecode[listOut](t, rec.Body.String())
	if rec.Code != 200 || len(l.Apps) != 3 || l.Summary["apps"] != 3 || l.Summary["high_risk"] != 2 || len(l.Sync) != 2 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if l.Apps[0].RiskScore < l.Apps[len(l.Apps)-1].RiskScore {
		t.Error("the list is not highest risk first")
	}
	for q, want := range map[string]int{"provider=google": 2, "severity=critical": 1, "severity=high": 1, "vendor=salesloft%20drift": 2,
		"q=calendar": 1, "flag=unverified": 1, "status=revoked": 0, "status=all": 3} {
		rec = corrDo(h, viewer, "GET", "/api/oauth-apps?"+q, "")
		if got := len(oaDecode[listOut](t, rec.Body.String()).Apps); rec.Code != 200 || got != want {
			t.Errorf("?%s: %d apps (%d), want %d: %s", q, got, rec.Code, want, rec.Body)
		}
	}
	for _, q := range []string{"provider=okta", "severity=bad", "status=x", "flag=y", "unused_days=0", "unused_days=x"} {
		if rec = corrDo(h, viewer, "GET", "/api/oauth-apps?"+q, ""); rec.Code != 422 {
			t.Errorf("?%s: %d", q, rec.Code)
		}
	}
	var drift, sfDrift oauthAppView
	for _, a := range l.Apps {
		switch {
		case a.ClientID == "drift.google":
			drift = a
		case a.Provider == "salesforce":
			sfDrift = a
		}
	}

	// detail with scope risk
	rec = corrDo(h, viewer, "GET", "/api/oauth-apps/"+drift.ID, "")
	d := oaDecode[struct {
		App    oauthAppView
		Grants []oauthGrantView
	}](t, rec.Body.String())
	if rec.Code != 200 || len(d.Grants) != 2 || d.Grants[0].Scopes[0].Severity != "critical" || d.App.Grants != 2 || d.App.Users != 2 {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, viewer, "GET", "/api/oauth-apps/not-an-id", ""); rec.Code != 404 {
		t.Errorf("bad id: %d", rec.Code)
	}

	// tenant isolation: B sees nothing of A's and cannot reach it by id
	rec = corrDo(h, paB, "GET", "/api/oauth-apps?status=all", "")
	if rec.Code != 200 || len(oaDecode[listOut](t, rec.Body.String()).Apps) != 0 {
		t.Errorf("B's list: %d %s", rec.Code, rec.Body)
	}
	for _, c := range [][3]string{{"GET", "/api/oauth-apps/" + drift.ID, ""}, {"PUT", "/api/oauth-apps/" + drift.ID + "/owner", `{"identity_id":null}`},
		{"POST", "/api/oauth-apps/" + drift.ID + "/revoke", `{"reason":"cross tenant attempt"}`},
		{"POST", "/api/oauth-apps/" + drift.ID + "/grants/" + d.Grants[0].ID + "/revoke", `{"reason":"cross tenant attempt"}`}} {
		if rec = corrDo(h, paB, c[0], c[1], c[2]); rec.Code != 404 {
			t.Errorf("B %s %s: %d %s", c[0], c[1], rec.Code, rec.Body)
		}
	}
	if len(google.Users[0].Tokens) != 1 {
		t.Error("B's attempt reached A's provider")
	}

	// owner
	if rec = corrDo(h, viewer, "PUT", "/api/oauth-apps/"+drift.ID+"/owner", `{"identity_id":null}`); rec.Code != 403 {
		t.Errorf("viewer sets owner: %d", rec.Code)
	}
	if rec = corrDo(h, ta, "PUT", "/api/oauth-apps/"+drift.ID+"/owner", `{"identity_id":999999}`); rec.Code != 422 {
		t.Errorf("unknown identity: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, ta, "PUT", "/api/oauth-apps/"+drift.ID+"/owner", `{"identity_id":`+itoa(f.A.IDs["alice"])+`}`); rec.Code != 200 {
		t.Errorf("set owner: %d %s", rec.Code, rec.Body)
	}
	rec = corrDo(h, viewer, "GET", "/api/oauth-apps/"+drift.ID, "")
	if o := oaDecode[struct{ App oauthAppView }](t, rec.Body.String()).App.Owner; o == nil || o.ID != f.A.IDs["alice"] {
		t.Errorf("owner = %+v", o)
	}

	// revoke: permission, step-up, reason, tenant-admin lacks oauthapps.revoke
	path := "/api/oauth-apps/" + drift.ID + "/revoke"
	body := `{"reason":"vendor breach, rotate everything"}`
	if rec = corrDo(h, ta, "POST", path, body); rec.Code != 403 {
		t.Errorf("tenant admin revoke: %d", rec.Code)
	}
	if rec = corrDo(h, stale, "POST", path, body); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale revoke: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, pa1, "POST", path, `{"reason":"short"}`); rec.Code != 422 {
		t.Errorf("short reason: %d", rec.Code)
	}

	// four-eyes: two grants of a critical app need a second admin
	rec = corrDo(h, pa1, "POST", path, body)
	if rec.Code != 202 || !strings.Contains(rec.Body.String(), "pending_second_admin") || google.Deleted() != 0 {
		t.Fatalf("first request: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, pa1, "POST", path, body); rec.Code != 403 || !strings.Contains(rec.Body.String(), "four_eyes_required") || google.Deleted() != 0 {
		t.Errorf("same admin: %d %s", rec.Code, rec.Body)
	}
	rec = corrDo(h, viewer, "GET", "/api/oauth-apps", "")
	if pend := oaDecode[struct {
		Pending []map[string]any `json:"pending_requests"`
	}](t, rec.Body.String()).Pending; len(pend) != 1 {
		t.Errorf("pending requests: %s", rec.Body)
	}
	rec = corrDo(h, pa2, "POST", path, body)
	out := oaDecode[oauthapps.RevokeReport](t, rec.Body.String())
	if rec.Code != 200 || !out.OK || out.Revoked != 2 || google.Deleted() != 2 {
		t.Fatalf("second admin: %d %s", rec.Code, rec.Body)
	}
	if got := len(google.Users[0].Tokens) + len(google.Users[1].Tokens); got != 1 {
		t.Errorf("tokens left at google: %d", got)
	}
	if rec = corrDo(h, pa2, "POST", path, body); rec.Code != 409 {
		t.Errorf("revoke again: %d", rec.Code)
	}

	// a single grant needs no second admin; a dry run changes nothing
	sfPath := "/api/oauth-apps/" + sfDrift.ID
	sd := oaDecode[struct{ Grants []oauthGrantView }](t, corrDo(h, viewer, "GET", sfPath, "").Body.String())
	rec = corrDo(h, pa1, "POST", "/api/oauth-apps/revoke-vendor", `{"vendor":"salesloft drift","reason":"vendor breach drill","dry_run":true}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"grants":1`) || len(sf.Tokens) != 1 {
		t.Errorf("dry run: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, pa1, "POST", sfPath+"/grants/"+sd.Grants[0].ID+"/revoke", `{"reason":"user reported a phish"}`); rec.Code != 200 || len(sf.Tokens) != 0 {
		t.Errorf("single grant: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, pa1, "POST", "/api/oauth-apps/revoke-vendor", `{"vendor":"  ","reason":"vendor breach drill"}`); rec.Code != 422 {
		t.Errorf("blank vendor: %d", rec.Code)
	}
	if rec = corrDo(h, pa1, "POST", "/api/oauth-apps/revoke-vendor", `{"vendor":"nobody","reason":"vendor breach drill"}`); rec.Code != 404 {
		t.Errorf("unknown vendor: %d", rec.Code)
	}

	// a revoke the provider refuses answers 502 with the report, and the grant stays visible
	google.Refuse.Store(true)
	cal := ""
	for _, a := range oaDecode[listOut](t, corrDo(h, viewer, "GET", "/api/oauth-apps", "").Body.String()).Apps {
		if a.ClientID == "cal.google" {
			cal = a.ID
		}
	}
	rec = corrDo(h, pa1, "POST", "/api/oauth-apps/"+cal+"/revoke", `{"reason":"unused calendar app"}`)
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), "oauth_revoke_incomplete") || !strings.Contains(rec.Body.String(), `"failed":1`) {
		t.Errorf("refused: %d %s", rec.Code, rec.Body)
	}
	rec = corrDo(h, viewer, "GET", "/api/oauth-apps/"+cal, "")
	if g := oaDecode[struct{ Grants []oauthGrantView }](t, rec.Body.String()).Grants; g[0].Status != store.OAuthRevokeFailed || g[0].RevokeError == "" {
		t.Errorf("grant after refusal: %+v", g[0])
	}

	// the ledger holds the sync, the request, the approval and the revokes, and no token
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		log, err := c.AuditLog(-1)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, e := range log {
			raw, _ := json.Marshal(e)
			if strings.Contains(string(raw), oauthfake.Token) {
				t.Errorf("audit event %s carries a provider token", e.Action)
			}
			seen[e.Action] = true
		}
		for _, a := range []string{"oauthapps.synced", "oauthapps.revoke_requested", "oauthapps.revoke_approved", "oauthapps.revoke_started",
			"oauthapps.revoked", "oauthapps.owner_set"} {
			if !seen[a] {
				t.Errorf("no %s event", a)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The queue job refreshes each tenant that has credentials and leaves no run
// for one that has none.
func TestOAuthSyncQueueJob(t *testing.T) {
	f, srv, _, _ := newOAuthRig(t)
	ctx := context.Background()
	res, err := srv.queueOAuthSync(ctx, queue.Job{Tenant: f.A.ID})
	if err != nil || res == nil {
		t.Fatalf("A: %v %v", res, err)
	}
	if res, err = srv.queueOAuthSync(ctx, queue.Job{Tenant: f.B.ID}); err != nil || res != nil {
		t.Errorf("B has no credentials: %v %v", res, err)
	}
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if n, err := c.CountOAuthApps(); err != nil || n != 3 {
			t.Errorf("apps = %d, %v", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range jobs.Kinds {
		found = found || k == jobs.OAuthSync
	}
	if !found {
		t.Error("oauth_sync is not in jobs.Kinds")
	}
}
