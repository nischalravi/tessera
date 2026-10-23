package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/ghtokens"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps/oauthfake"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// GitHub and CI token inventory (issue #476): permissions, sync, list, tenant
// scoping, and no token material in a response.
func TestGitHubTokensAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := containServer(t, f)
	gh := &oauthfake.GitHub{Org: "acme",
		Credentials: []*oauthfake.GitHubCredential{{ID: 21, Login: "octocat", Type: "OAuth app token", Title: "GitHub CLI",
			Authorized: "2026-05-01T00:00:00Z", Scopes: []string{"repo", "workflow"}}},
		FineGrained: []*oauthfake.GitHubPAT{{ID: 31, Owner: "octocat", Name: "release-bot", Permissions: map[string]string{"contents": "write"},
			Granted: "2026-09-20T00:00:00Z"}},
		Secrets: []*oauthfake.GitHubSecret{{Name: "NPM_TOKEN", Created: "2025-11-01T00:00:00Z", Updated: "2025-11-01T00:00:00Z", Visibility: "all"}}}
	ghs := httptest.NewServer(gh)
	t.Cleanup(ghs.Close)
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		id := store.NewID()
		if err := c.InsertConnection(&store.Connection{ID: id, Name: "github", ConnectorType: "github", System: "github", Role: "account_source",
			CreatedAt: storetest.Now, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		return srv.containment.PutCredential(c, id, containment.CredentialInput{Token: oauthfake.Token, BaseURL: ghs.URL, Org: "acme"}, "admin", storetest.Now)
	})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	user := func(tenant *storetest.Tenant, email string, role auth.Role) authtest.Login {
		return signIn(t, f.DB, tenant.ID, authtest.User{Email: email, Roles: []auth.Role{role}}, authtest.Phr, storetest.Now)
	}
	ta, viewer, auditor := user(&f.A, "ta@a.example", auth.RoleTenantAdmin), user(&f.A, "v@a.example", auth.RoleViewer), user(&f.A, "au@a.example", auth.RoleAuditor)
	viewerB := user(&f.B, "v@b.example", auth.RoleViewer)

	rec := corrDo(h, viewer, "GET", "/api/github-tokens", "")
	if out := oaDecode[struct{ Tokens []ghtokens.View }](t, rec.Body.String()); rec.Code != 200 || len(out.Tokens) != 0 {
		t.Fatalf("empty list: %d %s", rec.Code, rec.Body)
	}
	for _, l := range []authtest.Login{viewer, auditor} {
		if rec = corrDo(h, l, "POST", "/api/github-tokens/sync", ""); rec.Code != 403 {
			t.Errorf("sync as viewer or auditor: %d", rec.Code)
		}
	}
	rec = corrDo(h, ta, "POST", "/api/github-tokens/sync", "")
	if rep := oaDecode[ghtokens.Report](t, rec.Body.String()); rec.Code != 200 || rep.Status != "ok" || rep.Tokens != 3 {
		t.Fatalf("sync: %d %s", rec.Code, rec.Body)
	}
	rec = corrDo(h, viewer, "GET", "/api/github-tokens", "")
	out := oaDecode[struct {
		Tokens  []ghtokens.View
		Summary ghtokens.Summary
	}](t, rec.Body.String())
	if rec.Code != 200 || len(out.Tokens) != 3 || out.Summary.Total != 3 || out.Summary.ByKind["actions_secret"] != 1 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "SECRET00") || strings.Contains(rec.Body.String(), oauthfake.Token) {
		t.Errorf("response carries token material: %s", rec.Body)
	}
	// tenant B sees none of A's credentials and cannot sync (it has no GitHub connection)
	rec = corrDo(h, viewerB, "GET", "/api/github-tokens", "")
	if b := oaDecode[struct{ Tokens []ghtokens.View }](t, rec.Body.String()); rec.Code != 200 || len(b.Tokens) != 0 {
		t.Errorf("tenant B list: %d %s", rec.Code, rec.Body)
	}
	if rec = corrDo(h, user(&f.B, "ta@b.example", auth.RoleTenantAdmin), "POST", "/api/github-tokens/sync", ""); rec.Code != 200 ||
		oaDecode[ghtokens.Report](t, rec.Body.String()).Status != "skipped" {
		t.Errorf("tenant B sync: %d %s", rec.Code, rec.Body)
	}
}
