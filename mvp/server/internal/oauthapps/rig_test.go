package oauthapps_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps"
	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps/oauthfake"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// rig is tenant A with a live connection and credential for each provider,
// each pointing at a stateful fake served over loopback through a real
// safehttp client.
type rig struct {
	f      *storetest.Fixture
	svc    *oauthapps.Service
	google *oauthfake.Google
	entra  *oauthfake.Entra
	sf     *oauthfake.Salesforce
	gh     *oauthfake.GitHub
	now    time.Time
}

func newRig(t *testing.T, providers ...string) *rig {
	t.Helper()
	r := &rig{f: storetest.TwoTenants(t), now: storetest.Now,
		google: &oauthfake.Google{}, entra: &oauthfake.Entra{}, sf: &oauthfake.Salesforce{}, gh: &oauthfake.GitHub{Org: "acme"}}
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	cs := &containment.Service{HTTP: hc, Sealer: sealer, Clock: func() time.Time { return r.now },
		Sleep: func(context.Context, time.Duration) error { return nil }}
	r.svc = &oauthapps.Service{Containment: cs, Clock: func() time.Time { return r.now }}
	if len(providers) == 0 {
		providers = oauthapps.Providers
	}
	urls := map[string]string{}
	for name, h := range map[string]interface {
		ServeHTTP(http.ResponseWriter, *http.Request)
	}{
		oauthapps.Google: r.google, oauthapps.Entra: r.entra, oauthapps.Salesforce: r.sf, oauthapps.GitHub: r.gh} {
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		urls[name] = srv.URL
	}
	r.entra.BaseURL = urls[oauthapps.Entra]
	err = r.f.DB.InTenant(context.Background(), r.f.A.ID, func(c *store.TenantTx) error {
		for _, name := range providers {
			id := store.NewID()
			if err := c.InsertConnection(&store.Connection{ID: id, Name: name, ConnectorType: name, System: name,
				Role: "account_source", CreatedAt: r.now, UpdatedAt: r.now}); err != nil {
				return err
			}
			in := containment.CredentialInput{Token: oauthfake.Token, BaseURL: urls[name]}
			if name == oauthapps.GitHub {
				in.Org = "acme"
			}
			if err := cs.PutCredential(c, id, in, "admin", r.now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// advance moves the clock, so a later sync sees the earlier rows as unseen.
func (r *rig) advance(d time.Duration) { r.now = r.now.Add(d) }

// seed fills the fakes: two apps per provider where the provider has apps, one
// of them risky and held by several users.
func (r *rig) seed() {
	r.google.Users = []*oauthfake.GoogleUser{
		{ID: "g1", Email: "alice@a.example", Tokens: []oauthfake.GoogleToken{
			{ClientID: "drift.apps.googleusercontent.com", DisplayText: "Salesloft Drift", Scopes: []string{"https://mail.google.com/"}},
			{ClientID: "cal.apps.googleusercontent.com", DisplayText: "Calendar sync", Scopes: []string{"openid"}}}},
		{ID: "g2", Email: "bob@a.example", Tokens: []oauthfake.GoogleToken{
			{ClientID: "drift.apps.googleusercontent.com", DisplayText: "Salesloft Drift", Scopes: []string{"https://mail.google.com/"}}}},
		{ID: "g3", Email: "root@a.example", Admin: true},
	}
	r.entra.SPs = []*oauthfake.EntraSP{
		{ID: "sp-graph", AppID: "00000003-0000-0000-c000-000000000000", Name: "Microsoft Graph", Roles: map[string]string{"role-dir": "Directory.ReadWrite.All"}},
		{ID: "sp-gain", AppID: "app-gainsight", Name: "Gainsight", Publisher: "Gainsight Inc"},
		{ID: "sp-klue", AppID: "app-klue", Name: "Klue", Publisher: "Klue Labs", VerifiedPublisher: "v-1"},
		{ID: "sp-idle", AppID: "app-idle", Name: "Idle app"},
	}
	r.entra.UserNames = map[string]string{"u-alice": "alice@a.example"}
	r.entra.Delegated = []*oauthfake.EntraDelegated{
		{ID: "d1", ClientSP: "sp-gain", ConsentType: "Principal", Principal: "u-alice", Scope: " Mail.Read offline_access"},
		{ID: "d2", ClientSP: "sp-klue", ConsentType: "AllPrincipals", Scope: "User.Read"},
		{ID: "d3", ClientSP: "sp-gain", ConsentType: "AllPrincipals", Scope: "Files.Read.All"},
	}
	r.entra.Roles = []*oauthfake.EntraRole{{ID: "ra1", ClientSP: "sp-gain", Resource: "sp-graph", RoleID: "role-dir", Created: "2026-09-01T00:00:00Z"}}
	r.sf.Tokens = []*oauthfake.SalesforceToken{
		{ID: oauthfake.ID("00Xa", 1), AppName: "Salesloft Drift", AppID: oauthfake.ID("0Aa", 1), UserID: "005A", Username: "alice@a.example",
			Created: "2026-08-01T10:00:00.000+0000", LastUsed: "2026-10-01T10:00:00.000+0000", Scopes: "api refresh_token"},
		{ID: oauthfake.ID("00Xa", 2), AppName: "Salesloft Drift", AppID: oauthfake.ID("0Aa", 1), UserID: "005B", Username: "bob@a.example",
			ModifyAll: true, Created: "2026-08-02T10:00:00.000+0000", Scopes: "full"},
		{ID: oauthfake.ID("00Xa", 3), AppName: "Quiet app", AppID: oauthfake.ID("0Aa", 2), UserID: "005A", Username: "alice@a.example", Scopes: "id"},
	}
	r.gh.Installs = []*oauthfake.GitHubInstall{
		{ID: 11, Slug: "deploy-bot", Owner: "acme-tools", Permissions: map[string]string{"contents": "write", "metadata": "read"}, Created: "2026-07-01T00:00:00Z"},
	}
	r.gh.Credentials = []*oauthfake.GitHubCredential{
		{ID: 21, Login: "octocat", Type: "OAuth app token", Authorized: "2026-06-01T00:00:00Z", Accessed: "2026-10-10T00:00:00Z", Scopes: []string{"repo"}},
		{ID: 22, Login: "hubot", Type: "personal access token", Authorized: "2026-06-02T00:00:00Z", Scopes: []string{"read:user"}},
		{ID: 23, Login: "mona", Type: "OAuth app token", Authorized: "2026-06-03T00:00:00Z", Scopes: []string{"read:org"}},
	}
}
