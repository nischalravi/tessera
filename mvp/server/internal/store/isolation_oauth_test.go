package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Third-party OAuth apps (issue #107): a tenant sees and changes only its own
// apps, grants and sync state; a row naming another tenant's app, identity or
// account is refused by the guard triggers.

type oauthSeed struct{ app, grant map[string]string }

func seedOAuth(t *testing.T, f *storetest.Fixture) oauthSeed {
	t.Helper()
	out := oauthSeed{app: map[string]string{}, grant: map[string]string{}}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			app := &store.OAuthApp{Provider: store.OAuthGoogle, ClientID: "client-" + tn.Slug, Name: "App " + tn.Slug, Publisher: "Acme"}
			if err := c.UpsertOAuthApp(app, storetest.Now); err != nil {
				return err
			}
			g := &store.OAuthGrant{AppID: app.ID, Provider: app.Provider, GrantKey: "u:alice", ProviderRef: "alice@x.example",
				Kind: "token", UserRef: "alice@x.example", Scopes: []string{"https://mail.google.com/"}, ConsentType: "user"}
			if err := c.UpsertOAuthGrant(g, storetest.Now); err != nil {
				return err
			}
			out.app[tn.Slug], out.grant[tn.Slug] = app.ID, g.ID
			return c.PutOAuthSyncState(&store.OAuthSyncState{Provider: store.OAuthGoogle, Status: "ok", AttemptedAt: storetest.Now,
				SucceededAt: &storetest.Now, Apps: 1, Grants: 1})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestIsolation_OAuthReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedOAuth(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		apps, err := c.OAuthApps()
		if err != nil || len(apps) != 1 || apps[0].ID != ids.app[f.B.Slug] {
			t.Errorf("OAuthApps = %v, %v", apps, err)
		}
		if n, err := c.CountOAuthApps(); err != nil || n != 1 {
			t.Errorf("CountOAuthApps = %d, %v", n, err)
		}
		if _, err := c.OAuthApp(ids.app[f.A.Slug]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OAuthApp(A's) = %v", err)
		}
		if _, err := c.OAuthAppByKey(store.OAuthGoogle, "client-"+f.A.Slug); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OAuthAppByKey(A's) = %v", err)
		}
		if _, err := c.OAuthGrant(ids.grant[f.A.Slug]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OAuthGrant(A's) = %v", err)
		}
		if gs, err := c.OAuthGrantsOf(ids.app[f.A.Slug]); err != nil || len(gs) != 0 {
			t.Errorf("OAuthGrantsOf(A's app) = %v, %v", gs, err)
		}
		gs, err := c.OAuthGrants()
		if err != nil || len(gs) != 1 || gs[0].ID != ids.grant[f.B.Slug] {
			t.Errorf("OAuthGrants = %v, %v", gs, err)
		}
		st, err := c.OAuthSyncStates()
		if err != nil || len(st) != 1 || st[0].Apps != 1 {
			t.Errorf("OAuthSyncStates = %v, %v", st, err)
		}
		return nil
	})
}

func TestIsolation_OAuthWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedOAuth(t, f)
	by := "b"
	later := storetest.Now.Add(time.Hour)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		for name, err := range map[string]error{
			"SetOAuthAppRisk":     c.SetOAuthAppRisk(ids.app[f.A.Slug], 99, []string{"x"}, nil, "active"),
			"SetOAuthAppOwner":    c.SetOAuthAppOwner(ids.app[f.A.Slug], nil),
			"MarkOAuthAppRevoked": c.MarkOAuthAppRevoked(ids.app[f.A.Slug], by, later),
			"SetOAuthGrantStatus": c.SetOAuthGrantStatus(ids.grant[f.A.Slug], "revoked", &by, &later, ""),
		} {
			if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s on A's row in B = %v, want ErrNotFound", name, err)
			}
		}
		if err := c.DefaultOAuthAppOwner(ids.app[f.A.Slug], f.B.IDs["alice"]); err != nil { // matches no row of B
			t.Error(err)
		}
		// B's sweep of "unseen" grants never touches A's
		if _, err := c.RemoveUnseenOAuthGrants(store.OAuthGoogle, later); err != nil {
			t.Error(err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		a, err := c.OAuthApp(ids.app[f.A.Slug])
		if err != nil || a.Status != "active" || a.RiskScore != 0 || a.OwnerIdentityID != nil {
			t.Errorf("A's app = %+v, %v", a, err)
		}
		g, err := c.OAuthGrant(ids.grant[f.A.Slug])
		if err != nil || g.Status != "active" {
			t.Errorf("A's grant = %+v, %v", g, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIsolation_OAuthCrossTenantReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedOAuth(t, f)
	a := f.A.IDs
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"grant.app_id": func(c *store.TenantTx) error {
			return c.UpsertOAuthGrant(&store.OAuthGrant{AppID: ids.app[f.A.Slug], Provider: "google", GrantKey: "u:evil", Kind: "token",
				ConsentType: "user"}, storetest.Now)
		},
		"grant.identity_id": func(c *store.TenantTx) error {
			id := a["alice"]
			return c.UpsertOAuthGrant(&store.OAuthGrant{AppID: ids.app[f.B.Slug], Provider: "google", GrantKey: "u:evil", Kind: "token",
				ConsentType: "user", IdentityID: &id}, storetest.Now)
		},
		"grant.account_id": func(c *store.TenantTx) error {
			id := a["acct:okta:alice"]
			return c.UpsertOAuthGrant(&store.OAuthGrant{AppID: ids.app[f.B.Slug], Provider: "google", GrantKey: "u:evil", Kind: "token",
				ConsentType: "user", AccountID: &id}, storetest.Now)
		},
		"app.owner": func(c *store.TenantTx) error {
			id := a["alice"]
			return c.SetOAuthAppOwner(ids.app[f.B.Slug], &id)
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := f.DB.InTenant(context.Background(), f.B.ID, fn)
			if !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("err = %v, want ErrCrossTenant", err)
			}
		})
	}
}

// The upsert is keyed on provider + client id (apps) and app + grant key
// (grants); a grant a full sync no longer lists is removed, not deleted; a
// grant seen again is active again; a failed revoke stays visible.
func TestOAuthUpsertAndRemoval(t *testing.T) {
	f := storetest.TwoTenants(t)
	t1, t2 := storetest.Now, storetest.Now.Add(time.Hour)
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		app := &store.OAuthApp{Provider: "entra", ClientID: "c1", Name: "One"}
		if err := c.UpsertOAuthApp(app, t1); err != nil {
			return err
		}
		id := app.ID
		again := &store.OAuthApp{Provider: "entra", ClientID: "c1", Name: "One renamed", Publisher: "P", Verified: true}
		if err := c.UpsertOAuthApp(again, t2); err != nil {
			return err
		}
		if again.ID != id || again.Name != "One renamed" || !again.Verified || !again.FirstSeen.Equal(t1) || !again.LastSeen.Equal(t2) {
			t.Errorf("upsert = %+v (want id %s kept, first_seen %s)", again, id, t1)
		}
		keep := &store.OAuthGrant{AppID: id, Provider: "entra", GrantKey: "d:1", Kind: "delegated", Scopes: []string{"Mail.Read"}, ConsentType: "user"}
		gone := &store.OAuthGrant{AppID: id, Provider: "entra", GrantKey: "d:2", Kind: "delegated", ConsentType: "admin"}
		failed := &store.OAuthGrant{AppID: id, Provider: "entra", GrantKey: "d:3", Kind: "delegated", ConsentType: "user"}
		for _, g := range []*store.OAuthGrant{keep, gone, failed} {
			if err := c.UpsertOAuthGrant(g, t1); err != nil {
				return err
			}
		}
		by := "admin"
		if err := c.SetOAuthGrantStatus(failed.ID, store.OAuthRevokeFailed, &by, nil, "boom"); err != nil {
			return err
		}
		// a later sync sees d:1 and d:3 only
		for _, g := range []*store.OAuthGrant{{AppID: id, Provider: "entra", GrantKey: "d:1", Kind: "delegated", ConsentType: "user", Scopes: []string{"Mail.Read", "Files.Read"}},
			{AppID: id, Provider: "entra", GrantKey: "d:3", Kind: "delegated", ConsentType: "user"}} {
			if err := c.UpsertOAuthGrant(g, t2); err != nil {
				return err
			}
		}
		n, err := c.RemoveUnseenOAuthGrants("entra", t2)
		if err != nil || n != 1 {
			t.Errorf("RemoveUnseenOAuthGrants = %d, %v, want 1", n, err)
		}
		gs, err := c.OAuthGrantsOf(id)
		if err != nil || len(gs) != 3 {
			t.Fatalf("grants = %v, %v (removed grants are kept)", gs, err)
		}
		got := map[string]*store.OAuthGrant{}
		for _, g := range gs {
			got[g.GrantKey] = g
		}
		if got["d:1"].ID != keep.ID || len(got["d:1"].Scopes) != 2 || got["d:1"].Status != "active" {
			t.Errorf("d:1 = %+v", got["d:1"])
		}
		if got["d:2"].Status != "removed" {
			t.Errorf("d:2 = %+v, want removed", got["d:2"])
		}
		if got["d:3"].Status != "revoke_failed" || got["d:3"].RevokeError != "boom" {
			t.Errorf("d:3 = %+v, want revoke_failed kept", got["d:3"])
		}
		// a removed grant seen again is active again
		if err := c.UpsertOAuthGrant(&store.OAuthGrant{AppID: id, Provider: "entra", GrantKey: "d:2", Kind: "delegated", ConsentType: "admin"}, t2.Add(time.Hour)); err != nil {
			return err
		}
		g2, err := c.OAuthGrant(gone.ID)
		if err != nil || g2.Status != "active" {
			t.Errorf("d:2 seen again = %+v, %v", g2, err)
		}
		// a failed sync keeps the last good counts
		if err := c.PutOAuthSyncState(&store.OAuthSyncState{Provider: "entra", Status: "ok", AttemptedAt: t1, SucceededAt: &t1, Apps: 4, Grants: 9}); err != nil {
			return err
		}
		if err := c.PutOAuthSyncState(&store.OAuthSyncState{Provider: "entra", Status: "failed", AttemptedAt: t2, Error: "429"}); err != nil {
			return err
		}
		st, err := c.OAuthSyncStates()
		if err != nil || len(st) != 1 || st[0].Status != "failed" || st[0].Apps != 4 || st[0].SucceededAt == nil || !st[0].SucceededAt.Equal(t1) {
			t.Errorf("sync state = %+v, %v", st, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func oauthCovered() map[string]bool {
	return map[string]bool{"UpsertOAuthApp": true, "OAuthAppByKey": true, "OAuthApp": true, "OAuthApps": true, "CountOAuthApps": true,
		"OAuthGrant": true, "OAuthGrantsOf": true, "OAuthGrants": true, "OAuthSyncStates": true, // TestIsolation_OAuthReads
		"SetOAuthAppRisk": true, "SetOAuthAppOwner": true, "DefaultOAuthAppOwner": true, "MarkOAuthAppRevoked": true,
		"SetOAuthGrantStatus": true, "RemoveUnseenOAuthGrants": true, // TestIsolation_OAuthWritesScoped
		"UpsertOAuthGrant": true, "PutOAuthSyncState": true} // TestIsolation_OAuthCrossTenantReferences, TestOAuthUpsertAndRemoval
}
