package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// OAuth app facts and changes (issue #474): a tenant sees and changes only its
// own; a row naming another tenant's app is refused by the guard triggers.

type oauthChangeSeed struct{ fact, change map[string]string }

func seedOAuthChanges(t *testing.T, f *storetest.Fixture, apps oauthSeed) oauthChangeSeed {
	t.Helper()
	out := oauthChangeSeed{fact: map[string]string{}, change: map[string]string{}}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			fact := &store.OAuthFact{AppID: apps.app[tn.Slug], Kind: store.OAuthFactSecret, Key: "k1", Label: "secret"}
			if _, err := c.UpsertOAuthFact(fact, storetest.Now); err != nil {
				return err
			}
			ch := &store.OAuthChange{AppID: apps.app[tn.Slug], Kind: store.OAuthChangeCredential, Subject: fact.ID, Summary: "s",
				DetectedAt: storetest.Now}
			if _, err := c.InsertOAuthChange(ch); err != nil {
				return err
			}
			out.fact[tn.Slug], out.change[tn.Slug] = fact.ID, ch.ID
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestIsolation_OAuthChangesReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	apps := seedOAuth(t, f)
	ids := seedOAuthChanges(t, f, apps)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.OAuthFact(ids.fact[f.A.Slug]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OAuthFact(A's) = %v", err)
		}
		if _, err := c.OAuthChange(ids.change[f.A.Slug]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OAuthChange(A's) = %v", err)
		}
		if fs, err := c.OAuthFactsOf(apps.app[f.A.Slug]); err != nil || len(fs) != 0 {
			t.Errorf("OAuthFactsOf(A's app) = %v, %v", fs, err)
		}
		if cs, err := c.OAuthChangesOf(apps.app[f.A.Slug]); err != nil || len(cs) != 0 {
			t.Errorf("OAuthChangesOf(A's app) = %v, %v", cs, err)
		}
		if _, err := c.OAuthGrantByKey(apps.app[f.A.Slug], "u:alice"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OAuthGrantByKey(A's app) = %v", err)
		}
		cs, err := c.OpenOAuthChanges()
		if err != nil || len(cs) != 1 || cs[0].ID != ids.change[f.B.Slug] {
			t.Errorf("OpenOAuthChanges = %v, %v", cs, err)
		}
		return nil
	})
}

func TestIsolation_OAuthChangesWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	apps := seedOAuth(t, f)
	ids := seedOAuthChanges(t, f, apps)
	later := storetest.Now.Add(time.Hour)
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if err := c.SetOAuthFactStatus(ids.fact[f.A.Slug], "removed"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetOAuthFactStatus on A's row in B = %v, want ErrNotFound", err)
		}
		if err := c.ResolveOAuthChangeID(ids.change[f.A.Slug], "x", later); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ResolveOAuthChangeID on A's row in B = %v, want ErrNotFound", err)
		}
		if err := c.ResolveOAuthChange(apps.app[f.A.Slug], store.OAuthChangeCredential, ids.fact[f.A.Slug], "x", later); err != nil {
			t.Error(err) // matches no row of B
		}
		return c.RemoveUnseenOAuthFacts(store.OAuthGoogle, later) // B's sweep never touches A's
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		fa, err := c.OAuthFact(ids.fact[f.A.Slug])
		if err != nil || fa.Status != "active" {
			t.Errorf("A's fact = %+v, %v", fa, err)
		}
		ch, err := c.OAuthChange(ids.change[f.A.Slug])
		if err != nil || ch.Status != store.OAuthChangeOpen {
			t.Errorf("A's change = %+v, %v", ch, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIsolation_OAuthChangesCrossTenantReferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	apps := seedOAuth(t, f)
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"fact.app_id": func(c *store.TenantTx) error {
			_, err := c.UpsertOAuthFact(&store.OAuthFact{AppID: apps.app[f.A.Slug], Kind: store.OAuthFactOwner, Key: "evil"}, storetest.Now)
			return err
		},
		"change.app_id": func(c *store.TenantTx) error {
			_, err := c.InsertOAuthChange(&store.OAuthChange{AppID: apps.app[f.A.Slug], Kind: store.OAuthChangeOwner, Subject: "evil",
				Summary: "s", DetectedAt: storetest.Now})
			return err
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

// A fact is new once; seen again it is active again; a full sync that no
// longer lists it marks it removed, and the baseline marker is never swept. A
// change is recorded once per subject and closes once.
func TestOAuthFactsAndChanges(t *testing.T) {
	f := storetest.TwoTenants(t)
	apps := seedOAuth(t, f)
	t1, t2 := storetest.Now, storetest.Now.Add(time.Hour)
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		id := apps.app[f.A.Slug]
		base := &store.OAuthFact{AppID: id, Kind: store.OAuthFactBaseline, Key: "-"}
		sec := &store.OAuthFact{AppID: id, Kind: store.OAuthFactSecret, Key: "s1"}
		for _, x := range []*store.OAuthFact{base, sec} {
			if isNew, err := c.UpsertOAuthFact(x, t1); err != nil || !isNew {
				t.Fatalf("first upsert = %v, %v", isNew, err)
			}
		}
		if isNew, err := c.UpsertOAuthFact(&store.OAuthFact{AppID: id, Kind: store.OAuthFactSecret, Key: "s1", Label: "renamed"}, t2); err != nil || isNew {
			t.Errorf("second upsert = %v, %v", isNew, err)
		}
		if err := c.RemoveUnseenOAuthFacts(store.OAuthGoogle, t2); err != nil { // provider google: the seeded app
			t.Fatal(err)
		}
		fs, err := c.OAuthFactsOf(id)
		if err != nil || len(fs) != 2 {
			t.Fatalf("facts = %v, %v", fs, err)
		}
		for _, x := range fs {
			if x.Status != "active" {
				t.Errorf("fact %s status = %s", x.Kind, x.Status)
			}
		}
		if err := c.RemoveUnseenOAuthFacts(store.OAuthGoogle, t2.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		got, _ := c.OAuthFact(sec.ID)
		bl, _ := c.OAuthFact(base.ID)
		if got.Status != "removed" || bl.Status != "active" {
			t.Errorf("after sweep: secret %s, baseline %s", got.Status, bl.Status)
		}
		if isNew, err := c.UpsertOAuthFact(&store.OAuthFact{AppID: id, Kind: store.OAuthFactSecret, Key: "s1"}, t2.Add(2*time.Hour)); err != nil || !isNew {
			t.Errorf("a removed fact seen again = new %v, %v", isNew, err)
		}
		ch := &store.OAuthChange{AppID: id, Kind: store.OAuthChangeCredential, Subject: sec.ID, Summary: "s", DetectedAt: t1}
		if ok, err := c.InsertOAuthChange(ch); err != nil || !ok {
			t.Fatalf("insert = %v, %v", ok, err)
		}
		if ok, err := c.InsertOAuthChange(&store.OAuthChange{AppID: id, Kind: store.OAuthChangeCredential, Subject: sec.ID, Summary: "s", DetectedAt: t2}); err != nil || ok {
			t.Errorf("repeat insert = %v, %v, want a no-op", ok, err)
		}
		if err := c.ResolveOAuthChangeID(ch.ID, "done", t2); err != nil {
			t.Fatal(err)
		}
		if err := c.ResolveOAuthChangeID(ch.ID, "again", t2); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second resolve = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func oauthChangesCovered() map[string]bool {
	return map[string]bool{"OAuthFact": true, "OAuthFactsOf": true, "OAuthChange": true, "OAuthChangesOf": true, "OpenOAuthChanges": true,
		"OAuthGrantByKey":    true,                                                                                           // TestIsolation_OAuthChangesReads
		"SetOAuthFactStatus": true, "RemoveUnseenOAuthFacts": true, "ResolveOAuthChange": true, "ResolveOAuthChangeID": true, // TestIsolation_OAuthChangesWritesScoped
		"UpsertOAuthFact": true, "InsertOAuthChange": true} // TestIsolation_OAuthChangesCrossTenantReferences, TestOAuthFactsAndChanges
}
