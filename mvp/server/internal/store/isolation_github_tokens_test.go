package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// GitHub and CI token inventory (issue #476): a tenant sees and sweeps only its
// own credentials; a credential naming another tenant's identity is refused.

func seedGitHubTokens(t *testing.T, f *storetest.Fixture) {
	t.Helper()
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return c.UpsertGitHubToken(&store.GitHubToken{Key: "pat:1", Kind: store.GHClassicPAT, Name: "pat of " + tn.Slug,
				OwnerLogin: "octocat", Scopes: []string{"repo"}}, storetest.Now)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestIsolation_GitHubTokensReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedGitHubTokens(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		ts, err := c.GitHubTokens()
		if err != nil || len(ts) != 1 || ts[0].Name != "pat of "+f.B.Slug {
			t.Errorf("GitHubTokens = %v, %v", ts, err)
		}
		return nil
	})
}

func TestIsolation_GitHubTokensSweepScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedGitHubTokens(t, f)
	later := storetest.Now.Add(time.Hour)
	inB(t, f, func(c *store.TenantTx) error { return c.RemoveUnseenGitHubTokens(later) })
	inA(t, f, func(c *store.TenantTx) error {
		ts, err := c.GitHubTokens()
		if err != nil || len(ts) != 1 || ts[0].Status != store.GHTokenActive {
			t.Errorf("A's tokens after B's sweep = %v, %v", ts, err)
		}
		return nil
	})
}

func TestIsolation_GitHubTokensCrossTenantReference(t *testing.T) {
	f := storetest.TwoTenants(t)
	id := f.A.IDs["alice"]
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.UpsertGitHubToken(&store.GitHubToken{Key: "pat:evil", Kind: store.GHClassicPAT, Name: "x", OwnerIdentityID: &id}, storetest.Now)
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Fatalf("err = %v, want ErrCrossTenant", err)
	}
}

// The upsert is keyed on the token key; a credential a full read no longer
// lists is removed, not deleted; one seen again is active again.
func TestGitHubTokensUpsertAndRemoval(t *testing.T) {
	f := storetest.TwoTenants(t)
	t1, t2 := storetest.Now, storetest.Now.Add(time.Hour)
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.UpsertGitHubToken(&store.GitHubToken{Key: "s:1", Kind: store.GHActionsSecret, Name: "DEPLOY_KEY", Visibility: "all"}, t1); err != nil {
			return err
		}
		if err := c.UpsertGitHubToken(&store.GitHubToken{Key: "s:2", Kind: store.GHActionsSecret, Name: "OTHER"}, t1); err != nil {
			return err
		}
		if err := c.UpsertGitHubToken(&store.GitHubToken{Key: "s:1", Kind: store.GHActionsSecret, Name: "DEPLOY_KEY", Visibility: "private", RotatedAt: &t2}, t2); err != nil {
			return err
		}
		if err := c.RemoveUnseenGitHubTokens(t2); err != nil {
			return err
		}
		ts, err := c.GitHubTokens()
		if err != nil || len(ts) != 2 {
			t.Fatalf("tokens = %v, %v", ts, err)
		}
		for _, tk := range ts {
			switch tk.Key {
			case "s:1":
				if tk.Status != "active" || tk.Visibility != "private" || tk.RotatedAt == nil || !tk.FirstSeen.Equal(t1) || !tk.LastSeen.Equal(t2) {
					t.Errorf("s:1 = %+v", tk)
				}
			case "s:2":
				if tk.Status != "removed" {
					t.Errorf("s:2 = %+v, want removed", tk)
				}
			}
		}
		return nil
	})
}

func githubTokensCovered() map[string]bool {
	return map[string]bool{"GitHubTokens": true, "RemoveUnseenGitHubTokens": true, "UpsertGitHubToken": true} // the tests above
}
