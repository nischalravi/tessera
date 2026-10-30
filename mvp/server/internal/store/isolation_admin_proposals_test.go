package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The machine client behind a config proposal (schema/0952_config_proposals.sql, issue #721): the proposer of a change
// request is the tenant's own record. B sees no proposer for A's request, cannot file one for it (the guard trigger
// and, in Postgres, the composite foreign key refuse the reference), and the same client id in B is B's own row.
func TestIsolation_AdminChangeProposals(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := seedAdminRows(t, f)
	now := storetest.Now
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.InsertAdminChangeProposal(a.pending.ID, "tsc_shared", now)
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if got, err := c.AdminChangeProposer(a.pending.ID); err != nil || got != "" {
			t.Errorf("B reads A's proposer = %q, %v", got, err)
		}
		return nil
	})
	// a refused insert aborts its transaction, so each attempt has its own
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertAdminChangeProposal(a.pending.ID, "tsc_shared", now)
	}); err == nil {
		t.Error("B filed a proposer for A's change request")
	}
	inB(t, f, func(c *store.TenantTx) error {
		if got, err := c.AdminChangeProposer(b.pending.ID); err != nil || got != "" {
			t.Errorf("B's own change has proposer %q, %v", got, err)
		}
		return c.InsertAdminChangeProposal(b.pending.ID, "tsc_shared", now)
	})
	if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertAdminChangeProposal(b.pending.ID, "tsc_other", now)
	}); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("a second proposer = %v, want ErrDuplicate", err)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		if got, err := c.AdminChangeProposer(a.pending.ID); err != nil || got != "tsc_shared" {
			t.Errorf("A's proposer = %q, %v", got, err)
		}
		if got, err := c.AdminChangeProposer(b.pending.ID); err != nil || got != "" {
			t.Errorf("A reads B's proposer = %q, %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A proposer's open requests and the reasoned cancellation are the tenant's own: the same client id in B lists none of
// A's, and B cannot cancel A's request.
func TestIsolation_CancelProposalsOf(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := seedAdminRows(t, f)
	now := storetest.Now
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.InsertAdminChangeProposal(a.pending.ID, "tsc_shared", now)
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if got, err := c.OpenAdminChangesOfProposer("tsc_shared"); err != nil || len(got) != 0 {
			t.Errorf("B lists A's proposals: %v, %v", got, err)
		}
		if err := c.CancelAdminChangeWhy(a.pending.ID, b.pending.RequestedBy, now, "proposer_revoked"); !errors.Is(err, store.ErrAdminChangeState) {
			t.Errorf("B cancelling A's request = %v, want ErrAdminChangeState", err)
		}
		return nil
	})
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		got, err := c.OpenAdminChangesOfProposer("tsc_shared")
		if err != nil || len(got) != 1 || got[0].ID != a.pending.ID {
			t.Errorf("A lists %v, %v", got, err)
		}
		if err := c.CancelAdminChangeWhy(a.pending.ID, a.pending.RequestedBy, now, "proposer_revoked"); err != nil {
			return err
		}
		ch, err := c.AdminChange(a.pending.ID)
		if err == nil && (ch.Status != store.ChangeCancelled || ch.Failure != "proposer_revoked") {
			t.Errorf("cancelled request = %s %q", ch.Status, ch.Failure)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// SetAPIClientScopes changes only the calling tenant's machine client: B cannot widen A's client, and the
// first-party CLI client's scopes are never rewritten.
func TestIsolation_SetAPIClientScopes(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	mk := func(tn storetest.Tenant, tag byte, kind string) {
		t.Helper()
		owner := seedAuthRows(t, f.DB, tn.ID, tag).user
		if err := f.DB.InTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			cl := &store.APIClient{ClientID: "tsc_" + kind, Name: kind, Kind: kind, GrantTypes: []string{"client_credentials"},
				TokenEndpointAuthMethod: "private_key_jwt", AllowedScopes: []string{"tessera:read"}, Roles: []string{"viewer"},
				OwnerUserID: &owner.ID, CreatedAt: storetest.Now}
			if kind == store.ClientFirstPartyCLI {
				cl.GrantTypes, cl.TokenEndpointAuthMethod, cl.DPoPRequired = []string{"device_code"}, "none", true
			}
			return c.InsertAPIClient(cl)
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk(f.A, 'a', store.ClientMachine)
	mk(f.A, 'c', store.ClientFirstPartyCLI)
	if err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.SetAPIClientScopes("tsc_"+store.ClientMachine, []string{"tessera:read", "config.propose"})
	}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("B setting A's client scopes = %v, want ErrNotFound", err)
	}
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if err := c.SetAPIClientScopes("tsc_"+store.ClientFirstPartyCLI, []string{"tessera:admin"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("rewriting the first-party client = %v, want ErrNotFound", err)
		}
		return c.SetAPIClientScopes("tsc_"+store.ClientMachine, []string{"tessera:read", "config.propose"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		cl, err := c.APIClientByClientID("tsc_" + store.ClientMachine)
		if err != nil || len(cl.AllowedScopes) != 2 || cl.AllowedScopes[1] != "config.propose" {
			t.Errorf("A's client = %+v, %v", cl, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func adminProposalsCovered() map[string]bool {
	return map[string]bool{"InsertAdminChangeProposal": true, "AdminChangeProposer": true, "SetAPIClientScopes": true,
		"OpenAdminChangesOfProposer": true, "CancelAdminChangeWhy": true} // the tests above
}
