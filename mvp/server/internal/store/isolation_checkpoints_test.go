package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Connector checkpoints (issue #104): a tenant sees, replaces and deletes only
// its own cursors and snapshots, even for the same system and name.

func checkpointsCovered() map[string]bool {
	return map[string]bool{"ConnectorCheckpoint": true, "ConnectorCheckpoints": true, // TestIsolation_ConnectorCheckpointReads
		"PutConnectorCheckpoint": true, "DeleteConnectorCheckpoint": true} // TestIsolation_ConnectorCheckpointWriteAndDeleteScoped
}

func seedCheckpoints(t *testing.T, f *storetest.Fixture) {
	t.Helper()
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			return c.PutConnectorCheckpoint(&store.ConnectorCheckpoint{System: "okta", Name: "users",
				Cursor: "cursor-" + tn.Slug, State: []byte("state-" + tn.Slug), FullSyncAt: &storetest.Now, UpdatedAt: storetest.Now})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestIsolation_ConnectorCheckpointReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedCheckpoints(t, f)
	inB(t, f, func(c *store.TenantTx) error {
		k, err := c.ConnectorCheckpoint("okta", "users")
		if err != nil || k.Cursor != "cursor-"+f.B.Slug || string(k.State) != "state-"+f.B.Slug {
			t.Errorf("ConnectorCheckpoint = %v, %v", k, err)
		}
		all, err := c.ConnectorCheckpoints()
		if err != nil || len(all) != 1 || all[0].Cursor != "cursor-"+f.B.Slug {
			t.Errorf("ConnectorCheckpoints = %v, %v", all, err)
		}
		if _, err := c.ConnectorCheckpoint("okta", "groups"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("missing checkpoint = %v, want ErrNotFound", err)
		}
		return nil
	})
}

func TestIsolation_ConnectorCheckpointWriteAndDeleteScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedCheckpoints(t, f)
	// B overwrites and then deletes "its" okta/users checkpoint: A's is untouched.
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if err := c.PutConnectorCheckpoint(&store.ConnectorCheckpoint{System: "okta", Name: "users", Cursor: "b2",
			UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		return c.DeleteConnectorCheckpoint("okta", "users")
	})
	if err != nil {
		t.Fatal(err)
	}
	inA(t, f, func(c *store.TenantTx) error {
		k, err := c.ConnectorCheckpoint("okta", "users")
		if err != nil || k.Cursor != "cursor-"+f.A.Slug || string(k.State) != "state-"+f.A.Slug {
			t.Errorf("A's checkpoint = %v, %v", k, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.ConnectorCheckpoint("okta", "users"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B's deleted checkpoint = %v, want ErrNotFound", err)
		}
		return nil
	})
}
