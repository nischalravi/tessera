package ingest_test

import (
	"context"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestIsolation_SyncLeavesOtherTenantsAlone is the regression test for the
// two bulk statements of ingest (design §14.1): the wholesale delete of agent
// delegations and the usage-event bulk insert. The Python MVP's delete was
// unscoped and would have wiped every tenant's delegations. A full connector
// sync in tenant B must leave tenant A byte-for-byte unchanged, and must
// replace B's own delegations and add B's usage events.
func TestIsolation_SyncLeavesOtherTenantsAlone(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	beforeA := storetest.Dump(t, f.DB, f.A.ID)
	counts := func(id storetest.Tenant) (dels, usage int) {
		t.Helper()
		if err := f.DB.ReadTenant(ctx, id.ID, func(c *store.TenantTx) error {
			d, err := c.Delegations()
			if err != nil {
				return err
			}
			u, err := c.UsageAggregates(storetest.Now.AddDate(-1, 0, 0))
			dels, usage = len(d), len(u)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return dels, usage
	}
	aDels, aUsage := counts(f.A)
	if aDels == 0 || aUsage == 0 {
		t.Fatalf("tenant A has %d delegations and %d usage aggregates; the fixture is not exercising the test", aDels, aUsage)
	}
	for range 2 { // twice: the second sync deletes and re-inserts B's delegations
		if err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
			_, err := ingest.Sync(c, storetest.Now, []connectors.Connector{connectors.Tiny{Now: storetest.Now}}, nil)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if storetest.Dump(t, f.DB, f.A.ID) != beforeA {
		t.Fatal("a sync in tenant B changed tenant A")
	}
	if d, u := counts(f.A); d != aDels || u != aUsage {
		t.Errorf("tenant A: %d delegations and %d usage aggregates after B's sync, want %d and %d", d, u, aDels, aUsage)
	}
	if d, _ := counts(f.B); d != 1 {
		t.Errorf("tenant B has %d delegations after re-sync, want its 1 (replaced, not duplicated)", d)
	}
}
