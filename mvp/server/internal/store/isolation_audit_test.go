package store_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Audit ledger isolation (design §13, §14.4): every tenant has its own chain;
// tenant B never sees, links to, certifies or changes tenant A's events and
// checkpoints, and A's event ids look nonexistent from B.

func auditCovered() map[string]bool {
	out := map[string]bool{}
	for _, m := range []string{"AppendAudit", "RecordAudit", "AuditHead", "AuditEvents", "AuditEventsRange",
		"AuditEventStats", "AuditEvent", "AuditEventBySeq", "InsertAuditCheckpoint", "AuditCheckpoints",
		"LatestAuditCheckpoint", "CoveringAuditCheckpoint", "UnanchoredAuditCheckpoints", "SetAuditCheckpointAnchor"} {
		out[m] = true // TestIsolation_AuditLedger
	}
	return out
}

// auditFixture appends a few events to both tenants and checkpoints A at its
// head. It returns A's events.
func auditFixture(t *testing.T, f *storetest.Fixture) (aEvents []*store.AuditEvent, aCkpt store.AuditCheckpoint) {
	t.Helper()
	ctx := context.Background()
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		if err := f.DB.InTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			for i := range 3 {
				if err := c.Audit(storetest.Now, "fixture", "fixture.event", ojson.Object{{Key: "i", Value: i},
					{Key: "tenant", Value: tn.Slug}}); err != nil {
					return err
				}
			}
			if tn.ID != f.A.ID {
				return nil
			}
			head, err := c.AuditHead()
			if err != nil {
				return err
			}
			aCkpt, err = c.InsertAuditCheckpoint(store.AuditCheckpoint{Seq: head.LastSeq, HeadHash: head.LastHash, JWS: "x.y.z"})
			if err != nil {
				return err
			}
			aEvents, err = c.AuditLog(-1)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	return aEvents, aCkpt
}

func TestIsolation_AuditLedger(t *testing.T) {
	f := storetest.TwoTenants(t)
	aEvents, aCkpt := auditFixture(t, f)
	if len(aEvents) == 0 {
		t.Fatal("tenant A has no events")
	}
	aLast := aEvents[0]
	ctx := context.Background()

	t.Run("reads", func(t *testing.T) {
		err := f.DB.ReadTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
			all, err := c.AuditEvents(store.AuditFilter{IncludeHTTP: true})
			if err != nil {
				return err
			}
			rng, err := c.AuditEventsRange(1, 0, 0)
			if err != nil {
				return err
			}
			for _, e := range slices.Concat(all, rng) {
				if e.TenantID != f.B.ID {
					t.Errorf("B reads an event of tenant %s", e.TenantID)
				}
				if strings.Contains(string(e.Detail), storetest.Sentinel) || slices.ContainsFunc(aEvents,
					func(a *store.AuditEvent) bool { return a.ID == e.ID || a.Hash == e.Hash }) {
					t.Errorf("B reads A's event %s", e.ID)
				}
			}
			if _, err := c.AuditEvent(aLast.ID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("AuditEvent(A's id) in B = %v, want ErrNotFound", err)
			}
			if _, err := c.AuditEvent(uuid.New()); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("AuditEvent(missing) = %v", err)
			}
			if e, err := c.AuditEventBySeq(aLast.Seq); err == nil && e.TenantID != f.B.ID {
				t.Errorf("AuditEventBySeq returned tenant %s", e.TenantID)
			}
			ck, err := c.AuditCheckpoints(0, 0)
			if err != nil {
				return err
			}
			if len(ck) != 0 {
				t.Errorf("B sees %d checkpoints, want 0 (only A has one)", len(ck))
			}
			if _, err := c.LatestAuditCheckpoint(); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("LatestAuditCheckpoint in B = %v", err)
			}
			if _, err := c.CoveringAuditCheckpoint(1); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("CoveringAuditCheckpoint in B = %v", err)
			}
			un, err := c.UnanchoredAuditCheckpoints()
			if err != nil || len(un) != 0 {
				t.Errorf("UnanchoredAuditCheckpoints in B = %d, %v", len(un), err)
			}
			n, _, last, err := c.AuditEventStats(1, 0)
			if err != nil {
				return err
			}
			head, err := c.AuditHead()
			if err != nil {
				return err
			}
			if head.TenantID != f.B.ID || head.LastSeq != last || n != last || head.LastHash == aLast.Hash {
				t.Errorf("B's head %+v / stats n=%d last=%d mix in A's chain", head, n, last)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("writes", func(t *testing.T) {
		before := storetest.Dump(t, f.DB, f.A.ID)
		err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
			if _, err := c.AppendAudit(store.AuditEvent{TenantID: f.A.ID, ActorType: store.ActorSystem, Action: "x"}); !errors.Is(err, store.ErrCrossTenant) {
				t.Errorf("AppendAudit with A's tenant in B = %v, want ErrCrossTenant", err)
			}
			if _, err := c.InsertAuditCheckpoint(store.AuditCheckpoint{TenantID: f.A.ID, Seq: 1, HeadHash: aLast.Hash, JWS: "x"}); !errors.Is(err, store.ErrCrossTenant) {
				t.Errorf("InsertAuditCheckpoint with A's tenant = %v, want ErrCrossTenant", err)
			}
			// B certifying A's head (seq and hash of A's last event) is refused by the schema.
			if _, err := c.InsertAuditCheckpoint(store.AuditCheckpoint{Seq: aLast.Seq, HeadHash: aLast.Hash, JWS: "x"}); !errors.Is(err, store.ErrCrossTenant) {
				t.Errorf("checkpoint of A's head in B = %v, want ErrCrossTenant", err)
			}
			if err := c.SetAuditCheckpointAnchor(aCkpt.ID, store.AnchorAnchored, nil, storetest.Now); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("SetAuditCheckpointAnchor(A's checkpoint) in B = %v, want ErrNotFound", err)
			}
			_, err := c.RecordAudit(store.AuditRecord{Action: "b.only", LegacyActor: "b"})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if storetest.Dump(t, f.DB, f.A.ID) != before {
			t.Error("writes in B changed tenant A's ledger")
		}
	})

	t.Run("platform chain is separate", func(t *testing.T) {
		f.DB.RecordContextMissing(ctx, "test")
		err := f.DB.ReadTenant(ctx, tenancy.Platform, func(c *store.TenantTx) error {
			log, err := c.AuditLog(-1)
			for _, e := range log {
				if e.TenantID != tenancy.Platform {
					t.Errorf("platform chain holds an event of %s", e.TenantID)
				}
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}
