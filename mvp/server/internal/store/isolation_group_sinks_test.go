package store_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Group event sinks (issue #61, GR-18): a tenant's sinks, dead letters and
// sink cursors are its own. Another tenant's sink id looks nonexistent, writes
// that name it fail, and a dead letter that names it is refused by the guard
// trigger.

func seedSinks(t *testing.T, f *storetest.Fixture) map[string]string {
	t.Helper()
	ids := map[string]string{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		id := "11111111-1111-4111-8111-11111111111" + string(tn.Slug[len(tn.Slug)-1]-'a'+'1')
		err := f.DB.InTenant(t.Context(), tn.ID, func(c *store.TenantTx) error {
			if err := c.InsertGrpSink(&store.GrpSink{ID: id, Name: "main", Kind: store.SinkKafka, Enabled: true,
				Config: json.RawMessage(`{"topic":"t"}`), EventTypes: []string{"membership."}, SecretEnc: []byte("sealed"),
				CreatedBy: "test", CreatedAt: storetest.Now}); err != nil {
				return err
			}
			if err := c.InsertGrpDeadLetter(&store.GrpDeadLetter{SinkID: id, Seq: 7, EventType: "group.created", ObjectID: "g",
				Payload: `{"id":"x"}`, Attempts: 8, LastError: "boom", CreatedAt: storetest.Now}); err != nil {
				return err
			}
			return c.SetGrpCursor("sink:"+id, 0, storetest.Now)
		})
		if err != nil {
			t.Fatal(err)
		}
		ids[tn.Slug] = id
	}
	return ids
}

func TestIsolation_GroupEventSinks(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedSinks(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	now := storetest.Now
	later := now.Add(time.Hour)

	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.GrpSink(a); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GrpSink(A's) = %v, want ErrNotFound", err)
		}
		all, err := c.GrpSinks()
		if err != nil || len(all) != 1 || all[0].ID != b || all[0].Name != "main" || string(all[0].SecretEnc) != "sealed" ||
			len(all[0].EventTypes) != 1 {
			t.Errorf("GrpSinks() = %v, %v; want B's one", all, err)
		}
		if ds, err := c.GrpDeadLetters(a, "", 10); err != nil || len(ds) != 0 {
			t.Errorf("GrpDeadLetters(A's sink) = %d, %v; want none", len(ds), err)
		}
		if n, err := c.CountGrpDeadLetters(a, store.DeadLetterDead); err != nil || n != 0 {
			t.Errorf("CountGrpDeadLetters(A's sink) = %d, %v; want 0", n, err)
		}
		if _, err := c.GrpDeadLetter(a, 7); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GrpDeadLetter(A's sink) = %v, want ErrNotFound", err)
		}
		// writes that name A's sink change nothing
		if err := c.UpdateGrpSink(&store.GrpSink{ID: a, Name: "x", Config: json.RawMessage(`{}`)}, later); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateGrpSink(A's) = %v, want ErrNotFound", err)
		}
		if err := c.SetGrpSinkHealth(a, store.GrpSinkHealth{State: store.SinkOK, LastDeliveredAt: later}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetGrpSinkHealth(A's) = %v, want ErrNotFound", err)
		}
		if err := c.SetGrpDeadLetterStatus(a, 7, store.DeadLetterDiscarded, 1, "", later); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetGrpDeadLetterStatus(A's) = %v, want ErrNotFound", err)
		}
		if err := c.DeleteGrpSink(a); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteGrpSink(A's) = %v, want ErrNotFound", err)
		}
		return nil
	})
	// a dead letter that names A's sink is refused
	err := f.DB.InTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertGrpDeadLetter(&store.GrpDeadLetter{SinkID: a, Seq: 9, EventType: "group.created", ObjectID: "g", Payload: `{}`,
			Attempts: 1, LastError: "x", CreatedAt: now})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("InsertGrpDeadLetter(A's sink) in B = %v, want ErrCrossTenant", err)
	}

	// A is untouched by all of it, and the same name is free in each tenant
	inA(t, f, func(c *store.TenantTx) error {
		k, err := c.GrpSink(a)
		if err != nil || k.Name != "main" || k.State != store.SinkIdle || k.DeliveredCount != 0 {
			t.Errorf("A's sink = %+v, %v", k, err)
		}
		if n, err := c.CountGrpDeadLetters(a, store.DeadLetterDead); err != nil || n != 1 {
			t.Errorf("A's dead letters = %d, %v", n, err)
		}
		return nil
	})

	// health, dead-letter status and delete work inside the tenant, and delete takes the cursor with it
	inB(t, f, func(c *store.TenantTx) error {
		next := later.Add(time.Minute)
		if err := c.SetGrpSinkHealth(b, store.GrpSinkHealth{State: store.SinkRetrying, Attempts: 2, NextAttemptAt: &next, LastError: "e"}); err != nil {
			return err
		}
		if err := c.SetGrpSinkHealth(b, store.GrpSinkHealth{State: store.SinkOK, Delivered: 3, LastDeliveredSeq: 12, LastDeliveredAt: later}); err != nil {
			return err
		}
		k, err := c.GrpSink(b)
		if err != nil || k.State != store.SinkOK || k.DeliveredCount != 3 || k.LastDeliveredSeq != 12 || k.LastDeliveredAt == nil ||
			k.NextAttemptAt != nil || k.LastError != "" {
			t.Errorf("health = %+v, %v", k, err)
		}
		if err := c.SetGrpDeadLetterStatus(b, 7, store.DeadLetterRequeued, 8, "boom", later); err != nil {
			return err
		}
		if ds, err := c.GrpDeadLetters(b, store.DeadLetterRequeued, 10); err != nil || len(ds) != 1 {
			t.Errorf("requeued = %d, %v", len(ds), err)
		}
		if err := c.DeleteGrpSink(b); err != nil {
			return err
		}
		if _, err := c.GrpSink(b); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GrpSink after delete = %v", err)
		}
		if ds, err := c.GrpDeadLetters(b, "", 10); err != nil || len(ds) != 0 {
			t.Errorf("dead letters after delete = %d, %v", len(ds), err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		if _, err := c.GrpSink(a); err != nil {
			t.Errorf("A's sink after B's delete = %v", err)
		}
		if n, err := c.CountGrpDeadLetters(a, store.DeadLetterDead); err != nil || n != 1 {
			t.Errorf("A's dead letters after B's delete = %d, %v", n, err)
		}
		return nil
	})
}

// groupSinksCovered lists the repository methods of GR-18 that
// TestIsolation_GroupEventSinks exercises.
func groupSinksCovered() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{
		"InsertGrpSink", "GrpSink", "GrpSinks", "UpdateGrpSink", "SetGrpSinkHealth", "DeleteGrpSink",
		"InsertGrpDeadLetter", "GrpDeadLetter", "GrpDeadLetters", "CountGrpDeadLetters", "SetGrpDeadLetterStatus",
	} {
		m[name] = true
	}
	return m
}
