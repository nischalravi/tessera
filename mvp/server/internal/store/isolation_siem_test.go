package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// SIEM sink isolation (issue #169): a tenant sees and moves only its own
// sinks and dead letters, and no row may point at another tenant's sink or user.

func seedSiemSink(t *testing.T, f *storetest.Fixture, b bool, id string) {
	t.Helper()
	fn := func(c *store.TenantTx) error {
		return c.InsertSiemSink(&store.SiemSink{ID: id, Name: "sink " + id, Kind: "webhook", Format: "json", Target: "https://siem.example/x",
			Flavor: "json", Enabled: true, CursorSeq: 3, CreatedAt: storetest.Now, UpdatedAt: storetest.Now})
	}
	if b {
		inB(t, f, fn)
	} else {
		inA(t, f, fn)
	}
}

func TestIsolation_SiemSinks(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedSiemSink(t, f, false, "sink-a")
	seedSiemSink(t, f, true, "sink-b")
	inA(t, f, func(c *store.TenantTx) error {
		return c.DeadLetterSiemBatch(&store.SiemDeadLetter{ID: "dl-a", SinkID: "sink-a", FromSeq: 4, ToSeq: 5, Events: 2, Error: "400", CreatedAt: storetest.Now})
	})
	before := storetest.Dump(t, f.DB, f.A.ID)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		if ks, err := c.SiemSinks(); err != nil || len(ks) != 1 || ks[0].ID != "sink-b" {
			t.Errorf("SiemSinks = %v, %v", ks, err)
		}
		if _, err := c.SiemSink("sink-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SiemSink(A's) = %v", err)
		}
		if ds, err := c.SiemDeadLetters("sink-a"); err != nil || len(ds) != 0 {
			t.Errorf("SiemDeadLetters(A's) = %v, %v", ds, err)
		}
		for name, err := range map[string]error{
			"UpdateSiemSink":      c.UpdateSiemSink(&store.SiemSink{ID: "sink-a", Name: "x", Format: "json", Target: "x", UpdatedAt: now}),
			"AckSiemBatch":        c.AckSiemBatch("sink-a", 5, 9, 4, now),
			"FailSiemBatch":       c.FailSiemBatch("sink-a", 5, 1, now, "x"),
			"SetSiemCursor":       c.SetSiemCursor("sink-a", 0, now),
			"DeadLetterSiemBatch": c.DeadLetterSiemBatch(&store.SiemDeadLetter{ID: "dl-x", SinkID: "sink-a", FromSeq: 6, ToSeq: 6, Events: 1, Error: "x", CreatedAt: now}),
		} {
			if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s(A's) = %v", name, err)
			}
		}
		return nil
	})
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
}

// TestSiemCursorOptimistic: an ack or failure for a stale cursor changes nothing.
func TestSiemCursorOptimistic(t *testing.T) {
	f := storetest.TwoTenants(t)
	seedSiemSink(t, f, false, "sink-a")
	now := storetest.Now
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.AckSiemBatch("sink-a", 3, 10, 7, now); err != nil {
			return err
		}
		if err := c.AckSiemBatch("sink-a", 3, 12, 9, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("stale ack = %v", err)
		}
		if err := c.FailSiemBatch("sink-a", 3, 2, now.Add(time.Minute), "x"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("stale fail = %v", err)
		}
		k, err := c.SiemSink("sink-a")
		if err != nil || k.CursorSeq != 10 || k.DeliveredCount != 7 || k.LastSuccessAt == nil {
			t.Errorf("sink = %+v, %v", k, err)
		}
		return nil
	})
}

func siemCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"SiemSinks", "SiemSink", "InsertSiemSink", "UpdateSiemSink", "AckSiemBatch", "FailSiemBatch",
		"DeadLetterSiemBatch", "SetSiemCursor", "SiemDeadLetters"} {
		out[k] = true // TestIsolation_SiemSinks
	}
	return out
}
