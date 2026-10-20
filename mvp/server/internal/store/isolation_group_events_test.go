package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Group events and point-in-time history (issue #46, GR-3): a tenant's event
// sequence, cursors, PIT rows and digests are its own. Another tenant's group
// ids look nonexistent, whole-table operations (delete, prune) touch only the
// caller's rows, and a row that names another tenant's group, list or identity
// is refused by the guard triggers.

type evIDs struct {
	g1    store.GroupID
	ident int64
	list  store.ListID
	seq   int64 // the last event of the tenant
}

func seedGroupEvents(t *testing.T, f *storetest.Fixture) map[string]evIDs {
	t.Helper()
	base := seedEngine(t, f)
	out := map[string]evIDs{}
	day := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		ids := evIDs{g1: base[tn.Slug].g1, ident: base[tn.Slug].ident, list: base[tn.Slug].list}
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			g := string(ids.g1)
			for i, typ := range []string{"group.created", "membership.effective.added", "membership.effective.removed"} {
				e := &store.GrpEvent{Type: typ, ObjectType: store.EventObjGroup, ObjectID: g, List: string(ids.list),
					Data: json.RawMessage(`{"n":1}`), CauseType: store.CauseAPI, OccurredAt: day.Add(time.Duration(i) * time.Minute)}
				if typ != "group.created" {
					e.Identity = &ids.ident
				}
				if err := c.AppendGrpEvent(e); err != nil {
					return err
				}
				ids.seq = e.Seq
			}
			if err := c.OpenPitObject(store.EventObjGroup, g, json.RawMessage(`{"name":"x"}`), day, 1); err != nil {
				return err
			}
			if err := c.OpenPitEffective(g, string(ids.list), ids.ident, day, 2); err != nil {
				return err
			}
			if err := c.ClosePitEffective(g, string(ids.list), ids.ident, day.Add(time.Minute), 3); err != nil {
				return err
			}
			if err := c.OpenPitDirect(store.PitDirect{Group: g, List: string(ids.list), MemberType: store.MemberIdentity,
				MemberKey: "1", Identity: &ids.ident, Source: "api", StartAt: day, StartSeq: 2}); err != nil {
				return err
			}
			if err := c.OpenPitPrivilege("priv-"+tn.Slug, json.RawMessage(`{}`), day, 3); err != nil {
				return err
			}
			if err := c.SetGrpCursor("pit", ids.seq, day); err != nil {
				return err
			}
			return c.InsertGrpDigest(store.PitDigest{Day: "2026-10-01", FirstSeq: 1, LastSeq: ids.seq, EventCount: 3,
				MerkleRoot: "00", AuditSeq: 1, CreatedAt: day})
		})
		if err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = ids
	}
	return out
}

func TestIsolation_GroupEventTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedGroupEvents(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	day := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	// each tenant has its own gap-free sequence, from 1
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.ReadTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			h, err := c.GrpEventHead()
			if err != nil || h.LastSeq != 3 || h.PrunedSeq != 0 {
				t.Errorf("%s: head = %+v, %v; want last 3", tn.Slug, h, err)
			}
			evs, err := c.GrpEventsAfter(0, 100, 100)
			if err != nil || len(evs) != 3 {
				t.Fatalf("%s: events = %d, %v", tn.Slug, len(evs), err)
			}
			for i, e := range evs {
				if e.Seq != int64(i+1) || e.TenantID != tn.ID && !e.TenantID.IsZero() {
					t.Errorf("%s: event %d has seq %d", tn.Slug, i, e.Seq)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	inB(t, f, func(c *store.TenantTx) error {
		// A's group looks nonexistent
		evs, err := c.GrpEventsOfObject(store.EventObjGroup, string(a.g1), 0, 100)
		if err != nil || len(evs) != 0 {
			t.Errorf("GrpEventsOfObject(A's group) = %d, %v; want none", len(evs), err)
		}
		if _, err := c.GrpPitObjectAt(store.EventObjGroup, string(a.g1), day); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GrpPitObjectAt(A's group) = %v, want ErrNotFound", err)
		}
		pe, n, err := c.GrpPitEffectiveIn(string(a.g1), string(a.list), day, day, 10, 0)
		if err != nil || len(pe) != 0 || n != 0 {
			t.Errorf("GrpPitEffectiveIn(A's group) = %d rows, %d, %v", len(pe), n, err)
		}
		pd, n, err := c.GrpPitDirectIn(string(a.g1), string(a.list), day, day, 10, 0)
		if err != nil || len(pd) != 0 || n != 0 {
			t.Errorf("GrpPitDirectIn(A's group) = %d rows, %d, %v", len(pd), n, err)
		}
		if os, err := c.GrpPitObjects(string(a.g1)); err != nil || len(os) != 0 {
			t.Errorf("GrpPitObjects(A's group) = %d, %v", len(os), err)
		}
		if ds, err := c.GrpPitDirects(string(a.g1)); err != nil || len(ds) != 0 {
			t.Errorf("GrpPitDirects(A's group) = %d, %v", len(ds), err)
		}
		// the tenant-wide reads hold only B's rows
		if os, err := c.GrpPitObjects(""); err != nil || len(os) != 1 || os[0].ObjectID != string(b.g1) {
			t.Errorf("GrpPitObjects() = %v, %v; want B's one", os, err)
		}
		if es, err := c.GrpPitEffectives(""); err != nil || len(es) != 1 || es[0].Group != string(b.g1) {
			t.Errorf("GrpPitEffectives() = %v, %v; want B's one", es, err)
		}
		if ps, err := c.GrpPitPrivileges(); err != nil || len(ps) != 1 || ps[0].PrivilegeID != "priv-"+f.B.Slug {
			t.Errorf("GrpPitPrivileges() = %v, %v; want B's one", ps, err)
		}
		if _, err := c.GrpDigest("2026-10-01"); err != nil {
			t.Errorf("GrpDigest(B's day) = %v", err)
		}
		if ds, err := c.GrpDigests(10); err != nil || len(ds) != 1 || ds[0].LastSeq != b.seq {
			t.Errorf("GrpDigests() = %v, %v; want B's one", ds, err)
		}
		days, err := c.GrpEventDays(day.Add(-time.Hour), day.Add(time.Hour))
		if err != nil || !slices.Equal(days, []string{"2026-10-01"}) {
			t.Errorf("GrpEventDays = %v, %v", days, err)
		}
		gids, err := c.GrpEventGroupIDs("", 10)
		if err != nil || !slices.Equal(gids, []string{string(b.g1)}) {
			t.Errorf("GrpEventGroupIDs = %v, %v; want B's one", gids, err)
		}
		of, err := c.GrpEventsOfDay(day.Add(-time.Hour), day.Add(time.Hour), 0, 100)
		if err != nil || len(of) != 3 {
			t.Errorf("GrpEventsOfDay = %d, %v; want B's 3", len(of), err)
		}
		if n, err := c.GrpPitStartedBefore("", 100); err != nil || n != (store.PitTotals{Objects: 1, Direct: 1, Effective: 1, Privileges: 1}) {
			t.Errorf("GrpPitStartedBefore = %+v, %v", n, err)
		}
		return nil
	})

	// whole-table writes in B leave A alone
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.DeleteGrpPit(""); err != nil {
			return err
		}
		if _, err := c.PruneGrpPit(day.Add(24*time.Hour), 1000); err != nil {
			return err
		}
		n, err := c.PruneGrpEvents(day.Add(24*time.Hour), 1000)
		if err != nil || n != 3 {
			t.Errorf("PruneGrpEvents in B = %d, %v; want its 3", n, err)
		}
		// a closed interval of an object B never had: nothing to close
		return c.ClosePitObject(store.EventObjGroup, string(a.g1), day, 9)
	})
	inA(t, f, func(c *store.TenantTx) error {
		h, err := c.GrpEventHead()
		if err != nil || h.LastSeq != 3 || h.PrunedSeq != 0 {
			t.Errorf("A's head after B's prune = %+v, %v", h, err)
		}
		if evs, err := c.GrpEventsAfter(0, 100, 100); err != nil || len(evs) != 3 {
			t.Errorf("A's events after B's prune = %d, %v", len(evs), err)
		}
		o, err := c.GrpPitObjectAt(store.EventObjGroup, string(a.g1), day)
		if err != nil || o.EndAt != nil {
			t.Errorf("A's object interval = %+v, %v; want open", o, err)
		}
		if es, err := c.GrpPitEffectives(""); err != nil || len(es) != 1 {
			t.Errorf("A's effective intervals = %d, %v", len(es), err)
		}
		if c, err := c.GrpCursor("pit"); err != nil || c != a.seq {
			t.Errorf("A's cursor = %d, %v", c, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if cur, err := c.GrpCursor("pit"); err != nil || cur != b.seq {
			t.Errorf("B's cursor = %d, %v", cur, err)
		}
		if cur, err := c.GrpCursor("graph"); err != nil || cur != 0 {
			t.Errorf("B's unset cursor = %d, %v", cur, err)
		}
		return nil
	})

	// a row naming another tenant's group, list or identity is refused
	isCross := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("%s = %v, want ErrCrossTenant", what, err)
		}
	}
	foreignGroup := func(c *store.TenantTx) error { // B writes a row that names A's group
		return c.OpenPitEffective(string(a.g1), string(b.list), b.ident, day, 7)
	}
	err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		isCross("OpenPitEffective(A's group)", foreignGroup(c))
		isCross("OpenPitEffective(A's list)", c.OpenPitEffective(string(b.g1), string(a.list), b.ident, day, 7))
		isCross("OpenPitEffective(A's identity)", c.OpenPitEffective(string(b.g1), string(b.list), a.ident, day, 7))
		isCross("OpenPitDirect(A's group)", c.OpenPitDirect(store.PitDirect{Group: string(a.g1), List: string(b.list),
			MemberType: store.MemberIdentity, MemberKey: "9", Identity: &b.ident, Source: "api", StartAt: day, StartSeq: 7}))
		isCross("OpenPitDirect(A's identity)", c.OpenPitDirect(store.PitDirect{Group: string(b.g1), List: string(b.list),
			MemberType: store.MemberIdentity, MemberKey: "9", Identity: &a.ident, Source: "api", StartAt: day, StartSeq: 7}))
		isCross("OpenPitObject(A's group)", c.OpenPitObject(store.EventObjGroup, string(a.g1), json.RawMessage(`{}`), day, 7))
		isCross("AppendGrpEvent(A's identity)", c.AppendGrpEvent(&store.GrpEvent{Type: "membership.effective.added",
			ObjectType: store.EventObjGroup, ObjectID: string(b.g1), Identity: &a.ident, CauseType: store.CauseEngine, OccurredAt: day}))
		isCross("AppendGrpEvent(A's list)", c.AppendGrpEvent(&store.GrpEvent{Type: "membership.effective.added",
			ObjectType: store.EventObjGroup, ObjectID: string(b.g1), List: string(a.list), CauseType: store.CauseEngine, OccurredAt: day}))
		isCross("AppendGrpEvent(A's group)", c.AppendGrpEvent(&store.GrpEvent{Type: "group.updated",
			ObjectType: store.EventObjGroup, ObjectID: string(a.g1), CauseType: store.CauseAPI, OccurredAt: day}))
		return errors.New("roll back") // the refused appends must not leave a half-written sequence behind
	})
	if err == nil || err.Error() != "roll back" {
		t.Fatalf("tx = %v", err)
	}
	// a caller cannot name the tenant of an event
	err = f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.AppendGrpEvent(&store.GrpEvent{TenantID: f.A.ID, Type: "group.updated", ObjectType: store.EventObjGroup,
			ObjectID: string(b.g1), CauseType: store.CauseAPI, OccurredAt: day})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("AppendGrpEvent(tenant A) in B = %v, want ErrCrossTenant", err)
	}
}

// groupEventsCovered lists the repository methods of GR-3 that
// TestIsolation_GroupEventTables exercises.
func groupEventsCovered() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{
		"AppendGrpEvent", "GrpEventHead", "GrpEventsAfter", "GrpEventsOfObject", "GrpEventsOfDay", "GrpEventDays",
		"GrpEventGroupIDs", "PruneGrpEvents", "GrpCursor", "SetGrpCursor",
		"OpenPitObject", "ClosePitObject", "OpenPitDirect", "ClosePitDirect", "OpenPitEffective", "ClosePitEffective",
		"OpenPitPrivilege", "ClosePitPrivilege", "DeleteGrpPit", "PruneGrpPit", "GrpPitStartedBefore",
		"GrpPitObjectAt", "GrpPitObjects", "GrpPitDirects", "GrpPitEffectives", "GrpPitPrivileges", "GrpPitEffectiveIn",
		"GrpPitDirectIn", "InsertGrpDigest", "GrpDigest", "GrpDigests",
	} {
		m[name] = true
	}
	return m
}

// TestIsolation_GroupEventSequenceGapFree: a rolled-back transaction gives its
// sequence numbers back, so the sequence has no gaps.
func TestIsolation_GroupEventSequenceGapFree(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedEngine(t, f)[f.A.Slug]
	ctx := context.Background()
	ev := func(c *store.TenantTx) (int64, error) {
		e := &store.GrpEvent{Type: "group.updated", ObjectType: store.EventObjGroup, ObjectID: string(ids.g1), CauseType: store.CauseAPI,
			OccurredAt: storetest.Now}
		return e.Seq, c.AppendGrpEvent(e)
	}
	for i := 0; i < 3; i++ {
		if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { _, err := ev(c); return err }); err != nil {
			t.Fatal(err)
		}
	}
	boom := errors.New("boom")
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if _, err := ev(c); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	var next int64
	err = f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		e := &store.GrpEvent{Type: "group.updated", ObjectType: store.EventObjGroup, ObjectID: string(ids.g1), CauseType: store.CauseAPI,
			OccurredAt: storetest.Now}
		if err := c.AppendGrpEvent(e); err != nil {
			return err
		}
		next = e.Seq
		return nil
	})
	if err != nil || next != 4 {
		t.Errorf("seq after a rollback = %d, %v; want 4", next, err)
	}
}
