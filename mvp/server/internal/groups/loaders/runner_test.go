package loaders_test

import (
	"context"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

func (h *harness) runner() *loaders.Runner { return &loaders.Runner{Svc: h.svc} }

func (h *harness) once() {
	h.t.Helper()
	if err := h.runner().Once(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

// TestRunner_RunsDueLoaders: the scheduler runs a loader when its cron schedule
// has fired, not before and not twice; a failed run waits for the next firing; a
// held or disabled loader is left alone; an incremental loader runs every
// incremental_secs once it has had a full load.
func TestRunner_RunsDueLoaders(t *testing.T) {
	h := newHarness(t)
	h.write("staff.csv", people(seq(0, 3)...))
	daily := h.create(h.csvSpec("Daily", "staff.csv", "daily"), "") // @daily, created 2026-10-08 09:30
	broken := h.create(h.csvSpec("Broken", "nowhere.csv", "broken"), "")
	held := h.create(h.csvSpec("Held", "staff.csv", "held"), "")
	disabled := h.create(h.csvSpec("Off", "staff.csv", "off"), "")
	if err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		if err := tx.SetGrpLoaderStatus(held.ID, store.LoaderHeld, h.now); err != nil {
			return err
		}
		return tx.SetGrpLoaderStatus(disabled.ID, store.LoaderDisabled, h.now)
	}); err != nil {
		t.Fatal(err)
	}

	h.once() // nothing is due the day it was made
	for _, l := range []*store.GrpLoader{daily, broken, held, disabled} {
		if n := len(h.runs(l.ID)); n != 0 {
			t.Errorf("loader %s ran %d times before its schedule fired", l.Name, n)
		}
	}
	h.now = time.Date(2026, 10, 9, 0, 0, 30, 0, time.UTC) // midnight has passed
	h.once()
	if rs := h.runs(daily.ID); len(rs) != 1 || rs[0].Status != store.RunApplied || rs[0].RequestedBy != nil {
		t.Fatalf("daily runs = %+v", rs)
	}
	wantMembers(t, h, "ref:daily", seq(0, 3))
	if rs := h.runs(broken.ID); len(rs) != 1 || rs[0].Status != store.RunFailed {
		t.Errorf("broken runs = %+v", rs)
	}
	for _, l := range []*store.GrpLoader{held, disabled} {
		if n := len(h.runs(l.ID)); n != 0 {
			t.Errorf("loader %s (%s) ran", l.Name, h.loader(l.ID).Status)
		}
	}
	// a second pass the same minute runs nothing, a failed loader included
	h.now = h.now.Add(time.Minute)
	h.once()
	if n := len(h.runs(daily.ID)); n != 1 {
		t.Errorf("daily ran %d times in a day", n)
	}
	if n := len(h.runs(broken.ID)); n != 1 {
		t.Errorf("broken ran %d times in a day: a failed run must wait for the next firing", n)
	}
	// the next day both run again
	h.now = time.Date(2026, 10, 10, 0, 1, 0, 0, time.UTC)
	h.once()
	if n := len(h.runs(daily.ID)); n != 2 {
		t.Errorf("daily ran %d times in two days", n)
	}
	if n := len(h.runs(broken.ID)); n != 2 {
		t.Errorf("broken ran %d times in two days", n)
	}
	// the job status says when it runs next and how long since it applied
	h.read(func(tx *store.TenantTx) error {
		st, err := loaders.StatusOf(tx, h.loader(daily.ID), h.now)
		if err != nil {
			return err
		}
		if st.State != "idle" || !st.NextFull.Equal(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)) || st.LastRun == nil || st.LagSeconds != 0 {
			t.Errorf("status = %+v", st)
		}
		hs, err := loaders.StatusOf(tx, h.loader(held.ID), h.now)
		if err != nil {
			return err
		}
		if hs.State != "held" || !hs.NextFull.IsZero() || hs.LagSeconds != -1 {
			t.Errorf("held status = %+v", hs)
		}
		ds, err := loaders.StatusOf(tx, h.loader(disabled.ID), h.now)
		if err != nil || ds.State != "disabled" {
			t.Errorf("disabled status = %+v, %v", ds, err)
		}
		return nil
	})

	// incremental: every 60 seconds after a full load
	h.hrAdd("hr.db", hrRow{xid: "u0", dept: "eng", title: "u0"}, hrRow{xid: "u1", dept: "eng", title: "u1"})
	secs := int64(60)
	inc := h.create(loaders.Spec{Name: "Inc", Type: loaders.TypeSQLGroupList, TargetFolder: string(h.folder("inc")), IncrementalSecs: &secs,
		Schedule: "0 3 * * *", Config: []byte(`{"database":"hr.db",
			"query":"SELECT department AS group_name, external_id AS subject_id FROM identities",
			"incremental_query":"SELECT department AS group_name, title AS subject_id, 'add' AS op, id AS seq FROM identities WHERE id > @cursor ORDER BY id"}`)}, "")
	h.now = time.Date(2026, 10, 11, 3, 0, 30, 0, time.UTC)
	h.once() // the full load (its schedule has fired)
	if rs := h.runs(inc.ID); len(rs) != 1 || rs[0].Kind != store.RunFull {
		t.Fatalf("inc runs = %+v", rs)
	}
	h.hrAdd("hr.db", hrRow{xid: "u2", dept: "eng", title: "u2"})
	h.now = h.now.Add(30 * time.Second)
	h.once() // too soon
	if n := len(h.runs(inc.ID)); n != 1 {
		t.Errorf("inc ran %d times inside its interval", n)
	}
	h.now = h.now.Add(40 * time.Second)
	h.once()
	rs := h.runs(inc.ID)
	if len(rs) != 2 || rs[0].Kind != store.RunIncremental || rs[0].Status != store.RunApplied {
		t.Fatalf("inc runs = %+v", rs)
	}
	wantMembers(t, h, "inc:eng", []string{"u0", "u1", "u2"})
}

// TestRun_OtherTenantsLoader: a loader and its runs belong to one tenant; another
// tenant's request for them is a not-found and changes nothing.
func TestRun_OtherTenantsLoader(t *testing.T) {
	h := newHarness(t)
	h.write("staff.csv", people(seq(0, 10)...))
	l := h.create(h.csvSpec("Staff", "staff.csv", "staff"), "")
	h.run(l, store.RunFull)
	h.write("staff.csv", people(seq(0, 2)...))
	h.now = h.now.Add(time.Hour)
	held := h.run(l, store.RunFull)
	if held.Status != store.RunHeld {
		t.Fatalf("run = %+v", held)
	}
	other := tenancy.MustParse("00000000-0000-4000-8000-0000000000f7")
	if err := h.db.InSystem(context.Background(), "test", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: other, Slug: "other", Name: "other", CreatedAt: t0})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := h.svc.Run(ctx, other, l.ID, store.RunFull, loaders.Actor{}); errCode(err) != "not_found" {
		t.Errorf("run of another tenant's loader = %v", err)
	}
	if _, err := h.svc.Approve(ctx, other, l.ID, held.ID, loaders.Actor{}); errCode(err) != "not_found" {
		t.Errorf("approve of another tenant's run = %v", err)
	}
	if _, err := h.svc.Reject(ctx, other, l.ID, held.ID, loaders.Actor{}); errCode(err) != "not_found" {
		t.Errorf("reject of another tenant's run = %v", err)
	}
	wantMembers(t, h, "ref:staff", seq(0, 10))
	if got := h.loader(l.ID).Status; got != store.LoaderHeld {
		t.Errorf("loader status = %s, want still held", got)
	}
	// a loader's run is not another loader's
	l2 := h.create(h.csvSpec("Other", "staff.csv", "other"), "")
	if _, err := h.svc.Approve(ctx, tid, l2.ID, held.ID, loaders.Actor{}); errCode(err) != "not_found" {
		t.Errorf("approve of a run through another loader = %v", err)
	}
}
