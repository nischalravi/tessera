package pit_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// replayAt rebuilds every group's members at a moment from the events alone:
// each effective.added / effective.removed that occurred at or before the
// moment, in seq order. It shares no code with the PIT tables.
func replayAt(evs []*events.Event, at time.Time) map[string][]int64 {
	set := map[string]map[int64]bool{}
	for _, e := range evs {
		if e.OccurredAt.After(at) {
			continue
		}
		switch e.Type {
		case events.MembershipEffectiveAdded:
			if set[e.ObjectID] == nil {
				set[e.ObjectID] = map[int64]bool{}
			}
			set[e.ObjectID][*e.Identity] = true
		case events.MembershipEffectiveRemoved:
			delete(set[e.ObjectID], *e.Identity)
		}
	}
	out := map[string][]int64{}
	for g, m := range set {
		ids := []int64{}
		for id := range m {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		out[g] = ids
	}
	return out
}

func memberIDs(rows []*store.PitEffective) []int64 {
	ids := []int64{}
	for _, r := range rows {
		if !slices.Contains(ids, r.Identity) {
			ids = append(ids, r.Identity)
		}
	}
	slices.Sort(ids)
	return ids
}

// TestPIT_AsOfMatchesReplay: after a long random history, the members of every
// group at every recorded moment are what the group had then (read live at the
// time), and what an independent replay of the events says.
func TestPIT_AsOfMatchesReplay(t *testing.T) {
	for seed := int64(1); seed <= 4; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			x := newHarness(t, 4, 6)
			snaps := x.randomRun(seed, 60)
			evs := x.allEvents()
			if len(evs) < 50 {
				t.Fatalf("only %d events: the random run did too little", len(evs))
			}
			nonEmpty := 0
			x.read(func(tx *store.TenantTx) error {
				for _, s := range snaps {
					replay := replayAt(evs, s.at)
					for _, g := range x.groups {
						want := s.members[g]
						got, n, err := pit.MembersAt(tx, g, x.list(), s.at, 1000, 0)
						if err != nil {
							return err
						}
						if ids := memberIDs(got); !slices.Equal(ids, want) || n != len(want) {
							t.Errorf("at %s group %s: PIT %v (total %d), live then %v", s.at.Format(time.RFC3339), g, ids, n, want)
						}
						if r := replay[string(g)]; len(r)+len(want) > 0 && !slices.Equal(r, want) {
							t.Errorf("at %s group %s: replay %v, live then %v", s.at.Format(time.RFC3339), g, r, want)
						}
						if len(want) > 0 {
							nonEmpty++
						}
					}
				}
				return nil
			})
			if nonEmpty < 20 {
				t.Errorf("only %d non-empty memberships were compared", nonEmpty)
			}
		})
	}
}

// TestPIT_BetweenFindsAnyoneInTheWindow: between returns an identity that was a
// member at any time in the window, including one who left inside it.
func TestPIT_BetweenFindsAnyoneInTheWindow(t *testing.T) {
	x := newHarness(t, 2, 3)
	g := x.groups[0]
	a, b, c := x.idents[0], x.idents[1], x.idents[2]
	add := func(id int64) {
		x.must(func(e model.Env) error { _, err := e.AddMember(g, model.MemberInput{Identity: &id}); return err })
	}
	remove := func(id int64) {
		x.must(func(e model.Env) error { _, err := e.RemoveMember(g, fmt.Sprint(id)); return err })
	}
	add(a)               // t0
	x.advance(time.Hour) // t0+1h
	add(b)               // b from t0+1h
	x.advance(time.Hour) // t0+2h
	remove(a)            // a until t0+2h (exclusive)
	x.advance(time.Hour) // t0+3h
	add(c)               // c from t0+3h
	x.advance(time.Hour) // t0+4h
	remove(b)            // b until t0+4h
	between := func(from, to time.Duration) []int64 {
		var ids []int64
		x.read(func(tx *store.TenantTx) error {
			rows, _, err := pit.MembersBetween(tx, g, x.list(), t0.Add(from), t0.Add(to), 100, 0)
			ids = memberIDs(rows)
			return err
		})
		return ids
	}
	want := func(ids ...int64) []int64 { slices.Sort(ids); return ids }
	for _, c := range []struct {
		name     string
		from, to time.Duration
		want     []int64
	}{
		{"before anything", -time.Hour, -time.Minute, want()},
		{"first instant", 0, 0, want(a)},
		{"a alone", 0, 30 * time.Minute, want(a)},
		{"a leaves while b is in", 90 * time.Minute, 2 * time.Hour, want(a, b)},
		{"just after a left", 2*time.Hour + time.Minute, 2*time.Hour + 2*time.Minute, want(b)},
		{"c joins", 3 * time.Hour, 3*time.Hour + time.Minute, want(b, c)},
		{"all of it", 0, 5 * time.Hour, want(a, b, c)},
		{"after b left", 4*time.Hour + time.Minute, 5 * time.Hour, want(c)},
	} {
		if got := between(c.from, c.to); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	x.read(func(tx *store.TenantTx) error {
		if _, _, err := pit.MembersBetween(tx, g, x.list(), t0.Add(time.Hour), t0, 10, 0); !errors.Is(err, pit.ErrWindow) {
			t.Errorf("a window that ends before it starts = %v, want ErrWindow", err)
		}
		if _, _, err := pit.MembersBetween(tx, g, x.list(), t0, t0.Add(pit.MaxWindow+time.Hour), 10, 0); !errors.Is(err, pit.ErrWindow) {
			t.Errorf("a window over the maximum = %v, want ErrWindow", err)
		}
		return nil
	})
}

// TestPIT_ObjectsAndDirectHistory: renames, moves, status changes and direct
// rows (with their dates) are kept as intervals.
func TestPIT_ObjectsAndDirectHistory(t *testing.T) {
	x := newHarness(t, 2, 2)
	g := x.groups[0]
	id := x.idents[0]
	var folder store.FolderID
	x.must(func(e model.Env) error {
		f, err := e.CreateFolder(model.CreateFolderInput{Extension: "app"})
		folder = f.ID
		return err
	})
	x.advance(time.Hour) // t0+1h
	x.must(func(e model.Env) error {
		ext := "renamed"
		_, err := e.UpdateGroup(g, model.UpdateGroupInput{Extension: &ext})
		return err
	})
	x.advance(time.Hour) // t0+2h
	x.must(func(e model.Env) error { _, err := e.MoveGroup(g, folder); return err })
	x.advance(time.Hour) // t0+3h
	to := x.now.Add(10 * time.Hour)
	x.must(func(e model.Env) error { _, err := e.AddMember(g, model.MemberInput{Identity: &id}); return err })
	x.advance(time.Hour) // t0+4h
	x.must(func(e model.Env) error {
		_, err := e.AddMember(g, model.MemberInput{Identity: &id, DisabledAt: &to})
		return err
	})
	x.advance(time.Hour) // t0+5h
	status := store.GroupDisabled
	x.must(func(e model.Env) error {
		_, err := e.UpdateGroup(g, model.UpdateGroupInput{Status: &status})
		return err
	})
	x.advance(time.Hour) // t0+6h
	x.must(func(e model.Env) error { return e.DeleteGroup(g) })
	x.advance(time.Hour) // t0+7h
	x.must(func(e model.Env) error { _, err := e.RestoreGroup(g); return err })

	type snap struct {
		Name, Status, Folder string
	}
	at := func(h int) snap {
		var s snap
		x.read(func(tx *store.TenantTx) error {
			o, err := pit.ObjectAt(tx, store.EventObjGroup, string(g), t0.Add(time.Duration(h)*time.Hour))
			if err != nil {
				return err
			}
			var m struct {
				Name     string `json:"name"`
				Status   string `json:"status"`
				FolderID string `json:"folder_id"`
			}
			if err := json.Unmarshal(o.Snapshot, &m); err != nil {
				return err
			}
			s = snap{m.Name, m.Status, m.FolderID}
			return nil
		})
		return s
	}
	if s := at(0); s.Name != "g0" || s.Status != "active" || s.Folder != string(x.root) {
		t.Errorf("at 0h: %+v", s)
	}
	if s := at(1); s.Name != "renamed" {
		t.Errorf("at 1h (after the rename): %+v", s)
	}
	if s := at(2); s.Name != "app:renamed" || s.Folder != string(folder) {
		t.Errorf("at 2h (after the move): %+v", s)
	}
	for h, want := range map[int]string{4: "active", 5: "disabled", 6: "deleted", 7: "active"} {
		if s := at(h); s.Status != want {
			t.Errorf("at %dh: status %q, want %q", h, s.Status, want)
		}
	}
	x.read(func(tx *store.TenantTx) error {
		if _, err := pit.ObjectAt(tx, store.EventObjGroup, string(g), t0.Add(-time.Hour)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("before the group existed: %v, want ErrNotFound", err)
		}
		// the direct row was added at 3h and its dates changed at 4h: two intervals
		rows, n, err := pit.DirectBetween(tx, g, x.list(), t0.Add(3*time.Hour), t0.Add(8*time.Hour), 10, 0)
		if err != nil || n != 2 || len(rows) != 2 {
			t.Fatalf("direct rows = %d (%d), %v; want 2", len(rows), n, err)
		}
		if rows[0].DisabledAt != nil || rows[1].DisabledAt == nil || !rows[1].DisabledAt.Equal(to) {
			t.Errorf("the dates of the direct intervals: %+v %+v", rows[0], rows[1])
		}
		if rows[0].EndSeq == nil || rows[1].EndSeq != nil || rows[0].EndAt == nil || !rows[0].EndAt.Equal(t0.Add(4*time.Hour)) {
			t.Errorf("the first direct interval must close when the dates change: %+v", rows[0])
		}
		now, _, err := pit.DirectAt(tx, g, x.list(), t0.Add(3*time.Hour+time.Minute), 10, 0)
		if err != nil || len(now) != 1 || now[0].DisabledAt != nil {
			t.Errorf("DirectAt(3h+1m) = %v, %v", now, err)
		}
		return nil
	})
}

// TestPIT_PrivilegeIntervals: privilege events (GR-4 will emit them) open and
// close intervals.
func TestPIT_PrivilegeIntervals(t *testing.T) {
	x := newHarness(t, 2, 1)
	emit := func(typ string, at time.Time, data json.RawMessage) {
		x.t.Helper()
		x.must(func(e model.Env) error {
			ev := events.New(typ, "priv-1", at, store.CauseAPI)
			ev.Data = data
			return pit.Emit(e.Tx, ev)
		})
	}
	emit(events.PrivilegeGranted, t0, events.Data(map[string]any{"snapshot": map[string]any{"privilege": "admin"}}))
	emit(events.PrivilegeRevoked, t0.Add(time.Hour), nil)
	emit(events.PrivilegeGranted, t0.Add(2*time.Hour), events.Data(map[string]any{"snapshot": map[string]any{"privilege": "read"}}))
	x.read(func(tx *store.TenantTx) error {
		ps, err := tx.GrpPitPrivileges()
		if err != nil || len(ps) != 2 {
			t.Fatalf("intervals = %d, %v", len(ps), err)
		}
		if ps[0].EndAt == nil || !ps[0].EndAt.Equal(t0.Add(time.Hour)) || ps[1].EndAt != nil {
			t.Errorf("intervals: %+v %+v", ps[0], ps[1])
		}
		return nil
	})
	err := x.run(func(e model.Env) error {
		return pit.Emit(e.Tx, events.New(events.PrivilegeGranted, "priv-2", t0, store.CauseAPI)) // no snapshot
	})
	if err == nil {
		t.Error("a grant without a snapshot was accepted")
	}
}

// TestEvents_GapFreeSeqUnderConcurrency: writers racing in one tenant, through
// the model and through the outbox directly, leave seq 1..n without a gap, and
// failed transactions leave no hole.
func TestEvents_GapFreeSeqUnderConcurrency(t *testing.T) {
	x := newHarness(t, 3, 8)
	const workers, perWorker = 8, 12
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := x.idents[(w+i)%len(x.idents)]
				g := x.groups[(w+i)%3]
				err := x.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
					e := model.Env{Tx: tx, Now: x.now.Add(time.Duration(w*perWorker+i) * time.Second), Engine: x.eng}
					switch i % 4 {
					case 0:
						_, err := e.AddMember(g, model.MemberInput{Identity: &id})
						return err
					case 1:
						_, err := e.RemoveMember(g, fmt.Sprint(id))
						if me := (*model.Error)(nil); errors.As(err, &me) && me.Kind == model.NotFound {
							return nil
						}
						return err
					case 2:
						// a transaction that fails after taking a number must give it back
						ev := events.New(events.RuleFired, fmt.Sprintf("rule-%d", w), e.Now, store.CauseRule)
						if err := pit.Emit(tx, ev); err != nil {
							return err
						}
						return errors.New("abandoned")
					default:
						return pit.Emit(tx, events.New(events.RuleFired, fmt.Sprintf("rule-%d", w), e.Now, store.CauseRule))
					}
				})
				if err != nil && err.Error() != "abandoned" {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	evs := x.allEvents()
	if len(evs) < workers*perWorker/2 {
		t.Fatalf("only %d events", len(evs))
	}
	for i, e := range evs {
		if e.Seq != int64(i+1) {
			t.Fatalf("event %d has seq %d: the sequence has a gap or a duplicate", i, e.Seq)
		}
	}
	x.read(func(tx *store.TenantTx) error {
		h, err := tx.GrpEventHead()
		if err != nil || h.LastSeq != int64(len(evs)) {
			t.Errorf("head = %+v, %v; want last %d", h, err, len(evs))
		}
		cur, err := tx.GrpCursor(pit.Consumer)
		if err != nil || cur != h.LastSeq {
			t.Errorf("pit cursor = %d, %v; want %d", cur, err, h.LastSeq)
		}
		return nil
	})
	// the PIT rows the writers made are what a rebuild makes
	live := x.dump("")
	x.must(func(e model.Env) error { _, err := pit.Rebuild(e.Tx, ""); return err })
	if !live.Equal(x.dump("")) {
		t.Error("PIT rows written concurrently differ from a rebuild")
	}
}

func (x *harness) dump(group string) *pit.Snapshot {
	x.t.Helper()
	var s *pit.Snapshot
	x.read(func(tx *store.TenantTx) error {
		var err error
		s, err = pit.Dump(tx, group)
		return err
	})
	return s
}

// TestPIT_RebuildEqualsLive: dropping the derived tables and replaying the
// events gives back exactly the rows the writer made, for the whole tenant and
// for one group; and a damaged group is found and repaired by the comparison.
func TestPIT_RebuildEqualsLive(t *testing.T) {
	x := newHarness(t, 4, 6)
	x.randomRun(7, 80)
	live := x.dump("")
	if tot := live.Totals(); tot.Objects < 5 || tot.Direct < 5 || tot.Effective < 10 {
		t.Fatalf("the scenario made too little history: %+v", tot)
	}
	// one group
	for _, g := range x.groups {
		before := x.dump(string(g))
		x.must(func(e model.Env) error { _, err := pit.Rebuild(e.Tx, string(g)); return err })
		if !before.Equal(x.dump(string(g))) {
			t.Errorf("rebuilding group %s changed its rows", g)
		}
	}
	if !live.Equal(x.dump("")) {
		t.Error("the tenant's rows changed after rebuilding every group")
	}
	// the whole tenant
	var n int64
	x.must(func(e model.Env) error {
		var err error
		n, err = pit.Rebuild(e.Tx, "")
		return err
	})
	if n != int64(len(x.allEvents())) {
		t.Errorf("rebuild replayed %d events, the outbox has %d", n, len(x.allEvents()))
	}
	if after := x.dump(""); !live.Equal(after) {
		t.Errorf("rebuild differs from live: %+v vs %+v", live.Totals(), after.Totals())
	}
	// damage one group's rows: the comparison notices and repairs
	g := x.groups[0]
	x.must(func(e model.Env) error { return e.Tx.DeleteGrpPit(string(g)) })
	if x.dump("").Equal(live) {
		t.Fatal("deleting a group's PIT rows changed nothing")
	}
	var cmp *pit.Comparison
	x.must(func(e model.Env) error {
		var err error
		cmp, err = pit.CompareRebuild(e.Tx, string(g))
		return err
	})
	if cmp.Equal || cmp.Before.Effective != 0 || cmp.After.Effective == 0 {
		t.Errorf("comparison of a damaged group = %+v", cmp)
	}
	if !live.Equal(x.dump("")) {
		t.Error("the comparison did not repair the group")
	}
	x.must(func(e model.Env) error {
		cmp, _ = pit.CompareRebuild(e.Tx, string(g))
		return nil
	})
	if !cmp.Equal {
		t.Errorf("a healthy group compared unequal: %+v", cmp)
	}
}

// TestPIT_DigestDetectsTamper: a day's digest verifies until an event of that
// day is edited, deleted or invented.
func TestPIT_DigestDetectsTamper(t *testing.T) {
	x := newHarness(t, 2, 3)
	day1 := pit.Day(t0)
	for i := 0; i < 3; i++ {
		id := x.idents[i]
		x.must(func(e model.Env) error {
			_, err := e.AddMember(x.groups[0], model.MemberInput{Identity: &id})
			return err
		})
		x.advance(10 * time.Minute)
	}
	x.now = t0.Add(24 * time.Hour) // day 2
	x.must(func(e model.Env) error {
		_, err := e.AddMember(x.groups[1], model.MemberInput{Identity: &x.idents[0]})
		return err
	})

	var d *store.PitDigest
	x.must(func(e model.Env) error {
		if _, _, err := pit.WriteDigest(e.Tx, pit.Day(x.now), x.now); !errors.Is(err, pit.ErrDayOpen) {
			t.Errorf("digest of an unfinished day = %v, want ErrDayOpen", err)
		}
		var created bool
		var err error
		if d, created, err = pit.WriteDigest(e.Tx, day1, x.now); err != nil || !created {
			t.Fatalf("WriteDigest = %v, %v, %v", d, created, err)
		}
		if d2, created, err := pit.WriteDigest(e.Tx, day1, x.now); err != nil || created || d2.MerkleRoot != d.MerkleRoot {
			t.Errorf("a second WriteDigest = %v, %v, %v; want the stored one", d2, created, err)
		}
		if _, _, err := pit.WriteDigest(e.Tx, "2020-01-01", x.now); !errors.Is(err, pit.ErrNoEvents) {
			t.Errorf("digest of a day without events = %v, want ErrNoEvents", err)
		}
		if _, _, err := pit.WriteDigest(e.Tx, "tomorrow", x.now); !errors.Is(err, pit.ErrBadDay) {
			t.Errorf("digest of a bad day = %v, want ErrBadDay", err)
		}
		return nil
	})
	if d.EventCount < 6 || d.FirstSeq != 1 || len(d.MerkleRoot) != 64 {
		t.Fatalf("digest = %+v", d)
	}
	verify := func() pit.Verdict {
		var v pit.Verdict
		x.read(func(tx *store.TenantTx) error {
			var err error
			v, err = pit.VerifyDay(tx, day1)
			return err
		})
		return v
	}
	if v := verify(); !v.OK() {
		t.Fatalf("an untouched day: %+v", v)
	}
	// the digest is in the audit ledger, with the same root
	x.read(func(tx *store.TenantTx) error {
		ev, err := tx.AuditEventBySeq(d.AuditSeq)
		if err != nil || ev.Action != pit.ActionDigest {
			t.Fatalf("ledger event %d = %+v, %v", d.AuditSeq, ev, err)
		}
		var detail map[string]any
		if err := json.Unmarshal(ev.Detail, &detail); err != nil || detail["root"] != d.MerkleRoot || detail["day"] != day1 {
			t.Errorf("ledger detail = %v, %v", detail, err)
		}
		return nil
	})
	// day 2 has no digest: that is reported, not an error
	x.read(func(tx *store.TenantTx) error {
		if v, err := pit.VerifyDay(tx, pit.Day(x.now)); err != nil || v.Status != pit.VerdictNoDigest {
			t.Errorf("a day without a digest = %+v, %v", v, err)
		}
		return nil
	})

	ctx := context.Background()
	tamper, err := x.db.TamperForTest()
	if err != nil {
		t.Fatal(err)
	}
	if err := tamper.DropTriggers(ctx); err != nil {
		t.Fatal(err)
	}
	// an edit of one event's data
	if err := tamper.EditGrpEventData(ctx, tid, 4, `{"rewritten":true}`); err != nil {
		t.Fatal(err)
	}
	if v := verify(); v.Status != pit.VerdictMismatch || v.Got == v.Expected {
		t.Errorf("after an edit: %+v", v)
	}
	// the edit is not repaired by waiting; deleting another event is found as well
	if err := tamper.DeleteGrpEvent(ctx, tid, 5); err != nil {
		t.Fatal(err)
	}
	if v := verify(); v.Status != pit.VerdictMismatch {
		t.Errorf("after a delete: %+v", v)
	}
}

// TestPIT_DigestDetectsInventedAndMissingEvents covers the other two ways of
// changing a day: an event added to it afterwards, and every event removed.
func TestPIT_DigestDetectsInventedAndMissingEvents(t *testing.T) {
	x := newHarness(t, 2, 2)
	day1 := pit.Day(t0)
	x.must(func(e model.Env) error {
		_, err := e.AddMember(x.groups[0], model.MemberInput{Identity: &x.idents[0]})
		return err
	})
	x.now = t0.Add(25 * time.Hour)
	x.must(func(e model.Env) error { _, _, err := pit.WriteDigest(e.Tx, day1, x.now); return err })
	verdict := func() pit.Verdict {
		var v pit.Verdict
		x.read(func(tx *store.TenantTx) error {
			var err error
			v, err = pit.VerifyDay(tx, day1)
			return err
		})
		return v
	}
	if v := verdict(); !v.OK() {
		t.Fatalf("%+v", v)
	}
	// an event dated in the digested day, appended later (a clock or a forger)
	x.must(func(e model.Env) error {
		return pit.Emit(e.Tx, events.New(events.RuleFired, "late", t0.Add(time.Hour), store.CauseRule))
	})
	if v := verdict(); v.Status != pit.VerdictMismatch {
		t.Errorf("an event added to a digested day: %+v", v)
	}
	tamper, err := x.db.TamperForTest()
	if err != nil {
		t.Fatal(err)
	}
	head := x.allEvents()
	for _, e := range head {
		if err := tamper.DeleteGrpEvent(context.Background(), tid, e.Seq); err != nil {
			t.Fatal(err)
		}
	}
	if v := verdict(); v.Status != pit.VerdictMismatch {
		t.Errorf("every event gone: %+v", v)
	}
}

// TestPIT_RetentionPrunesAndKeepsDigests: events and intervals older than the
// window go, only after they were digested; the digest stays and verifies as
// pruned; a rebuild that would lose history refuses.
func TestPIT_RetentionPrunesAndKeepsDigests(t *testing.T) {
	x := newHarness(t, 2, 3)
	a, b := x.idents[0], x.idents[1]
	add := func(g store.GroupID, id int64) {
		x.must(func(e model.Env) error { _, err := e.AddMember(g, model.MemberInput{Identity: &id}); return err })
	}
	add(x.groups[0], a) // day 0: a joins g0 and stays
	add(x.groups[1], b) // day 0: b joins g1 ...
	x.advance(time.Hour)
	x.must(func(e model.Env) error { _, err := e.RemoveMember(x.groups[1], fmt.Sprint(b)); return err }) // ... and leaves
	x.now = t0.Add(10 * 24 * time.Hour)
	add(x.groups[1], b) // day 10: recent history

	prune := func(days int) *pit.PruneResult {
		var r *pit.PruneResult
		x.must(func(e model.Env) error {
			var err error
			r, err = pit.Prune(e.Tx, x.now, days)
			return err
		})
		return r
	}
	// nothing is digested yet, so nothing may go
	if r := prune(5); r.Events != 0 {
		t.Errorf("pruned %d undigested events", r.Events)
	}
	x.must(func(e model.Env) error { _, _, err := pit.WriteDigest(e.Tx, pit.Day(t0), x.now); return err })
	r := prune(5)
	if r.Events == 0 || r.PrunedSeq == 0 || r.Intervals.Effective == 0 {
		t.Fatalf("prune = %+v; want events and a closed interval gone", r)
	}
	// only the old, ended interval went: a is still in g0 since day 0
	x.read(func(tx *store.TenantTx) error {
		at, _, err := pit.MembersAt(tx, x.groups[0], x.list(), x.now, 10, 0)
		if err != nil || len(at) != 1 || at[0].Identity != a {
			t.Errorf("g0 now = %v, %v; want a, whose interval is still open", at, err)
		}
		old, _, err := pit.MembersAt(tx, x.groups[1], x.list(), t0.Add(30*time.Minute), 10, 0)
		if err != nil || len(old) != 0 {
			t.Errorf("g1 on day 0 = %v, %v; its interval was pruned", old, err)
		}
		v, err := pit.VerifyDay(tx, pit.Day(t0))
		if err != nil || v.Status != pit.VerdictPruned {
			t.Errorf("a pruned day verifies as %+v, %v; want pruned", v, err)
		}
		led, err := tx.AuditEvents(store.AuditFilter{Action: pit.ActionRetention})
		if err != nil || len(led) != 1 {
			t.Errorf("retention audit events = %d, %v", len(led), err)
		}
		return nil
	})
	// a's open interval began before the events were pruned: a rebuild would lose it
	err := x.run(func(e model.Env) error { _, err := pit.Rebuild(e.Tx, ""); return err })
	if !errors.Is(err, pit.ErrHistoryPruned) {
		t.Errorf("Rebuild after pruning = %v, want ErrHistoryPruned", err)
	}
	if r := prune(5); r.Events != 0 {
		t.Errorf("a second prune removed %d events", r.Events)
	}
}

// TestPIT_RunnerDigestsFinishedDaysOnce: the job digests each finished day, in
// order, once, and catches up after downtime; it does not touch today.
func TestPIT_RunnerDigestsFinishedDaysOnce(t *testing.T) {
	x := newHarness(t, 2, 2)
	g := x.groups[0]
	for d := 0; d < 3; d++ {
		x.now = t0.Add(time.Duration(d) * 24 * time.Hour)
		id := x.idents[d%2]
		x.must(func(e model.Env) error {
			if d%2 == 1 {
				_, err := e.RemoveMember(g, fmt.Sprint(x.idents[0]))
				return err
			}
			_, err := e.AddMember(g, model.MemberInput{Identity: &id})
			return err
		})
	}
	// day 3 (the 11th) is 09:30 now; digests are due for the 8th and 9th (the 10th is today)
	clock := t0.Add(2*24*time.Hour + time.Hour)
	r := &pit.Runner{DB: x.db, Clock: func() time.Time { return clock }, RetentionDays: 1000}
	if err := r.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	days := func() []string {
		var out []string
		x.read(func(tx *store.TenantTx) error {
			ds, err := tx.GrpDigests(10)
			for _, d := range ds {
				out = append(out, d.Day)
			}
			return err
		})
		slices.Sort(out)
		return out
	}
	if got := days(); !slices.Equal(got, []string{"2026-10-08", "2026-10-09"}) {
		t.Errorf("digests after the first pass: %v", got)
	}
	if err := r.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := days(); len(got) != 2 {
		t.Errorf("a second pass wrote digests: %v", got)
	}
	// just after midnight, before 00:05, the previous day is not yet digested
	clock = time.Date(2026, 10, 11, 0, 4, 0, 0, time.UTC)
	if err := r.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := days(); len(got) != 2 {
		t.Errorf("a digest was written before 00:05: %v", got)
	}
	clock = time.Date(2026, 10, 11, 0, 5, 0, 0, time.UTC)
	if err := r.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := days(); !slices.Equal(got, []string{"2026-10-08", "2026-10-09", "2026-10-10"}) {
		t.Errorf("digests at 00:05: %v", got)
	}
	x.read(func(tx *store.TenantTx) error {
		vs, err := pit.VerifyAll(tx, 10)
		if err != nil || len(vs) != 3 {
			t.Fatalf("VerifyAll = %v, %v", vs, err)
		}
		for _, v := range vs {
			if !v.OK() {
				t.Errorf("%+v", v)
			}
		}
		return nil
	})
}

// TestPIT_RunnerSampleRepairsDamagedGroup: the weekly comparison rebuilds a
// sample, finds a group whose rows were damaged and records the mismatch.
func TestPIT_RunnerSampleRepairsDamagedGroup(t *testing.T) {
	x := newHarness(t, 2, 3)
	x.randomRun(3, 20)
	live := x.dump("")
	clock := x.now
	r := &pit.Runner{DB: x.db, Clock: func() time.Time { return clock }, SampleEvery: time.Hour, SampleSize: 50}
	if err := r.Once(context.Background()); err != nil { // the first pass only starts the schedule
		t.Fatal(err)
	}
	x.must(func(e model.Env) error { return e.Tx.DeleteGrpPit(string(x.groups[0])) })
	clock = clock.Add(2 * time.Hour)
	if err := r.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !live.Equal(x.dump("")) {
		t.Error("the sample did not repair the damaged group")
	}
	x.read(func(tx *store.TenantTx) error {
		led, err := tx.AuditEvents(store.AuditFilter{Action: pit.ActionMismatch})
		if err != nil || len(led) != 1 {
			t.Errorf("mismatch audit events = %d, %v; want 1", len(led), err)
		}
		return nil
	})
}
