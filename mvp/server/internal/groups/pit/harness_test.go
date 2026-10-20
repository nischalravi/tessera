package pit_test

import (
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var (
	t0  = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	tid = tenancy.MustParse("00000000-0000-4000-8000-0000000000d4")
)

// harness is a one-tenant database with basic groups g0..g(n-1), a composite
// (the union of g0 and g1), m identities and a clock the test moves by hand.
type harness struct {
	t      testing.TB
	db     *store.DB
	eng    *engine.Engine
	now    time.Time
	groups []store.GroupID // g0..g(n-1) then the composite
	idents []int64
	root   store.FolderID
}

func newHarness(t testing.TB, nGroups, nIdents int) *harness {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "pit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.InSystem(ctx, "test", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: tid, Slug: "pit", Name: "pit", CreatedAt: t0})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	x := &harness{t: t, db: db, eng: engine.New(0), now: t0}
	x.must(func(e model.Env) error {
		root, err := e.EnsureRoot()
		if err != nil {
			return err
		}
		x.root = root.ID
		for i := 0; i < nGroups; i++ {
			g, err := e.CreateGroup(model.CreateGroupInput{Folder: root.ID, Extension: fmt.Sprintf("g%d", i)})
			if err != nil {
				return err
			}
			x.groups = append(x.groups, g.ID)
		}
		c, err := e.CreateGroup(model.CreateGroupInput{Folder: root.ID, Extension: "c", Definition: store.DefinitionComposite,
			Op: store.CompUnion, Factors: []store.GroupID{x.groups[0], x.groups[1]}})
		if err != nil {
			return err
		}
		x.groups = append(x.groups, c.ID)
		for i := 0; i < nIdents; i++ {
			id, err := e.Tx.InsertIdentity(&store.Identity{ExternalID: fmt.Sprintf("u%d", i), Name: fmt.Sprintf("User %d", i),
				Type: "person", Status: "active", CreatedAt: t0})
			if err != nil {
				return err
			}
			x.idents = append(x.idents, id)
		}
		return nil
	})
	return x
}

func (x *harness) run(fn func(e model.Env) error) error {
	return x.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		return fn(model.Env{Tx: tx, Now: x.now, Engine: x.eng})
	})
}

func (x *harness) must(fn func(e model.Env) error) {
	x.t.Helper()
	if err := x.run(fn); err != nil {
		x.t.Fatal(err)
	}
}

func (x *harness) read(fn func(tx *store.TenantTx) error) {
	x.t.Helper()
	if err := x.db.ReadTenant(context.Background(), tid, fn); err != nil {
		x.t.Fatal(err)
	}
}

// advance moves the clock and runs one time wheel tick at the new time.
func (x *harness) advance(d time.Duration) {
	x.t.Helper()
	x.now = x.now.Add(d)
	x.must(func(e model.Env) error {
		_, err := x.eng.Tick(e.Tx, x.now)
		return err
	})
}

func (x *harness) list() store.ListID { return store.MembersListID(tid) }

// members is the live effective membership of every group right now.
func (x *harness) members() map[store.GroupID][]int64 {
	x.t.Helper()
	out := map[store.GroupID][]int64{}
	x.read(func(tx *store.TenantTx) error {
		for _, g := range x.groups {
			rows, err := tx.GrpEffectiveList(g, x.list(), 100000, 0)
			if err != nil {
				return err
			}
			ids := []int64{}
			for _, r := range rows {
				ids = append(ids, r.Identity)
			}
			slices.Sort(ids)
			out[g] = ids
		}
		return nil
	})
	return out
}

// snapshot is the live membership at a moment.
type snapshot struct {
	at      time.Time
	members map[store.GroupID][]int64
}

// randomRun does n random steps, an hour apart, and records the live
// membership after each. Failed operations (a cycle, a missing row) are part
// of the mix: they roll back and change nothing.
func (x *harness) randomRun(seed int64, n int) []snapshot {
	x.t.Helper()
	rng := rand.New(rand.NewSource(seed))
	basic := x.groups[:len(x.groups)-1]
	var snaps []snapshot
	for i := 0; i < n; i++ {
		step := time.Hour
		if rng.Intn(3) == 0 {
			step = 20 * time.Minute
		}
		x.advance(step)
		g := basic[rng.Intn(len(basic))]
		h := basic[rng.Intn(len(basic))]
		id := x.idents[rng.Intn(len(x.idents))]
		switch rng.Intn(7) {
		case 0, 1:
			in := model.MemberInput{Identity: &id}
			switch rng.Intn(4) {
			case 0:
				from := x.now.Add(25 * time.Minute)
				in.EnabledFrom = &from
			case 1:
				to := x.now.Add(95 * time.Minute)
				in.DisabledAt = &to
			}
			_ = x.run(func(e model.Env) error { _, err := e.AddMember(g, in); return err })
		case 2:
			_ = x.run(func(e model.Env) error { _, err := e.RemoveMember(g, fmt.Sprint(id)); return err })
		case 3:
			_ = x.run(func(e model.Env) error { _, err := e.AddMember(g, model.MemberInput{Group: h}); return err })
		case 4:
			_ = x.run(func(e model.Env) error { _, err := e.RemoveMember(g, string(h)); return err })
		case 5:
			status := store.GroupDisabled
			if rng.Intn(2) == 0 {
				status = store.GroupActive
			}
			_ = x.run(func(e model.Env) error {
				_, err := e.UpdateGroup(g, model.UpdateGroupInput{Status: &status})
				return err
			})
		case 6:
			// let the clock and the wheel do the work
		}
		snaps = append(snaps, snapshot{at: x.now, members: x.members()})
	}
	return snaps
}

// allEvents reads the whole outbox.
func (x *harness) allEvents() []*events.Event {
	x.t.Helper()
	var out []*events.Event
	x.read(func(tx *store.TenantTx) error {
		h, err := tx.GrpEventHead()
		if err != nil {
			return err
		}
		out, err = tx.GrpEventsAfter(0, h.LastSeq, int(h.LastSeq)+1)
		return err
	})
	return out
}
