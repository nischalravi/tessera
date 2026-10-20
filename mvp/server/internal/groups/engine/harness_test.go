package engine_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var (
	t0  = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	tid = tenancy.MustParse("00000000-0000-4000-8000-0000000000c3")
)

var sharedDirs []string

func TestMain(m *testing.M) {
	code := m.Run()
	for _, d := range sharedDirs {
		_ = os.RemoveAll(d)
	}
	os.Exit(code)
}

// harness is a one-tenant database with n groups g0..g(n-1), m identities and a
// clock the test moves by hand.
type harness struct {
	t      testing.TB
	db     *store.DB
	eng    *engine.Engine
	now    time.Time
	groups []store.GroupID
	idents []int64
}

func newHarness(t testing.TB, nGroups, nIdents int, eng *engine.Engine) *harness {
	t.Helper()
	ctx := context.Background()
	// not t.TempDir: under the fuzzer one T serves every seed and would share the directory
	dir, err := os.MkdirTemp("", "groups-engine-*")
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, shared := t.(*testing.B); shared {
		// the benchmark tenant outlives the benchmark that built it
		sharedDirs = append(sharedDirs, dir)
	} else {
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		t.Cleanup(func() { _ = db.Close() })
	}
	if err := db.InSystem(ctx, "test", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: tid, Slug: "engine", Name: "engine", CreatedAt: t0})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if eng == nil {
		eng = engine.New(0)
	}
	x := &harness{t: t, db: db, eng: eng, now: t0}
	x.must(func(e model.Env) error {
		root, err := e.EnsureRoot()
		if err != nil {
			return err
		}
		for i := 0; i < nGroups; i++ {
			g, err := e.CreateGroup(model.CreateGroupInput{Folder: root.ID, Extension: fmt.Sprintf("g%d", i)})
			if err != nil {
				return err
			}
			x.groups = append(x.groups, g.ID)
		}
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

// run executes fn in a write transaction at the harness clock.
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

// read executes fn in a read transaction.
func (x *harness) read(fn func(e model.Env) error) {
	x.t.Helper()
	err := x.db.ReadTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		return fn(model.Env{Tx: tx, Now: x.now, Engine: x.eng})
	})
	if err != nil {
		x.t.Fatal(err)
	}
}

// advance moves the clock and runs one time wheel tick at the new time.
func (x *harness) advance(d time.Duration) {
	x.t.Helper()
	x.now = x.now.Add(d)
	x.tick()
}

func (x *harness) tick() {
	x.t.Helper()
	x.must(func(e model.Env) error {
		_, err := x.eng.Tick(e.Tx, x.now)
		return err
	})
}

// drain runs the engine queue to empty and returns the number of chunks.
func (x *harness) drain() int {
	x.t.Helper()
	chunks := 0
	for {
		var did bool
		x.must(func(e model.Env) error {
			var err error
			did, err = x.eng.Drain(e.Tx, x.now)
			return err
		})
		if !did {
			return chunks
		}
		chunks++
	}
}

func (x *harness) list() store.ListID { return store.MembersListID(tid) }

func (x *harness) support(g store.GroupID, identity int64) int32 {
	x.t.Helper()
	var n int32
	x.read(func(e model.Env) error {
		var err error
		n, err = e.Tx.GrpEffectiveSupport(g, x.list(), identity)
		return err
	})
	return n
}

func (x *harness) isMember(g store.GroupID, identity int64) bool {
	x.t.Helper()
	var ok bool
	x.read(func(e model.Env) error {
		var err error
		ok, err = e.IsMember(g, identity)
		return err
	})
	return ok
}

func (x *harness) group(g store.GroupID) *store.NativeGroup {
	x.t.Helper()
	var out *store.NativeGroup
	x.read(func(e model.Env) error {
		var err error
		out, err = e.Group(g)
		return err
	})
	return out
}

func (x *harness) addIdentity(g store.GroupID, identity int64) {
	x.t.Helper()
	x.must(func(e model.Env) error {
		_, err := e.AddMember(g, model.MemberInput{Identity: &identity})
		return err
	})
}

func (x *harness) addGroup(parent, child store.GroupID) error {
	return x.run(func(e model.Env) error {
		_, err := e.AddMember(parent, model.MemberInput{Group: child})
		return err
	})
}

// verify runs a full verification and fails the test if it repaired anything.
func (x *harness) verifyClean() {
	x.t.Helper()
	x.must(func(e model.Env) error {
		rep, err := x.eng.Verify(e.Tx, x.now)
		if err != nil {
			return err
		}
		if rep.RepairCount != 0 {
			x.t.Errorf("verification repaired %d rows: %+v", rep.RepairCount, rep.Repairs)
		}
		return nil
	})
}
