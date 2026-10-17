package store_test

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The group loader statements (issue #53, GR-10): another tenant's loaders,
// runs and unresolved subjects look nonexistent to every one of them, and a
// write in one tenant leaves the other alone.

func newLoader(folder string, name string) *store.GrpLoader {
	return &store.GrpLoader{Name: name, Type: "csv", Config: `{"path":"a.csv","group":"g","subject_column":"id"}`,
		TargetFolder: store.FolderID(folder), NameTemplate: "{{.Name}}", OnMissingGroup: "empty", Schedule: "@daily",
		Failsafe: `{}`, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}
}

func TestIsolation_GroupLoaderStatements(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedGroups(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	now := storetest.Now
	var la, lb *store.GrpLoader
	var runA *store.GrpLoaderRun
	inA(t, f, func(c *store.TenantTx) error {
		la = newLoader(a.folder, "Staff")
		la.SecretEnc = []byte("sealed")
		if err := c.InsertGrpLoader(la); err != nil {
			return err
		}
		held := &store.GrpLoaderRun{LoaderID: la.ID, Kind: store.RunFull, StartedAt: now, FinishedAt: &now, Status: store.RunHeld,
			Plan: loaderStr(`{"groups":[]}`), Impact: loaderStr(`{}`), FailsafeTripped: loaderStr(`[]`)}
		if err := c.InsertGrpLoaderRun(held); err != nil {
			return err
		}
		runA = held
		if err := c.InsertGrpLoaderRun(&store.GrpLoaderRun{LoaderID: la.ID, Kind: store.RunIncremental, StartedAt: now.Add(time.Hour),
			Status: store.RunApplied}); err != nil {
			return err
		}
		if err := c.UpsertGrpLoaderUnresolved(&store.GrpLoaderUnresolved{LoaderID: la.ID, Source: "hris", Identifier: "9",
			FirstSeen: now, LastSeen: now, Groups: `["app:staff"]`}); err != nil {
			return err
		}
		return c.SetGrpLoaderStatus(la.ID, store.LoaderHeld, now)
	})
	inB(t, f, func(c *store.TenantTx) error {
		// A's loader, runs and unresolved subjects do not exist for B
		if _, err := c.GrpLoader(la.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GrpLoader(A's) = %v, want ErrNotFound", err)
		}
		if _, err := c.GrpLoaderByName("staff"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GrpLoaderByName(A's) = %v, want ErrNotFound", err)
		}
		if ls, err := c.GrpLoaders(); err != nil || len(ls) != 0 {
			t.Errorf("GrpLoaders = %v, %v; want none", ls, err)
		}
		if _, err := c.GrpLoaderRun(runA.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GrpLoaderRun(A's) = %v, want ErrNotFound", err)
		}
		if rs, err := c.GrpLoaderRuns(la.ID, 50, 0); err != nil || len(rs) != 0 {
			t.Errorf("GrpLoaderRuns(A's loader) = %v, %v", rs, err)
		}
		if n, err := c.GrpLoaderRunCount(la.ID); err != nil || n != 0 {
			t.Errorf("GrpLoaderRunCount(A's loader) = %d, %v", n, err)
		}
		if hs, err := c.GrpLoaderHeldRuns(); err != nil || len(hs) != 0 {
			t.Errorf("GrpLoaderHeldRuns = %v, %v; want none (A's is held)", hs, err)
		}
		if _, err := c.GrpLoaderLastRun(la.ID, ""); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GrpLoaderLastRun(A's) = %v, want ErrNotFound", err)
		}
		if us, err := c.GrpLoaderUnresolved(la.ID, 50, 0); err != nil || len(us) != 0 {
			t.Errorf("GrpLoaderUnresolved(A's loader) = %v, %v", us, err)
		}
		if n, err := c.GrpLoaderUnresolvedCount(la.ID); err != nil || n != 0 {
			t.Errorf("GrpLoaderUnresolvedCount(A's loader) = %d, %v", n, err)
		}
		if gs, err := c.GrpGroupsOfLoader(la.ID); err != nil || len(gs) != 0 {
			t.Errorf("GrpGroupsOfLoader(A's loader) = %v, %v", gs, err)
		}
		// writes naming A's rows change nothing and report not found
		if err := c.SetGrpLoaderStatus(la.ID, store.LoaderDisabled, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetGrpLoaderStatus(A's) = %v, want ErrNotFound", err)
		}
		if err := c.RecordGrpLoaderRan(la.ID, store.RunFull, now, nil); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RecordGrpLoaderRan(A's) = %v, want ErrNotFound", err)
		}
		if err := c.DecideGrpLoaderRun(runA.ID, store.RunApproved, "b", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DecideGrpLoaderRun(A's run) = %v, want ErrNotFound", err)
		}
		stale := *la
		stale.Name = "hijacked"
		if err := c.UpdateGrpLoader(&stale); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateGrpLoader(A's) = %v, want ErrNotFound", err)
		}
		if n, err := c.PruneGrpLoaderUnresolved(la.ID, now.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("PruneGrpLoaderUnresolved(A's) = %d, %v; want 0", n, err)
		}
		if err := c.DeleteGrpLoaderUnresolved(la.ID, "hris", "9"); err != nil {
			t.Errorf("DeleteGrpLoaderUnresolved(A's) = %v", err)
		}
		// B names its loader as A does, and may not point a run at A's loader
		lb = newLoader(b.folder, "Staff")
		if err := c.InsertGrpLoader(lb); err != nil {
			t.Errorf("B's loader of the name A has: %v", err)
		}
		if err := c.InsertGrpLoader(newLoader(b.folder, "STAFF")); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("a loader named like B's, in another case = %v, want ErrDuplicate", err)
		}
		if err := c.InsertGrpLoader(newLoader(a.folder, "Other")); err == nil {
			t.Error("B stored a loader that targets A's folder")
		}
		if err := c.InsertGrpLoaderRun(&store.GrpLoaderRun{LoaderID: la.ID, Kind: store.RunFull, StartedAt: now, Status: store.RunApplied}); err == nil {
			t.Error("B stored a run of A's loader")
		}
		if err := c.UpsertGrpLoaderUnresolved(&store.GrpLoaderUnresolved{LoaderID: la.ID, Source: "x", Identifier: "y", FirstSeen: now,
			LastSeen: now, Groups: `[]`}); err == nil {
			t.Error("B stored an unresolved subject of A's loader")
		}
		return nil
	})
	// A's rows are intact
	inA(t, f, func(c *store.TenantTx) error {
		got, err := c.GrpLoader(la.ID)
		if err != nil || got.Name != "Staff" || got.Status != store.LoaderHeld || string(got.SecretEnc) != "sealed" || got.Version != 1 {
			t.Errorf("A's loader after B's attempts = %+v, %v", got, err)
		}
		if n, _ := c.GrpLoaderUnresolvedCount(la.ID); n != 1 {
			t.Errorf("A's unresolved count = %d, want 1", n)
		}
		return nil
	})

	// the rest of the statements, in one tenant
	inA(t, f, func(c *store.TenantTx) error {
		if got, err := c.GrpLoaderByName("STAFF"); err != nil || got.ID != la.ID {
			t.Errorf("GrpLoaderByName is case-insensitive: %v, %v", got, err)
		}
		hs, err := c.GrpLoaderHeldRuns()
		if err != nil || len(hs) != 1 || hs[0].ID != runA.ID || hs[0].Plan == nil || hs[0].FailsafeTripped == nil {
			t.Errorf("GrpLoaderHeldRuns = %+v, %v", hs, err)
		}
		if last, err := c.GrpLoaderLastRun(la.ID, ""); err != nil || last.Kind != store.RunIncremental {
			t.Errorf("GrpLoaderLastRun(any) = %+v, %v; want the incremental one", last, err)
		}
		if last, err := c.GrpLoaderLastRun(la.ID, store.RunFull); err != nil || last.ID != runA.ID {
			t.Errorf("GrpLoaderLastRun(full) = %+v, %v", last, err)
		}
		rs, err := c.GrpLoaderRuns(la.ID, 1, 0)
		if err != nil || len(rs) != 1 || rs[0].Kind != store.RunIncremental {
			t.Errorf("GrpLoaderRuns newest first = %+v, %v", rs, err)
		}
		if n, _ := c.GrpLoaderRunCount(la.ID); n != 2 {
			t.Errorf("GrpLoaderRunCount = %d, want 2", n)
		}
		if err := c.DecideGrpLoaderRun(runA.ID, store.RunApproved, "u1", now); err != nil {
			t.Errorf("DecideGrpLoaderRun: %v", err)
		}
		if err := c.DecideGrpLoaderRun(runA.ID, store.RunRejected, "u2", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a decided run was decided again: %v", err)
		}
		got, err := c.GrpLoaderRun(runA.ID)
		if err != nil || got.Status != store.RunApproved || got.DecidedBy == nil || *got.DecidedBy != "u1" || got.DecidedAt == nil {
			t.Errorf("decided run = %+v, %v", got, err)
		}
		// the unresolved list keeps first_seen, and a prune forgets what no run saw since
		later := now.Add(2 * time.Hour)
		if err := c.UpsertGrpLoaderUnresolved(&store.GrpLoaderUnresolved{LoaderID: la.ID, Source: "hris", Identifier: "9", FirstSeen: later,
			LastSeen: later, Groups: `["app:staff","app:x"]`}); err != nil {
			return err
		}
		if err := c.UpsertGrpLoaderUnresolved(&store.GrpLoaderUnresolved{LoaderID: la.ID, Source: "hris", Identifier: "10", FirstSeen: later,
			LastSeen: later, Groups: `[]`}); err != nil {
			return err
		}
		us, err := c.GrpLoaderUnresolved(la.ID, 50, 0) // ordered by source, then identifier as text: "10" before "9"
		if err != nil || len(us) != 2 || us[0].Identifier != "10" || !us[1].FirstSeen.Equal(now) || !us[1].LastSeen.Equal(later) ||
			us[1].Groups != `["app:staff","app:x"]` {
			t.Errorf("unresolved = %+v, %v", us, err)
		}
		if n, err := c.PruneGrpLoaderUnresolved(la.ID, later); err != nil || n != 0 {
			t.Errorf("prune before the last sighting = %d, %v; want 0", n, err)
		}
		if err := c.DeleteGrpLoaderUnresolved(la.ID, "hris", "10"); err != nil {
			t.Error(err)
		}
		if n, _ := c.GrpLoaderUnresolvedCount(la.ID); n != 1 {
			t.Errorf("unresolved count = %d, want 1", n)
		}
		if n, err := c.PruneGrpLoaderUnresolved(la.ID, later.Add(time.Hour)); err != nil || n != 1 {
			t.Errorf("prune after = %d, %v; want 1", n, err)
		}
		// ran: the cursor only moves when given
		cur := "42"
		if err := c.RecordGrpLoaderRan(la.ID, store.RunIncremental, later, &cur); err != nil {
			t.Error(err)
		}
		if err := c.RecordGrpLoaderRan(la.ID, store.RunFull, later.Add(time.Minute), nil); err != nil {
			t.Error(err)
		}
		got2, err := c.GrpLoader(la.ID)
		if err != nil || got2.Cursor == nil || *got2.Cursor != "42" || got2.LastFullAt == nil || got2.LastIncrAt == nil {
			t.Errorf("loader after ran = %+v, %v", got2, err)
		}
		// update is version-checked
		upd := *got2
		upd.Name, upd.Schedule = "Staff 2", "0 3 * * *"
		if err := c.UpdateGrpLoader(&upd); err != nil || upd.Version != 2 {
			t.Errorf("UpdateGrpLoader = %v, version %d", err, upd.Version)
		}
		if err := c.UpdateGrpLoader(got2); !errors.Is(err, store.ErrVersionConflict) {
			t.Errorf("a stale update = %v, want ErrVersionConflict", err)
		}
		// loader-owned groups and direct rows by source
		g := &store.NativeGroup{FolderID: store.FolderID(a.folder), Extension: "loaded", DisplayExtension: "loaded", Name: "app:loaded",
			DisplayName: "app:loaded", ManagedBy: store.ManagedByLoader, LoaderID: &la.ID, CreatedAt: now}
		if err := c.InsertGrpGroup(g); err != nil {
			return err
		}
		list, err := c.EnsureGrpMembersList()
		if err != nil {
			return err
		}
		ident, err := c.InsertIdentity(&store.Identity{ExternalID: "ld", Name: "Ld", Type: "person", Status: "active", CreatedAt: now})
		if err != nil {
			return err
		}
		ref := la.ID
		if err := c.InsertGrpDirect(&store.DirectMembership{GroupID: g.ID, ListID: list, MemberType: store.MemberIdentity, MemberIdentity: &ident,
			Source: "loader", SourceRef: &ref, CreatedAt: now}); err != nil {
			return err
		}
		if gs, err := c.GrpGroupsOfLoader(la.ID); err != nil || len(gs) != 1 || gs[0].ID != g.ID {
			t.Errorf("GrpGroupsOfLoader = %v, %v", gs, err)
		}
		if rows, err := c.GrpDirectBySource(g.ID, list, "loader", la.ID); err != nil || len(rows) != 1 {
			t.Errorf("GrpDirectBySource = %v, %v", rows, err)
		}
		if rows, err := c.GrpDirectBySource(g.ID, list, "loader", "another loader"); err != nil || len(rows) != 0 {
			t.Errorf("GrpDirectBySource(other ref) = %v, %v", rows, err)
		}
		if es, err := c.EdgesTo("group:" + "999999"); err != nil || len(es) != 0 {
			t.Errorf("EdgesTo(nothing) = %v, %v", es, err)
		}
		return nil
	})
	// B's edges to a group are not A's
	inB(t, f, func(c *store.TenantTx) error {
		es, err := c.EdgesTo("group:" + strconv.FormatInt(f.A.IDs["group:aws:ProdAdmin"], 10))
		if err != nil {
			return err
		}
		for _, e := range es {
			if e.TenantID != f.B.ID {
				t.Errorf("EdgesTo returned tenant %s's edge", e.TenantID)
			}
		}
		return nil
	})
}

func loaderStr(s string) *string { return &s }

// groupLoadersCovered lists the repository methods of GR-10 that the tests above exercise.
func groupLoadersCovered() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{"InsertGrpLoader", "GrpLoader", "GrpLoaderByName", "GrpLoaders", "UpdateGrpLoader", "SetGrpLoaderStatus",
		"RecordGrpLoaderRan", "InsertGrpLoaderRun", "GrpLoaderRun", "GrpLoaderRuns", "GrpLoaderRunCount", "GrpLoaderHeldRuns",
		"GrpLoaderLastRun", "DecideGrpLoaderRun", "UpsertGrpLoaderUnresolved", "PruneGrpLoaderUnresolved", "DeleteGrpLoaderUnresolved",
		"GrpLoaderUnresolved", "GrpLoaderUnresolvedCount", "GrpGroupsOfLoader", "GrpDirectBySource", "EdgesTo"} {
		m[name] = true
	}
	return m
}
