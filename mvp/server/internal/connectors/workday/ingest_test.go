package workday

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

var (
	tenantA = tenancy.MustParse("00000000-0000-4000-8000-0000000000f1")
	tenantB = tenancy.MustParse("00000000-0000-4000-8000-0000000000f2")
)

// directory is a stand-in for another connector (Google, Okta, Entra) whose
// accounts must correlate to the Workday identities.
type directory struct{}

func (directory) System() string      { return "directory" }
func (directory) DisplayName() string { return "Directory (test)" }
func (directory) TypeName() string    { return "TestDirectory" }
func (directory) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	return &connectors.DiscoveryResult{Accounts: []connectors.AccountRecord{
		{System: "directory", ExternalID: "d-1", Username: "avery", Kind: "user", Status: "active",
			Identity: &connectors.IdentityRef{ExternalID: "E1001", Email: "somebody.else@example.com"}},
		{System: "directory", ExternalID: "d-2", Username: "riley", Kind: "user", Status: "active",
			Identity: &connectors.IdentityRef{ExternalID: "google:77", Email: "RILEY.SAMPLE@example.com"}},
		{System: "directory", ExternalID: "d-3", Username: "stranger", Kind: "user", Status: "active",
			Identity: &connectors.IdentityRef{ExternalID: "google:78", Email: "stranger@example.net"}},
	}}, nil
}
func (directory) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

func syncAt(t *testing.T, db *store.DB, tn tenancy.ID, ctx context.Context, now time.Time, conns ...connectors.Connector) ingest.SyncStats {
	t.Helper()
	var st ingest.SyncStats
	err := db.InTenant(ctx, tn, func(c *store.TenantTx) error {
		var err error
		st, err = ingest.Sync(c, now, conns, nil)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestIngestEndToEnd(t *testing.T) {
	f := newFake(t)
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "workday-e2e")
	st := syncAt(t, db, tenantA, context.Background(), now0, f.connector(baseCfg()))
	if st.Discovery.Identities != 5 || st.Discovery.Accounts != 5 || st.Discovery.Groups != 2 || st.Discovery.Edges != 4 || st.Events.Hris != 6 {
		t.Fatalf("sync stats = %+v", st)
	}
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
		idents, err := tx.Identities()
		if err != nil || len(idents) != 5 {
			t.Fatalf("identities = %d, %v", len(idents), err)
		}
		byXID := map[string]*store.Identity{}
		for _, i := range idents {
			byXID[i.ExternalID] = i
		}
		if byXID["E1003"] != nil {
			t.Error("the worker hired in the future is an identity")
		}
		if i := byXID["E1004"]; i == nil || i.Status != "active" || i.TerminatedAt != nil {
			t.Errorf("the worker terminating in the future = %+v", i)
		}
		if i := byXID["E1002"]; i == nil || i.Status != "terminated" || i.TerminatedAt == nil {
			t.Errorf("the worker terminated last week = %+v", i)
		}
		avery := byXID["E1001"]
		if avery.ManagerID == nil || *avery.ManagerID != byXID["E1000"].ID {
			t.Errorf("avery's manager = %v, want E1000", avery.ManagerID)
		}
		accts, _ := tx.Accounts()
		for _, a := range accts {
			if a.System != "workday" || a.IdentityID == nil || *a.IdentityID != byXID[a.ExternalID].ID {
				t.Errorf("account %s is not its own worker's: %+v", a.ExternalID, a)
			}
		}
		k, err := tx.ConnectorCheckpoint(System, checkpointName)
		if err != nil || len(k.State) == 0 || k.FullSyncAt == nil {
			t.Errorf("discover checkpoint = %+v, %v", k, err)
		}
		if _, err := tx.ConnectorCheckpoint(System, eventsCheckpoint); err != nil {
			t.Errorf("events checkpoint: %v", err)
		}

		// HRIS events: the future-dated ones are pending with their own dates
		evs, err := tx.HrisEvents()
		if err != nil || len(evs) != 6 {
			t.Fatalf("hris events = %d, %v", len(evs), err)
		}
		by := map[string]*store.HrisEvent{}
		for _, e := range evs {
			by[e.ExternalID] = e
		}
		for _, tc := range []struct {
			id, typ, status string
			eff             time.Time
		}{
			{"wd-evt-EVT-1", "joiner", "pending", time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)},
			{"wd-evt-EVT-2", "leaver", "pending", time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)},
			{"wd-evt-EVT-3", "mover", "pending", time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)},
			{"wd-evt-EVT-4", "mover", "pending", time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)},
			{"wd-evt-EVT-5", "leaver", "pending", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
			{"wd-evt-EVT-6", "joiner", "executed", time.Date(2021, 4, 12, 0, 0, 0, 0, time.UTC)},
		} {
			e := by[tc.id]
			if e == nil || e.Type != tc.typ || e.Status != tc.status || !e.EffectiveAt.Equal(tc.eff) {
				t.Errorf("%s = %+v, want %s %s %s", tc.id, e, tc.typ, tc.status, tc.eff)
			}
		}
		if by["wd-evt-EVT-1"].IdentityID != nil {
			t.Error("the future hire is already tied to an identity")
		}
		if e := by["wd-evt-EVT-2"]; e.IdentityID == nil || *e.IdentityID != byXID["E1004"].ID {
			t.Errorf("the future leaver is tied to %v, want E1004", e.IdentityID)
		}

		// the joiner / mover / leaver flow consumes the events
		for _, id := range []string{"wd-evt-EVT-1", "wd-evt-EVT-2", "wd-evt-EVT-3", "wd-evt-EVT-5"} {
			if _, err := jml.PlanForEvent(tx, now0, by[id], false, nil); err != nil {
				t.Errorf("jml.PlanForEvent(%s): %v", id, err)
			}
		}
		return nil
	})

	// a second sync resumes from the checkpoints and changes nothing that was decided
	f.changed = true
	f.now = now0.Add(time.Hour)
	st = syncAt(t, db, tenantA, context.Background(), now0.Add(time.Hour), f.connector(baseCfg()))
	if st.Discovery.Identities != 6 || st.Events.Hris != 1 {
		t.Errorf("incremental stats = %+v", st)
	}
	if f.fullWorkerReads() != 1 || f.fullEventReads() != 1 {
		t.Errorf("full reads: workers %d, events %d, want 1 and 1", f.fullWorkerReads(), f.fullEventReads())
	}
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
		evs, _ := tx.HrisEvents()
		if len(evs) != 6 {
			t.Errorf("hris events after the update = %d, want 6 (the rescheduled event keeps its row)", len(evs))
		}
		for _, e := range evs {
			if e.ExternalID == "wd-evt-EVT-3" && !e.EffectiveAt.Equal(time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC)) {
				t.Errorf("the rescheduled event kept its old date: %v", e.EffectiveAt)
			}
		}
		return nil
	})

	// full re-sync on demand
	syncAt(t, db, tenantA, connsync.WithMode(context.Background(), connsync.Full), now0.Add(2*time.Hour), f.connector(baseCfg()))
	if f.fullWorkerReads() != 2 || f.fullEventReads() != 2 {
		t.Errorf("after a full re-sync: workers %d, events %d, want 2 and 2", f.fullWorkerReads(), f.fullEventReads())
	}
}

func TestIngestCorrelatesOtherSystemsToWorkdayByEmployeeIDThenEmail(t *testing.T) {
	f := newFake(t)
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "workday-corr")
	st := syncAt(t, db, tenantA, context.Background(), now0, f.connector(baseCfg()), directory{})
	if st.Discovery.Accounts != 8 {
		t.Fatalf("stats = %+v", st)
	}
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
		idents, _ := tx.Identities()
		id := map[string]int64{}
		for _, i := range idents {
			id[i.ExternalID] = i.ID
		}
		accts, _ := tx.Accounts()
		got := map[string]*int64{}
		for _, a := range accts {
			if a.System == "directory" {
				got[a.ExternalID] = a.IdentityID
			}
		}
		if got["d-1"] == nil || *got["d-1"] != id["E1001"] {
			t.Errorf("d-1 -> %v, want E1001 (%d): the employee id wins over a different e-mail address", got["d-1"], id["E1001"])
		}
		if got["d-2"] == nil || *got["d-2"] != id["E1002"] {
			t.Errorf("d-2 -> %v, want E1002 (%d): by e-mail address, case-insensitive", got["d-2"], id["E1002"])
		}
		if got["d-3"] != nil {
			t.Errorf("d-3 -> %v: an account matching no worker stays uncorrelated", got["d-3"])
		}
		return nil
	})
}

func TestCheckpointsAreRolledBackWithAFailedIngest(t *testing.T) {
	f := newFake(t)
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "workday-rollback")
	boom := errors.New("boom")
	err := db.InTenant(context.Background(), tenantA, func(tx *store.TenantTx) error {
		if _, err := ingest.Sync(tx, now0, []connectors.Connector{f.connector(baseCfg())}, nil); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
		for _, name := range []string{checkpointName, eventsCheckpoint} {
			if _, err := tx.ConnectorCheckpoint(System, name); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("checkpoint %s survived a rolled-back ingest: %v", name, err)
			}
		}
		if evs, _ := tx.HrisEvents(); len(evs) != 0 {
			t.Errorf("hris events survived a rolled-back ingest: %d", len(evs))
		}
		return nil
	})
}

func TestCheckpointsAreTenantScoped(t *testing.T) {
	f := newFake(t)
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "workday-a")
	testkit.CreateTenant(t, db, tenantB, "workday-b")
	syncAt(t, db, tenantA, context.Background(), now0, f.connector(baseCfg()))
	syncAt(t, db, tenantB, context.Background(), now0, f.connector(baseCfg()))
	if f.fullWorkerReads() != 2 {
		t.Fatalf("full worker reads after two first syncs = %d, want 2 (B must not resume from A's watermark)", f.fullWorkerReads())
	}
	for _, tn := range []tenancy.ID{tenantA, tenantB} {
		syncAt(t, db, tn, context.Background(), now0, f.connector(baseCfg()))
	}
	if f.fullWorkerReads() != 2 || f.fullEventReads() != 2 {
		t.Errorf("after the second round: workers %d, events %d, want still 2 (each tenant resumes from its own checkpoints)",
			f.fullWorkerReads(), f.fullEventReads())
	}
	for _, tn := range []tenancy.ID{tenantA, tenantB} {
		testkit.Read(t, &testkit.DB{DB: db, Tenant: tn}, func(tx *store.TenantTx) error {
			ks, err := tx.ConnectorCheckpoints()
			if err != nil || len(ks) != 2 {
				t.Errorf("tenant %s sees %d checkpoints, %v", tn, len(ks), err)
			}
			return nil
		})
	}
}
