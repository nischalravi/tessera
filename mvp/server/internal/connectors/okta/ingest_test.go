package okta

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

var (
	tenantA = tenancy.MustParse("00000000-0000-4000-8000-0000000000c1")
	tenantB = tenancy.MustParse("00000000-0000-4000-8000-0000000000c2")
)

// hr is a stand-in for an authoritative HR connector (Workday): the people
// Okta accounts must correlate to.
type hr struct{}

func (hr) System() string      { return "workday" }
func (hr) DisplayName() string { return "HR (test)" }
func (hr) TypeName() string    { return "TestHR" }
func (hr) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	email := func(s string) *string { return &s }
	return &connectors.DiscoveryResult{Identities: []connectors.IdentityRecord{
		{ExternalID: "E1001", Name: "Avery Example (HR)", Type: "human", Email: email("avery.example@example.com"), Status: "active"},
		{ExternalID: "E1002", Name: "Morgan Sample (HR)", Type: "human", Email: email("Morgan.Sample@Example.com"), Status: "active"},
	}}, nil
}
func (hr) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error { return nil }

func syncTenant(t *testing.T, db *store.DB, tn tenancy.ID, ctx context.Context, conns ...connectors.Connector) ingest.SyncStats {
	t.Helper()
	var st ingest.SyncStats
	err := db.InTenant(ctx, tn, func(c *store.TenantTx) error {
		var err error
		st, err = ingest.Sync(c, testkit.Now, conns, nil)
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
	testkit.CreateTenant(t, db, tenantA, "okta-e2e")
	c := f.connector(ssws())

	st := syncTenant(t, db, tenantA, context.Background(), c)
	if st.Discovery.Identities != 4 || st.Discovery.Accounts != 4 || st.Discovery.Groups != 5 ||
		st.Discovery.Resources != 1 || st.Discovery.Permissions != 1 || st.Events.Usage != 2 {
		t.Fatalf("sync stats = %+v", st)
	}
	err := db.ReadTenant(context.Background(), tenantA, func(tx *store.TenantTx) error {
		idents, err := tx.Identities()
		if err != nil || len(idents) != 4 {
			t.Fatalf("identities = %d, %v", len(idents), err)
		}
		byXID := map[string]*store.Identity{}
		for _, i := range idents {
			byXID[i.ExternalID] = i
		}
		accts, err := tx.Accounts()
		if err != nil || len(accts) != 4 {
			t.Fatalf("accounts = %d, %v", len(accts), err)
		}
		for _, a := range accts {
			if a.System != "okta" || a.IdentityID == nil {
				t.Errorf("account %s system=%s identity=%v: every account must correlate to its identity", a.ExternalID, a.System, a.IdentityID)
			}
		}
		for _, a := range accts {
			if a.ExternalID == avery {
				if *a.IdentityID != byXID["E1001"].ID || a.LastLoginAt == nil || a.Status != "active" {
					t.Errorf("avery's account = %+v, identity E1001 = %+v", a, byXID["E1001"])
				}
			}
			if a.ExternalID == drew && a.Status != "disabled" {
				t.Errorf("deprovisioned account status = %q", a.Status)
			}
		}
		// manager of avery is morgan's identity (resolved through the Okta user id)
		if m := byXID["E1001"].ManagerID; m == nil || *m != byXID["okta:"+morgan].ID {
			t.Errorf("avery's manager = %v, want morgan's identity %d", m, byXID["okta:"+morgan].ID)
		}
		groups, err := tx.Groups()
		if err != nil || len(groups) != 5 {
			t.Fatalf("groups = %d, %v", len(groups), err)
		}
		edges, err := tx.Edges()
		if err != nil || len(edges) != 8 {
			t.Errorf("edges = %d, %v, want 8", len(edges), err)
		}
		n, err := tx.CountUsageEvents()
		if err != nil || n != 2 {
			t.Errorf("usage events = %d, %v", n, err)
		}
		k, err := tx.ConnectorCheckpoint(System, checkpointName)
		if err != nil || k.Cursor == "" || len(k.State) == 0 || k.FullSyncAt == nil {
			t.Errorf("checkpoint = %+v, %v", k, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Second sync is incremental from the stored checkpoint (no fresh connector,
	// no in-memory state), and changes arrive: morgan leaves Engineers.
	f.changed = true
	c2 := f.connector(ssws())
	before := len(f.srv.Requests())
	st = syncTenant(t, db, tenantA, context.Background(), c2)
	if st.Discovery.Accounts != 4 || st.Discovery.Identities != 4 {
		t.Errorf("incremental stats = %+v", st)
	}
	filtered := 0
	for _, r := range f.srv.Requests()[before:] {
		q, _ := url.ParseQuery(r.Query)
		if r.Path == "/api/v1/users" && q.Get("search") != "" {
			filtered++
		}
		if r.Path == "/api/v1/users" && q.Get("search") == "" {
			t.Errorf("the second sync listed all users: %s?%s", r.Path, r.Query)
		}
	}
	if filtered != 1 {
		t.Errorf("filtered user calls = %d, want 1", filtered)
	}
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
		edges, err := tx.Edges()
		if err != nil || len(edges) != 7 {
			t.Errorf("edges after incremental sync = %d, %v, want 7 (morgan's membership pruned)", len(edges), err)
		}
		return nil
	})

	// A full re-sync on demand reads everything again.
	b2 := countQuery(f.srv.Requests(), "/api/v1/users", "")
	f.changed = false
	syncTenant(t, db, tenantA, connsync.WithMode(context.Background(), connsync.Full), c2)
	if countQuery(f.srv.Requests(), "/api/v1/users", "") != b2+1 {
		t.Error("full re-sync on demand did not list all users")
	}
}

func TestIngestCorrelatesToTheHRIdentities(t *testing.T) {
	f := newFake(t)
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "okta-hr")
	cfg := ssws()
	cfg.EmitIdentities = false
	st := syncTenant(t, db, tenantA, context.Background(), hr{}, f.connector(cfg))
	if st.Discovery.Identities != 2 || st.Discovery.Accounts != 4 {
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
			got[a.ExternalID] = a.IdentityID
		}
		if got[avery] == nil || *got[avery] != id["E1001"] {
			t.Errorf("avery -> %v, want E1001 (%d): correlation by employeeNumber", got[avery], id["E1001"])
		}
		if got[morgan] == nil || *got[morgan] != id["E1002"] {
			t.Errorf("morgan -> %v, want E1002 (%d): correlation by e-mail address, case-insensitive", got[morgan], id["E1002"])
		}
		if got[casey] != nil || got[drew] != nil {
			t.Errorf("casey -> %v, drew -> %v: accounts matching no person stay uncorrelated for review", got[casey], got[drew])
		}
		return nil
	})
}

func TestCheckpointIsRolledBackWithAFailedIngest(t *testing.T) {
	f := newFake(t)
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "okta-rollback")
	boom := errors.New("boom")
	err := db.InTenant(context.Background(), tenantA, func(tx *store.TenantTx) error {
		if _, err := ingest.Sync(tx, testkit.Now, []connectors.Connector{f.connector(ssws())}, nil); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
		if _, err := tx.ConnectorCheckpoint(System, checkpointName); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("checkpoint survived a rolled-back ingest: %v", err)
		}
		return nil
	})
}

func TestCheckpointsAreTenantScoped(t *testing.T) {
	f := newFake(t)
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "okta-a")
	testkit.CreateTenant(t, db, tenantB, "okta-b")
	syncTenant(t, db, tenantA, context.Background(), f.connector(ssws()))
	if n := countQuery(f.srv.Requests(), "/api/v1/users", ""); n != 1 {
		t.Fatalf("unfiltered user calls after A = %d", n)
	}
	// B has no checkpoint: it must read everything, not resume from A's cursor.
	syncTenant(t, db, tenantB, context.Background(), f.connector(ssws()))
	if n := countQuery(f.srv.Requests(), "/api/v1/users", ""); n != 2 {
		t.Errorf("tenant B did a filtered read from tenant A's checkpoint (unfiltered calls = %d)", n)
	}
	// Each tenant resumes from its own.
	for _, tn := range []tenancy.ID{tenantA, tenantB} {
		before := countQuery(f.srv.Requests(), "/api/v1/users", "")
		syncTenant(t, db, tn, context.Background(), f.connector(ssws()))
		if countQuery(f.srv.Requests(), "/api/v1/users", "") != before {
			t.Errorf("tenant %s did a full read although it has a checkpoint", tn)
		}
	}
	for _, tn := range []tenancy.ID{tenantA, tenantB} {
		testkit.Read(t, &testkit.DB{DB: db, Tenant: tn}, func(tx *store.TenantTx) error {
			ks, err := tx.ConnectorCheckpoints()
			if err != nil || len(ks) != 1 {
				t.Errorf("tenant %s sees %d checkpoints, %v", tn, len(ks), err)
			}
			return nil
		})
	}
}
