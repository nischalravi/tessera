package entra

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

var (
	tenantA = tenancy.MustParse("00000000-0000-4000-8000-0000000000d1")
	tenantB = tenancy.MustParse("00000000-0000-4000-8000-0000000000d2")
)

// hr is a stand-in for an authoritative HR connector: the people Entra
// accounts must correlate to.
type hr struct{}

func (hr) System() string      { return "workday" }
func (hr) DisplayName() string { return "HR (test)" }
func (hr) TypeName() string    { return "TestHR" }
func (hr) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	email := func(s string) *string { return &s }
	return &connectors.DiscoveryResult{Identities: []connectors.IdentityRecord{
		{ExternalID: "EMP-2001", Name: "Ada Fixture (HR)", Type: "human", Email: email("ada.fixture@example.com"), Status: "active"},
		{ExternalID: "EMP-2002", Name: "Ben Sample (HR)", Type: "human", Email: email("Ben.Sample@Fixture.onmicrosoft.com"), Status: "active"},
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
	testkit.CreateTenant(t, db, tenantA, "entra-e2e")
	st := syncTenant(t, db, tenantA, context.Background(), f.connector(baseCfg()))
	if st.Discovery.Identities != 4 || st.Discovery.Accounts != 4 || st.Discovery.Groups != 5 || st.Discovery.Resources != 2 ||
		st.Discovery.Permissions != 5 || st.Discovery.Edges != 12 || st.Events.Usage != 2 {
		t.Fatalf("sync stats = %+v", st)
	}
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
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
			if a.System != "entra" || a.IdentityID == nil {
				t.Errorf("account %s: system=%s identity=%v", a.ExternalID, a.System, a.IdentityID)
			}
			switch a.ExternalID {
			case ada:
				if *a.IdentityID != byXID["EMP-2001"].ID || a.LastLoginAt == nil {
					t.Errorf("ada's account = %+v", a)
				}
			case spBilling:
				if a.Kind != "service" || byXID["entra-sp:"+spBilling].Type != "service" {
					t.Errorf("service principal account = %+v", a)
				}
			}
		}
		groups, err := tx.Groups()
		if err != nil || len(groups) != 5 {
			t.Fatalf("groups = %d, %v", len(groups), err)
		}
		k, err := tx.ConnectorCheckpoint(System, checkpointName)
		if err != nil || !strings.Contains(k.Cursor, "dt-users-1") || len(k.State) == 0 {
			t.Errorf("checkpoint = %+v, %v", k, err)
		}
		return nil
	})

	// Nesting is visible to the existing graph analysis: ada is in Engineering,
	// which is in Platform Admins, which holds Global Administrator.
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
		g, err := graph.Build(tx, testkit.Now)
		if err != nil {
			t.Fatal(err)
		}
		accts, _ := tx.Accounts()
		groups, _ := tx.Groups()
		node := map[string]string{}
		for _, a := range accts {
			node["account:"+a.ExternalID] = graph.Key("account", a.ID)
		}
		for _, gr := range groups {
			node["group:"+gr.ExternalID] = graph.Key("group", gr.ID)
		}
		seen := map[string]bool{}
		var walk func(string)
		walk = func(n string) {
			if seen[n] {
				return
			}
			seen[n] = true
			for _, s := range g.Successors(n) {
				walk(s)
			}
		}
		walk(node["account:"+ada])
		for _, want := range []string{"group:" + g1, "group:" + g2, "group:role:" + roleAdmin} {
			if !seen[node[want]] {
				t.Errorf("ada does not reach %s through the nested groups", want)
			}
		}
		if seen[node["group:"+g3]] {
			t.Error("ada reaches a group she is not in")
		}
		return nil
	})

	// the second sync resumes from the checkpoint in the database
	f.changed = true
	before := len(f.srv.Requests())
	st = syncTenant(t, db, tenantA, context.Background(), f.connector(baseCfg()))
	if st.Discovery.Accounts != 4 || st.Discovery.Groups != 4 {
		t.Errorf("incremental stats = %+v", st)
	}
	for _, r := range f.srv.Requests()[before:] {
		if r.Path == "/v1.0/users/delta" && strings.Contains(r.Query, "select") {
			t.Errorf("incremental sync enumerated all users: %s", r.Query)
		}
	}
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
		accts, _ := tx.Accounts()
		have := map[string]bool{}
		for _, a := range accts {
			have[a.ExternalID] = true
		}
		// the ingest upserts; cy stays in the table until a later cleanup (accounts are not pruned),
		// but dee, who arrived by delta, is there
		if !have[dee] {
			t.Errorf("dee (new in the delta) is missing: %v", have)
		}
		return nil
	})

	// full re-sync on demand
	full := func() int {
		n := 0
		for _, r := range f.srv.Requests() {
			if r.Path == "/v1.0/users/delta" && strings.Contains(r.Query, "select") {
				n++
			}
		}
		return n
	}
	b := full()
	f.changed = false
	syncTenant(t, db, tenantA, connsync.WithMode(context.Background(), connsync.Full), f.connector(baseCfg()))
	if full() != b+1 {
		t.Error("full re-sync on demand did not enumerate all users")
	}
}

func TestIngestCorrelatesToTheHRIdentities(t *testing.T) {
	f := newFake(t)
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "entra-hr")
	cfg := baseCfg()
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
		if got[ada] == nil || *got[ada] != id["EMP-2001"] {
			t.Errorf("ada -> %v, want EMP-2001 (%d): by employeeId", got[ada], id["EMP-2001"])
		}
		if got[ben] == nil || *got[ben] != id["EMP-2002"] {
			t.Errorf("ben -> %v, want EMP-2002 (%d): by e-mail address (the UPN), case-insensitive", got[ben], id["EMP-2002"])
		}
		if got[cy] != nil || got[spBilling] != nil {
			t.Errorf("cy -> %v, service principal -> %v: accounts matching no person stay uncorrelated", got[cy], got[spBilling])
		}
		return nil
	})
}

func TestCheckpointIsRolledBackWithAFailedIngest(t *testing.T) {
	f := newFake(t)
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "entra-rollback")
	boom := errors.New("boom")
	err := db.InTenant(context.Background(), tenantA, func(tx *store.TenantTx) error {
		if _, err := ingest.Sync(tx, testkit.Now, []connectors.Connector{f.connector(baseCfg())}, nil); err != nil {
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
	testkit.CreateTenant(t, db, tenantA, "entra-a")
	testkit.CreateTenant(t, db, tenantB, "entra-b")
	enumerations := func() int {
		n := 0
		for _, r := range f.srv.Requests() {
			if r.Path == "/v1.0/users/delta" && strings.Contains(r.Query, "select") {
				n++
			}
		}
		return n
	}
	syncTenant(t, db, tenantA, context.Background(), f.connector(baseCfg()))
	syncTenant(t, db, tenantB, context.Background(), f.connector(baseCfg()))
	if n := enumerations(); n != 2 {
		t.Fatalf("full enumerations after two first syncs = %d, want 2 (B must not resume from A's delta link)", n)
	}
	for _, tn := range []tenancy.ID{tenantA, tenantB} {
		syncTenant(t, db, tn, context.Background(), f.connector(baseCfg()))
	}
	if n := enumerations(); n != 2 {
		t.Errorf("full enumerations after the second round = %d, want still 2 (each tenant resumes from its own checkpoint)", n)
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
