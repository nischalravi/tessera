package google

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
	tenantA = tenancy.MustParse("00000000-0000-4000-8000-0000000000e1")
	tenantB = tenancy.MustParse("00000000-0000-4000-8000-0000000000e2")
)

// hr is a stand-in for an authoritative HR connector: the people Google
// accounts must correlate to.
type hr struct{}

func (hr) System() string      { return "workday" }
func (hr) DisplayName() string { return "HR (test)" }
func (hr) TypeName() string    { return "TestHR" }
func (hr) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	email := func(s string) *string { return &s }
	return &connectors.DiscoveryResult{Identities: []connectors.IdentityRecord{
		{ExternalID: "EMP-3001", Name: "Ada Fixture (HR)", Type: "human", Email: email("ada.fixture@example.com"), Status: "active"},
		{ExternalID: "EMP-3002", Name: "Ben Sample (HR)", Type: "human", Email: email("ben.sample@example.com"), Status: "active"},
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
	testkit.CreateTenant(t, db, tenantA, "google-e2e")
	st := syncTenant(t, db, tenantA, context.Background(), f.connector(baseCfg(t)))
	if st.Discovery.Identities != 3 || st.Discovery.Accounts != 3 || st.Discovery.Groups != 6 || st.Discovery.Edges != 8 || st.Events.Usage != 0 {
		t.Fatalf("sync stats = %+v", st)
	}
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tenantA}, func(tx *store.TenantTx) error {
		idents, err := tx.Identities()
		if err != nil || len(idents) != 3 {
			t.Fatalf("identities = %d, %v", len(idents), err)
		}
		byXID := map[string]*store.Identity{}
		for _, i := range idents {
			byXID[i.ExternalID] = i
		}
		accts, err := tx.Accounts()
		if err != nil || len(accts) != 3 {
			t.Fatalf("accounts = %d, %v", len(accts), err)
		}
		for _, a := range accts {
			if a.System != "google" || a.IdentityID == nil {
				t.Errorf("account %s: system=%s identity=%v", a.ExternalID, a.System, a.IdentityID)
			}
			switch a.ExternalID {
			case ada:
				if *a.IdentityID != byXID["EMP-3001"].ID || a.LastLoginAt == nil || a.Status != "active" {
					t.Errorf("ada's account = %+v", a)
				}
			case ben:
				if *a.IdentityID != byXID["google:"+ben].ID || a.Status != "disabled" {
					t.Errorf("ben's account = %+v", a)
				}
			}
		}
		groups, err := tx.Groups()
		if err != nil || len(groups) != 6 {
			t.Fatalf("groups = %d, %v", len(groups), err)
		}
		k, err := tx.ConnectorCheckpoint(System, checkpointName)
		if err != nil || len(k.State) == 0 || k.Cursor == "" || k.FullSyncAt == nil {
			t.Errorf("checkpoint = %+v, %v", k, err)
		}
		return nil
	})

	// Nesting is visible to the existing graph analysis: ada is in Engineering,
	// which is in Platform Admins, which holds the Help Desk Admin role.
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
		for _, want := range []string{"group:" + gEng, "group:" + gPlat, "group:role:" + roleHD, "group:role:" + roleSup} {
			if !seen[node[want]] {
				t.Errorf("ada does not reach %s through the nested groups", want)
			}
		}
		if seen[node["group:"+gFin]] {
			t.Error("ada reaches a group she is not in")
		}
		return nil
	})

	// the second sync resumes from the checkpoint in the database: no member list is read again
	members := f.members()
	st = syncTenant(t, db, tenantA, context.Background(), f.connector(baseCfg(t)))
	if st.Discovery.Accounts != 3 || st.Discovery.Edges != 8 || f.members() != members {
		t.Errorf("incremental stats = %+v, member requests %d -> %d", st, members, f.members())
	}
	// a full re-sync on demand reads them all
	syncTenant(t, db, tenantA, connsync.WithMode(context.Background(), connsync.Full), f.connector(baseCfg(t)))
	if f.members() != members+4 {
		t.Errorf("full re-sync member requests = %d, want %d", f.members(), members+4)
	}
}

func TestIngestCorrelatesToTheHRIdentities(t *testing.T) {
	f := newFake(t)
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "google-hr")
	cfg := baseCfg(t)
	cfg.EmitIdentities = false
	st := syncTenant(t, db, tenantA, context.Background(), hr{}, f.connector(cfg))
	if st.Discovery.Identities != 2 || st.Discovery.Accounts != 3 {
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
		if got[ada] == nil || *got[ada] != id["EMP-3001"] {
			t.Errorf("ada -> %v, want EMP-3001 (%d): by the employee id in externalIds", got[ada], id["EMP-3001"])
		}
		if got[ben] == nil || *got[ben] != id["EMP-3002"] {
			t.Errorf("ben -> %v, want EMP-3002 (%d): by e-mail address, case-insensitive", got[ben], id["EMP-3002"])
		}
		if got[cy] != nil {
			t.Errorf("cy -> %v: an account matching no person stays uncorrelated", got[cy])
		}
		return nil
	})
}

func TestCheckpointIsRolledBackWithAFailedIngest(t *testing.T) {
	f := newFake(t)
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "google-rollback")
	boom := errors.New("boom")
	err := db.InTenant(context.Background(), tenantA, func(tx *store.TenantTx) error {
		if _, err := ingest.Sync(tx, testkit.Now, []connectors.Connector{f.connector(baseCfg(t))}, nil); err != nil {
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
	testkit.CreateTenant(t, db, tenantA, "google-a")
	testkit.CreateTenant(t, db, tenantB, "google-b")
	syncTenant(t, db, tenantA, context.Background(), f.connector(baseCfg(t)))
	syncTenant(t, db, tenantB, context.Background(), f.connector(baseCfg(t)))
	if n := f.members(); n != 8 {
		t.Fatalf("member requests after two first syncs = %d, want 8 (B must not resume from A's snapshot)", n)
	}
	for _, tn := range []tenancy.ID{tenantA, tenantB} {
		syncTenant(t, db, tn, context.Background(), f.connector(baseCfg(t)))
	}
	if n := f.members(); n != 8 {
		t.Errorf("member requests after the second round = %d, want still 8 (each tenant resumes from its own checkpoint)", n)
	}
	for _, tn := range []tenancy.ID{tenantA, tenantB} {
		testkit.Read(t, &testkit.DB{DB: db, Tenant: tn}, func(tx *store.TenantTx) error {
			ks, err := tx.ConnectorCheckpoints()
			if err != nil || len(ks) != 1 || !strings.Contains(ks[0].System, "google") {
				t.Errorf("tenant %s sees %v checkpoints, %v", tn, ks, err)
			}
			return nil
		})
	}
}
