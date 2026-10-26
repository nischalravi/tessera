// Package testkit holds shared test fixtures: a small hand-written world
// loaded through a real Connector implementation, and the seeded demo company.
//
// The tiny world:
//
//	alice (human)   okta:alice -> okta:eng -> aws:DevAdmin -> s3:GetObject on customer-pii
//	                okta:alice -> okta:eng -> aws:DevAdmin -> s3:PutObject on ml-artifacts
//	bob (human)     okta:bob -> okta:payments-clerks -> wd:payments:create
//	                okta:bob -> okta:payments-approvers -> wd:payments:approve        (SoD!)
//	carol (human)   okta:carol -> okta:platform -> aws:ProdAdmin -> iam:* on prod     (standing admin)
//	dave (human, terminated) owns svc-etl; manager is carol
//	svc-etl (service, owner dave) -> direct s3:GetObject on customer-pii; access key 400 days old
//	helper-bot (ai_agent, owner alice) -> snowflake:ANALYST -> snowflake:PII_READER -> SELECT CUSTOMERS
package testkit

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// Now is the reference time of every fixture.
var Now = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

// TinyConnector is the tiny world (connectors.Tiny).
type TinyConnector = connectors.Tiny

// IDs maps "alice", "acct:okta:alice", "group:aws:ProdAdmin" etc. to database ids.
type IDs map[string]int64

// TinyTenant is the tenant testkit.Tiny loads the tiny world into.
var TinyTenant = tenancy.MustParse("00000000-0000-4000-8000-0000000000aa")

// DB is a test database plus the tenant its fixture data lives in.
type DB struct {
	*store.DB
	Tenant tenancy.ID
}

// Open opens an empty database in a temporary directory.
func Open(tb testing.TB) *store.DB {
	tb.Helper()
	st, err := store.Open(context.Background(), store.TestTarget(tb))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = st.Close() })
	return st
}

// CreateTenant creates a tenant, failing the test on error.
func CreateTenant(tb testing.TB, db *store.DB, id tenancy.ID, slug string) {
	tb.Helper()
	if err := db.InSystem(context.Background(), "test fixture", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: id, Slug: slug, Name: slug, CreatedAt: Now})
		return err
	}); err != nil {
		tb.Fatal(err)
	}
}

var tiny struct {
	once sync.Once
	db   []byte // SQLite: the loaded file
	src  string // Postgres: the template database
	ids  IDs
	err  error
}

// Tiny returns a database whose tenant TinyTenant holds the tiny world (usage
// relative to Now). The world is loaded once per test binary; every call gets
// its own copy of that database, with the same ids.
func Tiny(tb testing.TB) (*DB, IDs) {
	tb.Helper()
	tiny.once.Do(buildTiny)
	if tiny.err != nil {
		tb.Fatal(tiny.err)
	}
	target := tiny.src
	if tiny.db != nil { // SQLite: a private copy of the loaded file
		target = filepath.Join(tb.TempDir(), "test.db")
		if err := os.WriteFile(target, tiny.db, 0o600); err != nil {
			tb.Fatal(err)
		}
	} else { // Postgres: a database created from the loaded template
		target = store.TestClone(tb, tiny.src)
	}
	st, err := store.Open(context.Background(), target)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = st.Close() })
	return &DB{st, TinyTenant}, maps.Clone(tiny.ids)
}

func buildTiny() {
	dir, err := makeTempDir()
	if err != nil {
		tiny.err = err
		return
	}
	defer os.RemoveAll(dir)
	// A SQLite file in dir, or (TESSERA_TEST_PG_URL) a Postgres template database.
	src, err := store.TestSharedTarget(dir, "tiny", func(target string) error {
		ctx := context.Background()
		st, err := store.Open(ctx, target)
		if err != nil {
			return err
		}
		defer st.Close()
		err = st.InSystem(ctx, "test fixture", func(s *store.SystemTx) error {
			_, err := s.CreateTenant(store.Tenant{ID: TinyTenant, Slug: "tiny", Name: "tiny", CreatedAt: Now})
			return err
		})
		if err == nil {
			err = st.InTenant(ctx, TinyTenant, func(c *store.TenantTx) error {
				_, err := ingest.Sync(c, Now, []connectors.Connector{TinyConnector{Now: Now}}, nil)
				return err
			})
		}
		if err == nil {
			err = st.ReadTenant(ctx, TinyTenant, func(c *store.TenantTx) error { tiny.ids, err = loadIDs(c); return err })
		}
		if err == nil {
			err = st.Checkpoint(ctx)
		}
		if err == nil {
			err = st.Close()
		}
		return err
	})
	if err == nil {
		if store.IsPostgresDSN(src) {
			tiny.src = src
		} else {
			tiny.db, err = os.ReadFile(src) // #nosec G304 -- path made above
		}
	}
	tiny.err = err
}

// LoadIDs builds the id map for the current contents of db's tenant.
func LoadIDs(tb testing.TB, db *DB) IDs {
	tb.Helper()
	var ids IDs
	Read(tb, db, func(c *store.TenantTx) (err error) {
		ids, err = loadIDs(c)
		return err
	})
	return ids
}

func loadIDs(c *store.TenantTx) (IDs, error) {
	ids := IDs{}
	idents, err := c.Identities()
	if err != nil {
		return nil, err
	}
	for _, i := range idents {
		ids[i.ExternalID] = i.ID
	}
	accts, err := c.Accounts()
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		ids["acct:"+a.System+":"+a.ExternalID] = a.ID
	}
	groups, err := c.Groups()
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		ids["group:"+g.System+":"+g.ExternalID] = g.ID
	}
	return ids, nil
}

// Read runs fn in a read-only transaction of db's tenant, failing the test on error.
func Read(tb testing.TB, db *DB, fn func(*store.TenantTx) error) {
	tb.Helper()
	if err := db.ReadTenant(context.Background(), db.Tenant, fn); err != nil {
		tb.Fatal(err)
	}
}

// Get returns fn's result, run in a read-only transaction of db's tenant.
func Get[T any](tb testing.TB, db *DB, fn func(*store.TenantTx) (T, error)) T {
	tb.Helper()
	var out T
	Read(tb, db, func(c *store.TenantTx) error {
		var err error
		out, err = fn(c)
		return err
	})
	return out
}

// Write runs fn in a write transaction of db's tenant, failing the test on error.
func Write(tb testing.TB, db *DB, fn func(*store.TenantTx) error) {
	tb.Helper()
	if err := db.InTenant(context.Background(), db.Tenant, fn); err != nil {
		tb.Fatal(err)
	}
}

// Policies loads the repository policies.
func Policies(tb testing.TB) []*policy.Policy {
	tb.Helper()
	pols, err := policy.NewLoader(policies.FS).Load()
	if err != nil {
		tb.Fatal(err)
	}
	return pols
}

var (
	demoOnce sync.Once
	demoDir  string
	demoSrc  string
	demoErr  error
)

// DemoPath seeds the demo company once per test binary and returns a fresh
// copy-on-open path to it. Callers must not modify the returned database;
// use Demo for a private, writable copy.
func demoPath() (string, error) {
	demoOnce.Do(func() {
		dir, err := makeTempDir()
		if err != nil {
			demoErr = err
			return
		}
		demoDir = dir
		// A SQLite file in dir, or (TESSERA_TEST_PG_URL) a Postgres template database.
		demoSrc, demoErr = store.TestSharedTarget(dir, "demo", func(target string) error {
			ctx := context.Background()
			st, err := store.Open(ctx, target)
			if err != nil {
				return err
			}
			defer st.Close()
			pols, err := policy.NewLoader(policies.FS).Load()
			if err != nil {
				return err
			}
			conns, err := connectors.Load("demo", Now)
			if err != nil {
				return err
			}
			if _, err := seed.Run(ctx, st, Now, pols, []seed.Tenant{seed.Larkspur(conns)}); err != nil {
				return err
			}
			return st.Checkpoint(ctx)
		})
	})
	return demoSrc, demoErr
}

// Demo returns a private, writable copy of the seeded demo company database
// (tenant seed.LarkspurID only).
func Demo(tb testing.TB) *DB {
	tb.Helper()
	src, err := demoPath()
	if err != nil {
		tb.Fatal(err)
	}
	st, err := store.Open(context.Background(), store.TestClone(tb, src))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = st.Close() })
	return &DB{st, seed.LarkspurID}
}

// ExplainEdges turns every grant edge of db's tenant into an evaluator edge
// (allow, exact) whose explanation id is name(edge); an edge that name maps to
// "" is left as it is. It is the evaluated-edge fixture for EP-8 wiring tests.
func ExplainEdges(tb testing.TB, db *DB, name func(*store.GrantEdge) string) {
	tb.Helper()
	Write(tb, db, func(c *store.TenantTx) error {
		edges, err := c.Edges()
		if err != nil {
			return err
		}
		for _, e := range edges {
			id := name(e)
			if id == "" {
				continue
			}
			if err := c.DeleteEdge(e.ID, time.Now()); err != nil {
				return err
			}
			ok, err := c.UpsertEvaluatorEdge(e.Src, e.Dst, e.Relation, Now,
				store.EdgeEvaluation{ExplanationID: id, Outcome: "allow", Fidelity: "exact"})
			if err != nil || !ok {
				tb.Fatalf("UpsertEvaluatorEdge(%s, %s) = %v, %v", e.Src, e.Dst, ok, err)
			}
		}
		return nil
	})
}
