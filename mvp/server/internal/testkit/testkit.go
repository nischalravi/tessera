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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// Now is the reference time of every fixture.
var Now = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func sp(s string) *string { return &s }

func iref(x string) *connectors.IdentityRef { return &connectors.IdentityRef{ExternalID: x} }

func acct(system, xid string) connectors.Ref {
	return connectors.Ref{Kind: "account", System: system, ExternalID: xid}
}
func grp(system, xid string) connectors.Ref {
	return connectors.Ref{Kind: "group", System: system, ExternalID: xid}
}
func perm(system, xid string) connectors.Ref {
	return connectors.Ref{Kind: "perm", System: system, ExternalID: xid}
}

// TinyConnector is a minimal Connector implementation describing the tiny world.
type TinyConnector struct{ Now time.Time }

// System implements connectors.Connector.
func (TinyConnector) System() string { return "tiny" }

// DisplayName implements connectors.Connector.
func (TinyConnector) DisplayName() string { return "Tiny test connector" }

// TypeName implements connectors.Connector.
func (TinyConnector) TypeName() string { return "TinyConnector" }

// Discover implements connectors.Connector.
func (t TinyConnector) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	term := t.Now.Add(-days(10))
	human := func(xid, name, email, dept string, mgr *connectors.IdentityRef) connectors.IdentityRecord {
		return connectors.IdentityRecord{ExternalID: xid, Name: name, Type: "human", Email: sp(email), Department: sp(dept), Manager: mgr}
	}
	dave := human("dave", "Dave", "dave@t.example", "Data", iref("carol"))
	dave.Status, dave.TerminatedAt = "terminated", &term
	r := &connectors.DiscoveryResult{
		Identities: []connectors.IdentityRecord{
			human("alice", "Alice", "alice@t.example", "Engineering", iref("carol")),
			human("bob", "Bob", "bob@t.example", "Finance", iref("carol")),
			human("carol", "Carol", "carol@t.example", "Engineering", nil),
			dave,
			{ExternalID: "svc-etl", Name: "svc-etl", Type: "service", Owner: iref("dave")},
			{ExternalID: "helper-bot", Name: "Helper Bot", Type: "ai_agent", Owner: iref("alice")},
		},
		Resources: []connectors.ResourceRecord{
			{System: "aws", ExternalID: "customer-pii", Name: "s3://customer-pii", Kind: "s3_bucket", Environment: sp("prod"), Tags: []string{"pii"}},
			{System: "aws", ExternalID: "ml-artifacts", Name: "s3://ml-artifacts", Kind: "s3_bucket", Environment: sp("staging")},
			{System: "aws", ExternalID: "prod", Name: "aws/prod", Kind: "aws_account", Environment: sp("prod")},
			{System: "workday", ExternalID: "payments", Name: "Supplier Payments", Kind: "business_process", Environment: sp("prod"), Tags: []string{"payments"}},
			{System: "snowflake", ExternalID: "CUSTOMERS", Name: "snowflake/CUSTOMERS", Kind: "database", Environment: sp("prod"), Tags: []string{"pii"}},
		},
		Permissions: []connectors.PermissionRecord{
			{System: "aws", ExternalID: "get-pii", Action: "s3:GetObject", ResourceExternalID: "customer-pii"},
			{System: "aws", ExternalID: "put-ml", Action: "s3:PutObject", ResourceExternalID: "ml-artifacts"},
			{System: "aws", ExternalID: "admin-prod", Action: "iam:*", ResourceExternalID: "prod", Privileged: true},
			{System: "workday", ExternalID: "pay-create", Action: "payments:create", ResourceExternalID: "payments"},
			{System: "workday", ExternalID: "pay-approve", Action: "payments:approve", ResourceExternalID: "payments"},
			{System: "snowflake", ExternalID: "select-customers", Action: "snowflake:SELECT", ResourceExternalID: "CUSTOMERS"},
		},
		Groups: []connectors.GroupRecord{
			{System: "okta", ExternalID: "eng", Name: "eng"},
			{System: "okta", ExternalID: "platform", Name: "platform"},
			{System: "okta", ExternalID: "payments-clerks", Name: "payments-clerks"},
			{System: "okta", ExternalID: "payments-approvers", Name: "payments-approvers"},
			{System: "aws", ExternalID: "DevAdmin", Name: "DevAdmin", Kind: "role"},
			{System: "aws", ExternalID: "ProdAdmin", Name: "ProdAdmin", Kind: "role", Privileged: true, Requestable: true},
			{System: "snowflake", ExternalID: "ANALYST", Name: "ANALYST", Kind: "role"},
			{System: "snowflake", ExternalID: "PII_READER", Name: "PII_READER", Kind: "role"},
		},
		Accounts: []connectors.AccountRecord{
			{System: "okta", ExternalID: "alice", Username: "alice@t.example", Identity: iref("alice")},
			{System: "okta", ExternalID: "bob", Username: "bob@t.example", Identity: iref("bob")},
			{System: "okta", ExternalID: "carol", Username: "carol@t.example", Identity: iref("carol")},
			{System: "okta", ExternalID: "dave", Username: "dave@t.example", Identity: iref("dave"), Status: "disabled"},
			{System: "aws", ExternalID: "dave-iam", Username: "dave", Identity: iref("dave")}, // missed in offboarding
			{System: "aws", ExternalID: "svc-etl", Username: "svc-etl", Identity: iref("svc-etl"), Kind: "service"},
			{System: "snowflake", ExternalID: "HELPER_BOT", Username: "HELPER_BOT", Identity: iref("helper-bot"), Kind: "agent"},
		},
		Edges: []connectors.EdgeRecord{
			{Src: acct("okta", "alice"), Dst: grp("okta", "eng"), Relation: "member_of"},
			{Src: grp("okta", "eng"), Dst: grp("aws", "DevAdmin"), Relation: "maps_to"},
			{Src: grp("aws", "DevAdmin"), Dst: perm("aws", "get-pii"), Relation: "grants"},
			{Src: grp("aws", "DevAdmin"), Dst: perm("aws", "put-ml"), Relation: "grants"},
			{Src: acct("okta", "bob"), Dst: grp("okta", "payments-clerks"), Relation: "member_of"},
			{Src: acct("okta", "bob"), Dst: grp("okta", "payments-approvers"), Relation: "member_of"},
			{Src: grp("okta", "payments-clerks"), Dst: perm("workday", "pay-create"), Relation: "grants"},
			{Src: grp("okta", "payments-approvers"), Dst: perm("workday", "pay-approve"), Relation: "grants"},
			{Src: acct("okta", "carol"), Dst: grp("okta", "platform"), Relation: "member_of"},
			{Src: acct("okta", "carol"), Dst: grp("okta", "eng"), Relation: "member_of"},
			{Src: grp("okta", "platform"), Dst: grp("aws", "ProdAdmin"), Relation: "maps_to"},
			{Src: grp("aws", "ProdAdmin"), Dst: perm("aws", "admin-prod"), Relation: "grants"},
			{Src: acct("okta", "dave"), Dst: grp("okta", "eng"), Relation: "member_of"},
			{Src: acct("aws", "dave-iam"), Dst: perm("aws", "get-pii"), Relation: "direct_grant"},
			{Src: acct("aws", "svc-etl"), Dst: perm("aws", "get-pii"), Relation: "direct_grant"},
			{Src: acct("snowflake", "HELPER_BOT"), Dst: grp("snowflake", "ANALYST"), Relation: "member_of"},
			{Src: grp("snowflake", "ANALYST"), Dst: grp("snowflake", "PII_READER"), Relation: "maps_to"},
			{Src: grp("snowflake", "PII_READER"), Dst: perm("snowflake", "select-customers"), Relation: "grants"},
		},
		Secrets: []connectors.SecretRecord{
			{System: "aws", ExternalID: "svc-etl-key", Account: acct("aws", "svc-etl"), Kind: "access_key", Name: "AKIAETL",
				CreatedAt: t.Now.Add(-days(400))},
		},
		Delegations: []connectors.DelegationRecord{
			{Agent: connectors.IdentityRef{ExternalID: "helper-bot"}, Principal: connectors.IdentityRef{ExternalID: "alice"},
				Scopes: []string{"snowflake:query"}},
		},
	}
	return r, nil
}

// StreamEvents implements connectors.Connector: alice uses PutObject on
// ml-artifacts every third day and never touches customer-pii; carol last used
// prod admin 75 days ago; bob created a payment yesterday.
func (t TinyConnector) StreamEvents(_ context.Context, _ *time.Time, yield func(connectors.Event) error) error {
	for d := 0; d < 90; d += 3 {
		if err := yield(&connectors.UsageRecord{Identity: *iref("alice"), Permission: perm("aws", "put-ml"), Day: t.Now.Add(-days(d)), Count: 5}); err != nil {
			return err
		}
	}
	if err := yield(&connectors.UsageRecord{Identity: *iref("carol"), Permission: perm("aws", "admin-prod"), Day: t.Now.Add(-days(75)), Count: 1}); err != nil {
		return err
	}
	return yield(&connectors.UsageRecord{Identity: *iref("bob"), Permission: perm("workday", "pay-create"), Day: t.Now.Add(-days(1)), Count: 3})
}

// IDs maps "alice", "acct:okta:alice", "group:aws:ProdAdmin" etc. to database ids.
type IDs map[string]int64

// Open opens an empty database in a temporary directory.
func Open(tb testing.TB) *store.Store {
	tb.Helper()
	st, err := store.Open(context.Background(), filepath.Join(tb.TempDir(), "test.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = st.Close() })
	return st
}

// Tiny returns a database loaded with the tiny world (usage relative to Now).
func Tiny(tb testing.TB) (*store.Store, IDs) {
	tb.Helper()
	st := Open(tb)
	ctx := context.Background()
	if err := st.Write(ctx, func(c *store.Conn) error {
		_, err := ingest.Sync(c, Now, []connectors.Connector{TinyConnector{Now}}, nil)
		return err
	}); err != nil {
		tb.Fatal(err)
	}
	return st, LoadIDs(tb, st)
}

// LoadIDs builds the id map for the current database contents.
func LoadIDs(tb testing.TB, st *store.Store) IDs {
	tb.Helper()
	c := st.Read(context.Background())
	ids := IDs{}
	idents, err := c.Identities("")
	if err != nil {
		tb.Fatal(err)
	}
	for _, i := range idents {
		ids[i.ExternalID] = i.ID
	}
	accts, err := c.Accounts("")
	if err != nil {
		tb.Fatal(err)
	}
	for _, a := range accts {
		ids["acct:"+a.System+":"+a.ExternalID] = a.ID
	}
	groups, err := c.Groups("ORDER BY id")
	if err != nil {
		tb.Fatal(err)
	}
	for _, g := range groups {
		ids["group:"+g.System+":"+g.ExternalID] = g.ID
	}
	return ids
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

// Conn returns a read connection.
func Conn(st *store.Store) *store.Conn { return st.Read(context.Background()) }

// Write runs fn in a write transaction, failing the test on error.
func Write(tb testing.TB, st *store.Store, fn func(*store.Conn) error) {
	tb.Helper()
	if err := st.Write(context.Background(), fn); err != nil {
		tb.Fatal(err)
	}
}

var (
	demoOnce sync.Once
	demoDir  string
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
		ctx := context.Background()
		st, err := store.Open(ctx, filepath.Join(dir, "demo.db"))
		if err != nil {
			demoErr = err
			return
		}
		defer st.Close()
		pols, err := policy.NewLoader(policies.FS).Load()
		if err != nil {
			demoErr = err
			return
		}
		conns, err := connectors.Load("demo", Now)
		if err != nil {
			demoErr = err
			return
		}
		if _, err := seed.Run(ctx, st, conns, Now, pols); err != nil {
			demoErr = err
			return
		}
		_, demoErr = st.DB.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	})
	return filepath.Join(demoDir, "demo.db"), demoErr
}

// Demo returns a private, writable copy of the seeded demo company database.
func Demo(tb testing.TB) *store.Store {
	tb.Helper()
	src, err := demoPath()
	if err != nil {
		tb.Fatal(err)
	}
	dst := filepath.Join(tb.TempDir(), "demo.db")
	if err := copyFile(src, dst); err != nil {
		tb.Fatal(err)
	}
	st, err := store.Open(context.Background(), dst)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = st.Close() })
	return st
}
