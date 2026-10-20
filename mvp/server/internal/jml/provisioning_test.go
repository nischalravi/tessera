package jml_test

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// stub is a target that records what it is asked to do ("<kind> <user>
// <group>"). Verify confirms every change unless dropAll is set.
type stub struct {
	mu       sync.Mutex
	calls    []string
	failWith error
	dropAll  bool
}

func key(r target.Request) string {
	return r.Kind + " " + r.Account.Username + " " + r.Group.ExternalID
}

func (s *stub) Apply(_ context.Context, r target.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWith != nil {
		return s.failWith
	}
	s.calls = append(s.calls, key(r))
	return nil
}

func (s *stub) Verify(_ context.Context, r target.Request) (target.Verdict, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := !s.dropAll
	return target.Verdict{OK: ok, Expected: "applied", Observed: map[bool]string{true: "applied", false: "unchanged"}[ok]}, nil
}

// writeBack turns write-back on for the tenant's okta connection (creating it
// when the database has none) and returns an engine driving the stub.
func writeBack(t *testing.T, st *testkit.DB, s *stub) *provision.Engine {
	t.Helper()
	testkit.Write(t, st, func(c *store.TenantTx) error {
		conns, err := c.Connections()
		if err != nil {
			return err
		}
		var id string
		for _, cn := range conns {
			if cn.System == "okta" {
				id = cn.ID
			}
		}
		if id == "" {
			id = store.NewID()
			if err := c.InsertConnection(&store.Connection{ID: id, Name: "Okta (jml test)", ConnectorType: "demo-okta", System: "okta",
				Role: "account_source", CreatedAt: testkit.Now, UpdatedAt: testkit.Now}); err != nil {
				return err
			}
		}
		return c.UpsertProvTarget(&store.ProvTarget{ID: store.NewID(), ConnectionID: id, Kind: provision.KindSCIM,
			BaseURL: "https://okta.example/scim/v2", Settings: "{}", WriteBack: true, CreatedBy: "test"}, testkit.Now)
	})
	return &provision.Engine{DB: st.DB, Clock: func() time.Time { return testkit.Now }, MaxAttempts: 2, MaxVerifies: 2,
		Backoff: func(int) time.Duration { return 0 },
		Build:   func(*store.ProvTarget, string) (target.Connector, error) { return s, nil }}
}

func execute(t *testing.T, st *testkit.DB, evID int64) {
	t.Helper()
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := jml.ExecuteEvent(c, testkit.Now, evID, store.UserRef{Display: "jml-automation"}, testkit.Policies(t))
		return err
	})
}

func leaverEvent(t *testing.T, st *testkit.DB, identity int64) int64 {
	t.Helper()
	var id int64
	testkit.Write(t, st, func(c *store.TenantTx) (err error) {
		id, err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: "t-prov", Type: "leaver", IdentityID: &identity,
			EffectiveAt: testkit.Now, Status: "pending"})
		return
	})
	return id
}

func oktaState(t *testing.T, st *testkit.DB, ids testkit.IDs, who string) (status string, groups []string) {
	t.Helper()
	testkit.Read(t, st, func(c *store.TenantTx) error {
		a, err := c.Account(ids["acct:okta:"+who])
		if err != nil {
			return err
		}
		status = a.Status
		edges, err := c.EdgesFrom("account:" + itoa(a.ID))
		for _, e := range edges {
			groups = append(groups, e.Dst)
		}
		return err
	})
	return
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// A leaver whose okta connection has write-back on: the account and its group
// memberships are removed from the target first; the graph changes only after
// the re-read confirms each one.
func TestExecuteLeaverThroughTheEngine(t *testing.T) {
	st, ids := testkit.Tiny(t)
	s := &stub{}
	eng := writeBack(t, st, s)
	execute(t, st, leaverEvent(t, st, ids["bob"]))

	status, groups := oktaState(t, st, ids, "bob")
	if status != "active" || len(groups) != 2 {
		t.Fatalf("before the target confirmed: status = %s, groups = %v; the graph must not change yet", status, groups)
	}
	testkit.Read(t, st, func(c *store.TenantTx) error {
		ops, err := c.ProvOps(store.ProvOpFilter{})
		if err != nil || len(ops) != 3 {
			t.Fatalf("ops = %d, %v; want the account and two memberships", len(ops), err)
		}
		for _, o := range ops {
			if o.Status != provision.Queued || o.Source != provision.SourceJML {
				t.Errorf("op = %+v", o)
			}
		}
		return nil
	})
	stats, err := eng.RunTenant(context.Background(), st.Tenant)
	if err != nil || stats.Verified != 3 {
		t.Fatalf("run = %+v, %v", stats, err)
	}
	if status, groups = oktaState(t, st, ids, "bob"); status != "disabled" || len(groups) != 0 {
		t.Errorf("after: status = %s, groups = %v", status, groups)
	}
	if len(s.calls) != 3 {
		t.Errorf("target calls = %v", s.calls)
	}
	// Executing is audited as before, plus the engine's events.
	testkit.Read(t, st, func(c *store.TenantTx) error {
		evs, _ := c.AuditLog(-1)
		seen := map[string]int{}
		for _, e := range evs {
			seen[e.Action]++
		}
		if seen["jml.leaver"] != 1 || seen["provision.enqueued"] != 3 || seen["provision.verified"] != 3 {
			t.Errorf("audit = %v", seen)
		}
		return nil
	})
}

// A target that refuses the write leaves the account active and the edges in place.
func TestExecuteLeaverFailedTargetWriteLeavesTheGraphAlone(t *testing.T) {
	st, ids := testkit.Tiny(t)
	s := &stub{failWith: &target.Error{Status: 400, Msg: "refused"}}
	eng := writeBack(t, st, s)
	execute(t, st, leaverEvent(t, st, ids["bob"]))
	stats, err := eng.RunTenant(context.Background(), st.Tenant)
	if err != nil || stats.Failed != 3 {
		t.Fatalf("run = %+v, %v", stats, err)
	}
	if status, groups := oktaState(t, st, ids, "bob"); status != "active" || len(groups) != 2 {
		t.Errorf("status = %s, groups = %v; a failed write must change nothing in Tessera", status, groups)
	}
}

// A target that says yes but does not change: mismatch, nothing changes in Tessera.
func TestExecuteLeaverUnverifiedChangeLeavesTheGraphAlone(t *testing.T) {
	st, ids := testkit.Tiny(t)
	s := &stub{dropAll: true}
	eng := writeBack(t, st, s)
	execute(t, st, leaverEvent(t, st, ids["bob"]))
	for i := 0; i < 3; i++ {
		if _, err := eng.RunTenant(context.Background(), st.Tenant); err != nil {
			t.Fatal(err)
		}
	}
	if status, groups := oktaState(t, st, ids, "bob"); status != "active" || len(groups) != 2 {
		t.Errorf("status = %s, groups = %v", status, groups)
	}
	testkit.Read(t, st, func(c *store.TenantTx) error {
		ops, _ := c.ProvOps(store.ProvOpFilter{Status: provision.Mismatch})
		fs, _ := c.ProvFindings("open", "")
		if len(ops) != 3 || len(fs) != 3 {
			t.Errorf("mismatched ops = %d, findings = %d; want 3 and 3", len(ops), len(fs))
		}
		return nil
	})
}

// A joiner: the okta account and group memberships are created in the target;
// Tessera's account and edges appear after verification. Systems without
// write-back (snowflake) are created at once.
func TestExecuteJoinerThroughTheEngine(t *testing.T) {
	st := testkit.Demo(t)
	s := &stub{}
	eng := writeBack(t, st, s)
	ev := demoEvent(t, st, "joiner", "")
	execute(t, st, ev.ID)

	type view struct{ okta, snowflake int }
	count := func() (v view) {
		testkit.Read(t, st, func(c *store.TenantTx) error {
			id, err := c.IdentityByExternalID("emp-new-" + itoa(ev.ID))
			if err != nil {
				t.Fatal(err)
			}
			as, err := c.IdentityAccounts(id.ID)
			for _, a := range as {
				switch a.System {
				case "okta":
					v.okta++
				case "snowflake":
					v.snowflake++
				}
			}
			return err
		})
		return
	}
	if v := count(); v.okta != 0 || v.snowflake != 1 {
		t.Fatalf("before the target confirmed: %+v; okta must wait, snowflake must not", v)
	}
	stats, err := eng.RunTenant(context.Background(), st.Tenant)
	if err != nil || stats.Verified == 0 || stats.Failed != 0 || stats.Mismatch != 0 {
		t.Fatalf("run = %+v, %v", stats, err)
	}
	if v := count(); v.okta != 1 {
		t.Errorf("after: %+v", v)
	}
	if len(s.calls) == 0 || s.calls[0][:len("create_account")] != "create_account" {
		t.Errorf("the account is created before memberships are added: %v", s.calls)
	}
	var edges int
	testkit.Read(t, st, func(c *store.TenantTx) error {
		id, _ := c.IdentityByExternalID("emp-new-" + itoa(ev.ID))
		as, _ := c.IdentityAccounts(id.ID)
		for _, a := range as {
			if a.System == "okta" {
				es, err := c.EdgesFrom("account:" + itoa(a.ID))
				if err != nil {
					t.Fatal(err)
				}
				edges = len(es)
			}
		}
		return nil
	})
	if edges == 0 {
		t.Error("no okta memberships after verification")
	}
}
