package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Role mining (issue #298): a tenant sees and decides only its own runs and
// candidates; a candidate that names another tenant's role is refused by the
// guard triggers.

type miningRows struct {
	roleRows
	run, cand string
}

func seedMiningRows(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) miningRows {
	t.Helper()
	r := miningRows{roleRows: seedRoleRows(t, db, tn, tag), run: "mrun-" + tag, cand: "mcand-" + tag}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		uid := r.user.ID.String()
		if err := c.InsertMiningRun(&store.MiningRun{ID: r.run, Status: store.MiningQueued, Params: "{}", Algorithm: "x",
			RequestedBy: &uid, RequestedActor: "x", CreatedAt: storetest.Now}); err != nil {
			return err
		}
		return c.InsertMiningCandidate(&store.MiningCandidate{ID: r.cand, RunID: r.run, Rank: 1, Name: "Mined " + tag,
			Entitlements: "[1,2]", Members: "[3,4,5]", Outliers: "[]", Coverage: 3, Confidence: 80, Cohesion: 90,
			SimilarRoleID: &r.role})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func miningFixture(t *testing.T) (*storetest.Fixture, miningRows, miningRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedMiningRows(t, f.DB, f.A, "a"), seedMiningRows(t, f.DB, f.B, "b")
}

func TestIsolation_MiningReads(t *testing.T) {
	f, a, b := miningFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if rs, err := c.MiningRuns(10); err != nil || len(rs) != 1 || rs[0].ID != b.run {
			t.Errorf("MiningRuns = %v, %v", rs, err)
		}
		if _, err := c.MiningRun(a.run); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MiningRun(A's) = %v", err)
		}
		if ar, err := c.ActiveMiningRun(); err != nil || ar.ID != b.run {
			t.Errorf("ActiveMiningRun = %v, %v", ar, err)
		}
		if cs, err := c.MiningCandidates(a.run); err != nil || len(cs) != 0 {
			t.Errorf("MiningCandidates(A's run) = %v, %v", cs, err)
		}
		if cs, err := c.MiningCandidates(b.run); err != nil || len(cs) != 1 || cs[0].ID != b.cand {
			t.Errorf("MiningCandidates(B's run) = %v, %v", cs, err)
		}
		if _, err := c.MiningCandidate(a.cand); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("MiningCandidate(A's) = %v", err)
		}
		return nil
	})
}

var miningMutations = map[string]func(c *store.TenantTx, a, b miningRows, af, bf storetest.Tenant) error{
	"StartMiningRun": func(c *store.TenantTx, a, _ miningRows, _, _ storetest.Tenant) error {
		return c.StartMiningRun(a.run, storetest.Now)
	},
	"FinishMiningRun": func(c *store.TenantTx, a, _ miningRows, _, _ storetest.Tenant) error {
		return c.FinishMiningRun(&store.MiningRun{ID: a.run, Status: store.MiningFailed, Error: "x"}, storetest.Now)
	},
	"DecideMiningCandidate": func(c *store.TenantTx, a, _ miningRows, _, _ storetest.Tenant) error {
		return c.DecideMiningCandidate(a.cand, store.CandidateDismissed, nil, "x", storetest.Now, "no", nil)
	},
	"InsertMiningCandidate(A's run)": func(c *store.TenantTx, a, _ miningRows, _, _ storetest.Tenant) error {
		return c.InsertMiningCandidate(&store.MiningCandidate{ID: "x", RunID: a.run, Rank: 2, Name: "x", Entitlements: "[]",
			Members: "[]", Outliers: "[]"})
	},
	"InsertMiningCandidate(A's similar role)": func(c *store.TenantTx, a, b miningRows, _, _ storetest.Tenant) error {
		return c.InsertMiningCandidate(&store.MiningCandidate{ID: "x", RunID: b.run, Rank: 2, Name: "x", Entitlements: "[]",
			Members: "[]", Outliers: "[]", SimilarRoleID: &a.role})
	},
	"DecideMiningCandidate(A's role)": func(c *store.TenantTx, a, b miningRows, _, _ storetest.Tenant) error {
		return c.DecideMiningCandidate(b.cand, store.CandidateAccepted, nil, "x", storetest.Now, "", &a.role)
	},
	"InsertMiningRun(A's user)": func(c *store.TenantTx, a, _ miningRows, _, _ storetest.Tenant) error {
		uid := a.user.ID.String()
		return c.InsertMiningRun(&store.MiningRun{ID: "x", Status: store.MiningQueued, Params: "{}", Algorithm: "x",
			RequestedBy: &uid, RequestedActor: "x", CreatedAt: storetest.Now})
	},
}

func TestIsolation_MiningMutationsScoped(t *testing.T) {
	for name, fn := range miningMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := miningFixture(t)
			before := miningDump(t, f.DB, f.A.ID, a)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b, f.A, f.B) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v", name, err)
			}
			if miningDump(t, f.DB, f.A.ID, a) != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

func miningCovered() map[string]bool {
	out := map[string]bool{}
	for k := range miningMutations {
		out[k] = true
	}
	for _, k := range []string{"MiningRuns", "MiningRun", "ActiveMiningRun", "MiningCandidates", "MiningCandidate"} {
		out[k] = true // TestIsolation_MiningReads
	}
	for _, k := range []string{"InsertMiningRun", "InsertMiningCandidate"} {
		out[k] = true // the A's-user, A's-run and A's-role cases of miningMutations, and the seed
	}
	return out
}

// A candidate is decided once; a finished run cannot be finished again.
func TestMining_DecideOnceAndFinishOnce(t *testing.T) {
	f, a, _ := miningFixture(t)
	ctx := context.Background()
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if err := c.StartMiningRun(a.run, storetest.Now); err != nil {
			return err
		}
		if err := c.FinishMiningRun(&store.MiningRun{ID: a.run, Status: store.MiningSucceeded, SnapshotHash: "h", Candidates: 1},
			storetest.Now); err != nil {
			return err
		}
		if err := c.FinishMiningRun(&store.MiningRun{ID: a.run, Status: store.MiningFailed}, storetest.Now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second finish = %v", err)
		}
		if _, err := c.ActiveMiningRun(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ActiveMiningRun after finish = %v", err)
		}
		if err := c.DecideMiningCandidate(a.cand, store.CandidateAccepted, nil, "x", storetest.Now, "", &a.role); err != nil {
			return err
		}
		if err := c.DecideMiningCandidate(a.cand, store.CandidateDismissed, nil, "x", storetest.Now, "late", nil); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second decision = %v", err)
		}
		got, err := c.MiningCandidate(a.cand)
		if err != nil || got.Status != store.CandidateAccepted || got.RoleID == nil || *got.RoleID != a.role {
			t.Errorf("candidate = %+v, %v", got, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func miningDump(t *testing.T, db *store.DB, tid tenancy.ID, a miningRows) string {
	t.Helper()
	out := roleDump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		runs, err := c.MiningRuns(100)
		if err != nil {
			return err
		}
		cs, err := c.MiningCandidates(a.run)
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{runs, cs})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
