package reviews_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// The demo company of the parity fixtures: 219 standing grants, 84 review
// items and 135 auto-certified grants at the launch the seed performs.
var now = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

type world struct {
	db   *store.DB
	pols []*policy.Policy
	t    *testing.T
}

// The demo company is seeded once per test binary into a template database
// file (seeding is slow under -race); every test works on its own copy.
var (
	templateOnce sync.Once
	templateDir  string
	templateErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if templateDir != "" {
		_ = os.RemoveAll(templateDir)
	}
	os.Exit(code)
}

func seedTemplate() (string, error) {
	templateOnce.Do(func() {
		ctx := context.Background()
		dir, err := os.MkdirTemp("", "reviews-template-")
		if err != nil {
			templateErr = err
			return
		}
		templateDir = dir
		db, err := store.Open(ctx, filepath.Join(dir, "template.db"))
		if err != nil {
			templateErr = err
			return
		}
		pols, err := policy.NewLoader(policies.FS).Load()
		if err == nil {
			var conns []connectors.Connector
			if conns, err = connectors.Load("demo", now); err == nil {
				_, err = seed.Run(ctx, db, now, pols, []seed.Tenant{seed.Larkspur(conns), seed.Globex(now)})
			}
		}
		if err == nil {
			err = db.Checkpoint(ctx) // so the file can be copied on its own
		}
		templateErr = errors.Join(err, db.Close())
	})
	return filepath.Join(templateDir, "template.db"), templateErr
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	src, err := seedTemplate()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(src) // #nosec G304 -- the template this test binary created
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "reviews.db")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pols, err := policy.NewLoader(policies.FS).Load()
	if err != nil {
		t.Fatal(err)
	}
	return &world{db: db, pols: pols, t: t}
}

func (w *world) in(tenant tenancy.ID, fn func(c *store.TenantTx) error) {
	w.t.Helper()
	if err := w.db.InTenant(context.Background(), tenant, fn); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) larkspur(fn func(c *store.TenantTx) error) { w.t.Helper(); w.in(seed.LarkspurID, fn) }

// launch starts another campaign on the unchanged data.
func (w *world) launch(name string) int64 {
	w.t.Helper()
	var id int64
	w.larkspur(func(c *store.TenantTx) error {
		var err error
		id, err = reviews.GenerateCampaign(c, now, name, 60, w.pols)
		return err
	})
	return id
}

const seedCampaign = int64(1)

var reviewer = store.UserRef{Display: "Alice Auditor"}

// expectedInScope derives the population independently of the freezer, from
// the graph: every standing grant edge of an active account with effective
// permissions, for any identity (terminated included). It also returns the
// grant edges that must NOT be in the population.
func expectedInScope(t *testing.T, c *store.TenantTx) (in map[int64]string, out map[int64]string) {
	t.Helper()
	g, err := graph.Build(c, now)
	if err != nil {
		t.Fatal(err)
	}
	in, out = map[int64]string{}, map[int64]string{}
	for _, iid := range g.Identities(true) {
		eff := g.EffectivePermissions(iid)
		for _, ag := range g.GrantEdgesFromAccounts(iid) {
			if ag.Edge.EdgeID == nil {
				continue
			}
			edge := [2]string{ag.Acct, ag.Dst}
			switch {
			case ag.Edge.Source == "jit":
				out[*ag.Edge.EdgeID] = "jit"
			case g.Node(ag.Acct).Status != "active":
				out[*ag.Edge.EdgeID] = "inactive account"
			case len(graph.PermsViaEdge(eff, edge)) == 0:
				out[*ag.Edge.EdgeID] = "no effective permissions"
			default:
				in[*ag.Edge.EdgeID] = g.Node(ag.Acct).System
			}
		}
	}
	return in, out
}

func TestPopulationCompleteness(t *testing.T) {
	w := newWorld(t)
	w.larkspur(func(c *store.TenantTx) error {
		in, out := expectedInScope(t, c)
		pop, err := c.ReviewPopulation(seedCampaign)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := c.PopulationRows(seedCampaign)
		if err != nil {
			t.Fatal(err)
		}
		cmp, _ := c.Campaign(seedCampaign)
		if len(rows) != len(in) || pop.ItemCount != len(in) || cmp.TotalGrants != len(in) {
			t.Fatalf("rows %d, item_count %d, total_grants %d, in-scope grants %d", len(rows), pop.ItemCount, cmp.TotalGrants, len(in))
		}
		bySystem := map[string]int{}
		for i, r := range rows {
			sys, ok := in[r.EdgeID]
			if !ok {
				t.Errorf("row %d (edge %d) is not an in-scope grant", r.Ordinal, r.EdgeID)
			}
			if r.System != sys {
				t.Errorf("edge %d: system %q, want %q", r.EdgeID, r.System, sys)
			}
			if r.Ordinal != i+1 || (i > 0 && rows[i-1].EdgeID >= r.EdgeID) {
				t.Errorf("row %d is out of canonical order (ordinal %d, edge %d after %d)", i, r.Ordinal, r.EdgeID, rows[i-1].EdgeID)
			}
			if r.InScopeReason != reviews.InScope {
				t.Errorf("in_scope_reason %q", r.InScopeReason)
			}
			bySystem[r.System]++
			delete(in, r.EdgeID)
		}
		if len(in) != 0 {
			t.Errorf("%d in-scope grants are missing from the population: %v", len(in), in)
		}
		// out-of-scope grants are not in the snapshot, and there are some to leave out
		reasons := map[string]int{}
		for _, why := range out {
			reasons[why]++
		}
		if reasons["jit"] == 0 {
			t.Errorf("the demo has no JIT grant to exclude: %v", reasons)
		}
		for _, r := range rows {
			if why, bad := out[r.EdgeID]; bad {
				t.Errorf("edge %d (%s) is out of scope but in the population", r.EdgeID, why)
			}
		}
		// per-system counts in the header match the rows
		var counts map[string]int
		if err := json.Unmarshal(pop.SystemCounts, &counts); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(counts, bySystem) {
			t.Errorf("system_counts %v, rows say %v", counts, bySystem)
		}
		sum := 0
		for _, n := range counts {
			sum += n
		}
		if sum != pop.ItemCount {
			t.Errorf("system_counts sum %d != item_count %d", sum, pop.ItemCount)
		}
		// every system has a sync timestamp entry
		var syncs map[string]*string
		if err := json.Unmarshal(pop.SourceSyncs, &syncs); err != nil || len(syncs) != len(counts) {
			t.Errorf("source_syncs %s: %v", pop.SourceSyncs, err)
		}
		// review items + auto-certified = the population
		items, _ := c.CampaignItems(seedCampaign)
		autos, _ := c.AutoDecisions(seedCampaign)
		if len(items)+len(autos) != len(rows) || cmp.AutoCertified != len(autos) {
			t.Errorf("items %d + auto %d != rows %d (auto_certified %d)", len(items), len(autos), len(rows), cmp.AutoCertified)
		}
		return nil
	})
}

func TestPopulationSourceSyncTimestamps(t *testing.T) {
	w := newWorld(t)
	syncAt := now.Add(-3 * time.Hour)
	var camp int64
	w.larkspur(func(c *store.TenantTx) error {
		if err := c.Audit(syncAt, "system", "connectors.sync", nil); err != nil {
			return err
		}
		var err error
		camp, err = reviews.GenerateCampaign(c, now, "after sync", 60, w.pols)
		return err
	})
	w.larkspur(func(c *store.TenantTx) error {
		pop, err := c.ReviewPopulation(camp)
		if err != nil {
			t.Fatal(err)
		}
		var syncs map[string]*string
		if err := json.Unmarshal(pop.SourceSyncs, &syncs); err != nil {
			t.Fatal(err)
		}
		if len(syncs) == 0 {
			t.Fatal("no systems")
		}
		for sys, ts := range syncs {
			if ts == nil || *ts != "2026-10-08T06:30:00" {
				t.Errorf("%s synced at %v, want 2026-10-08T06:30:00", sys, ts)
			}
		}
		return nil
	})
}

func TestPopulationReproducible(t *testing.T) {
	w := newWorld(t)
	second := w.launch("second launch") // same data, new campaign
	w.larkspur(func(c *store.TenantTx) error {
		p1, _ := c.ReviewPopulation(seedCampaign)
		p2, err := c.ReviewPopulation(second)
		if err != nil {
			t.Fatal(err)
		}
		if p1.PopulationHash != p2.PopulationHash || p1.ItemCount != p2.ItemCount {
			t.Errorf("same data, different population: %s (%d) vs %s (%d)", p1.PopulationHash, p1.ItemCount, p2.PopulationHash, p2.ItemCount)
		}
		for _, id := range []int64{seedCampaign, second} {
			e, err := reviews.BuildExport(c, id, now)
			if err != nil {
				t.Fatal(err)
			}
			if !e.HashMatch() || e.Recomputed != e.Population.PopulationHash {
				t.Errorf("campaign %d: recomputed %s != stored %s", id, e.Recomputed, e.Population.PopulationHash)
			}
		}
		return nil
	})
	// a revoked grant changes the population of the next launch only
	w.larkspur(func(c *store.TenantTx) error {
		rows, _ := c.PopulationRows(seedCampaign)
		e, err := c.EdgeBetween(rows[0].EdgeSrc, rows[0].EdgeDst)
		if err != nil {
			t.Fatal(err)
		}
		return c.RevokeEdge(e.ID, now, "test")
	})
	third := w.launch("after a revoke")
	w.larkspur(func(c *store.TenantTx) error {
		p1, _ := c.ReviewPopulation(seedCampaign)
		p3, _ := c.ReviewPopulation(third)
		if p3.ItemCount != p1.ItemCount-1 || p3.PopulationHash == p1.PopulationHash {
			t.Errorf("population after a revoke: %d rows %s, want %d rows and a new hash", p3.ItemCount, p3.PopulationHash, p1.ItemCount-1)
		}
		// the frozen population of the first campaign is untouched by the revoke
		e, err := reviews.BuildExport(c, seedCampaign, now)
		if err != nil || !e.HashMatch() || e.Population.PopulationHash != p1.PopulationHash {
			t.Errorf("first campaign after a revoke: %v, match %v", err, e != nil && e.HashMatch())
		}
		return nil
	})
}

func row(n int) *store.PopulationRow {
	return &store.PopulationRow{Ordinal: n, EdgeID: int64(100 + n), IdentityID: int64(n), IdentityRef: "u" + string(rune('a'+n)),
		AccountRef: "acct", System: "okta", Entitlement: "Admins ü \"q\" <b>", EdgeSrc: "account:1", EdgeDst: "group:2",
		InScopeReason: reviews.InScope, Disposition: reviews.DispositionReview}
}

func TestPopulationHashProperties(t *testing.T) {
	rows := []*store.PopulationRow{row(1), row(2), row(3)}
	h1, err := reviews.PopulationHash(rows)
	if err != nil || len(h1) != 64 {
		t.Fatalf("hash %q %v", h1, err)
	}
	rev := []*store.PopulationRow{rows[2], rows[0], rows[1]}
	if h2, _ := reviews.PopulationHash(rev); h2 != h1 {
		t.Error("the hash depends on the order the rows are given in")
	}
	for name, mutate := range map[string]func(r *store.PopulationRow){
		"entitlement":   func(r *store.PopulationRow) { r.Entitlement += "x" },
		"edge id":       func(r *store.PopulationRow) { r.EdgeID++ },
		"identity":      func(r *store.PopulationRow) { r.IdentityRef = "other" },
		"disposition":   func(r *store.PopulationRow) { r.Disposition = reviews.DispositionAuto },
		"system":        func(r *store.PopulationRow) { r.System = "aws" },
		"in scope why":  func(r *store.PopulationRow) { r.InScopeReason = "other" },
		"edge dst":      func(r *store.PopulationRow) { r.EdgeDst = "group:3" },
		"identity id":   func(r *store.PopulationRow) { r.IdentityID++ },
		"account":       func(r *store.PopulationRow) { r.AccountRef = "b" },
		"edge src":      func(r *store.PopulationRow) { r.EdgeSrc = "account:9" },
		"ordinal order": func(r *store.PopulationRow) { r.Ordinal = 9 },
	} {
		cp := *rows[1]
		mutate(&cp)
		if h, _ := reviews.PopulationHash([]*store.PopulationRow{rows[0], &cp, rows[2]}); h == h1 {
			t.Errorf("changing the %s does not change the hash", name)
		}
	}
	if h, _ := reviews.PopulationHash(rows[:2]); h == h1 {
		t.Error("dropping a row does not change the hash")
	}
	if a, _ := reviews.PopulationHash(nil); a == h1 || len(a) != 64 {
		t.Errorf("empty population hash %q", a)
	}
}
