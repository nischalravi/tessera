package reviews_test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func TestSelectQASample(t *testing.T) {
	edges := func(n int) []int64 {
		out := make([]int64, n)
		for i := range out {
			out[i] = int64(1000 + i*3)
		}
		return out
	}
	for _, tc := range []struct{ n, pct, want int }{
		{0, 5, 0}, {1, 5, 1}, {3, 1, 1}, {20, 5, 1}, {21, 5, 2}, {135, 5, 7}, {135, 50, 68}, {135, 100, 135}, {10, 0, 0}, {10, 250, 10},
	} {
		got := reviews.SelectQASample("abc", edges(tc.n), tc.pct)
		if len(got) != tc.want {
			t.Errorf("n=%d pct=%d: %d sampled, want %d", tc.n, tc.pct, len(got), tc.want)
		}
		for e := range got {
			if !slices.Contains(edges(tc.n), e) {
				t.Errorf("sampled edge %d is not an input", e)
			}
		}
	}
	// reproducible: same seed and inputs, same sample, whatever the input order
	a := reviews.SelectQASample("hash-1", edges(135), 5)
	rev := edges(135)
	slices.Reverse(rev)
	if !reflect.DeepEqual(a, reviews.SelectQASample("hash-1", rev, 5)) || !reflect.DeepEqual(a, reviews.SelectQASample("hash-1", edges(135), 5)) {
		t.Error("the sample is not reproducible")
	}
	// seeded by the population hash
	if reflect.DeepEqual(a, reviews.SelectQASample("hash-2", edges(135), 5)) {
		t.Error("a different population hash selected the same sample")
	}
	// a larger percentage contains the smaller sample (same ranking)
	b := reviews.SelectQASample("hash-1", edges(135), 20)
	for e := range a {
		if !b[e] {
			t.Errorf("edge %d sampled at 5%% but not at 20%%", e)
		}
	}
}

func TestQASampleAndRuleRecording(t *testing.T) {
	w := newWorld(t)
	w.larkspur(func(c *store.TenantTx) error {
		pop, _ := c.ReviewPopulation(seedCampaign)
		rows, _ := c.PopulationRows(seedCampaign)
		autos, err := c.AutoDecisions(seedCampaign)
		if err != nil {
			t.Fatal(err)
		}
		cmp, _ := c.Campaign(seedCampaign)
		if len(autos) == 0 || len(autos) != cmp.AutoCertified {
			t.Fatalf("%d auto-decisions, campaign says %d", len(autos), cmp.AutoCertified)
		}
		var autoEdges []int64
		byOrdinal := map[int]*store.PopulationRow{}
		for _, r := range rows {
			byOrdinal[r.Ordinal] = r
			if r.Disposition == reviews.DispositionAuto {
				autoEdges = append(autoEdges, r.EdgeID)
			}
		}
		if len(autoEdges) != len(autos) {
			t.Fatalf("%d auto rows, %d auto-decisions", len(autoEdges), len(autos))
		}
		want := reviews.SelectQASample(pop.PopulationHash, autoEdges, reviews.DefaultQASamplePct)
		sampled := 0
		for _, a := range autos {
			if a.QASample != want[a.EdgeID] || byOrdinal[a.Ordinal].EdgeID != a.EdgeID {
				t.Errorf("auto-decision %d: sample flag %v, re-derived %v", a.ID, a.QASample, want[a.EdgeID])
			}
			if a.QASample {
				sampled++
				if a.QAReviewerID == nil {
					t.Errorf("sampled item %d has no QA reviewer", a.ID)
				}
			}
			// the recorded rule and the inputs that matched it
			var rule struct {
				ID      string `json:"id"`
				Version int    `json:"version"`
				Inputs  struct {
					Threshold  int     `json:"unused_days_threshold"`
					LastUsed   *string `json:"last_used"`
					Days       *int    `json:"days_since_used"`
					Used       int     `json:"permissions_used"`
					Privileged bool    `json:"privileged"`
					Violation  bool    `json:"policy_violation"`
					Status     string  `json:"identity_status"`
				} `json:"inputs"`
			}
			if err := json.Unmarshal(a.Rule, &rule); err != nil {
				t.Fatalf("rule %s: %v", a.Rule, err)
			}
			in := rule.Inputs
			if rule.ID != reviews.RuleAutoCertify || rule.Version != reviews.RuleVersion || in.Threshold != 60 ||
				in.Used < 1 || in.Violation || in.Status == "terminated" || in.Days == nil || *in.Days >= 60 || in.LastUsed == nil ||
				(in.Privileged && *in.Days >= 30) {
				t.Errorf("auto-decision %d rule %s does not justify an auto-certification", a.ID, a.Rule)
			}
		}
		if sampled != 7 || sampled != len(want) || pop.QASamplePct != 5 {
			t.Errorf("%d sampled of %d auto-decisions at %d%%, want 7", sampled, len(autos), pop.QASamplePct)
		}
		return nil
	})
}

func TestQASamplePctSetting(t *testing.T) {
	w := newWorld(t)
	w.larkspur(func(c *store.TenantTx) error {
		if pct, err := reviews.QASamplePct(c); err != nil || pct != 5 {
			t.Errorf("default = %d, %v", pct, err)
		}
		for _, bad := range []int{-1, 101} {
			var re *reviews.Error
			if err := reviews.SetQASamplePct(c, now, bad, reviewer); !errors.As(err, &re) {
				t.Errorf("SetQASamplePct(%d) = %v, want a caller error", bad, err)
			}
		}
		return nil
	})
	count := func(id int64) (sampled int, pct int) {
		w.larkspur(func(c *store.TenantTx) error {
			autos, _ := c.AutoDecisions(id)
			for _, a := range autos {
				if a.QASample {
					sampled++
				}
			}
			p, _ := c.ReviewPopulation(id)
			pct = p.QASamplePct
			return nil
		})
		return
	}
	for _, tc := range []struct{ pct, want int }{{50, 68}, {1, 2}, {0, 0}, {100, 135}} {
		w.larkspur(func(c *store.TenantTx) error { return reviews.SetQASamplePct(c, now, tc.pct, reviewer) })
		id := w.launch("pct")
		if got, pct := count(id); got != tc.want || pct != tc.pct {
			t.Errorf("qa_sample_pct %d: %d sampled (recorded %d%%), want %d", tc.pct, got, pct, tc.want)
		}
	}
	w.larkspur(func(c *store.TenantTx) error {
		evs, _ := c.AuditEvents(store.AuditFilter{Action: "review.qa_sample_pct_changed"})
		if len(evs) != 4 {
			t.Errorf("%d setting-change events, want 4", len(evs))
		}
		return nil
	})
}

func TestFrozenEventAudited(t *testing.T) {
	w := newWorld(t)
	id := w.launch("audited")
	w.larkspur(func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{Action: "review.population_frozen", Limit: 1})
		if err != nil || len(evs) != 1 {
			t.Fatalf("events %v %v", evs, err)
		}
		pop, _ := c.ReviewPopulation(id)
		d := string(evs[0].Detail)
		if !strings.Contains(d, pop.PopulationHash) || !strings.Contains(d, `"items":219`) || !strings.Contains(d, `"campaign_id":`) {
			t.Errorf("event detail %s lacks the hash or counts", d)
		}
		return nil
	})
}

func TestQADecide(t *testing.T) {
	w := newWorld(t)
	var sampledID, otherSampled, unsampled int64
	var edge [2]string
	w.larkspur(func(c *store.TenantTx) error {
		autos, _ := c.AutoDecisions(seedCampaign)
		rows, _ := c.PopulationRows(seedCampaign)
		for _, a := range autos {
			switch {
			case a.QASample && sampledID == 0:
				sampledID = a.ID
				edge = [2]string{rows[a.Ordinal-1].EdgeSrc, rows[a.Ordinal-1].EdgeDst}
			case a.QASample && otherSampled == 0:
				otherSampled = a.ID
			case !a.QASample && unsampled == 0:
				unsampled = a.ID
			}
		}
		return nil
	})
	if sampledID == 0 || otherSampled == 0 || unsampled == 0 {
		t.Fatal("the demo campaign needs sampled and unsampled auto-decisions")
	}
	w.larkspur(func(c *store.TenantTx) error {
		var re *reviews.Error
		for name, fn := range map[string]func() error{
			"bad decision": func() error { _, err := reviews.QADecide(c, now, sampledID, "maybe", reviewer, nil); return err },
			"unknown":      func() error { _, err := reviews.QADecide(c, now, 999999, "keep", reviewer, nil); return err },
			"not sampled":  func() error { _, err := reviews.QADecide(c, now, unsampled, "revoke", reviewer, nil); return err },
		} {
			if err := fn(); !errors.As(err, &re) {
				t.Errorf("%s: %v, want a caller error", name, err)
			}
		}
		if _, err := c.EdgeBetween(edge[0], edge[1]); err != nil {
			t.Errorf("a refused QA decision removed the grant: %v", err)
		}
		// overturn: revoke the auto-keep
		comment := "still used by a leaver"
		ad, err := reviews.QADecide(c, now, sampledID, "revoke", reviewer, &comment)
		if err != nil || !ad.Overturned || *ad.QADecision != "revoke" {
			t.Fatalf("overturn: %+v, %v", ad, err)
		}
		if _, err := c.EdgeBetween(edge[0], edge[1]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the overturned grant is still there: %v", err)
		}
		if _, err := reviews.QADecide(c, now, sampledID, "keep", reviewer, nil); !errors.As(err, &re) {
			t.Errorf("second decision: %v, want a caller error", err)
		}
		// confirm: keep
		if ad, err := reviews.QADecide(c, now, otherSampled, "keep", reviewer, nil); err != nil || ad.Overturned {
			t.Errorf("confirm: %+v, %v", ad, err)
		}
		for action, want := range map[string]int{"review.qa_overturned": 1, "review.qa_confirmed": 1} {
			evs, _ := c.AuditEvents(store.AuditFilter{Action: action})
			if len(evs) != want {
				t.Errorf("%d %s events, want %d", len(evs), action, want)
			}
		}
		// the export shows both, and the population hash still verifies
		e, err := reviews.BuildExport(c, seedCampaign, now)
		if err != nil {
			t.Fatal(err)
		}
		if !e.HashMatch() || e.QA.Sampled != 7 || e.QA.Decided != 2 || e.QA.Overturned != 1 {
			t.Errorf("QA counts %+v, hash match %v", e.QA, e.HashMatch())
		}
		for _, d := range e.Decisions {
			if d.Row.EdgeSrc == edge[0] && d.Row.EdgeDst == edge[1] {
				if d.Decision != "revoke" || d.Source != "qa_overturn" || d.Verification != reviews.VerifyVerified || d.Reason != comment ||
					d.QADecision != "revoke" || !d.QASample || d.Rule == "" {
					t.Errorf("overturned decision %+v", d)
				}
			}
		}
		return nil
	})
}

func TestExportContent(t *testing.T) {
	w := newWorld(t)
	var kept, revoked, open *store.ReviewItem
	w.larkspur(func(c *store.TenantTx) error {
		items, _ := c.CampaignItems(seedCampaign)
		kept, revoked, open = items[0], items[1], items[2]
		comment := "needed for quarter close"
		if _, err := reviews.Decide(c, now, kept.ID, "keep", reviewer, &comment); err != nil {
			t.Fatal(err)
		}
		if _, err := reviews.Decide(c, now, revoked.ID, "revoke", reviewer, nil); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	w.larkspur(func(c *store.TenantTx) error {
		e, err := reviews.BuildExport(c, seedCampaign, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(e.Decisions) != len(e.Rows) || len(e.Rows) != 219 {
			t.Fatalf("%d decisions for %d rows", len(e.Decisions), len(e.Rows))
		}
		items, _ := c.CampaignItems(seedCampaign)
		byEdge := map[int64]reviews.Decision{}
		autoN := 0
		for _, d := range e.Decisions {
			byEdge[d.Row.EdgeID] = d
			switch d.Decision {
			case "auto_certified":
				autoN++
				if d.Rule == "" || d.Source != "rule" || d.Verification != reviews.VerifyNotApplicable || d.Reviewer != "" {
					t.Errorf("auto decision %+v", d)
				}
			}
		}
		if autoN != 135 || autoN+len(items) != len(e.Rows) {
			t.Errorf("%d auto-certified + %d items != %d rows", autoN, len(items), len(e.Rows))
		}
		if d := byEdge[*kept.EdgeID]; d.Decision != "keep" || d.Reviewer == "" || d.DecidedAt == nil || d.Reason != "needed for quarter close" ||
			d.Verification != reviews.VerifyNotApplicable || len(d.Reasons) == 0 || d.Source != "reviewer" {
			t.Errorf("kept item %+v", d)
		}
		if d := byEdge[*revoked.EdgeID]; d.Decision != "revoke" || d.Verification != reviews.VerifyVerified || d.DecidedAt == nil {
			t.Errorf("revoked item %+v", d)
		}
		if d := byEdge[*open.EdgeID]; d.Decision != "open" || d.DecidedAt != nil || d.Verification != reviews.VerifyNotApplicable {
			t.Errorf("open item %+v", d)
		}
		// a revoke whose grant came back (a sync that ignored the tombstone) is "pending"
		w2 := newWorld(t)
		w2.larkspur(func(c *store.TenantTx) error {
			it, _ := c.CampaignItems(seedCampaign)
			if err := c.DecideItem(it[0].ID, "revoke", nil, now, store.UserRef{}); err != nil {
				return err
			}
			e, err := reviews.BuildExport(c, seedCampaign, now)
			if err != nil {
				return err
			}
			if d := e.Decisions[slices.IndexFunc(e.Decisions, func(d reviews.Decision) bool { return d.Row.EdgeID == *it[0].EdgeID })]; d.Verification != reviews.VerifyPending {
				t.Errorf("revoke with the grant still present: %q, want pending", d.Verification)
			}
			return nil
		})

		// JSON
		doc, err := e.JSON()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := ojson.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		var j struct {
			Population struct {
				Stored   string           `json:"stored_hash"`
				Re       string           `json:"recomputed_hash"`
				Match    bool             `json:"hash_match"`
				Count    int              `json:"item_count"`
				Counts   map[string]int   `json:"system_counts"`
				Syncs    map[string]any   `json:"source_syncs"`
				Rows     []map[string]any `json:"rows"`
				FrozenAt string           `json:"frozen_at"`
			} `json:"population"`
			Decisions []map[string]any `json:"decisions"`
		}
		if err := json.Unmarshal(raw, &j); err != nil {
			t.Fatal(err)
		}
		p := j.Population
		if p.Stored == "" || p.Stored != p.Re || !p.Match || p.Count != 219 || len(p.Rows) != 219 || len(j.Decisions) != 219 ||
			len(p.Counts) == 0 || len(p.Syncs) != len(p.Counts) || p.FrozenAt == "" {
			t.Errorf("population section: %+v", p)
		}
		for _, k := range []string{"decision", "reviewer", "decided_at", "reason", "rule", "qa_sample", "revocation_verification", "identity", "entitlement"} {
			if _, ok := j.Decisions[0][k]; !ok {
				t.Errorf("decision lacks %q", k)
			}
		}
		// the rows of the export reproduce the stored hash (what an auditor does)
		var rebuilt []*store.PopulationRow
		for _, r := range p.Rows {
			rebuilt = append(rebuilt, &store.PopulationRow{Ordinal: int(r["ordinal"].(float64)), EdgeID: int64(r["edge_id"].(float64)),
				IdentityID: int64(r["identity_id"].(float64)), IdentityRef: r["identity_ref"].(string), AccountRef: r["account_ref"].(string),
				System: r["system"].(string), Entitlement: r["entitlement"].(string), EdgeSrc: r["edge_src"].(string),
				EdgeDst: r["edge_dst"].(string), InScopeReason: r["in_scope_reason"].(string), Disposition: r["disposition"].(string)})
		}
		if h, err := reviews.PopulationHash(rebuilt); err != nil || h != p.Stored {
			t.Errorf("hash of the exported rows = %s (%v), stored %s", h, err, p.Stored)
		}

		// CSV
		var buf bytes.Buffer
		if err := e.WriteCSV(&buf); err != nil {
			t.Fatal(err)
		}
		recs, err := csv.NewReader(&buf).ReadAll()
		if err != nil || len(recs) != 220 {
			t.Fatalf("csv: %d records, %v", len(recs), err)
		}
		col := map[string]int{}
		for i, h := range recs[0] {
			col[h] = i
		}
		for _, h := range []string{"decision", "reviewer", "decided_at", "reason", "rule", "revocation_verification", "population_hash", "recomputed_hash", "hash_match", "qa_sample", "source_sync"} {
			if _, ok := col[h]; !ok {
				t.Errorf("csv lacks column %q", h)
			}
		}
		for _, r := range recs[1:] {
			if r[col["population_hash"]] != p.Stored || r[col["recomputed_hash"]] != p.Stored || r[col["hash_match"]] != "true" {
				t.Fatalf("csv row hash columns: %v", r)
			}
		}
		return nil
	})
}

func TestExportFlagsHashMismatch(t *testing.T) {
	w := newWorld(t)
	w.larkspur(func(c *store.TenantTx) error {
		// a population whose stored hash does not match its rows (the store does not
		// check the hash it is given; the export must)
		camp, err := c.InsertCampaign(&store.ReviewCampaign{Name: "forged", CreatedAt: now, Status: "open"})
		if err != nil {
			return err
		}
		src, _ := c.PopulationRows(seedCampaign)
		r := *src[0]
		r.CampaignID, r.Ordinal = camp, 1
		if err := c.InsertReviewPopulation(&store.ReviewPopulation{CampaignID: camp, CreatedAt: now,
			PopulationHash: strings.Repeat("0", 64), ItemCount: 1, SystemCounts: json.RawMessage(`{}`),
			SourceSyncs: json.RawMessage(`{}`), Scope: json.RawMessage(`{}`), RulesVersion: "x"}, []*store.PopulationRow{&r}); err != nil {
			return err
		}
		e, err := reviews.BuildExport(c, camp, now)
		if err != nil {
			t.Fatal(err)
		}
		if e.HashMatch() {
			t.Error("a forged stored hash was not flagged")
		}
		doc, _ := e.JSON()
		raw, _ := ojson.Marshal(doc)
		if !strings.Contains(string(raw), `"hash_match":false`) {
			t.Error("the JSON export does not flag the mismatch")
		}
		var buf bytes.Buffer
		if err := e.WriteCSV(&buf); err != nil || !strings.Contains(buf.String(), ",false,") {
			t.Errorf("the CSV export does not flag the mismatch: %v", err)
		}
		return nil
	})
}

func TestExportWithoutPopulation(t *testing.T) {
	w := newWorld(t)
	w.larkspur(func(c *store.TenantTx) error {
		camp, err := c.InsertCampaign(&store.ReviewCampaign{Name: "legacy", CreatedAt: now, Status: "open"})
		if err != nil {
			return err
		}
		if _, err := reviews.BuildExport(c, camp, now); !errors.Is(err, reviews.ErrNoPopulation) {
			t.Errorf("legacy campaign: %v, want ErrNoPopulation", err)
		}
		if _, err := reviews.BuildExport(c, 999999, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("unknown campaign: %v, want ErrNotFound", err)
		}
		return nil
	})
}

// TestPopulationIsolation: another tenant's campaign id is as good as missing,
// and the tenants' populations are separate.
func TestPopulationIsolation(t *testing.T) {
	w := newWorld(t)
	var globexCamp int64
	var globexHash string
	w.in(seed.GlobexID, func(c *store.TenantTx) error {
		cs, _ := c.CampaignsNewestFirst()
		globexCamp = cs[0].ID
		p, err := c.ReviewPopulation(globexCamp)
		if err != nil {
			t.Fatal(err)
		}
		globexHash = p.PopulationHash
		return nil
	})
	w.larkspur(func(c *store.TenantTx) error {
		if _, err := reviews.BuildExport(c, globexCamp, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("larkspur exporting globex's campaign: %v, want ErrNotFound", err)
		}
		if _, err := reviews.PopulationView(c, globexCamp, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("larkspur reading globex's population: %v", err)
		}
		p, _ := c.ReviewPopulation(seedCampaign)
		if p.PopulationHash == globexHash {
			t.Error("two tenants share a population hash")
		}
		return nil
	})
}

func TestPopulationViewSummary(t *testing.T) {
	w := newWorld(t)
	w.larkspur(func(c *store.TenantTx) error {
		v, err := reviews.PopulationView(c, seedCampaign, now)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := ojson.Marshal(v)
		var j struct {
			Hash  string `json:"population_hash"`
			Match bool   `json:"hash_match"`
			Items int    `json:"item_count"`
			QA    struct {
				Auto, Sampled int `json:"-"`
			}
			Queue []struct {
				ID int64 `json:"id"`
			} `json:"qa_queue"`
		}
		if err := json.Unmarshal(raw, &j); err != nil {
			t.Fatal(err)
		}
		if j.Hash == "" || !j.Match || j.Items != 219 || len(j.Queue) != 7 {
			t.Errorf("view %s", raw)
		}
		return nil
	})
}
