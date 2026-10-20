package benchgen_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/benchgen"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var tid = tenancy.MustParse("00000000-0000-4000-8000-0000000000b7")

func newDB(t testing.TB) (*store.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bench.db")
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := benchgen.CreateTenant(context.Background(), db, tid, "bench"); err != nil {
		t.Fatal(err)
	}
	return db, path
}

func TestCounts_ScaleWithPercent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		percent float64
		want    benchgen.Counts
	}{
		{"reference tenant", 100, benchgen.Counts{Groups: 150000, Folders: 25000, Identities: 600000, Direct: 3000000, Ref: 45000, Policy: 400, Browse: 5000, Roster: 20000}},
		{"ten percent", 10, benchgen.Counts{Groups: 15000, Folders: 2500, Identities: 60000, Direct: 300000, Ref: 4500, Policy: 40, Browse: 500, Roster: 2000}},
		{"tiny tenant keeps a floor", 0.01, benchgen.Counts{Groups: 80, Folders: 8, Identities: 300, Direct: 400, Ref: 40, Policy: 4, Browse: 50, Roster: 40}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (benchgen.Spec{Percent: tc.percent}).Counts(); got != tc.want {
				t.Errorf("Counts() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestGenerateAndMeasure_Small runs the whole harness on a tenant of 0.1% of the
// reference: it checks the generator's shape and that every target of the table
// is measured. The numbers are not asserted here (a race-instrumented run on a
// shared machine says nothing about them): TestScaleGate does that.
func TestGenerateAndMeasure_Small(t *testing.T) {
	db, path := newDB(t)
	ctx := context.Background()
	spec := benchgen.Spec{Percent: 0.1, Samples: 20, Loader: 200, DBPath: path}
	tn, err := benchgen.Generate(ctx, db, tid, spec)
	if err != nil {
		t.Fatal(err)
	}
	c := tn.Stats.Counts
	if len(tn.Idents) != c.Identities || len(tn.Policy) != c.Policy || len(tn.Chain) != 12 {
		t.Fatalf("shape: %d identities, %d policy groups, chain %d; counts %+v", len(tn.Idents), len(tn.Policy), len(tn.Chain), c)
	}
	for lv, gs := range tn.Levels {
		if len(gs) == 0 {
			t.Errorf("level %d has no groups", lv)
		}
	}
	if tn.Stats.Effective < int64(c.Direct) {
		t.Errorf("effective rows %d fewer than direct rows %d: the load did not materialize", tn.Stats.Effective, c.Direct)
	}
	// the reference group has its members, and the browse folder its children
	if err := db.ReadTenant(ctx, tid, func(tx *store.TenantTx) error {
		n, err := tx.GrpEffectiveCount(tn.Ref, store.MembersListID(tid))
		if err != nil || n != c.Ref {
			t.Errorf("reference group has %d members (%v), want %d", n, err, c.Ref)
		}
		gs, err := model.Env{Tx: tx, Now: tn.Now()}.ListGroups(model.GroupQuery{Folder: tn.BrowseFolder, Limit: 500})
		if err != nil || len(gs) != c.Browse {
			t.Errorf("browse folder has %d groups (%v), want %d", len(gs), err, c.Browse)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	rep, err := benchgen.Measure(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]benchgen.Result{}
	for _, r := range rep.Results {
		have[r.Name] = r
		if r.Samples == 0 || r.Value < 0 {
			t.Errorf("%s: %d samples, value %v", r.Name, r.Samples, r.Value)
		}
	}
	for _, name := range []string{"has_member", "members_first_page_reference_group", "members_first_page_nested_group", "identity_groups",
		"folder_browser", "pit_members_as_of", "single_add", "single_remove", "loader", "provision_full_sync", "provision_incremental",
		"nest_reference_complete", "nest_reference_first_ops", "provision_catch_up", "verify", "verify_clean", "storage",
		"rollover_build_term", "rollover_archive_term", "rollover_next_term"} {
		if _, ok := have[name]; !ok {
			t.Errorf("no result for %s", name)
		}
	}
	// correctness is asserted at any size: the incremental engine and the full recompute agree
	if r := have["verify_clean"]; !r.Pass {
		t.Errorf("verification repaired %v rows after the benchmark's changes", r.Value)
	}
	if r := have["nest_reference_first_ops"]; r.Value <= 0 {
		t.Errorf("provisioning never applied an op after the nesting: %+v", r)
	}

	var md, js bytes.Buffer
	if err := rep.Markdown(&md); err != nil || !strings.Contains(md.String(), "hasMember(group, identity)") {
		t.Errorf("markdown: %v: %.200s", err, md.String())
	}
	var back benchgen.Report
	if err := rep.JSON(&js); err != nil || json.Unmarshal(js.Bytes(), &back) != nil || len(back.Results) != len(rep.Results) {
		t.Errorf("json: %v", err)
	}
}

// TestScaleGate is the gate of the design's section 6.7: every target on a
// generated tenant. It is heavy (minutes at 10%), so it only runs when asked:
//
//	TESSERA_GROUPS_SCALE_GATE=1 [TESSERA_GROUPS_SCALE_PERCENT=10] go test -run TestScaleGate -timeout 2h ./internal/groups/benchgen
//
// `./run.sh bench groups` does the same through cmd/tessera-bench and prints the table.
func TestScaleGate(t *testing.T) {
	if os.Getenv("TESSERA_GROUPS_SCALE_GATE") != "1" {
		t.Skip("set TESSERA_GROUPS_SCALE_GATE=1 to run the scale gate")
	}
	percent := 10.0
	if v, err := strconv.ParseFloat(os.Getenv("TESSERA_GROUPS_SCALE_PERCENT"), 64); err == nil && v > 0 {
		percent = v
	}
	db, path := newDB(t)
	ctx := context.Background()
	tn, err := benchgen.Generate(ctx, db, tid, benchgen.Spec{Percent: percent, DBPath: path, Log: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := benchgen.Measure(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	var md bytes.Buffer
	_ = rep.Markdown(&md)
	t.Log("\n" + md.String())
	for _, r := range rep.Failed() {
		t.Errorf("%s missed its target: %.4g %s against %g %s", r.Design, r.Value, r.Unit, r.Limit, r.Unit)
	}
}
