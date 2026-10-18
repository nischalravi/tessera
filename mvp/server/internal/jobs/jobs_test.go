package jobs_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

func TestSummarizeAndErrors(t *testing.T) {
	if s := jobs.Summarize(map[string]int{"n": 3}); s == nil || *s != `{"n":3}` {
		t.Errorf("small result %v", s)
	}
	big := map[string]any{"count": 7, "rows": strings.Repeat("x", 5000), "nested": map[string]int{"a": 1}}
	if s := jobs.Summarize(big); s == nil || *s != `{"count":7}` {
		t.Errorf("big result kept %v", s)
	}
	if jobs.Summarize(nil) != nil {
		t.Error("nil result")
	}
	long := errors.New("line one\nline two " + strings.Repeat("é", 600))
	if msg := jobs.ErrorSummary(long); strings.Contains(msg, "\n") || len(msg) > 504 || !strings.HasSuffix(msg, "…") {
		t.Errorf("error summary %q", msg)
	}
	if err := jobs.RunFailed(map[string]string{"status": "aborted"}); err == nil {
		t.Error("an aborted run is a failure")
	}
	if err := jobs.RunFailed(map[string]string{"status": "completed"}); err != nil {
		t.Error("a completed run (with findings) is not a failure")
	}
	if jobs.Idempotent(jobs.Provision) || !jobs.Idempotent(jobs.Sync) {
		t.Error("idempotency table")
	}
}

func TestRecordAndMaintain(t *testing.T) {
	st, _ := testkit.Tiny(t)
	ctx := context.Background()
	now := testkit.Now
	sweep := jobs.Start{Kind: jobs.JITSweep, Trigger: "schedule", Method: "POST", Route: "/api/jit/sweep", Path: "/api/jit/sweep", Actor: "jit.sweeper"}
	if err := jobs.Record(ctx, st.DB, st.Tenant, sweep, now.Add(-40*24*time.Hour), now.Add(-40*24*time.Hour), map[string]int{"expired": 2}, nil); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Record(ctx, st.DB, st.Tenant, jobs.Start{Kind: jobs.AuditAnchor, Trigger: "schedule", Actor: "audit.checkpointer"},
		now, now, nil, errors.New("anchor sink down")); err != nil {
		t.Fatal(err)
	}
	stale, err := jobs.Begin(ctx, st.DB, st.Tenant, jobs.Start{Kind: jobs.Sync, Trigger: "manual", Method: "POST", Route: "/api/connectors/sync",
		Path: "/api/connectors/sync", Body: []byte("{}"), Actor: "alice"}, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := jobs.Maintain(ctx, st.DB, now, time.Hour, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	runs := testkit.Get(t, st, func(tx *store.TenantTx) ([]*store.JobRun, error) { return tx.JobRuns(store.JobRunFilter{}) })
	if len(runs) != 2 {
		t.Fatalf("runs after upkeep: %d (the 40-day-old run should be pruned)", len(runs))
	}
	for _, r := range runs {
		switch {
		case r.ID == stale:
			if r.Status != "failed" || r.Error == nil || !strings.Contains(*r.Error, "interrupted") || !r.Retryable {
				t.Errorf("stale run %+v", r)
			}
		case r.Kind == jobs.AuditAnchor:
			if r.Status != "failed" || r.Retryable {
				t.Errorf("anchor run %+v", r)
			}
		}
	}
}
