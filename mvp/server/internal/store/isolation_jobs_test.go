package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Job run isolation (issue #172): runs are per tenant, and a run cannot
// point at another tenant's connection or retry another tenant's run.
func TestIsolation_JobRuns(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	aConn := f.A.Refs["connection:ad"]
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.InsertJobRun(&store.JobRun{ID: "job-a", Kind: "validation", Trigger: "manual", Status: "running",
			ConnectionID: &aConn, Actor: "alice", StartedAt: now.Add(-48 * time.Hour)}); err != nil {
			return err
		}
		return c.InsertJobRun(&store.JobRun{ID: "job-a2", Kind: "sync", Trigger: "manual", Status: "running", Actor: "alice",
			StartedAt: now})
	})
	before := storetest.Dump(t, f.DB, f.A.ID)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.JobRun("job-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("JobRun(A's) = %v", err)
		}
		if js, err := c.JobRuns(store.JobRunFilter{}); err != nil || len(js) != 0 {
			t.Errorf("JobRuns = %v, %v", js, err)
		}
		if err := c.FinishJobRun("job-a", "failed", now, nil, nil); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("FinishJobRun(A's) = %v", err)
		}
		if err := c.DeleteRunningJobRun("job-a"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteRunningJobRun(A's) = %v", err)
		}
		if n, err := c.FailStaleJobRuns(now, now, "x"); err != nil || n != 0 {
			t.Errorf("FailStaleJobRuns = %d, %v", n, err)
		}
		if n, err := c.PruneJobRuns(now.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("PruneJobRuns = %d, %v", n, err)
		}
		return nil
	})
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
	// B referencing A's connection or A's run is refused by the guard triggers.
	for name, j := range map[string]*store.JobRun{
		"connection": {ID: "job-b1", Kind: "validation", Trigger: "manual", Status: "running", ConnectionID: &aConn, Actor: "b", StartedAt: now},
		"retry_of":   {ID: "job-b2", Kind: "sync", Trigger: "retry", Status: "running", RetryOf: strPtr("job-a"), Actor: "b", StartedAt: now},
	} {
		err := f.DB.InTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error { return c.InsertJobRun(j) })
		if err == nil {
			t.Errorf("%s: cross-tenant reference accepted", name)
		}
	}
	// A's own lifecycle: stale runs fail, retention prunes, a newer retry's link is cleared.
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.InsertJobRun(&store.JobRun{ID: "job-a3", Kind: "validation", Trigger: "retry", Status: "running",
			RetryOf: strPtr("job-a"), Actor: "alice", StartedAt: now}); err != nil {
			return err
		}
		n, err := c.FailStaleJobRuns(now.Add(-time.Hour), now, "interrupted")
		if err != nil || n != 1 {
			t.Errorf("FailStaleJobRuns = %d, %v", n, err)
		}
		if n, err := c.PruneJobRuns(now.Add(-24 * time.Hour)); err != nil || n != 1 {
			t.Errorf("PruneJobRuns = %d, %v", n, err)
		}
		j, err := c.JobRun("job-a3")
		if err != nil || j.RetryOf != nil {
			t.Errorf("retry link after prune: %+v %v", j, err)
		}
		if err := c.FinishJobRun("job-a2", "succeeded", now, strPtr(`{"n":1}`), nil); err != nil {
			t.Errorf("FinishJobRun = %v", err)
		}
		if err := c.FinishJobRun("job-a2", "failed", now, nil, nil); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("finishing a finished run = %v", err)
		}
		js, err := c.JobRuns(store.JobRunFilter{Status: "running"})
		if err != nil || len(js) != 1 || js[0].ID != "job-a3" {
			t.Errorf("JobRuns(running) = %v, %v", js, err)
		}
		return nil
	})
}

func strPtr(s string) *string { return &s }

func jobsCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"InsertJobRun", "FinishJobRun", "DeleteRunningJobRun", "JobRun", "JobRuns", "FailStaleJobRuns", "PruneJobRuns"} {
		out[k] = true // TestIsolation_JobRuns
	}
	return out
}
