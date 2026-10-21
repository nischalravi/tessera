package store_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func workersDump(t *testing.T, f *storetest.Fixture, tn storetest.Tenant) string {
	t.Helper()
	var out []byte
	if err := f.DB.ReadTenant(t.Context(), tn.ID, func(c *store.TenantTx) error {
		ws, err := c.QueueWorkers()
		if err != nil {
			return err
		}
		js, err := c.AgentJobs(store.AgentJobFilter{})
		if err != nil {
			return err
		}
		out, err = json.Marshal(map[string]any{"workers": ws, "agent_jobs": js})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func workersCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"BeatQueueWorker", "QueueWorkers", "DeleteQueueWorker", "PruneQueueWorkers"} {
		out[k] = true // TestIsolation_QueueWorkers
	}
	for _, k := range []string{"EnqueueAgentJob", "AgentJob", "AgentJobs", "HasOpenAgentJob", "ClaimAgentJobs", "CompleteAgentJob",
		"FailAgentJob", "CancelAgentJobs", "PruneAgentJobs", "HasDueAgentJobs"} {
		out[k] = true // TestIsolation_AgentJobs
	}
	return out
}

// Worker health rows are per tenant: B sees none of A's, cannot delete or
// prune them, and the same worker id in B is B's own row.
func TestIsolation_QueueWorkers(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	w := &store.QueueWorker{WorkerID: "host-1-abcd", Mode: store.WorkerModeWorker, Hostname: "host", PID: 1, Kinds: "connector_sync",
		Concurrency: 4, StartedAt: now}
	inA(t, f, func(c *store.TenantTx) error { return c.BeatQueueWorker(w, now) })
	before := workersDump(t, f, f.A)
	inB(t, f, func(c *store.TenantTx) error {
		if ws, err := c.QueueWorkers(); err != nil || len(ws) != 0 {
			t.Errorf("QueueWorkers = %v, %v", ws, err)
		}
		if err := c.DeleteQueueWorker(w.WorkerID); err != nil {
			t.Error(err)
		}
		if n, err := c.PruneQueueWorkers(now.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("PruneQueueWorkers = %d, %v", n, err)
		}
		// B beats under the same id: its own row
		return c.BeatQueueWorker(w, now)
	})
	if got := workersDump(t, f, f.A); got != before {
		t.Errorf("tenant A changed:\nbefore %s\nafter  %s", before, got)
	}
	// a second beat updates in place, keeping the start time
	later := now.Add(time.Minute)
	w2 := *w
	w2.Running, w2.StartedAt = 2, later
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.BeatQueueWorker(&w2, later); err != nil {
			return err
		}
		ws, err := c.QueueWorkers()
		if err != nil || len(ws) != 1 || ws[0].Running != 2 || !ws[0].LastHeartbeatAt.Equal(later) {
			t.Errorf("after the second beat: %+v, %v", ws, err)
		}
		return nil
	})
	// a clean stop removes the row; a pruned one is gone by age
	inA(t, f, func(c *store.TenantTx) error {
		if n, err := c.PruneQueueWorkers(later.Add(time.Hour)); err != nil || n != 1 {
			t.Errorf("PruneQueueWorkers = %d, %v", n, err)
		}
		return nil
	})
}

// Agent jobs are per tenant and per agent: another tenant sees, claims,
// completes, fails and cancels none of them; another agent of the same tenant
// claims none of them; and a job cannot name another tenant's agent or
// connection.
func TestIsolation_AgentJobs(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	aConn, bConn := f.A.Refs["connection:ad"], f.B.Refs["connection:ad"]
	aAgent1, aAgent2, bAgent := store.NewID(), store.NewID(), store.NewID()
	for _, s := range []struct {
		tn    storetest.Tenant
		agent string
	}{{f.A, aAgent1}, {f.A, aAgent2}, {f.B, bAgent}} {
		if err := f.DB.InTenant(t.Context(), s.tn.ID, func(c *store.TenantTx) error {
			return c.InsertDirectoryAgent(&store.DirectoryAgent{ID: s.agent, Name: "agent-" + s.agent[:6], CreatedBy: "t", CreatedAt: now})
		}); err != nil {
			t.Fatal(err)
		}
	}
	key := "sync:1"
	j := &store.AgentJob{AgentID: aAgent1, ConnectionID: aConn, Kind: store.AgentJobSync, Payload: `{"x":1}`, IdempotencyKey: &key}
	inA(t, f, func(c *store.TenantTx) error {
		if created, err := c.EnqueueAgentJob(j, now); err != nil || !created {
			t.Fatalf("enqueue = %v, %v", created, err)
		}
		if created, err := c.EnqueueAgentJob(&store.AgentJob{AgentID: aAgent1, ConnectionID: aConn, Kind: store.AgentJobSync,
			Payload: `{}`, IdempotencyKey: &key}, now); err != nil || created {
			t.Errorf("a repeated key created again: %v, %v", created, err)
		}
		if open, err := c.HasOpenAgentJob(aConn, store.AgentJobSync); err != nil || !open {
			t.Errorf("HasOpenAgentJob = %v, %v", open, err)
		}
		// another agent of the same tenant claims nothing of aAgent1's
		if got, dead, err := c.ClaimAgentJobs(aAgent2, now, time.Minute, 10); err != nil || len(got)+len(dead) != 0 {
			t.Errorf("agent 2 claimed agent 1's job: %v %v %v", got, dead, err)
		}
		return nil
	})
	before := workersDump(t, f, f.A)

	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.AgentJob(j.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AgentJob(A's) = %v", err)
		}
		if js, err := c.AgentJobs(store.AgentJobFilter{}); err != nil || len(js) != 0 {
			t.Errorf("AgentJobs = %v, %v", js, err)
		}
		if open, err := c.HasOpenAgentJob(aConn, store.AgentJobSync); err != nil || open {
			t.Errorf("HasOpenAgentJob(A's connection) = %v, %v", open, err)
		}
		// even with A's agent id, B claims nothing
		if got, dead, err := c.ClaimAgentJobs(aAgent1, now, time.Minute, 10); err != nil || len(got)+len(dead) != 0 {
			t.Errorf("ClaimAgentJobs took A's job: %v %v %v", got, dead, err)
		}
		if err := c.CompleteAgentJob(j.ID, aAgent1, "{}", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("CompleteAgentJob(A's) = %v", err)
		}
		if err := c.FailAgentJob(&store.AgentJob{ID: j.ID, AgentID: aAgent1}, "x", false, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("FailAgentJob(A's) = %v", err)
		}
		if n, err := c.CancelAgentJobs(aAgent1, now); err != nil || n != 0 {
			t.Errorf("CancelAgentJobs(A's agent) = %d, %v", n, err)
		}
		if n, err := c.PruneAgentJobs(now.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("PruneAgentJobs = %d, %v", n, err)
		}
		// the same key in B is B's own job
		if created, err := c.EnqueueAgentJob(&store.AgentJob{AgentID: bAgent, ConnectionID: bConn, Kind: store.AgentJobSync,
			Payload: `{}`, IdempotencyKey: &key}, now); err != nil || !created {
			t.Errorf("B's enqueue with A's key = %v, %v", created, err)
		}
		return nil
	})
	if got := workersDump(t, f, f.A); got != before {
		t.Errorf("tenant A changed:\nbefore %s\nafter  %s", before, got)
	}
	// a job of B may not name A's agent or A's connection
	for name, bad := range map[string]*store.AgentJob{
		"agent":      {AgentID: aAgent1, ConnectionID: bConn, Kind: store.AgentJobSync, Payload: `{}`},
		"connection": {AgentID: bAgent, ConnectionID: aConn, Kind: store.AgentJobSync, Payload: `{}`},
	} {
		err := f.DB.InTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error {
			_, err := c.EnqueueAgentJob(bad, now)
			return err
		})
		if err == nil {
			t.Errorf("a job of B naming A's %s was accepted", name)
		}
	}
}

// The lease cycle of an agent job: claimed once, not claimed again while the
// lease runs, claimed again after it expires, failed for good when the last
// attempt's lease expires, completed only by the agent that holds it.
func TestAgentJobs_LeaseCycle(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	conn := f.A.Refs["connection:ad"]
	agent, other := store.NewID(), store.NewID()
	inA(t, f, func(c *store.TenantTx) error {
		for _, id := range []string{agent, other} {
			if err := c.InsertDirectoryAgent(&store.DirectoryAgent{ID: id, Name: "a-" + id[:6], CreatedBy: "t", CreatedAt: now}); err != nil {
				return err
			}
		}
		_, err := c.EnqueueAgentJob(&store.AgentJob{AgentID: agent, ConnectionID: conn, Kind: store.AgentJobSync, Payload: `{}`, MaxAttempts: 2}, now)
		return err
	})
	lease := time.Minute
	claim := func(at time.Time) (claimed, dead []*store.AgentJob) {
		inA(t, f, func(c *store.TenantTx) (err error) {
			claimed, dead, err = c.ClaimAgentJobs(agent, at, lease, 10)
			return err
		})
		return
	}
	got, _ := claim(now)
	if len(got) != 1 || got[0].Attempts != 1 || got[0].Status != store.AgentJobLeased {
		t.Fatalf("first claim = %+v", got)
	}
	if got, dead := claim(now.Add(30 * time.Second)); len(got)+len(dead) != 0 {
		t.Fatalf("claimed again while leased: %v %v", got, dead)
	}
	got, _ = claim(now.Add(2 * time.Minute)) // lease expired: second attempt
	if len(got) != 1 || got[0].Attempts != 2 {
		t.Fatalf("claim after expiry = %+v", got)
	}
	id := got[0].ID
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.CompleteAgentJob(id, other, "{}", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("another agent completed the job: %v", err)
		}
		return nil
	})
	got, dead := claim(now.Add(5 * time.Minute)) // expired with no attempts left
	if len(got) != 0 || len(dead) != 1 || dead[0].Status != store.AgentJobFailed {
		t.Fatalf("exhausted claim = %v, %v", got, dead)
	}
	inA(t, f, func(c *store.TenantTx) error {
		j, err := c.AgentJob(id)
		if err != nil || j.Status != store.AgentJobFailed || j.FinishedAt == nil {
			t.Errorf("job = %+v, %v", j, err)
		}
		return nil
	})
}
