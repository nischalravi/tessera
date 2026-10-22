package store_test

import (
	"encoding/json"
	"errors"
	"slices"
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
		ags, err := c.DirectoryAgents()
		if err != nil {
			return err
		}
		ls, err := c.AllConnectionLimits()
		if err != nil {
			return err
		}
		ts, err := c.WorkerTargetStates()
		if err != nil {
			return err
		}
		var keys []*store.AgentSealKey
		for _, a := range ags {
			if k, err := c.AgentSealKey(a.ID); err == nil {
				keys = append(keys, k)
			}
		}
		out, err = json.Marshal(map[string]any{"workers": ws, "agent_jobs": js, "limits": ls, "targets": ts, "seal_keys": keys})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func workersCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"BeatQueueWorker", "QueueWorkers", "DeleteQueueWorker", "PruneQueueWorkers", "QueueKindsInUse"} {
		out[k] = true // TestIsolation_QueueWorkers
	}
	for _, k := range []string{"EnqueueAgentJob", "AgentJob", "AgentJobs", "HasOpenAgentJob", "ClaimAgentJobs", "CompleteAgentJob",
		"FailAgentJob", "CancelAgentJobs", "PruneAgentJobs", "HasDueAgentJobs"} {
		out[k] = true // TestIsolation_AgentJobs
	}
	for _, k := range []string{"HasOpenAgentJobForOp", "CancelAgentJobsForOp"} {
		out[k] = true // TestIsolation_AgentPushJobs
	}
	for _, k := range []string{"AgentSealKey", "PutAgentSealKey", "DeleteAgentSealKey"} {
		out[k] = true // TestIsolation_AgentSealKeys
	}
	for _, k := range []string{"ConnectionLimits", "AllConnectionLimits", "PutConnectionLimits", "DeleteConnectionLimits"} {
		out[k] = true // TestIsolation_ConnectionLimits
	}
	for _, k := range []string{"ReplaceWorkerTargetStates", "WorkerTargetStates", "ClearWorkerTargetStates", "PruneWorkerTargetStates"} {
		out[k] = true // TestIsolation_WorkerTargetStates
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
	inA(t, f, func(c *store.TenantTx) error {
		// a kind only A has jobs of: B's operators must not learn of it (issue #403)
		if _, err := c.EnqueueQueueJob(&store.QueueJob{Kind: "a_only_kind", RunAt: now}, now); err != nil {
			return err
		}
		if ks, err := c.QueueKindsInUse(); err != nil || !slices.Contains(ks, "a_only_kind") {
			t.Errorf("A's kinds in use = %v, %v", ks, err)
		}
		return c.BeatQueueWorker(w, now)
	})
	before := workersDump(t, f, f.A)
	inB(t, f, func(c *store.TenantTx) error {
		if ks, err := c.QueueKindsInUse(); err != nil || slices.Contains(ks, "a_only_kind") {
			t.Errorf("B's kinds in use = %v, %v", ks, err)
		}
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

// Connection limits are per tenant: B cannot read, replace or delete A's, a
// limit cannot name another tenant's connection, and B's limits for its own
// connection are its own row.
func TestIsolation_ConnectionLimits(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	aConn, bConn := f.A.Refs["connection:ad"], f.B.Refs["connection:ad"]
	inA(t, f, func(c *store.TenantTx) error {
		return c.PutConnectionLimits(&store.ConnectionLimits{ConnectionID: aConn, MaxConcurrency: 2, RatePerMin: 30,
			BreakerThreshold: 3, BreakerCooldownSecs: 60, UpdatedBy: "a"}, now)
	})
	before := workersDump(t, f, f.A)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.ConnectionLimits(aConn); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ConnectionLimits(A's) = %v", err)
		}
		if ls, err := c.AllConnectionLimits(); err != nil || len(ls) != 0 {
			t.Errorf("AllConnectionLimits = %v, %v", ls, err)
		}
		if err := c.DeleteConnectionLimits(aConn); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteConnectionLimits(A's) = %v", err)
		}
		// a row of B's naming A's connection is refused by the schema
		if err := c.PutConnectionLimits(&store.ConnectionLimits{ConnectionID: aConn, UpdatedBy: "b"}, now); err == nil {
			t.Error("B limited A's connection")
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		return c.PutConnectionLimits(&store.ConnectionLimits{ConnectionID: bConn, MaxConcurrency: 9, UpdatedBy: "b"}, now)
	})
	if got := workersDump(t, f, f.A); got != before {
		t.Errorf("tenant A changed:\nbefore %s\nafter  %s", before, got)
	}
	// replacing keeps one row; the CHECKs refuse an out-of-range value
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.PutConnectionLimits(&store.ConnectionLimits{ConnectionID: aConn, MaxConcurrency: 4, UpdatedBy: "a"}, now.Add(time.Minute)); err != nil {
			return err
		}
		l, err := c.ConnectionLimits(aConn)
		if err != nil || l.MaxConcurrency != 4 || l.RatePerMin != 0 {
			t.Errorf("after replace: %+v, %v", l, err)
		}
		if ls, err := c.AllConnectionLimits(); err != nil || len(ls) != 1 {
			t.Errorf("AllConnectionLimits = %v, %v", ls, err)
		}
		return nil
	})
	if err := f.DB.InTenant(t.Context(), f.A.ID, func(c *store.TenantTx) error {
		return c.PutConnectionLimits(&store.ConnectionLimits{ConnectionID: aConn, MaxConcurrency: 65, UpdatedBy: "a"}, now)
	}); err == nil {
		t.Error("max_concurrency 65 was accepted")
	}
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.DeleteConnectionLimits(aConn); err != nil {
			t.Error(err)
		}
		return nil
	})
}

// Worker target states are per tenant: B sees, replaces, clears and prunes none
// of A's, a state cannot name another tenant's connection, and a worker's beat
// replaces its own rows only.
func TestIsolation_WorkerTargetStates(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	aConn, bConn := f.A.Refs["connection:ad"], f.B.Refs["connection:ad"]
	until := now.Add(time.Minute)
	open := store.WorkerTargetState{ConnectionID: aConn, State: store.BreakerOpen, ConsecutiveFailures: 5, OpenUntil: &until,
		LastError: "boom", Calls: 9, Failures: 5, Rejected: 2}
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.ReplaceWorkerTargetStates("w1", []store.WorkerTargetState{open}, now); err != nil {
			return err
		}
		return c.ReplaceWorkerTargetStates("w2", []store.WorkerTargetState{{ConnectionID: aConn, State: store.BreakerClosed}}, now)
	})
	before := workersDump(t, f, f.A)
	inB(t, f, func(c *store.TenantTx) error {
		if ts, err := c.WorkerTargetStates(); err != nil || len(ts) != 0 {
			t.Errorf("WorkerTargetStates = %v, %v", ts, err)
		}
		if err := c.ClearWorkerTargetStates("w1"); err != nil {
			t.Error(err)
		}
		if n, err := c.PruneWorkerTargetStates(now.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("PruneWorkerTargetStates = %d, %v", n, err)
		}
		if err := c.ReplaceWorkerTargetStates("w1", []store.WorkerTargetState{{ConnectionID: aConn, State: store.BreakerClosed}}, now); err == nil {
			t.Error("B published a state for A's connection")
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		return c.ReplaceWorkerTargetStates("w1", []store.WorkerTargetState{{ConnectionID: bConn, State: store.BreakerClosed}}, now)
	})
	if got := workersDump(t, f, f.A); got != before {
		t.Errorf("tenant A changed:\nbefore %s\nafter  %s", before, got)
	}
	inA(t, f, func(c *store.TenantTx) error {
		ts, err := c.WorkerTargetStates()
		if err != nil || len(ts) != 2 || ts[0].WorkerID != "w1" || ts[0].State != store.BreakerOpen || ts[0].OpenUntil == nil ||
			!ts[0].OpenUntil.Equal(until) || ts[0].LastError != "boom" || ts[0].Rejected != 2 {
			t.Errorf("WorkerTargetStates = %+v, %v", ts, err)
		}
		// a beat replaces the worker's rows, leaving the other worker's alone
		if err := c.ReplaceWorkerTargetStates("w1", nil, now.Add(time.Minute)); err != nil {
			return err
		}
		if ts, err := c.WorkerTargetStates(); err != nil || len(ts) != 1 || ts[0].WorkerID != "w2" {
			t.Errorf("after replace: %+v, %v", ts, err)
		}
		if n, err := c.PruneWorkerTargetStates(now.Add(time.Hour)); err != nil || n != 1 {
			t.Errorf("PruneWorkerTargetStates = %d, %v", n, err)
		}
		return nil
	})
}

func seedAgentOp(t *testing.T, f *storetest.Fixture, tn storetest.Tenant, opID, agentID string) {
	t.Helper()
	now := storetest.Now
	if err := f.DB.InTenant(t.Context(), tn.ID, func(c *store.TenantTx) error {
		if err := c.InsertDirectoryAgent(&store.DirectoryAgent{ID: agentID, Name: "agent-" + agentID[:6], CreatedBy: "t", CreatedAt: now}); err != nil {
			return err
		}
		return c.InsertProvOp(&store.ProvOp{ID: opID, ConnectionID: tn.Refs["connection:ad"], Kind: "disable_account", TargetRef: "x",
			Payload: "{}", Source: "test", IdempotencyKey: "k-" + opID, RequestedBy: "t"}, now)
	}); err != nil {
		t.Fatal(err)
	}
}

// A provision_push job names a provisioning operation of its own tenant: B
// cannot see, count or cancel A's, a job cannot name another tenant's
// operation, and an operation's open jobs are found and cancelled by id only.
func TestIsolation_AgentPushJobs(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	aAgent, bAgent := store.NewID(), store.NewID()
	seedAgentOp(t, f, f.A, "op-a", aAgent)
	seedAgentOp(t, f, f.B, "op-b", bAgent)
	aConn, bConn := f.A.Refs["connection:ad"], f.B.Refs["connection:ad"]
	opA, key := "op-a", "push:op-a:1"
	j := &store.AgentJob{AgentID: aAgent, ConnectionID: aConn, Kind: store.AgentJobProvisionPush, OpID: &opA, Payload: `{}`, IdempotencyKey: &key}
	inA(t, f, func(c *store.TenantTx) error {
		if created, err := c.EnqueueAgentJob(j, now); err != nil || !created {
			t.Fatalf("enqueue = %v, %v", created, err)
		}
		if open, err := c.HasOpenAgentJobForOp(opA); err != nil || !open {
			t.Errorf("HasOpenAgentJobForOp = %v, %v", open, err)
		}
		got, err := c.AgentJob(j.ID)
		if err != nil || got.OpID == nil || *got.OpID != opA || got.Kind != store.AgentJobProvisionPush {
			t.Errorf("AgentJob = %+v, %v", got, err)
		}
		return nil
	})
	before := workersDump(t, f, f.A)
	inB(t, f, func(c *store.TenantTx) error {
		if open, err := c.HasOpenAgentJobForOp(opA); err != nil || open {
			t.Errorf("HasOpenAgentJobForOp(A's op) from B = %v, %v", open, err)
		}
		if n, err := c.CancelAgentJobsForOp(opA, "x", now); err != nil || n != 0 {
			t.Errorf("CancelAgentJobsForOp(A's op) from B = %d, %v", n, err)
		}
		return nil
	})
	if got := workersDump(t, f, f.A); got != before {
		t.Errorf("tenant A changed:\nbefore %s\nafter  %s", before, got)
	}
	// B's job may not name A's operation (the schema refuses it)
	opAForB := "op-a"
	if err := f.DB.InTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error {
		_, err := c.EnqueueAgentJob(&store.AgentJob{AgentID: bAgent, ConnectionID: bConn, Kind: store.AgentJobProvisionPush, OpID: &opAForB,
			Payload: `{}`}, now)
		return err
	}); err == nil {
		t.Error("a job of B naming A's operation was accepted")
	}
	// an unknown kind is refused by the CHECK
	if err := f.DB.InTenant(t.Context(), f.A.ID, func(c *store.TenantTx) error {
		_, err := c.EnqueueAgentJob(&store.AgentJob{AgentID: aAgent, ConnectionID: aConn, Kind: "shell", Payload: `{}`}, now)
		return err
	}); err == nil {
		t.Error("an unknown job kind was accepted")
	}
	inA(t, f, func(c *store.TenantTx) error {
		if n, err := c.CancelAgentJobsForOp(opA, "the operation was cancelled", now); err != nil || n != 1 {
			t.Errorf("CancelAgentJobsForOp = %d, %v", n, err)
		}
		if open, err := c.HasOpenAgentJobForOp(opA); err != nil || open {
			t.Errorf("a cancelled job is still open: %v, %v", open, err)
		}
		if got, err := c.AgentJob(j.ID); err != nil || got.Status != store.AgentJobCancelled || got.LastError != "the operation was cancelled" {
			t.Errorf("cancelled job = %+v, %v", got, err)
		}
		return nil
	})
}

// An agent's sealing key is per tenant and per agent: B reads, replaces and
// deletes none of A's, a key cannot be registered for another tenant's agent,
// and registering again replaces the key in place.
func TestIsolation_AgentSealKeys(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	aAgent, bAgent := store.NewID(), store.NewID()
	seedAgentOp(t, f, f.A, "op-a", aAgent)
	seedAgentOp(t, f, f.B, "op-b", bAgent)
	key := func(b byte) *store.AgentSealKey {
		return &store.AgentSealKey{AgentID: aAgent, PublicKey: bytesOf(b, 32), KeyID: "k" + string(rune('0'+b))}
	}
	inA(t, f, func(c *store.TenantTx) error { return c.PutAgentSealKey(key(1), now) })
	before := workersDump(t, f, f.A)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.AgentSealKey(aAgent); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AgentSealKey(A's agent) from B = %v", err)
		}
		if err := c.DeleteAgentSealKey(aAgent); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteAgentSealKey(A's agent) from B = %v", err)
		}
		// registering a key for A's agent from B is refused by the schema, and replaces nothing
		if err := c.PutAgentSealKey(&store.AgentSealKey{AgentID: aAgent, PublicKey: bytesOf(9, 32), KeyID: "evil"}, now); err == nil {
			t.Error("B registered a key for A's agent")
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		return c.PutAgentSealKey(&store.AgentSealKey{AgentID: bAgent, PublicKey: bytesOf(2, 32), KeyID: "kb"}, now)
	})
	if got := workersDump(t, f, f.A); got != before {
		t.Errorf("tenant A changed:\nbefore %s\nafter  %s", before, got)
	}
	inA(t, f, func(c *store.TenantTx) error {
		k, err := c.AgentSealKey(aAgent)
		if err != nil || k.KeyID != "k1" || len(k.PublicKey) != 32 || k.PublicKey[0] != 1 || !k.RegisteredAt.Equal(now) {
			t.Fatalf("AgentSealKey = %+v, %v", k, err)
		}
		// replace in place
		if err := c.PutAgentSealKey(key(3), now.Add(time.Minute)); err != nil {
			return err
		}
		k, err = c.AgentSealKey(aAgent)
		if err != nil || k.KeyID != "k3" || k.PublicKey[0] != 3 || !k.RegisteredAt.Equal(now.Add(time.Minute)) {
			t.Errorf("after replace: %+v, %v", k, err)
		}
		// the CHECK refuses a key of the wrong length
		return nil
	})
	if err := f.DB.InTenant(t.Context(), f.A.ID, func(c *store.TenantTx) error {
		return c.PutAgentSealKey(&store.AgentSealKey{AgentID: aAgent, PublicKey: bytesOf(1, 31), KeyID: "short"}, now)
	}); err == nil {
		t.Error("a 31-byte key was accepted")
	}
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.DeleteAgentSealKey(aAgent); err != nil {
			t.Error(err)
		}
		if _, err := c.AgentSealKey(aAgent); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("after delete: %v", err)
		}
		return nil
	})
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
