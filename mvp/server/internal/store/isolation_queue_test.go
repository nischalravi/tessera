package store_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func queueDump(t *testing.T, f *storetest.Fixture, tn storetest.Tenant) string {
	t.Helper()
	var out []byte
	if err := f.DB.ReadTenant(t.Context(), tn.ID, func(c *store.TenantTx) error {
		js, err := c.QueueJobs(store.QueueJobFilter{})
		if err != nil {
			return err
		}
		ss, err := c.QueueSchedules()
		if err != nil {
			return err
		}
		out, err = json.Marshal(map[string]any{"jobs": js, "schedules": ss})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// Queue isolation (issue #300): jobs and schedules are per tenant, another
// tenant can neither see, claim, finish, retry nor prune them, the idempotency
// key is unique per tenant and kind, and a job cannot point at another
// tenant's schedule.
func TestIsolation_Queue(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	kinds := []string{"k"}
	key := "same-key"
	var jobID, schedID string
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.EnsureQueueSchedule(&store.QueueSchedule{Name: "s", Kind: "k", Spec: "@every 1m", NextRunAt: now.Add(-time.Minute)}, now); err != nil {
			return err
		}
		s, err := c.QueueSchedule("s")
		if err != nil {
			return err
		}
		schedID = s.ID
		j := &store.QueueJob{Kind: "k", IdempotencyKey: &key, RunAt: now, ScheduleID: &schedID}
		if created, err := c.EnqueueQueueJob(j, now); err != nil || !created {
			t.Fatalf("enqueue = %v, %v", created, err)
		}
		jobID = j.ID
		return nil
	})
	before := queueDump(t, f, f.A)

	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.QueueJob(jobID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("QueueJob(A's) = %v", err)
		}
		if js, err := c.QueueJobs(store.QueueJobFilter{}); err != nil || len(js) != 0 {
			t.Errorf("QueueJobs = %v, %v", js, err)
		}
		if ss, err := c.QueueSchedules(); err != nil || len(ss) != 0 {
			t.Errorf("QueueSchedules = %v, %v", ss, err)
		}
		if _, err := c.QueueSchedule("s"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("QueueSchedule(A's) = %v", err)
		}
		if ss, err := c.DueQueueSchedules(now); err != nil || len(ss) != 0 {
			t.Errorf("DueQueueSchedules = %v, %v", ss, err)
		}
		if due, err := c.HasDueQueueJobs(now, kinds); err != nil || due {
			t.Errorf("HasDueQueueJobs = %v, %v", due, err)
		}
		if got, dead, err := c.ClaimQueueJobs(now, "b", time.Minute, kinds, 10); err != nil || len(got)+len(dead) != 0 {
			t.Errorf("ClaimQueueJobs claimed A's job: %v %v %v", got, dead, err)
		}
		if err := c.HeartbeatQueueJob(jobID, "b", now, time.Minute); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("HeartbeatQueueJob(A's) = %v", err)
		}
		if err := c.CompleteQueueJob(jobID, "b", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("CompleteQueueJob(A's) = %v", err)
		}
		if err := c.FailQueueJob(jobID, "b", now, "x", nil); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("FailQueueJob(A's) = %v", err)
		}
		if err := c.ReleaseQueueJob(jobID, "b", now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ReleaseQueueJob(A's) = %v", err)
		}
		if err := c.RetryDeadQueueJob(jobID, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RetryDeadQueueJob(A's) = %v", err)
		}
		if err := c.SetDeadQueueJobPayload(jobID, `{"retried_by":["x"]}`, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetDeadQueueJobPayload(A's) = %v", err)
		}
		if err := c.AdvanceQueueSchedule(schedID, now, now, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AdvanceQueueSchedule(A's) = %v", err)
		}
		if err := c.SetQueueScheduleEnabled("s", false, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetQueueScheduleEnabled(A's) = %v", err)
		}
		if err := c.DeleteQueueSchedule("s"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteQueueSchedule(A's) = %v", err)
		}
		if n, err := c.PruneQueueJobs(now.Add(time.Hour)); err != nil || n != 0 {
			t.Errorf("PruneQueueJobs = %d, %v", n, err)
		}
		// the same kind and key in B is B's own job, not A's duplicate
		if created, err := c.EnqueueQueueJob(&store.QueueJob{Kind: "k", IdempotencyKey: &key, RunAt: now}, now); err != nil || !created {
			t.Errorf("B's enqueue with A's key = %v, %v", created, err)
		}
		return nil
	})
	if got := queueDump(t, f, f.A); got != before {
		t.Errorf("tenant A changed:\nbefore %s\nafter  %s", before, got)
	}
	// B's job may not point at A's schedule: a guard trigger (SQLite) or a
	// composite foreign key (Postgres) refuses it.
	err := f.DB.InTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error {
		_, err := c.EnqueueQueueJob(&store.QueueJob{Kind: "k", RunAt: now, ScheduleID: &schedID}, now)
		return err
	})
	if err == nil {
		t.Error("a job of B pointing at A's schedule was accepted")
	}
}

func queueCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"EnqueueQueueJob", "QueueJob", "QueueJobs", "ClaimQueueJobs", "HasDueQueueJobs", "HeartbeatQueueJob",
		"CompleteQueueJob", "FailQueueJob", "ReleaseQueueJob", "RetryDeadQueueJob", "SetDeadQueueJobPayload", "PruneQueueJobs", "EnsureQueueSchedule", "SetQueueSchedule",
		"QueueSchedule", "QueueSchedules", "DueQueueSchedules", "AdvanceQueueSchedule", "SetQueueScheduleEnabled", "DeleteQueueSchedule"} {
		out[k] = true // TestIsolation_Queue
	}
	return out
}

// SetQueueSchedule (a tenant's own sync schedule) replaces the schedule of that name in its own tenant only, takes
// the enabled flag and due time, and a second call updates the row instead of adding one.
func TestSetQueueSchedulePerTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	inA(t, f, func(c *store.TenantTx) error {
		return c.SetQueueSchedule(&store.QueueSchedule{Name: "connector_sync.delta", Kind: "connector_sync", Payload: `{"mode":"incremental"}`,
			Spec: "@every 15m", Enabled: true, NextRunAt: now.Add(15 * time.Minute)}, now)
	})
	before := queueDump(t, f, f.A)
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.SetQueueSchedule(&store.QueueSchedule{Name: "connector_sync.delta", Kind: "connector_sync", Spec: "@every 1h", Enabled: false,
			NextRunAt: now.Add(time.Hour)}, now); err != nil {
			return err
		}
		return c.SetQueueSchedule(&store.QueueSchedule{Name: "connector_sync.delta", Kind: "connector_sync", Spec: "@every 2h", Enabled: true,
			NextRunAt: now.Add(2 * time.Hour)}, now)
	})
	if queueDump(t, f, f.A) != before {
		t.Error("tenant A's schedule changed")
	}
	inA(t, f, func(c *store.TenantTx) error {
		s, err := c.QueueSchedule("connector_sync.delta")
		if err != nil || s.Spec != "@every 15m" || !s.Enabled || s.Payload != `{"mode":"incremental"}` {
			t.Errorf("A's schedule = %+v, %v", s, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		ss, err := c.QueueSchedules()
		if err != nil || len(ss) != 1 || ss[0].Spec != "@every 2h" || !ss[0].Enabled || !ss[0].NextRunAt.Equal(now.Add(2*time.Hour)) || ss[0].Payload != "{}" {
			t.Errorf("B's schedules = %+v, %v", ss, err)
		}
		return nil
	})
}
