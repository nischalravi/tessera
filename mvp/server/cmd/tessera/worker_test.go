package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TestWorkerCmdRefusesBadSettings: the worker validates its flags before it
// opens anything.
func TestWorkerCmdRefusesBadSettings(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	db := filepath.Join(t.TempDir(), "w.db")
	for name, args := range map[string][]string{
		"an unknown kind":      {"-kinds", "connector_sync,sweep_requests"},
		"no kind":              {"-kinds", ","},
		"no concurrency":       {"-concurrency", "0"},
		"too much concurrency": {"-concurrency", "65"},
		"a lease too short":    {"-lease", "1s"},
		"an unknown flag":      {"-listen", ":8000"}, // a worker has no API
		"a stray argument":     {"connector_sync"},
	} {
		var logs bytes.Buffer
		if err := run(context.Background(), append([]string{"worker", "-db", db}, args...), io.Discard, &logs); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	t.Setenv("TESSERA_ENV", "")
	if err := run(context.Background(), []string{"worker", "-db", db}, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "TESSERA_ENV") {
		t.Errorf("a worker without TESSERA_ENV: %v", err)
	}
}

// TestWorkerCmdRunsQueuedSyncsAndStopsCleanly: `tessera worker` on its own
// database picks up a queued connector_sync, runs it in the tenant, reports
// itself in Admin -> Jobs, and withdraws on SIGTERM (a context cancel here).
func TestWorkerCmdRunsQueuedSyncsAndStopsCleanly(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_CONNECTORS", "demo-workday")
	db := filepath.Join(t.TempDir(), "w.db")
	tenant := tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	st, err := store.Open(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.InSystem(t.Context(), "test fixture", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: tenant, Slug: "acme", Name: "Acme", CreatedAt: now})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	q := &queue.Queue{DB: st}
	if created, err := q.Enqueue(t.Context(), tenant, jobs.ConnectorSync, "{}", "k1", time.Time{}, 3); err != nil || !created {
		t.Fatal(created, err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	var logs bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"worker", "-db", db, "-kinds", "connector_sync", "-poll", "100ms", "-id", "test-worker", "-concurrency", "2"}, io.Discard, &logs)
	}()
	deadline := time.Now().Add(2 * time.Minute)
	var status string
	for status != store.QueueSucceeded {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("the worker never ran the job (status %q)\n%s", status, logs.String())
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("the worker exited early: %v\n%s", err, logs.String())
		default:
		}
		_ = st.ReadTenant(t.Context(), tenant, func(tx *store.TenantTx) error {
			js, err := tx.QueueJobs(store.QueueJobFilter{Kind: jobs.ConnectorSync})
			if err == nil && len(js) == 1 {
				status = js[0].Status
				if status == store.QueueDead {
					t.Fatalf("job dead: %s", js[0].LastError)
				}
			}
			return err
		})
		time.Sleep(50 * time.Millisecond)
	}
	_ = st.ReadTenant(t.Context(), tenant, func(tx *store.TenantTx) error {
		ws, err := tx.QueueWorkers()
		if err != nil || len(ws) != 1 || ws[0].WorkerID != "test-worker" || ws[0].Mode != store.WorkerModeWorker ||
			ws[0].Kinds != jobs.ConnectorSync || ws[0].Concurrency != 2 {
			t.Errorf("worker health: %+v %v", ws, err)
		}
		as, err := tx.Accounts()
		if err != nil || len(as) == 0 {
			t.Errorf("the sync ingested nothing: %d accounts, %v", len(as), err)
		}
		return nil
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the worker's exit: %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the worker did not stop")
	}
	_ = st.ReadTenant(t.Context(), tenant, func(tx *store.TenantTx) error {
		if ws, err := tx.QueueWorkers(); err != nil || len(ws) != 0 {
			t.Errorf("a worker that stopped cleanly is still listed: %v %v", ws, err)
		}
		return nil
	})
	if !strings.Contains(logs.String(), "tessera worker started") || !strings.Contains(logs.String(), "tessera worker stopped") {
		t.Errorf("logs: %s", logs.String())
	}
}
