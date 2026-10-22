package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
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
		"an unknown kind":                {"-kinds", "connector_sync,sweep_requests"},
		"no kind":                        {"-kinds", ","},
		"no concurrency":                 {"-concurrency", "0"},
		"too much concurrency":           {"-concurrency", "65"},
		"a lease too short":              {"-lease", "1s"},
		"an unknown flag":                {"-listen", ":8000"}, // a worker has no API
		"a stray argument":               {"connector_sync"},
		"a public metrics address":       {"-metrics-addr", "203.0.113.9:9465"},
		"a wildcard metrics address":     {"-metrics-addr", ":9465"},
		"a metrics host name":            {"-metrics-addr", "metrics.example.com:9465"},
		"a metrics address with no port": {"-metrics-addr", "127.0.0.1"},
		"too much target concurrency":    {"-target-concurrency", "65"},
		"a negative target rate":         {"-target-rate", "-1"},
		"too many breaker failures":      {"-target-breaker-failures", "101"},
		"a breaker cooldown too short":   {"-target-breaker-cooldown", "10ms"},
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

// TestWorkerCmdServesMetrics: -metrics-addr serves Prometheus text with the
// worker's own metrics on /metrics and nothing else, and stops with the worker.
func TestWorkerCmdServesMetrics(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_CONNECTORS", "demo-workday")
	db := filepath.Join(t.TempDir(), "w.db")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var logs bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"worker", "-db", db, "-kinds", "connector_sync", "-poll", "100ms", "-concurrency", "3",
			"-metrics-addr", addr}, io.Discard, &logs)
	}()
	get := func(path string) (int, string) {
		resp, err := http.Get("http://" + addr + path) // #nosec G107 -- a test against its own loopback listener
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	var code int
	var body string
	for deadline := time.Now().Add(2 * time.Minute); code != http.StatusOK; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no metrics at %s: %d %s\n%s", addr, code, body, logs.String())
		}
		code, body = get("/metrics")
	}
	for _, want := range []string{"tessera_worker_concurrency 3", "tessera_worker_jobs_running", "tessera_process_start_time_seconds"} {
		if !strings.Contains(body, want) {
			t.Errorf("no %q in:\n%s", want, body)
		}
	}
	if c, _ := get("/"); c != http.StatusNotFound {
		t.Errorf("GET /: %d, want 404 (only /metrics is served)", c)
	}
	if c, _ := get("/api/queue/workers"); c != http.StatusNotFound {
		t.Errorf("GET /api/queue/workers: %d", c)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the worker's exit: %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the worker did not stop")
	}
	if _, err := http.Get("http://" + addr + "/metrics"); err == nil { // #nosec G107 -- loopback test listener
		t.Error("the metrics listener outlived the worker")
	}
}
