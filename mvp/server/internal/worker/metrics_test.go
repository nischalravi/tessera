package worker_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

func scrape(t *testing.T, h http.Handler, method string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, "/metrics", nil))
	return rec
}

// The worker's exposition is Prometheus text with its queue, job and target
// metrics, carries no tenant, connection or worker identifier, and answers
// only GET and HEAD.
func TestWorkerMetrics(t *testing.T) {
	e := newEnv(t)
	g := e.guard(worker.Limits{BreakerThreshold: 1, BreakerCooldown: time.Minute})
	q := e.queue(t, "host-123-secret", time.Minute, &worker.Deps{Connectors: noConnectors}, jobs.ConnectorSync)
	q.Concurrency = 3
	m := worker.NewMetrics(q, g)
	wrapped := m.Wrap(jobs.ConnectorSync, func(context.Context, queue.Job) (any, error) { return nil, nil })
	failing := m.Wrap(jobs.ProvisionPush, func(context.Context, queue.Job) (any, error) { return nil, errors.New("boom") })
	_, _ = wrapped(t.Context(), queue.Job{})
	_, _ = wrapped(t.Context(), queue.Job{})
	_, _ = failing(t.Context(), queue.Job{})
	secretConn := "c-secret-connection-id"
	_ = g.Do(t.Context(), tenantA, secretConn, func(context.Context) error { return errors.New("down") })
	_ = g.Do(t.Context(), tenantA, secretConn, func(context.Context) error { return nil }) // refused: the breaker is open
	_ = g.Do(t.Context(), tenantA, "c-ok", func(context.Context) error { return nil })

	rec := scrape(t, m.Handler(), http.MethodGet)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("scrape: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	for _, want := range []string{
		`tessera_worker_jobs_total{kind="connector_sync",result="ok"} 2`,
		`tessera_worker_jobs_total{kind="provision_push",result="error"} 1`,
		`tessera_worker_job_duration_seconds_count{kind="connector_sync"} 2`,
		`tessera_worker_target_calls_total{outcome="ok"} 1`,
		`tessera_worker_target_calls_total{outcome="error"} 1`,
		`tessera_worker_target_calls_total{outcome="breaker_rejected"} 1`,
		`tessera_worker_targets{state="open"} 1`,
		`tessera_worker_targets{state="closed"} 1`,
		"tessera_worker_concurrency 3",
		"tessera_worker_jobs_running 0",
		"tessera_process_start_time_seconds", // obs.Default follows the worker's own registry
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the exposition has no %q:\n%s", want, body)
		}
	}
	for _, leak := range []string{"host-123-secret", secretConn, "c-ok", tenantA.String()} {
		if strings.Contains(body, leak) {
			t.Errorf("the exposition leaks %q", leak)
		}
	}
	if rec := scrape(t, m.Handler(), http.MethodHead); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD: %d %q", rec.Code, rec.Body)
	}
	if rec := scrape(t, m.Handler(), http.MethodPost); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
}
