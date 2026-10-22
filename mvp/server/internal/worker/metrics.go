package worker

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Metrics is the worker process's Prometheus exposition (issue #302): what its
// queue is doing and how its targets are faring. The names carry no tenant,
// connection or host: a scrape is an operator's view of the process, and
// the per-connection breaker state is in the tenant's own API
// (GET /api/queue/workers).
//
// The text is the worker's own registry followed by obs.Default (the process
// start time, the database and connector call metrics the shared packages
// record), so one scrape sees both.
type Metrics struct {
	reg      *obs.Registry
	jobs     *obs.Counter
	duration *obs.Histogram
	calls    *obs.Counter
	targets  *obs.Gauge
}

// NewMetrics registers the worker's metrics. q and g may be nil.
func NewMetrics(q *queue.Queue, g *Guard) *Metrics {
	reg := obs.NewRegistry()
	m := &Metrics{reg: reg,
		jobs: reg.NewCounter("tessera_worker_jobs_total",
			"Queue jobs this worker finished, by kind and result (ok, error).", "kind", "result"),
		duration: reg.NewHistogram("tessera_worker_job_duration_seconds",
			"Duration in seconds of the queue jobs this worker ran, by kind.", nil, "kind"),
		calls: reg.NewCounter("tessera_worker_target_calls_total",
			"Calls to customers' systems by outcome: ok, error, breaker_rejected (the circuit breaker was open), rate_limited.", "outcome"),
		targets: reg.NewGauge("tessera_worker_targets",
			"Targets this worker has called, by circuit breaker state (closed, open, half_open).", "state"),
	}
	if q != nil {
		reg.NewGaugeFunc("tessera_worker_concurrency", "Jobs this worker may run at once.",
			func() float64 { return float64(q.Concurrency) })
		reg.NewGaugeFunc("tessera_worker_jobs_running", "Jobs this worker is running now.",
			func() float64 { return float64(q.Running()) })
	}
	if g != nil {
		g.OnCall = m.OnCall
		reg.OnScrape(func() {
			counts := map[string]float64{store.BreakerClosed: 0, store.BreakerOpen: 0, store.BreakerHalfOpen: 0}
			for _, s := range g.Snapshot() {
				counts[s.State]++
			}
			for state, n := range counts {
				m.targets.Set(n, state)
			}
		})
	}
	return m
}

// OnCall counts the outcome of one call to a target (Guard.OnCall).
func (m *Metrics) OnCall(outcome string) { m.calls.Inc(outcome) }

// Wrap counts and times a handler (it is a Wrap for Deps.Register).
func (m *Metrics) Wrap(kind string, h queue.Handler) queue.Handler {
	return func(ctx context.Context, j queue.Job) (any, error) {
		start := time.Now()
		res, err := h(ctx, j)
		m.duration.Observe(time.Since(start).Seconds(), kind)
		result := "ok"
		if err != nil {
			result = "error"
		}
		m.jobs.Inc(kind, result)
		return res, err
	}
}

// Handler serves GET /metrics.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", obs.ContentType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodHead {
			return
		}
		var out io.Writer = w
		_ = m.reg.WriteText(out)
		_ = obs.Default.WriteText(out)
	})
}
