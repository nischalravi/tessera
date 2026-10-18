package obs

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// The metric names and label sets below are a contract: deploy/prometheus
// and docs/operations/slo.md depend on them, and TestMetricContract_Golden
// pins them. Change one only together with the rules and the golden file.
var (
	// HTTPRequests counts API requests by registered route pattern and status
	// class (1xx..5xx). Unknown routes are "unmatched".
	HTTPRequests = Default.NewCounter("tessera_http_requests_total",
		"HTTP requests by route pattern and status class.", "route", "class")
	// HTTPDuration is the request latency by route pattern and status class.
	HTTPDuration = Default.NewHistogram("tessera_http_request_duration_seconds",
		"HTTP request latency in seconds by route pattern and status class.", nil, "route", "class")

	// AuditWrites counts http.request audit events by write result (ok, error).
	AuditWrites = Default.NewCounter("tessera_audit_writes_total",
		"http.request audit events written, by result.", "result")
	// AuditWriteFailures counts http.request events that could not be written.
	AuditWriteFailures = Default.NewCounter("tessera_audit_write_failures_total",
		"http.request audit events that could not be written (reads then fail closed with 503).")

	// DBTxDuration times database transactions.
	DBTxDuration = Default.NewHistogram("tessera_db_tx_duration_seconds",
		"Database transaction duration in seconds by kind and outcome.", nil, "kind", "outcome")
	// DBLockWait times the wait for the single-writer lock.
	DBLockWait = Default.NewHistogram("tessera_db_write_lock_wait_seconds",
		"Time spent waiting for the database write lock, in seconds.", nil)
	// DBBusy counts SQLITE_BUSY / locked errors.
	DBBusy = Default.NewCounter("tessera_db_busy_total",
		"Transactions that failed with SQLITE_BUSY or a locked database, by kind.", "kind")

	// Logins counts sign-in outcomes.
	Logins = Default.NewCounter("tessera_login_total",
		"Sign-in outcomes by method (oidc, saml, oauth2, other) and result (success, failure).", "method", "result")

	// ConnectorCalls and ConnectorDuration cover calls to external systems.
	ConnectorCalls = Default.NewCounter("tessera_connector_calls_total",
		"Calls to external systems by connector, operation and result (ok, error).", "connector", "op", "result")
	ConnectorDuration = Default.NewHistogram("tessera_connector_call_duration_seconds",
		"Duration in seconds of calls to external systems by connector and operation.", nil, "connector", "op")

	// ReadyCheck is the last evaluation of each /readyz check (1 ok, 0 failing).
	ReadyCheck = Default.NewGauge("tessera_readiness_check_ok",
		"Last /readyz evaluation by check: 1 ok, 0 failing.", "check")
)

var startTime = time.Now()

func init() {
	Default.NewGaugeFunc("tessera_process_start_time_seconds", "Start time of the process, in Unix seconds.",
		func() float64 { return float64(startTime.Unix()) })
}

// ---------------------------------------------------------------- connector calls

// Connector names (the closed set of the connector label).
const (
	ConnContainment = "containment"
	ConnLDAP        = "ldap"
	ConnOIDC        = "oidc"
)

// StartCall records one call to an external system: connector and op must
// be constants of the call site (never a host name, tenant or identifier).
// Use it as
//
//	done := obs.StartCall(obs.ConnOIDC, "discovery")
//	err := call()
//	done(err)
func StartCall(connector, op string) func(err error) {
	start := time.Now()
	return func(err error) {
		res := "ok"
		if err != nil {
			res = "error"
		}
		ConnectorCalls.Inc(connector, op, res)
		ConnectorDuration.Observe(time.Since(start).Seconds(), connector, op)
	}
}

// ---------------------------------------------------------------- HTTP

// Unmatched is the route label of a request no route served.
const Unmatched = "unmatched"

// StatusClass is "2xx" for 200..299 and so on; anything outside 100..599 is
// "other".
func StatusClass(status int) string {
	if status < 100 || status > 599 {
		return Other
	}
	return strconv.Itoa(status/100) + "xx"
}

type routeKey struct{}

type routeHolder struct {
	mu    sync.Mutex
	route string
}

// WithRoute returns a context that SetRoute can later fill in. The HTTP
// middleware calls it once per request; the router (which may run on another
// goroutine behind http.TimeoutHandler) reports the pattern with SetRoute.
func WithRoute(ctx context.Context) (context.Context, func() string) {
	h := &routeHolder{route: Unmatched}
	return context.WithValue(ctx, routeKey{}, h), func() string {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.route
	}
}

// SetRoute records the registered route pattern ("GET /api/x/{id}") that
// serves the request. Never pass a raw path.
func SetRoute(ctx context.Context, route string) {
	if h, ok := ctx.Value(routeKey{}).(*routeHolder); ok {
		h.mu.Lock()
		h.route = route
		h.mu.Unlock()
	}
}

// RouteFrom returns the route recorded so far ("unmatched" before routing).
func RouteFrom(ctx context.Context) string {
	if h, ok := ctx.Value(routeKey{}).(*routeHolder); ok {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.route
	}
	return Unmatched
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Instrument wraps next so every request is counted and timed under its
// route pattern. It is the outermost wrapper, so rate-limited, refused and
// audit-unavailable responses are counted too.
func Instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx, route := WithRoute(r.Context())
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r.WithContext(ctx))
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		class := StatusClass(status)
		rt := route()
		HTTPRequests.Inc(rt, class)
		HTTPDuration.Observe(time.Since(start).Seconds(), rt, class)
	})
}

// ---------------------------------------------------------------- database pool

// PoolStats is a snapshot of the database connection pool.
type PoolStats struct {
	Open, InUse, Idle int
	WaitCount         int64
	WaitDuration      time.Duration
}

var poolSource atomic.Pointer[func() PoolStats]

// SetPoolStats sets where the pool gauges read from (the server's database).
func SetPoolStats(fn func() PoolStats) { poolSource.Store(&fn) }

// CurrentPoolStats returns the registered pool's snapshot (zero before
// SetPoolStats).
func CurrentPoolStats() PoolStats {
	if fn := poolSource.Load(); fn != nil {
		return (*fn)()
	}
	return PoolStats{}
}

func init() {
	pool := Default.NewGauge("tessera_db_pool_connections", "Database pool connections by state (open, in_use, idle).", "state")
	Default.OnScrape(func() {
		p := CurrentPoolStats()
		pool.Set(float64(p.Open), "open")
		pool.Set(float64(p.InUse), "in_use")
		pool.Set(float64(p.Idle), "idle")
	})
	Default.NewCounterFunc("tessera_db_pool_wait_total", "Connections waited for since start.",
		func() float64 { return float64(CurrentPoolStats().WaitCount) })
	Default.NewCounterFunc("tessera_db_pool_wait_seconds_total", "Total time blocked waiting for a pooled connection, in seconds.",
		func() float64 { return CurrentPoolStats().WaitDuration.Seconds() })
}
