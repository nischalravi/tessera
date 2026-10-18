package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Job run history (issue #172). A route marked with a jobSpec records a run
// around its transaction (serveJob); GET /api/jobs lists the runs and POST
// /api/jobs/{job_id}/retry runs an idempotent one again through a typed
// dispatcher (retryJob).

type jobSpec struct {
	kind      string
	connParam string // path parameter naming the connection, if any
}

// asJob marks a route as running a job of kind.
func (rt *route) asJob(kind, connParam string) *route {
	rt.job = &jobSpec{kind: kind, connParam: connParam}
	return rt
}

// retryKey carries the id of the run a retried operation re-runs.
type retryKey struct{}

func (s *Server) registerJobRoutes() {
	s.handle(http.MethodGet, "/api/jobs", read, need(auth.PermJobsRead), s.listJobs)
	s.handle(http.MethodGet, "/api/jobs/{job_id}", read, need(auth.PermJobsRead), s.getJob)
	// noTenant: the retry runs another route's handler, which opens its own transaction.
	s.handle(http.MethodPost, "/api/jobs/{job_id}/retry", noTenant, need(auth.PermJobsRead), s.retryJob)
}

// serveJob runs a job route, recording the run in transactions of its own.
func (s *Server) serveJob(rt *route, w http.ResponseWriter, r *http.Request, p *params, t tenancy.ID) (any, error) {
	ctx := r.Context()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errBodyTooLarge
		}
		return nil, errBodyUnreadable
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	st := jobs.Start{Kind: rt.job.kind, Trigger: "manual", Method: rt.method, Route: rt.pattern, Path: r.URL.Path,
		Body: body, Actor: actor(r)}
	if id, ok := ctx.Value(retryKey{}).(string); ok {
		st.Trigger, st.RetryOf = "retry", &id
	}
	if rt.job.connParam != "" {
		if cid := p.path[rt.job.connParam]; cid != "" && s.connectionExists(ctx, t, cid) {
			st.ConnectionID = &cid
		}
	}
	id, err := jobs.Begin(ctx, s.store, t, st, s.clock())
	if err != nil {
		return nil, err
	}
	out, runErr := s.serveTenant(rt, w, r, p, t)
	// Recording must survive a cancelled request: the run happened.
	rec := context.WithoutCancel(ctx)
	if runErr != nil && refusedBeforeRun(runErr) {
		if err := jobs.Discard(rec, s.store, t, id); err != nil {
			s.log.Error("job run: discard", "err", err)
		}
		return out, runErr
	}
	result := out
	if sb, ok := out.(statusBody); ok {
		result = sb.body
	}
	failed := runErr
	if failed == nil {
		failed = jobs.RunFailed(result)
	}
	if err := jobs.Finish(rec, s.store, t, id, result, failed, s.clock()); err != nil {
		s.log.Error("job run: finish", "err", err, "job_id", id)
	}
	return out, runErr
}

func (s *Server) connectionExists(ctx context.Context, t tenancy.ID, id string) bool {
	if !idRE.MatchString(id) {
		return false
	}
	err := s.store.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		_, err := tx.Connection(id)
		return err
	})
	return err == nil
}

// refusedBeforeRun: the request was refused (input, permission, a blocked
// gate, a missing row) rather than the job failing.
func refusedBeforeRun(err error) bool {
	var dn denial
	var ve *validationError
	var he *httpError
	var re *readiness.Error
	switch {
	case errors.As(err, &dn), errors.As(err, &ve), errors.Is(err, errBodyTooLarge), errors.Is(err, errBodyUnreadable),
		errors.Is(err, store.ErrNotFound):
		return true
	case errors.As(err, &he):
		return he.status < 500
	case errors.As(err, &re):
		return re.Status < 500
	}
	return false
}

type jobView struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	Trigger      string          `json:"trigger"`
	Status       string          `json:"status"`
	ConnectionID *string         `json:"connection_id"`
	Method       *string         `json:"method"`
	Path         *string         `json:"path"`
	Retryable    bool            `json:"retryable"`
	RetryOf      *string         `json:"retry_of"`
	Actor        string          `json:"actor"`
	StartedAt    string          `json:"started_at"`
	FinishedAt   *string         `json:"finished_at"`
	DurationMS   *int64          `json:"duration_ms"`
	Result       json.RawMessage `json:"result"`
	Error        *string         `json:"error"`
}

func viewJob(j *store.JobRun) jobView {
	v := jobView{ID: j.ID, Kind: j.Kind, Trigger: j.Trigger, Status: j.Status, ConnectionID: j.ConnectionID, Method: j.Method,
		Path: j.Path, Retryable: j.Retryable && j.Status != "running", RetryOf: j.RetryOf, Actor: j.Actor,
		StartedAt: j.StartedAt.UTC().Format(time.RFC3339), Error: j.Error, Result: json.RawMessage("null")}
	if j.FinishedAt != nil {
		f := j.FinishedAt.UTC().Format(time.RFC3339)
		d := j.FinishedAt.Sub(j.StartedAt).Milliseconds()
		v.FinishedAt, v.DurationMS = &f, &d
	}
	if j.Result != nil && json.Valid([]byte(*j.Result)) {
		v.Result = json.RawMessage(*j.Result)
	}
	return v
}

var jobStatuses = []string{"running", "succeeded", "failed"}

func (s *Server) listJobs(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, badRequest("invalid_query", "the query string is not valid")
	}
	f := store.JobRunFilter{Status: q.Get("status"), Kind: q.Get("kind"), ConnectionID: q.Get("connection_id"), Limit: 200}
	if f.Status != "" && !slices.Contains(jobStatuses, f.Status) {
		return nil, badRequest("invalid_status", "status must be running, succeeded or failed")
	}
	if f.Kind != "" && !slices.Contains(jobs.Kinds, f.Kind) {
		return nil, badRequest("invalid_kind", "unknown job kind")
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 500 {
			return nil, badRequest("invalid_limit", "limit must be 1 to 500")
		}
		f.Limit = n
	}
	runs, err := store.TxFrom(r.Context()).JobRuns(f)
	if err != nil {
		return nil, err
	}
	out := make([]jobView, 0, len(runs))
	for _, j := range runs {
		out = append(out, viewJob(j))
	}
	return out, nil
}

var jobIDRE = idRE

func (s *Server) getJob(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.path["job_id"]
	if !jobIDRE.MatchString(id) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	}
	j, err := store.TxFrom(r.Context()).JobRun(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	} else if err != nil {
		return nil, err
	}
	return viewJob(j), nil
}

// retryJob runs a retryable run's operation again as the signed-in user,
// through a typed dispatcher rather than a replayed HTTP request: it
// rechecks the original route's permission and step-up for the caller, then
// runs that route's handler with the recorded body. The new run is recorded
// with retry_of and a job.retried event.
func (s *Server) retryJob(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.path["job_id"]
	if !jobIDRE.MatchString(id) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	}
	pr := principal(r)
	var j *store.JobRun
	err := s.store.ReadTenant(r.Context(), pr.TenantID, func(tx *store.TenantTx) error {
		var err error
		j, err = tx.JobRun(id)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	} else if err != nil {
		return nil, err
	}
	if j.Status == "running" {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "job_running", Msg: "this job is still running"}
	}
	if !j.Retryable || j.Method == nil || j.Path == nil || j.Body == nil {
		return nil, notRetryable()
	}
	// The typed dispatcher: the route is the one registered for the run's
	// kind, never one named by the stored row, and a row that disagrees with
	// it is refused.
	rt := s.retryRoute(j.Kind)
	if rt == nil || *j.Method != rt.method || j.Route == nil || *j.Route != rt.pattern {
		return nil, notRetryable()
	}
	vars := map[string]string{}
	path := rt.pattern
	if rt.job.connParam != "" {
		// The connection comes from the run's connection_id, which is
		// checked as an id before it is put into a path.
		if j.ConnectionID == nil || !idRE.MatchString(*j.ConnectionID) {
			return nil, notRetryable()
		}
		vars[rt.job.connParam] = *j.ConnectionID
		path = strings.Replace(path, "{"+rt.job.connParam+"}", *j.ConnectionID, 1)
	}
	// This request is already authenticated (session, CSRF). Recheck the
	// original route's permission and step-up against the caller as they are
	// now; a caller who has lost the permission since the run cannot retry it.
	if d := auth.Check(pr, rt.spec.Perm, rt.spec.Authn, s.clock()); d != nil {
		return nil, denial{d}
	}
	// The operation runs on a request value that carries the recorded body and
	// this request's context (principal and audit attribution) and nothing
	// else: no cookie, Authorization or DPoP header is copied, so no
	// credential is replayed, and nothing re-enters the HTTP stack.
	ctx := context.WithValue(context.WithoutCancel(r.Context()), retryKey{}, j.ID)
	inner, err := http.NewRequestWithContext(ctx, rt.method, path, bytes.NewReader([]byte(*j.Body)))
	if err != nil {
		return nil, err
	}
	inner.Header.Set("Content-Type", "application/json")
	inner.RemoteAddr = r.RemoteAddr
	rec := &bufferedResponse{header: http.Header{}, status: http.StatusOK}
	out, err := s.serveJob(rt, rec, inner, &params{r: inner, path: vars}, pr.TenantID)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return statusBody{rec.status, json.RawMessage(rec.body.Bytes())}, nil
	}
	return out, nil
}

func notRetryable() error {
	return &readiness.Error{Status: http.StatusConflict, Code: "not_retryable",
		Msg: "this job cannot be retried from here: only idempotent jobs (sync, validation, dry run, health re-run, JIT sweep) are"}
}

// retryRoute is the route that runs a retryable kind: the one registered with
// asJob for it. Kinds that are not idempotent have none.
func (s *Server) retryRoute(kind string) *route {
	if !jobs.Idempotent(kind) {
		return nil
	}
	for _, rt := range s.routes {
		if rt.job != nil && rt.job.kind == kind {
			return rt
		}
	}
	return nil
}

// bufferedResponse collects the response a retried handler writes itself.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) WriteHeader(code int)        { b.status = code }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }

// ------------------------------------------------------------ background

// sweepAndRecord expires JIT grants in every active tenant, recording a
// jit_sweep run for each tenant where it expired something or failed.
func (s *Server) sweepAndRecord(ctx context.Context) {
	var tenants []store.Tenant
	if err := s.store.InSystem(ctx, "jit sweeper: tenants", func(sys *store.SystemTx) error {
		var err error
		tenants, err = sys.ActiveTenants()
		return err
	}); err != nil {
		if ctx.Err() == nil {
			s.log.Error("jit sweep: tenants", "err", err)
		}
		return
	}
	for _, t := range tenants {
		if ctx.Err() != nil {
			return
		}
		started := s.clock()
		n, err := s.sweepCount(ctx, t.ID, started)
		if n == 0 && err == nil {
			continue
		}
		if err != nil {
			s.log.Error("jit sweep failed", "tenant", t.Slug, "err", err)
		}
		st := jobs.Start{Kind: jobs.JITSweep, Trigger: "schedule", Method: http.MethodPost, Route: "/api/jit/sweep",
			Path: "/api/jit/sweep", Actor: "jit.sweeper"}
		if rerr := jobs.Record(ctx, s.store, t.ID, st, started, s.clock(), map[string]int{"expired": n}, err); rerr != nil {
			s.log.Error("jit sweep: record run", "tenant", t.Slug, "err", rerr)
		}
	}
}

func (s *Server) sweepCount(ctx context.Context, t tenancy.ID, now time.Time) (int, error) {
	var need bool
	if err := s.store.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		need, err = jit.NeedsSweep(tx, now)
		return err
	}); err != nil || !need {
		return 0, err
	}
	var n int
	err := s.store.InTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		n, err = jit.Sweep(tx, now)
		return err
	})
	return n, err
}

// Job history upkeep.
const (
	jobStaleAfter  = time.Hour
	jobRetention   = 30 * 24 * time.Hour
	jobMaintainGap = 10 * time.Minute
)

// RecordAnchorRun is the audit Checkpointer's per-tenant hook: it records an
// audit_anchor run when the checkpointer created or anchored a checkpoint,
// or failed.
func RecordAnchorRun(db *store.DB) func(ctx context.Context, t store.Tenant, started, finished time.Time, created bool, anchored, failed int, err error) {
	return func(ctx context.Context, t store.Tenant, started, finished time.Time, created bool, anchored, failed int, err error) {
		if !created && anchored == 0 && failed == 0 && err == nil {
			return
		}
		if err == nil && failed > 0 {
			err = errors.New(strconv.Itoa(failed) + " checkpoint(s) could not be anchored")
		}
		_ = jobs.Record(audit.WithSystemActor(ctx, "audit.checkpointer"), db, t.ID,
			jobs.Start{Kind: jobs.AuditAnchor, Trigger: "schedule", Actor: "audit.checkpointer"}, started, finished,
			map[string]any{"checkpoint_created": created, "anchored": anchored, "failed": failed}, err)
	}
}
