package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/access"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	guestlife "github.com/nischalravi/tessera/mvp/server/internal/guests/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/register"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/reconcile"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// The durable job queue (issue #300). The background work that used to be one
// ticker goroutine (RunSweeper) is a set of queue kinds with a schedule row
// per tenant; any number of instances can run it, because a job is leased to
// one worker at a time. Admin routes list the queue and schedules and retry
// a dead job.

// SweepInterval is how often each sweeper schedule fires.
const SweepInterval = 30 * time.Second

// maxSweepAttempts: a failing sweep is retried a couple of times; after that
// it is dead (visible, retryable) and the next window tries again anyway.
const maxSweepAttempts = 3

// SweeperLoops are the queue kinds whose runs are tracked as loops in
// obs.DefaultLoops (lag in /metrics, /readyz and Admin -> Platform health).
var SweeperLoops = []string{jobs.JITSweep, jobs.SweepRequests, jobs.SweepLifecycle, jobs.SweepAdminChanges, jobs.ContainmentRetry, jobs.SweepSoDMitigations, jobs.SweepDrift, jobs.SweepSSFPoll}

// tracked reports each run of a kind's handler, in any tenant, to its loop.
func tracked(kind string, h queue.Handler) queue.Handler {
	return func(ctx context.Context, j queue.Job) (result any, err error) {
		_ = obs.DefaultLoops.Run(kind, func() error { result, err = h(ctx, j); return err })
		return result, err
	}
}

func (s *Server) newQueue() *queue.Queue {
	for _, k := range SweeperLoops {
		every := SweepInterval
		if k == jobs.SweepDrift {
			every = driftEvery
		}
		obs.DefaultLoops.Register(k, every, true)
	}
	q := &queue.Queue{DB: s.store, Clock: func() time.Time { return s.clock() }, Log: s.log.With("component", "queue")}
	// jit_sweep is also the manual POST /api/jit/sweep: its runs carry the
	// route so the run history can retry them.
	q.Register(jobs.JITSweep, queue.Kind{Handler: tracked(jobs.JITSweep, s.queueJITSweep), Actor: "jit.sweeper", Method: http.MethodPost, Route: "/api/jit/sweep"})
	q.Register(jobs.SweepRequests, queue.Kind{Handler: tracked(jobs.SweepRequests, s.queueRequestSweep), Actor: requests.Sweeper})
	q.Register(jobs.SweepLifecycle, queue.Kind{Handler: tracked(jobs.SweepLifecycle, s.queueLifecycleSweep), Actor: lifecycle.Sweeper})
	q.Register(jobs.SweepAdminChanges, queue.Kind{Handler: tracked(jobs.SweepAdminChanges, s.queueAdminSweep), Actor: "admin.sweeper"})
	q.Register(jobs.ContainmentRetry, queue.Kind{Handler: tracked(jobs.ContainmentRetry, s.queueContainmentRetries), Actor: "containment.sweeper"})
	q.Register(jobs.SweepSoDMitigations, queue.Kind{Handler: tracked(jobs.SweepSoDMitigations, s.queueSoDSweep), Actor: sod.Sweeper})
	q.Register(jobs.SoDMitigationExpire, queue.Kind{Handler: s.queueSoDExpire, Actor: sod.Sweeper})
	q.Register(jobs.SweepSSFPoll, queue.Kind{Handler: tracked(jobs.SweepSSFPoll, s.queueSSFPoll), Actor: "ssf.poller"})
	q.Register(jobs.SweepDrift, queue.Kind{Handler: tracked(jobs.SweepDrift, s.queueDriftSweep), Actor: "drift.sweeper"})
	q.Register(jobs.GuestLifecycle, queue.Kind{Handler: tracked(jobs.GuestLifecycle, s.queueGuestLifecycleSweep), Actor: guestlife.Sweeper})
	q.Register(jobs.Maintenance, queue.Kind{Handler: s.queueMaintenance, Actor: "queue.worker"})
	// The worker kinds (issue #302): run here unless a `tessera worker` is
	// meant to. provision_push is not registered here: the process keeps the
	// provisioning loop (RunProvisioning), which the serve wiring skips when
	// the kind is external.
	if kinds := s.inProcessKinds(); len(kinds) > 0 {
		if err := s.workerDeps().Register(q, kinds, nil); err != nil {
			panic(err) // a programming error, found at startup
		}
	}
	every := "@every " + SweepInterval.String()
	for _, k := range []string{jobs.JITSweep, jobs.SweepRequests, jobs.SweepLifecycle, jobs.SweepAdminChanges, jobs.ContainmentRetry, jobs.SweepSoDMitigations, jobs.GuestLifecycle, jobs.SweepSSFPoll} {
		q.Schedule(k, k, every, maxSweepAttempts)
	}
	q.Schedule(jobs.SweepDrift, jobs.SweepDrift, "@every "+driftEvery.String(), maxSweepAttempts)
	q.Schedule(jobs.Maintenance, jobs.Maintenance, "@every "+jobMaintainGap.String(), 1)
	return q
}

// workerDeps are the handlers of the worker kinds, built on this server's
// parts (so an on-demand sync and a queued one run the same code).
func (s *Server) workerDeps() *worker.Deps {
	return &worker.Deps{DB: s.store, Clock: func() time.Time { return s.clock() }, Log: s.log.With("component", "worker"),
		Connectors: s.cfg.Connectors, Provision: s.prov, SyncSchedule: s.cfg.ConnectorSyncSchedule}
}

// inProcessKinds are the queue kinds of the worker pool that this process
// registers: connector_sync unless it is external. (provision_push is run by
// RunProvisioning, see newQueue.)
func (s *Server) inProcessKinds() []string {
	if slices.Contains(s.cfg.ExternalKinds, jobs.ConnectorSync) {
		return nil
	}
	return []string{jobs.ConnectorSync}
}

// ExternalKind reports whether kind is run by workers rather than this process.
func (s *Server) ExternalKind(kind string) bool { return slices.Contains(s.cfg.ExternalKinds, kind) }

// Queue is the job queue (tests drive it with Tick and Wait).
func (s *Server) Queue() *queue.Queue { return s.queue }

// RunQueue works the job queue until ctx is done: the sweepers, the
// containment retry sweep and job history upkeep.
func (s *Server) RunQueue(ctx context.Context) { s.queue.Run(ctx) }

// A sweep that finds nothing returns no result, so it leaves no job run.

func (s *Server) queueJITSweep(ctx context.Context, j queue.Job) (any, error) {
	n, err := s.sweepCount(audit.WithSystemActor(ctx, "jit.sweeper"), j.Tenant, s.clock())
	if n == 0 && err == nil {
		return nil, nil
	}
	return map[string]int{"expired": n}, err
}

func (s *Server) queueRequestSweep(ctx context.Context, j queue.Job) (any, error) {
	now := s.clock()
	return nil, s.store.InTenant(audit.WithSystemActor(ctx, requests.Sweeper), j.Tenant, func(tx *store.TenantTx) error {
		need, err := requests.NeedsSweep(tx, now)
		if err != nil || !need {
			return err
		}
		_, err = requests.Sweep(tx, now)
		return err
	})
}

// queueLifecycleSweep ends sponsorships first: the last one to end ends the
// person, and the lifecycle sweep then has nothing left. Guest claim links are
// swept in the same job (#202). They are one job so
// that order holds however many workers run.
func (s *Server) queueLifecycleSweep(ctx context.Context, j queue.Job) (any, error) {
	now := s.clock()
	err := s.store.InTenant(audit.WithSystemActor(ctx, sponsorship.Sweeper), j.Tenant, func(tx *store.TenantTx) error {
		need, err := sponsorship.NeedsSweep(tx, now)
		if err != nil || !need {
			return err
		}
		_, err = s.guests.Sweep(tx, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	if s.claimSvc != nil { // expire guest claim links, and the invitations whose last link lapsed unused
		err = s.store.InTenant(audit.WithSystemActor(ctx, "claim.sweeper"), j.Tenant, func(tx *store.TenantTx) error {
			need, err := claim.NeedsSweep(tx, now)
			if err != nil || !need {
				return err
			}
			_, err = s.claimSvc.Sweep(tx, now)
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	// pending registrations that waited too long, and the personal data of decided ones (GU-3)
	err = s.store.InTenant(audit.WithSystemActor(ctx, register.Sweeper), j.Tenant, func(tx *store.TenantTx) error {
		need, err := register.NeedsSweep(tx)
		if err != nil || !need {
			return err
		}
		_, err = s.reg.Sweep(tx, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	// bundles of ended sponsorships, waiting items and the reference groups (GU-12)
	err = s.store.InTenant(audit.WithSystemActor(ctx, access.Sweeper), j.Tenant, func(tx *store.TenantTx) error {
		return access.SweepTenant(tx, now, s.eligible())
	})
	if err != nil {
		return nil, err
	}
	_, err = lifecycle.SweepTenant(audit.WithSystemActor(ctx, lifecycle.Sweeper), readiness.Scope{DB: s.store, Tenant: j.Tenant},
		s.containment, now)
	return nil, err
}

// queueAdminSweep applies the admin changes whose cooling-off ended and
// expires the ones nobody approved in 72 hours (design §15.2).
func (s *Server) queueAdminSweep(ctx context.Context, j queue.Job) (any, error) {
	_, err := s.admin.SweepTenant(audit.WithSystemActor(ctx, "admin.sweeper"), j.Tenant)
	return nil, err
}

// queueContainmentRetries re-runs the containment retry tasks that are due.
// Each task keeps its own backoff and 24-hour give-up (containment_retries);
// the queue adds the lease, so two instances never run a tenant's tasks at once.
func (s *Server) queueContainmentRetries(ctx context.Context, j queue.Job) (any, error) {
	_, err := s.containment.RunRetries(audit.WithSystemActor(ctx, "containment.sweeper"), s.store, j.Tenant, "containment.sweeper", "")
	return nil, err
}

// queueSSFPoll polls the tenant's enabled Shared Signals poll streams.
func (s *Server) queueSSFPoll(ctx context.Context, j queue.Job) (any, error) {
	return nil, s.ssf.PollTenant(audit.WithSystemActor(ctx, "ssf.poller"), s.store, j.Tenant)
}

// queueSoDSweep warns about SoD mitigations ending soon and closes the ones
// whose end date has passed (the violation is open again).
func (s *Server) queueSoDSweep(ctx context.Context, j queue.Job) (any, error) {
	now := s.clock()
	return nil, s.store.InTenant(audit.WithSystemActor(ctx, sod.Sweeper), j.Tenant, func(tx *store.TenantTx) error {
		_, _, err := sod.Sweep(tx, now, s.cfg.SoD)
		return err
	})
}

// sodExpirePayload is the payload of a jobs.SoDMitigationExpire job.
type sodExpirePayload struct {
	MitigationID string `json:"mitigation_id"`
}

// queueSoDExpire re-opens the violation of one mitigation at its end date
// (issue #298). The job is queued in the transaction that activates the
// mitigation, to run at its end date; the periodic sweep is the backstop.
func (s *Server) queueSoDExpire(ctx context.Context, j queue.Job) (any, error) {
	var p sodExpirePayload
	if err := json.Unmarshal([]byte(j.Payload), &p); err != nil || p.MitigationID == "" {
		return nil, queue.Permanent(errors.New("sod_mitigation_expire: bad payload"))
	}
	now := s.clock()
	var reopened bool
	err := s.store.InTenant(audit.WithSystemActor(ctx, sod.Sweeper), j.Tenant, func(tx *store.TenantTx) error {
		var err error
		reopened, err = sod.ExpireOne(tx, now, p.MitigationID)
		return err
	})
	if err != nil || !reopened {
		return nil, err
	}
	return map[string]any{"mitigation_id": p.MitigationID, "reopened": true}, nil
}

// queueDriftSweep reconciles one tenant's intended and observed access: it opens,
// updates and resolves drift and runs the remediation policies (issue #301).
func (s *Server) queueDriftSweep(ctx context.Context, j queue.Job) (any, error) {
	now := s.clock()
	return nil, s.store.InTenant(audit.WithSystemActor(ctx, "drift.sweeper"), j.Tenant, func(tx *store.TenantTx) error {
		_, err := reconcile.RunDrift(tx, now, "drift.sweeper")
		return err
	})
}

func (s *Server) queueMaintenance(ctx context.Context, j queue.Job) (any, error) {
	now := s.clock()
	return nil, s.store.InTenant(ctx, j.Tenant, func(tx *store.TenantTx) error {
		if err := jobs.MaintainTx(tx, now, jobStaleAfter, jobRetention); err != nil {
			return err
		}
		_, err := s.queue.Prune(tx)
		return err
	})
}

// ---------------------------------------------------------------- routes

func (s *Server) registerQueueRoutes() {
	s.handle(http.MethodGet, "/api/queue/jobs", read, need(auth.PermJobsRead), s.listQueueJobs)
	s.handle(http.MethodGet, "/api/queue/schedules", read, need(auth.PermJobsRead), s.listQueueSchedules)
	s.handle(http.MethodGet, "/api/queue/workers", read, need(auth.PermJobsRead), s.listQueueWorkers)
	s.handle(http.MethodPost, "/api/queue/jobs/{job_id}/retry", write, needStepUp(auth.PermJobsManage, auth.StepUpPolicy), s.retryQueueJob)
}

type queueJobView struct {
	ID             string  `json:"id"`
	Kind           string  `json:"kind"`
	Status         string  `json:"status"`
	RunAt          string  `json:"run_at"`
	Attempts       int     `json:"attempts"`
	MaxAttempts    int     `json:"max_attempts"`
	LastError      string  `json:"last_error"`
	LeaseOwner     *string `json:"lease_owner"`
	LeaseExpiresAt *string `json:"lease_expires_at"`
	ScheduleID     *string `json:"schedule_id"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
	FinishedAt     *string `json:"finished_at"`
}

func isoPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	v := t.UTC().Format(time.RFC3339)
	return &v
}

func viewQueueJob(j *store.QueueJob) queueJobView {
	return queueJobView{ID: j.ID, Kind: j.Kind, Status: j.Status, RunAt: j.RunAt.UTC().Format(time.RFC3339),
		Attempts: j.Attempts, MaxAttempts: j.MaxAttempts, LastError: j.LastError, LeaseOwner: j.LeaseOwner,
		LeaseExpiresAt: isoPtr(j.LeaseExpiresAt), ScheduleID: j.ScheduleID, CreatedAt: j.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: j.UpdatedAt.UTC().Format(time.RFC3339), FinishedAt: isoPtr(j.FinishedAt)}
}

type queueScheduleView struct {
	Name           string  `json:"name"`
	Kind           string  `json:"kind"`
	Spec           string  `json:"spec"`
	Enabled        bool    `json:"enabled"`
	MaxAttempts    int     `json:"max_attempts"`
	NextRunAt      string  `json:"next_run_at"`
	LastEnqueuedAt *string `json:"last_enqueued_at"`
}

var (
	queueStatuses = []string{store.QueueQueued, store.QueueRunning, store.QueueSucceeded, store.QueueFailed, store.QueueDead}
	queueKindRE   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

func (s *Server) listQueueJobs(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, badRequest("invalid_query", "the query string is not valid")
	}
	f := store.QueueJobFilter{Status: q.Get("status"), Kind: q.Get("kind"), Limit: 200}
	if f.Status != "" && !slices.Contains(queueStatuses, f.Status) {
		return nil, badRequest("invalid_status", "status must be queued, running, succeeded, failed or dead")
	}
	if f.Kind != "" && !queueKindRE.MatchString(f.Kind) {
		return nil, badRequest("invalid_kind", "unknown job kind")
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 500 {
			return nil, badRequest("invalid_limit", "limit must be 1 to 500")
		}
		f.Limit = n
	}
	js, err := store.TxFrom(r.Context()).QueueJobs(f)
	if err != nil {
		return nil, err
	}
	out := make([]queueJobView, 0, len(js))
	for _, j := range js {
		out = append(out, viewQueueJob(j))
	}
	return out, nil
}

func (s *Server) listQueueSchedules(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	ss, err := store.TxFrom(r.Context()).QueueSchedules()
	if err != nil {
		return nil, err
	}
	out := make([]queueScheduleView, 0, len(ss))
	for _, v := range ss {
		out = append(out, queueScheduleView{Name: v.Name, Kind: v.Kind, Spec: v.Spec, Enabled: v.Enabled,
			MaxAttempts: v.MaxAttempts, NextRunAt: v.NextRunAt.UTC().Format(time.RFC3339), LastEnqueuedAt: isoPtr(v.LastEnqueuedAt)})
	}
	return out, nil
}

type queueWorkerView struct {
	WorkerID        string   `json:"worker_id"`
	Mode            string   `json:"mode"`
	Status          string   `json:"status"` // healthy | stale
	Hostname        string   `json:"hostname"`
	PID             int      `json:"pid"`
	Version         string   `json:"version"`
	Kinds           []string `json:"kinds"`
	Concurrency     int      `json:"concurrency"`
	Running         int      `json:"running"`
	StartedAt       string   `json:"started_at"`
	LastHeartbeatAt string   `json:"last_heartbeat_at"`
	LagSeconds      int      `json:"lag_seconds"` // since the last heartbeat
}

// listQueueWorkers shows the workers that serve the queue and when each last
// beat: a worker whose last beat is older than worker.StaleAfter is stale
// (crashed or cut off; its jobs return when their leases expire).
func (s *Server) listQueueWorkers(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	ws, err := store.TxFrom(r.Context()).QueueWorkers()
	if err != nil {
		return nil, err
	}
	now := s.clock()
	out := make([]queueWorkerView, 0, len(ws))
	for _, w := range ws {
		lag := max(0, int(now.Sub(w.LastHeartbeatAt).Seconds()))
		st := "healthy"
		if now.Sub(w.LastHeartbeatAt) > worker.StaleAfter {
			st = "stale"
		}
		kinds := []string{}
		if w.Kinds != "" {
			kinds = strings.Split(w.Kinds, ",")
		}
		out = append(out, queueWorkerView{WorkerID: w.WorkerID, Mode: w.Mode, Status: st, Hostname: w.Hostname, PID: w.PID,
			Version: w.Version, Kinds: kinds, Concurrency: w.Concurrency, Running: w.Running,
			StartedAt: w.StartedAt.UTC().Format(time.RFC3339), LastHeartbeatAt: w.LastHeartbeatAt.UTC().Format(time.RFC3339),
			LagSeconds: lag})
	}
	return out, nil
}

// retryQueueJob puts a dead job back in the queue with a fresh attempt
// budget, and audits it (queue.job_retried).
func (s *Server) retryQueueJob(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id := p.path["job_id"]
	if !idRE.MatchString(id) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	}
	c := store.TxFrom(r.Context())
	j, err := c.QueueJob(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	} else if err != nil {
		return nil, err
	}
	if j.Status != store.QueueDead {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "not_dead", Msg: "only a dead job can be retried"}
	}
	if err := s.queue.Retry(c, id, actor(r)); err != nil {
		return nil, err
	}
	j, err = c.QueueJob(id)
	if err != nil {
		return nil, err
	}
	return viewQueueJob(j), nil
}
