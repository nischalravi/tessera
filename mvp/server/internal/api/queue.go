package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/archive"
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
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/reconcile"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/roles/mining"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
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
		// On Postgres several replicas share the queue and a job runs on one
		// of them, so a replica's own sweeper lag says nothing about the
		// fleet: the loops are reported in /metrics but do not gate /readyz.
		obs.DefaultLoops.Register(k, every, !s.store.IsPostgres())
	}
	q := &queue.Queue{DB: s.store, Clock: func() time.Time { return s.clock() }, Log: s.log.With("component", "queue"),
		BoundLegacyPause: boundLegacyPause}
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
	q.Register(jobs.RoleMining, queue.Kind{Handler: s.queueRoleMining, Actor: mining.Worker})
	q.Register(jobs.Maintenance, queue.Kind{Handler: s.queueMaintenance, Actor: "queue.worker"})
	q.Register(jobs.CertificateExpiry, queue.Kind{Handler: s.queueCertificateExpiry, Actor: "certificate.sweeper"})
	q.Register(jobs.ArchiveSweep, queue.Kind{Handler: s.queueArchive, Actor: archive.Actor})
	q.Register(jobs.OAuthSync, queue.Kind{Handler: s.queueOAuthSync, Actor: oauthSyncActor})
	q.Register(jobs.VmsSync, queue.Kind{Handler: s.queueVmsSync, Actor: vmsSyncActor})
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
	q.Schedule(jobs.CertificateExpiry, jobs.CertificateExpiry, certificateExpirySchedule, maxSweepAttempts)
	q.Schedule(jobs.ArchiveSweep, jobs.ArchiveSweep, "@every "+archiveEvery.String(), maxArchiveAttempts)
	q.Schedule(jobs.OAuthSync, jobs.OAuthSync, "@every "+oauthSyncEvery.String(), maxOAuthSyncAttempts)
	q.Schedule(jobs.VmsSync, jobs.VmsSync, "@every "+vmsSyncEvery.String(), maxVmsSyncAttempts)
	return q
}

// workerDeps are the handlers of the worker kinds, built on this server's
// parts (so an on-demand sync and a queued one run the same code).
func (s *Server) workerDeps() *worker.Deps {
	return &worker.Deps{DB: s.store, Clock: func() time.Time { return s.clock() }, Log: s.log.With("component", "worker"),
		Connectors: s.cfg.Connectors, Provision: s.prov, Guard: s.guard, SyncSchedule: s.cfg.ConnectorSyncSchedule}
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

// Guard is the per-target limits and circuit breakers of this process's calls
// to customers' systems (its state goes out with the worker heartbeat).
func (s *Server) Guard() *worker.Guard { return s.guard }

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
	ctx = audit.WithSystemActor(ctx, "admin.sweeper")
	if _, err := s.admin.SweepTenant(ctx, j.Tenant); err != nil {
		return nil, err
	}
	// held deletions that waited past their expiry are discarded (internal/deleteguard)
	now := s.clock()
	return nil, s.store.InTenant(ctx, j.Tenant, func(tx *store.TenantTx) error {
		_, err := deleteguard.ExpireDue(tx, now)
		return err
	})
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

// certificateExpirySchedule runs the certificate expiry check once a day (UTC).
const certificateExpirySchedule = "17 6 * * *"

// queueCertificateExpiry raises, through the alerts engine, an alert for each certificate that expires in 30 days
// or less (and again in the last 7), and resolves the alerts of certificates that were rotated or retired.
func (s *Server) queueCertificateExpiry(ctx context.Context, j queue.Job) (any, error) {
	now := s.clock().UTC()
	var raised, resolved int
	err := s.store.InTenant(audit.WithSystemActor(ctx, "certificate.sweeper"), j.Tenant, func(tx *store.TenantTx) error {
		var err error
		raised, resolved, err = alerts.RunScheduled(tx, now, "certificate_expiry")
		return err
	})
	if err != nil || raised+resolved == 0 {
		return nil, err
	}
	return map[string]int{"raised": raised, "resolved": resolved}, nil
}

func (s *Server) queueMaintenance(ctx context.Context, j queue.Job) (any, error) {
	now := s.clock()
	return nil, s.store.InTenant(ctx, j.Tenant, func(tx *store.TenantTx) error {
		if s.archive.Enabled() {
			// finished runs leave the online store through the archive (issue #298)
			if err := jobs.FailStaleTx(tx, now, jobStaleAfter); err != nil {
				return err
			}
		} else if err := jobs.MaintainTx(tx, now, jobStaleAfter, jobRetention); err != nil {
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
	s.handle(http.MethodPost, "/api/queue/schedules/{name}/pause", write, needStepUp(auth.PermJobsManage, auth.StepUpPolicy), s.pauseQueueSchedule)
	s.handle(http.MethodPost, "/api/queue/schedules/{name}/resume", write, needStepUp(auth.PermJobsManage, auth.StepUpPolicy), s.resumeQueueSchedule)
	s.registerConnectionLimitRoutes()
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

func viewQueueJob(c *store.TenantTx, j *store.QueueJob) queueJobView {
	var owner *string
	if j.LeaseOwner != nil { // the lease owner is host-pid-random: show the worker's label instead
		l := workerLabel(c.Tenant(), *j.LeaseOwner)
		owner = &l
	}
	return queueJobView{ID: j.ID, Kind: j.Kind, Status: j.Status, RunAt: j.RunAt.UTC().Format(time.RFC3339),
		Attempts: j.Attempts, MaxAttempts: j.MaxAttempts, LastError: j.LastError, LeaseOwner: owner,
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
	// Protected marks a security schedule: pausing it needs a reason and ends by itself (at most MaxProtectedPause).
	Protected   bool    `json:"protected"`
	PausedUntil *string `json:"paused_until"`
}

// MaxProtectedPause is the longest a protected schedule stays paused: it resumes by itself after that (issue #512).
const MaxProtectedPause = 24 * time.Hour

// protectedSchedules are the schedules that do security work in the background: containment retries for leavers,
// the lifecycle, SoD mitigation and admin change sweeps, drift, certificate expiry, SSF polling, contractor feeds, guest
// lifecycle, OAuth app sync, JIT and request expiry, and the connector syncs that feed
// everything else. One admin pausing one of them for good would blind the platform without a trace beyond the audit
// log, so a pause needs a reason, is capped at MaxProtectedPause and raises the schedule_paused alert.
var protectedSchedules = map[string]bool{jobs.ContainmentRetry: true, jobs.SweepLifecycle: true, jobs.SweepSoDMitigations: true,
	jobs.SweepAdminChanges: true, jobs.CertificateExpiry: true, jobs.SweepDrift: true,
	// issue #521: incoming Shared Signals events, contractor feeds (and their leavers), guest grace and retention, OAuth
	// app risk, and the sweeps that expire temporary access and requests
	jobs.SweepSSFPoll: true, jobs.VmsSync: true, jobs.GuestLifecycle: true, jobs.OAuthSync: true, jobs.JITSweep: true,
	jobs.SweepRequests:       true,
	worker.DeltaScheduleName: true, worker.FullScheduleName: true}

// boundLegacyPause says which protected schedules get an end when found paused with none (issue #522). The two connector
// sync schedules are left out: a tenant turns them off with sync-schedule (0), which has its own alert.
func boundLegacyPause(name string) bool {
	return protectedSchedules[name] && name != worker.DeltaScheduleName && name != worker.FullScheduleName
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
		out = append(out, viewQueueJob(store.TxFrom(r.Context()), j))
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
		out = append(out, viewQueueSchedule(v))
	}
	return out, nil
}

func viewQueueSchedule(v *store.QueueSchedule) queueScheduleView {
	return queueScheduleView{Name: v.Name, Kind: v.Kind, Spec: v.Spec, Enabled: v.Enabled, MaxAttempts: v.MaxAttempts,
		NextRunAt: v.NextRunAt.UTC().Format(time.RFC3339), LastEnqueuedAt: isoPtr(v.LastEnqueuedAt),
		Protected: protectedSchedules[v.Name], PausedUntil: isoPtr(v.PausedUntil)}
}

var queueScheduleNameRE = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)

type queueScheduleInput struct {
	// Reason is free text kept in the audit event; pausing a protected schedule requires it.
	Reason string `json:"reason"`
	// ResumeAfterHours is how long a protected schedule stays paused (1 to 24, default 24); it then resumes by itself.
	// Other schedules stay paused until resumed, and take no value here.
	ResumeAfterHours int `json:"resume_after_hours"`
}

const maxScheduleReason = 500

func (s *Server) pauseQueueSchedule(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.setQueueSchedule(r, p, false)
}

func (s *Server) resumeQueueSchedule(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.setQueueSchedule(r, p, true)
}

// setQueueSchedule pauses or resumes a recurring job and audits it
// (queue.schedule_paused, queue.schedule_resumed) in the same transaction.
// Pausing stops new runs only: a job already queued or running finishes. A
// resumed schedule fires once if it came due while paused, then keeps its
// cadence. Repeating the state it already has is a no-op that is not audited.
func (s *Server) setQueueSchedule(r *http.Request, p *params, enable bool) (any, error) {
	name := p.path["name"]
	if !queueScheduleNameRE.MatchString(name) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	}
	var in queueScheduleInput
	if err := decodeBody(r, &in, true); err != nil {
		return nil, err
	}
	if len(in.Reason) > maxScheduleReason {
		return nil, badRequest("invalid_reason", "reason must be at most 500 characters")
	}
	c := store.TxFrom(r.Context())
	cur, err := c.QueueSchedule(name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &httpError{http.StatusNotFound, "Not Found"}
	} else if err != nil {
		return nil, err
	}
	if cur.Enabled == enable {
		return viewQueueSchedule(cur), nil
	}
	now := s.clock()
	detail := ojson.Object{{Key: "schedule", Value: name}, {Key: "kind", Value: cur.Kind}, {Key: "reason", Value: in.Reason}}
	protected := protectedSchedules[name]
	switch {
	case enable:
		if in.ResumeAfterHours != 0 {
			return nil, badRequest("invalid_resume_after_hours", "resume_after_hours applies to a pause")
		}
		err = c.SetQueueScheduleEnabled(name, true, now)
	case protected:
		hours := in.ResumeAfterHours
		if hours == 0 {
			hours = int(MaxProtectedPause / time.Hour)
		}
		if strings.TrimSpace(in.Reason) == "" {
			return nil, badRequest("reason_required", "pausing "+name+" needs a reason: it is a security schedule")
		}
		if hours < 1 || hours > int(MaxProtectedPause/time.Hour) {
			return nil, badRequest("invalid_resume_after_hours", "a security schedule can be paused for 1 to 24 hours; it then resumes by itself")
		}
		until := now.Add(time.Duration(hours) * time.Hour)
		detail = append(detail, ojson.KV{Key: "protected", Value: true}, ojson.KV{Key: "paused_until", Value: until.UTC().Format(time.RFC3339)})
		err = c.PauseQueueScheduleUntil(name, until, now)
	default:
		if in.ResumeAfterHours != 0 {
			return nil, badRequest("invalid_resume_after_hours", name+" has no automatic resume: resume it yourself")
		}
		err = c.SetQueueScheduleEnabled(name, false, now)
	}
	if err != nil {
		return nil, err
	}
	action := "queue.schedule_paused"
	if enable {
		action = "queue.schedule_resumed"
	}
	if err := c.Audit(now, actor(r), action, detail); err != nil {
		return nil, err
	}
	cur, err = c.QueueSchedule(name)
	if err != nil {
		return nil, err
	}
	return viewQueueSchedule(cur), nil
}

type queueWorkerView struct {
	WorkerID        string   `json:"worker_id"` // an opaque label, stable for the tenant; never a host or PID
	Mode            string   `json:"mode"`
	Status          string   `json:"status"` // healthy | stale
	Kinds           []string `json:"kinds"`
	Concurrency     int      `json:"concurrency"`
	Running         int      `json:"running"`
	StartedAt       string   `json:"started_at"`
	LastHeartbeatAt string   `json:"last_heartbeat_at"`
	LagSeconds      int      `json:"lag_seconds"` // since the last heartbeat
	// Targets is the worker's view of the connections it called: the circuit
	// breaker state and the calls in flight (issue #302). Empty until it calls one.
	Targets []queueTargetView `json:"targets"`
}

// queueTargetView is one connection as one worker sees it.
type queueTargetView struct {
	ConnectionID        string  `json:"connection_id"`
	Connection          string  `json:"connection"`
	Breaker             string  `json:"breaker"` // closed | open | half_open
	ConsecutiveFailures int     `json:"consecutive_failures"`
	OpenUntil           *string `json:"open_until"`
	LastError           string  `json:"last_error"`
	InFlight            int     `json:"in_flight"`
	Calls               int64   `json:"calls"`
	Failures            int64   `json:"failures"`
	Rejected            int64   `json:"rejected"`
}

// workerLabel is the tenant-visible name of a worker: a stable opaque id for
// this tenant, derived from the worker's lease owner (host-pid-random), which
// never leaves the server (issue #403). The same label stands for the worker
// in a job's lease_owner.
func workerLabel(tenant tenancy.ID, workerID string) string {
	sum := sha256.Sum256([]byte(tenant.String() + "\x00" + workerID))
	return "worker-" + hex.EncodeToString(sum[:])[:10]
}

// listQueueWorkers shows the workers that serve the queue's kinds in use by
// the tenant and when each last beat: a worker whose last beat is older than
// worker.StaleAfter is stale (crashed or cut off; its jobs return when their
// leases expire). Workers are shared infrastructure, so a tenant sees only the
// workers that serve kinds it uses, only those kinds, and no host name, PID or
// build (there is no platform-level operator role to show them to; they are in
// the worker's own log).
func (s *Server) listQueueWorkers(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	c := store.TxFrom(r.Context())
	ws, err := c.QueueWorkers()
	if err != nil {
		return nil, err
	}
	used, err := c.QueueKindsInUse()
	if err != nil {
		return nil, err
	}
	states, err := c.WorkerTargetStates()
	if err != nil {
		return nil, err
	}
	names, err := connNames(c)
	if err != nil {
		return nil, err
	}
	targets := map[string][]queueTargetView{}
	for _, t := range states {
		targets[t.WorkerID] = append(targets[t.WorkerID], queueTargetView{ConnectionID: t.ConnectionID,
			Connection: names[t.ConnectionID].name, Breaker: t.State, ConsecutiveFailures: t.ConsecutiveFailures,
			OpenUntil: isoPtr(t.OpenUntil), LastError: t.LastError, InFlight: t.InFlight, Calls: t.Calls,
			Failures: t.Failures, Rejected: t.Rejected})
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
		for _, k := range strings.Split(w.Kinds, ",") {
			if slices.Contains(used, k) {
				kinds = append(kinds, k)
			}
		}
		if len(kinds) == 0 {
			continue // it serves none of this tenant's kinds
		}
		out = append(out, queueWorkerView{WorkerID: workerLabel(c.Tenant(), w.WorkerID), Mode: w.Mode, Status: st,
			Kinds: kinds, Concurrency: w.Concurrency, Running: w.Running,
			StartedAt: w.StartedAt.UTC().Format(time.RFC3339), LastHeartbeatAt: w.LastHeartbeatAt.UTC().Format(time.RFC3339),
			LagSeconds: lag, Targets: append([]queueTargetView{}, targets[w.WorkerID]...)})
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
	// The retrier causes the run: a sync's holds name them as a contributor, so they cannot release
	// them (#495).
	if pr := principal(r); j.Kind == jobs.ConnectorSync && pr.UserID != nil {
		var sp worker.SyncPayload
		if j.Payload != "" && json.Unmarshal([]byte(j.Payload), &sp) != nil {
			return nil, &readiness.Error{Status: http.StatusConflict, Code: "bad_payload", Msg: "the job's payload cannot be read"}
		}
		raw, err := json.Marshal(sp.WithRetrier(pr.UserID.String()))
		if err != nil {
			return nil, err
		}
		if err := c.SetDeadQueueJobPayload(id, string(raw), s.clock()); err != nil {
			return nil, err
		}
	}
	if err := s.queue.Retry(c, id, actor(r)); err != nil {
		return nil, err
	}
	j, err = c.QueueJob(id)
	if err != nil {
		return nil, err
	}
	return viewQueueJob(c, j), nil
}
