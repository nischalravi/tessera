// Package worker is the connector worker pool (issue #302): the queue kinds
// that call out to customer systems (connector syncs, provisioning pushes),
// written so that `tessera worker` can run them without an HTTP API and so
// that `tessera serve` can stop running them in-process.
//
// The engine is internal/queue, unchanged: leases, heartbeats, backoff, dead
// letters and schedules are the same whether a kind runs in the API process or
// in a worker, and any number of either can share one database. This package
// holds what is specific to the pool: the kind registry (Kinds, ParseKinds),
// the handlers (Deps.Register), the sync routine the API's on-demand sync
// shares (RunSync), the fan-out to remote agents (QueueAgentSyncs,
// RecordAgentSync) and the worker's health beat (Beater).
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Kinds are the queue kinds a worker (or an API process) can run. The set is
// closed: `--kinds` and TESSERA_EXTERNAL_WORKER_KINDS accept nothing else.
var Kinds = []string{jobs.ConnectorSync, jobs.ProvisionPush}

// ParseKinds parses a comma-separated kind list: each must be one of Kinds,
// repeats are dropped, the result is sorted. An empty list is empty (not an
// error): callers decide what that means.
func ParseKinds(list string) ([]string, error) {
	var out []string
	for _, k := range strings.Split(list, ",") {
		k = strings.TrimSpace(k)
		switch {
		case k == "":
		case !slices.Contains(Kinds, k):
			return nil, fmt.Errorf("unknown job kind %q (want %s)", k, strings.Join(Kinds, ", "))
		case !slices.Contains(out, k):
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out, nil
}

// ProvisionEvery is how often each tenant's provisioning push is scheduled
// (the interval the in-process loop always had).
const ProvisionEvery = 5 * time.Second

// maxAttempts of the pool's scheduled jobs: a failing pass is retried a couple
// of times, and the next window runs anyway.
const maxAttempts = 3

// SyncPayload is the payload of a connector_sync job.
type SyncPayload struct {
	// Mode is "incremental" (default) or "full" (ignore checkpoints).
	Mode string `json:"mode,omitempty"`
	// RequestedBy is the platform user who queued the sync ("" for a schedule). The holds of the run
	// record them as a contributor, so they cannot release them (#487).
	RequestedBy string `json:"requested_by,omitempty"`
	// RetriedBy are the platform users who put the dead job back in the queue (#495): the retrier
	// causes the run, so the holds record them as contributors too. A schedule's run has no
	// RequestedBy, so the retrier is its only named actor.
	RetriedBy []string `json:"retried_by,omitempty"`
}

// WithRetrier returns the payload with user added as a retrier (once).
func (p SyncPayload) WithRetrier(user string) SyncPayload {
	if user == "" || user == p.RequestedBy || slices.Contains(p.RetriedBy, user) {
		return p
	}
	p.RetriedBy = append(slices.Clone(p.RetriedBy), user)
	return p
}

// Deps is what the handlers need.
type Deps struct {
	DB    *store.DB
	Clock func() time.Time
	Log   *slog.Logger
	// Connectors returns the configured connectors (the API's cfg.Connectors).
	Connectors func(now time.Time) ([]connectors.Connector, error)
	// Governed opens the connectors of a tenant's live governed connections
	// (readiness.Service.GovernedConnectors): they sync with the configured ones.
	// The map names the connections whose connector could not be opened. Nil:
	// only the configured connectors sync.
	Governed func(ctx context.Context, t tenancy.ID, now time.Time) ([]connectors.Connector, map[string]error, error)
	// Provision sends a tenant's due provisioning operations.
	Provision *provision.Engine
	// Guard enforces per-target limits and circuit breakers on every call to a
	// customer's system (nil: no limits). Set the same Guard on Provision.
	Guard *Guard
	// SyncSchedule, when set, is a queue spec ("@every 15m" or cron) that
	// schedules connector_sync for every tenant. Empty: syncs run on demand.
	SyncSchedule string
}

// Wrap decorates a handler (the API tracks the loop lag of its kinds).
type Wrap func(kind string, h queue.Handler) queue.Handler

// Register adds the handlers of kinds (a subset of Kinds) and their
// schedules to q. wrap may be nil.
func (d *Deps) Register(q *queue.Queue, kinds []string, wrap Wrap) error {
	if wrap == nil {
		wrap = func(_ string, h queue.Handler) queue.Handler { return h }
	}
	for _, k := range kinds {
		switch k {
		case jobs.ConnectorSync:
			if d.Connectors == nil {
				return errors.New("worker: connector_sync needs the connector list")
			}
			q.Register(k, queue.Kind{Handler: wrap(k, d.connectorSync), Actor: "connector.worker",
				Method: "POST", Route: "/api/connectors/sync"})
			if d.SyncSchedule != "" {
				if _, err := queue.ParseSpec(d.SyncSchedule); err != nil {
					return err
				}
				q.Schedule(k, k, d.SyncSchedule, maxAttempts)
			}
		case jobs.ProvisionPush:
			if d.Provision == nil {
				return errors.New("worker: provision_push needs the provisioning engine")
			}
			q.Register(k, queue.Kind{Handler: wrap(k, d.provisionPush), Actor: provision.WorkerActor})
			q.Schedule(k, k, "@every "+ProvisionEvery.String(), maxAttempts)
		default:
			return fmt.Errorf("worker: unknown kind %q", k)
		}
	}
	return nil
}

func (d *Deps) now() time.Time {
	if d.Clock != nil {
		return d.Clock()
	}
	return time.Now().UTC()
}

func (d *Deps) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

// provisionPush is one tenant's pass of the provisioning engine: the work the
// in-process loop did every few seconds. Like that loop it records a run only
// when it found work or broke, and a failed operation is the operation's own
// outcome (shown in the provisioning view), not a failed job. A shutdown
// returns the context's error so the queue hands the job back unrun.
func (d *Deps) provisionPush(ctx context.Context, j queue.Job) (any, error) {
	started := d.now()
	stats, err := d.Provision.RunTenant(ctx, j.Tenant)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if stats.Processed == 0 && err == nil {
		return nil, nil
	}
	if err != nil {
		d.log().Error("provisioning pass failed", "tenant", j.Tenant.String(), "err", err)
	}
	rec := jobs.Start{Kind: jobs.Provision, Trigger: "schedule", Actor: provision.WorkerActor}
	if rerr := jobs.Record(context.WithoutCancel(ctx), d.DB, j.Tenant, rec, started, d.now(), stats, err); rerr != nil {
		d.log().Error("provisioning: record run", "tenant", j.Tenant.String(), "err", rerr)
	}
	return nil, nil
}

// connectorSync reads the configured connectors into the tenant, then queues
// a sync for each connection that reaches its directory through a remote
// agent (the agent pulls it; see QueueAgentSyncs).
func (d *Deps) connectorSync(ctx context.Context, j queue.Job) (any, error) {
	var p SyncPayload
	if j.Payload != "" {
		if err := json.Unmarshal([]byte(j.Payload), &p); err != nil || (p.Mode != "" && p.Mode != "incremental" && p.Mode != "full") {
			return nil, queue.Permanent(errors.New("connector_sync: bad payload"))
		}
	}
	if p.RequestedBy != "" {
		if _, err := uuid.Parse(p.RequestedBy); err != nil {
			return nil, queue.Permanent(errors.New("connector_sync: bad payload"))
		}
	}
	for _, id := range p.RetriedBy {
		if _, err := uuid.Parse(id); err != nil {
			return nil, queue.Permanent(errors.New("connector_sync: bad payload"))
		}
	}
	ctx = deleteguard.WithRequester(ctx, append([]string{p.RequestedBy}, p.RetriedBy...)...)
	now := d.now()
	conns, err := d.Connectors(now)
	if err != nil {
		return nil, err
	}
	var failed map[string]error
	if d.Governed != nil {
		gov, f, err := d.Governed(ctx, j.Tenant, now)
		if err != nil {
			return nil, err
		}
		conns, failed = MergeGoverned(conns, gov), f
	}
	out, err := d.syncTenant(ctx, j.Tenant, now, conns, p.Mode == "full", "connector.worker", j.ID)
	if err != nil {
		return nil, err
	}
	if len(failed) > 0 {
		names := make([]string, 0, len(failed))
		for n, e := range failed {
			names = append(names, n)
			d.log().Warn("governed connection not synced", "tenant", j.Tenant.String(), "connection", n, "err", e)
		}
		sort.Strings(names)
		out = append(out, ojson.KV{Key: "governed_not_opened", Value: names})
	}
	return out, nil
}
