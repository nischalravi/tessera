package readiness

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// JobRerun names the scheduled re-run job in Admin → Jobs (§7.4).
const JobRerun = "readiness.rerun"

// dueEarly is how much before an interval ends a re-run is due, so live
// evidence (24 h TTL) is renewed before it goes stale instead of just after.
const dueEarly = time.Hour

// JobHook records the scheduled job in Admin → Jobs. Begin is called when a
// pass starts and returns the function that records how it ended. It is an
// interface so the job_runs wrapper can be wired in without this package
// knowing about it; a nil hook records nothing.
type JobHook interface {
	Begin(ctx context.Context, job string, now time.Time) (end func(summary string, err error))
}

// Scheduler re-runs the live checks of every live connection daily (1 to 7
// days, Runner.LiveEvery) and reconciles it weekly (Runner.ReconEvery) in
// live mode, then evaluates drift and Degraded state (§7.4, §7.5). The
// reconciliation writes the staging scratch tables and findings only, like a
// dry run; it never writes the live graph.
type Scheduler struct {
	Svc   *Service
	DB    *store.DB
	Clock func() time.Time
	// Stage writes a discovery result into the staging tables (ingest.Stage).
	// Without it live reconciliation is skipped.
	Stage StageFunc
	Hook  JobHook
}

// PassSummary counts what one pass did.
type PassSummary struct {
	Connections int // live connections seen
	Validated   int
	Reconciled  int
	Skipped     int // runs refused for an expected reason (running, rate limited, connector unavailable, ...)
	Degraded    int
	Recovered   int
}

func (p *PassSummary) add(o PassSummary) {
	p.Connections += o.Connections
	p.Validated += o.Validated
	p.Reconciled += o.Reconciled
	p.Skipped += o.Skipped
	p.Degraded += o.Degraded
	p.Recovered += o.Recovered
}

func (p PassSummary) String() string {
	return fmt.Sprintf("%d live connections: %d validated, %d reconciled, %d skipped, %d degraded, %d recovered",
		p.Connections, p.Validated, p.Reconciled, p.Skipped, p.Degraded, p.Recovered)
}

// ReconcileLive reconciles a connection's live revision: the post-activation
// reconciliation of §7.4, recorded as a 'live' reconciliation run.
func (s *Service) ReconcileLive(ctx context.Context, st Scope, connID, actor string, clock func() time.Time, stage StageFunc) (*DryRunView, error) {
	return s.dryRun(ctx, st, connID, actor, clock, stage, true)
}

func due(run *store.CheckRun, every time.Duration, now time.Time) bool {
	return run == nil || run.FinishedAt == nil || now.Sub(*run.FinishedAt) >= every-dueEarly
}

// RunOnce runs one pass over every active tenant. An error in one tenant
// does not stop the others; all errors are returned joined.
func (sc *Scheduler) RunOnce(ctx context.Context) (PassSummary, error) {
	var sum PassSummary
	end := func(string, error) {}
	if sc.Hook != nil {
		end = sc.Hook.Begin(ctx, JobRerun, sc.Clock())
	}
	tenants, err := sc.DB.ActiveTenants(ctx)
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	for _, t := range tenants {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		ts, err := sc.RunTenant(ctx, Scope{DB: sc.DB, Tenant: t.ID})
		sum.add(ts)
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Slug, err))
		}
	}
	err = errors.Join(errs...)
	end(sum.String(), err)
	return sum, err
}

// RunTenant runs one pass for one tenant.
func (sc *Scheduler) RunTenant(ctx context.Context, st Scope) (PassSummary, error) {
	var sum PassSummary
	opts := sc.Svc.Runner.withDefaults()
	type job struct {
		id          string
		live, recon bool
	}
	var jobs []job
	now := sc.Clock()
	if err := st.Read(ctx, func(c *store.TenantTx) error {
		conns, err := c.Connections()
		if err != nil {
			return err
		}
		for _, conn := range conns {
			if conn.RetiredAt != nil || conn.ActiveRevisionID == nil {
				continue
			}
			rev, err := c.Revision(*conn.ActiveRevisionID)
			if err != nil {
				return err
			}
			if !IsLive(rev.State) {
				continue
			}
			live, err := c.LatestLiveRun(rev.ID)
			if err != nil {
				return err
			}
			data, err := c.LatestDryRun(rev.ID)
			if err != nil {
				return err
			}
			jobs = append(jobs, job{conn.ID, due(live, opts.LiveEvery, now), sc.Stage != nil && due(data, opts.ReconEvery, now)})
		}
		return nil
	}); err != nil {
		return sum, err
	}
	var errs []error
	// ran counts a run, or notes that it was refused for an expected reason.
	ran := func(err error, n *int) {
		var re *Error
		switch {
		case err == nil:
			*n++
		case errors.As(err, &re):
			sum.Skipped++
		default:
			errs = append(errs, err)
		}
	}
	for _, j := range jobs {
		sum.Connections++
		if j.live {
			_, err := sc.Svc.Validate(ctx, st, j.id, SchedulerActor, sc.Clock)
			ran(err, &sum.Validated)
		}
		if j.recon {
			_, err := sc.Svc.ReconcileLive(ctx, st, j.id, SchedulerActor, sc.Clock, sc.Stage)
			ran(err, &sum.Reconciled)
		}
		err := st.Write(ctx, func(c *store.TenantTx) error {
			res, err := sc.Svc.Monitor(c, j.id, ExternalSignals{}, sc.Clock())
			if err != nil || res == nil {
				return err
			}
			if res.Degraded {
				sum.Degraded++
			}
			if res.Recovered {
				sum.Recovered++
			}
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return sum, errors.Join(errs...)
}

// Loop runs a pass now and then every interval until ctx ends. A failed pass
// is reported to onErr and the loop carries on.
func (sc *Scheduler) Loop(ctx context.Context, interval time.Duration, onErr func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := sc.RunOnce(ctx); err != nil && ctx.Err() == nil && onErr != nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
