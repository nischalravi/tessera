package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// readinessInterval is how often the scheduler looks for connections whose
// live checks or reconciliation are due (the due intervals are days).
const readinessInterval = 15 * time.Minute

// newReadinessService builds the deployment-readiness service the API and the
// scheduler share. TESSERA_READINESS_LIVE_CHECK_DAYS (1 to 7, default 1) sets
// how often live checks re-run on active connections (design §7.4).
func newReadinessService(env, scenario string) (*readiness.Service, error) {
	reg, err := template.Default()
	if err != nil {
		return nil, err
	}
	svc := readiness.NewService(reg, env)
	svc.Runner.Scenario = scenario
	if v := os.Getenv("TESSERA_READINESS_LIVE_CHECK_DAYS"); v != "" {
		days, err := strconv.Atoi(v)
		if err != nil || days < 1 || days > 7 {
			return nil, fmt.Errorf("TESSERA_READINESS_LIVE_CHECK_DAYS: %q is not a number of days from 1 to 7", v)
		}
		svc.Runner.LiveEvery = time.Duration(days) * 24 * time.Hour
	}
	return svc, nil
}

// runReadinessScheduler re-runs the live checks and reconciliation of every
// live connection in every tenant, evaluates drift and degrades or recovers
// connections (design §7.4, §7.5), until ctx ends. TESSERA_READINESS_SCHEDULER=off
// disables it. Admin → Jobs (#172) records the job once its job_runs wrapper
// can be set as Scheduler.Hook.
func runReadinessScheduler(ctx context.Context, svc *readiness.Service, st *store.DB, clock timeutil.Clock, logger *slog.Logger) {
	if os.Getenv("TESSERA_READINESS_SCHEDULER") == "off" {
		return
	}
	sc := &readiness.Scheduler{Svc: svc, DB: st, Clock: clock, Stage: func(c *store.TenantTx, runID, system string, res *connectors.DiscoveryResult) error {
		_, err := ingest.Stage(c, runID, system, res)
		return err
	}}
	sc.Loop(audit.WithSystemActor(ctx, readiness.SchedulerActor), readinessInterval, func(err error) {
		logger.Error("readiness scheduled re-run failed", "err", err)
	})
}
