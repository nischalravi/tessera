package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/all"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

// workerOptions are the flags of `tessera worker`.
type workerOptions struct {
	db          string
	kinds       string
	id          string
	concurrency int
	poll        time.Duration
	lease       time.Duration
	grace       time.Duration
}

const workerUsage = "usage: tessera worker [-db PATH|DSN] [-kinds connector_sync,provision_push] [-concurrency N] [-id NAME]"

// workerCmd is `tessera worker` (issue #302): the queue workers of the chosen
// kinds and nothing else. No HTTP API, no listener, no sweepers. It shares the
// database, the key and the lease/heartbeat/dead-letter semantics of the API
// process (internal/queue), so any number of workers and API processes can
// run at once; a worker that dies leaves leases that expire and another
// worker retries the jobs. SIGINT/SIGTERM stops claiming, lets running jobs
// finish for -shutdown-grace, then cancels the rest and releases their leases.
func workerCmd(ctx context.Context, args []string, stderr io.Writer) error {
	var o workerOptions
	fset := flag.NewFlagSet("tessera worker", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.StringVar(&o.db, "db", dbPath(os.Getenv("TESSERA_DB")), "SQLite database path or postgres:// DSN (the API's)")
	fset.StringVar(&o.kinds, "kinds", strings.Join(worker.Kinds, ","), "comma-separated job kinds to run: "+strings.Join(worker.Kinds, ", "))
	fset.StringVar(&o.id, "id", "", "worker name in leases and Admin -> Jobs (default host-pid-random)")
	fset.IntVar(&o.concurrency, "concurrency", 4, "jobs run at once (1 to 64)")
	fset.DurationVar(&o.poll, "poll", 2*time.Second, "how often the queue is polled")
	fset.DurationVar(&o.lease, "lease", 60*time.Second, "lease of a claimed job; a heartbeat renews it every third of this")
	fset.DurationVar(&o.grace, "shutdown-grace", 30*time.Second, "how long running jobs may finish after SIGTERM before they are cancelled and released")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() != 0 {
		return errors.New(workerUsage)
	}
	kinds, err := worker.ParseKinds(o.kinds)
	if err != nil {
		return fmt.Errorf("-kinds: %w", err)
	}
	switch {
	case len(kinds) == 0:
		return errors.New("-kinds: name at least one job kind")
	case o.concurrency < 1 || o.concurrency > 64:
		return errors.New("-concurrency must be 1 to 64")
	case o.poll < 100*time.Millisecond || o.lease < 5*time.Second || o.grace < 0:
		return errors.New("-poll must be at least 100ms, -lease at least 5s and -shutdown-grace not negative")
	}
	if os.Getenv("TESSERA_ENV") == "" {
		return errors.New("set TESSERA_ENV=dev (run.sh does), TESSERA_ENV=test or TESSERA_ENV=prod")
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	clock := cfg.Clock()
	sealer, err := cfg.Sealer(config.DevKEKPath(o.db))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, err := store.OpenApp(ctx, o.db, store.AppOptions{DSN: cfg.DBApp, AllowPrivileged: cfg.DBAllowPrivilegedApp})
	if err != nil {
		return err
	}
	defer st.Close()
	// Every outbound call of a worker goes through the same SSRF guard as the
	// API's, and the connectors share that client.
	outbound, err := safehttp.ForConfig(cfg)
	if err != nil {
		return err
	}
	all.Register(outbound, connsync.RuntimeFromConfig(cfg))
	deps := &worker.Deps{DB: st, Clock: clock, Log: logger.With("component", "worker"), SyncSchedule: cfg.ConnectorSyncSchedule,
		Connectors: func(now time.Time) ([]connectors.Connector, error) { return connectors.Load("", now) },
		Provision: &provision.Engine{DB: st, Sealer: sealer, HTTP: outbound, Clock: clock,
			Log: logger.With("component", "provisioning")}}
	q := &queue.Queue{DB: st, Clock: clock, Owner: o.id, Concurrency: o.concurrency, Poll: o.poll, Lease: o.lease,
		ShutdownGrace: o.grace, Log: logger.With("component", "queue")}
	if err := deps.Register(q, kinds, nil); err != nil {
		return err
	}
	beater := &worker.Beater{DB: st, Queue: q, Mode: store.WorkerModeWorker, Version: agent.Version, Clock: clock, Log: logger}
	logger.Info("tessera worker started", "id", q.WorkerID(), "kinds", kinds, "concurrency", o.concurrency)
	worker.Serve(ctx, q, beater)
	logger.Info("tessera worker stopped", "id", q.WorkerID())
	return nil
}
