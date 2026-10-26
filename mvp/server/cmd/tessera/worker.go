package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/all"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
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
	metricsAddr string
	// the defaults of the per-target limits (a connection's own limits override them)
	targetConcurrency int
	targetRate        int
	breakerFailures   int
	breakerCooldown   time.Duration
}

const workerUsage = "usage: tessera worker [-db PATH|DSN] [-kinds connector_sync,provision_push] [-concurrency N] [-id NAME] [-metrics-addr HOST:PORT] [-target-concurrency N] [-target-rate PER_MIN]"

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
	fset.StringVar(&o.metricsAddr, "metrics-addr", "", "serve Prometheus /metrics on this host:port (default TESSERA_WORKER_METRICS_ADDR; off when empty); a loopback or private IP literal unless TESSERA_WORKER_METRICS_ALLOW_PUBLIC=true")
	fset.IntVar(&o.targetConcurrency, "target-concurrency", worker.DefaultLimits.MaxConcurrency, "calls in flight at once to one connection's system, per worker (0 = no limit; a connection's own limit overrides it)")
	fset.IntVar(&o.targetRate, "target-rate", 0, "calls per minute to one connection's system, per worker (0 = no limit)")
	fset.IntVar(&o.breakerFailures, "target-breaker-failures", worker.DefaultLimits.BreakerThreshold, "consecutive failed calls that open a target's circuit breaker (0 = no breaker)")
	fset.DurationVar(&o.breakerCooldown, "target-breaker-cooldown", worker.DefaultLimits.BreakerCooldown, "how long an open circuit breaker refuses calls before one probe is let through")
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
	case o.targetConcurrency < 0 || o.targetConcurrency > 64 || o.targetRate < 0 || o.targetRate > 60000 ||
		o.breakerFailures < 0 || o.breakerFailures > 100 || o.breakerCooldown < time.Second || o.breakerCooldown > time.Hour:
		return errors.New("-target-concurrency must be 0 to 64, -target-rate 0 to 60000, -target-breaker-failures 0 to 100 and -target-breaker-cooldown 1s to 1h")
	}
	if os.Getenv("TESSERA_ENV") == "" {
		return errors.New("set TESSERA_ENV=dev (run.sh does), TESSERA_ENV=test or TESSERA_ENV=prod")
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load(envWithDB(o.db))
	if err != nil {
		return err
	}
	if o.metricsAddr == "" {
		o.metricsAddr = cfg.WorkerMetricsAddr
	} else if o.metricsAddr, err = config.CheckWorkerMetricsAddr(o.metricsAddr, cfg.WorkerMetricsAllowPublic); err != nil {
		return fmt.Errorf("-metrics-addr: %w", err)
	}
	clock := cfg.Clock()
	sealer, err := loadSealer(ctx, cfg, config.DevKEKPath(o.db))
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
	// Governed connections (Settings, Connections): the worker opens their connectors with
	// the same readiness service the API validates them with.
	templates, err := template.Default()
	if err != nil {
		return err
	}
	rsvc := readiness.NewService(templates, cfg.Env)
	awsHTTP, err := awsorg.NewHTTPClient(cfg) // the AWS write target's calls: safehttp, limits sized for IAM
	if err != nil {
		return err
	}
	rsvc.Runner.Live.Sealer = sealer
	rsvc.Runner.Gov = wire.Options(outbound, connsync.RuntimeFromConfig(cfg), cfg.LoaderDataDir, cfg.Env == config.Prod)
	guard := &worker.Guard{DB: st, Clock: clock, Defaults: &worker.Limits{MaxConcurrency: o.targetConcurrency,
		RatePerMin: o.targetRate, BreakerThreshold: o.breakerFailures, BreakerCooldown: o.breakerCooldown}}
	dialAllow, err := safedial.ParseAllow(cfg.SafedialAllow)
	if err != nil {
		return fmt.Errorf("TESSERA_SAFEDIAL_ALLOW: %w", err)
	}
	deps := &worker.Deps{DB: st, Clock: clock, Log: logger.With("component", "worker"), SyncSchedule: cfg.ConnectorSyncSchedule, Guard: guard,
		Governed: func(ctx context.Context, t tenancy.ID, now time.Time) ([]connectors.Connector, map[string]error, error) {
			return rsvc.GovernedConnectors(ctx, st, t, now)
		},
		Connectors: func(now time.Time) ([]connectors.Connector, error) { return connectors.Load("", now) },
		Provision: &provision.Engine{DB: st, Sealer: sealer, HTTP: outbound, Clock: clock, Guard: guard, Runtime: connsync.RuntimeFromConfig(cfg), DialAllow: dialAllow,
			Log: logger.With("component", "provisioning")}}
	awsFed := &awsorg.Federation{DB: st, Sealer: sealer, PublicURL: cfg.PublicURL, Clock: clock}
	deps.Provision.BuildAWS = func(ctx context.Context, t tenancy.ID, connectorID, writerRole string) (target.Connector, error) {
		return awsFed.OpenWriteTarget(ctx, t, connectorID, writerRole, awsHTTP, clock)
	}
	q := &queue.Queue{DB: st, Clock: clock, Owner: o.id, Concurrency: o.concurrency, Poll: o.poll, Lease: o.lease,
		ShutdownGrace: o.grace, Log: logger.With("component", "queue")}
	metrics := worker.NewMetrics(q, guard)
	if err := deps.Register(q, kinds, metrics.Wrap); err != nil {
		return err
	}
	beater := &worker.Beater{DB: st, Queue: q, Mode: store.WorkerModeWorker, Version: agent.Version, Clock: clock, Log: logger, Guard: guard}
	if o.metricsAddr != "" {
		ms, err := newWorkerMetricsServer(o.metricsAddr, metrics.Handler(), logger)
		if err != nil {
			return err
		}
		go ms.serve(logger)
		defer ms.close()
	}
	logger.Info("tessera worker started", "id", q.WorkerID(), "kinds", kinds, "concurrency", o.concurrency)
	worker.Serve(ctx, q, beater)
	logger.Info("tessera worker stopped", "id", q.WorkerID())
	return nil
}

// workerMetricsServer is the worker's /metrics listener (-metrics-addr). It
// serves /metrics and nothing else; the address was checked by
// config.CheckWorkerMetricsAddr.
type workerMetricsServer struct {
	srv *http.Server
	ln  net.Listener
}

func newWorkerMetricsServer(addr string, h http.Handler, logger *slog.Logger) (*workerMetricsServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("worker metrics listener: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", h)
	return &workerMetricsServer{ln: ln, srv: &http.Server{Handler: mux, ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout: readTimeout, WriteTimeout: 30 * time.Second, IdleTimeout: idleTimeout, MaxHeaderBytes: 16 << 10,
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn)}}, nil
}

func (m *workerMetricsServer) serve(logger *slog.Logger) {
	logger.Info("tessera worker metrics listening", "addr", m.ln.Addr().String())
	if err := m.srv.Serve(m.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("worker metrics listener stopped", "err", err)
	}
}

func (m *workerMetricsServer) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = m.srv.Shutdown(ctx)
}
