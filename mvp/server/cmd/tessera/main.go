// Command tessera runs the Tessera API server and seeds its database.
//
//	tessera [serve] [-addr 127.0.0.1:8000] [-db tessera.db] [-reseed]
//	tessera seed    [-db tessera.db]
//	tessera readiness lint [-dir path]   lint the readiness checklist templates
//
// Environment:
//
//	TESSERA_DB            database path (or sqlite:///path); default ./tessera.db
//	TESSERA_POLICY_DIR    read policies from this directory instead of the built-in copies
//	TESSERA_CONNECTORS    connector spec, e.g. "demo" (default) or "demo-workday,okta"
//	TESSERA_CORS_ORIGINS  comma-separated browser origins allowed by CORS
//	                      (default: the dev UI on localhost/127.0.0.1, port UI_PORT or 5173;
//	                      must be empty in prod)
//	TESSERA_KEK / TESSERA_KEK_FILE  the key-encryption key (base64 of 32 bytes) that seals
//	                      private keys; in dev it is generated at var/dev-kek next to the database
//	(internal/config lists every setting and the production guard rails that
//	refuse to start with unsafe ones)
//	TESSERA_NOW           freeze the clock at an ISO-8601 time (tests and demos; refused in prod)
//	TESSERA_ENV           must be "dev" (run.sh sets it). Until authentication lands,
//	                      the API serves one default tenant and refuses to start
//	                      otherwise, so an unset variable fails closed.
//	TESSERA_DEV_DEFAULT_TENANT  slug of that tenant (default larkspur)
//	TESSERA_READINESS_SCENARIO  simulated validation scenario for demo connectors: gaps (default) or happy
//	TESSERA_READINESS_DEMO      "off" skips seeding the demo Okta connection (larkspur only) for Deployment health
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/api"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tessera:", err)
		os.Exit(1)
	}
}

type options struct {
	addr   string
	db     string
	reseed bool
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	if cmd == "readiness" {
		return readinessCmd(args, stdout, stderr)
	}
	fset := flag.NewFlagSet("tessera "+cmd, flag.ContinueOnError)
	fset.SetOutput(stderr)
	var o options
	fset.StringVar(&o.db, "db", dbPath(os.Getenv("TESSERA_DB")), "SQLite database path")
	if cmd == "serve" {
		fset.StringVar(&o.addr, "addr", "127.0.0.1:8000", "listen address")
		fset.BoolVar(&o.reseed, "reseed", false, "wipe and re-seed the database before serving")
	}
	if err := fset.Parse(args); err != nil {
		return err
	}
	if cmd != "seed" && cmd != "serve" {
		return fmt.Errorf("unknown command %q (want serve, seed or readiness)", cmd)
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	// Typed configuration and the production guard rails come first: an
	// unsafe production setting refuses to start before anything else runs.
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	clock := cfg.Clock() // TESSERA_NOW, which config refuses in prod
	sealer, err := cfg.Sealer(config.DevKEKPath(o.db))
	if err != nil {
		return err
	}
	loader := policy.NewLoader(policyFS())
	if cmd == "seed" {
		return seedDB(ctx, o.db, clock, loader, sealer, stdout)
	}
	if _, err := os.Stat(o.db); o.reseed || errors.Is(err, fs.ErrNotExist) {
		if err := seedDB(ctx, o.db, clock, loader, sealer, stdout); err != nil {
			return err
		}
	}
	return serve(ctx, o, cfg, sealer, clock, loader, logger)
}

// dbPath accepts a plain path or the Python backend's sqlite:/// URL form.
func dbPath(v string) string {
	if v == "" {
		return "tessera.db"
	}
	return strings.TrimPrefix(v, "sqlite:///")
}

func policyFS() fs.FS {
	if dir := os.Getenv("TESSERA_POLICY_DIR"); dir != "" {
		return os.DirFS(dir)
	}
	return policies.FS
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func seedDB(ctx context.Context, path string, clock timeutil.Clock, loader *policy.Loader, sealer *seal.Sealer,
	stdout io.Writer) error {
	start := time.Now()
	st, err := store.Open(ctx, path)
	if err != nil {
		return err
	}
	defer st.Close()
	pols, err := loader.Load()
	if err != nil {
		return err
	}
	now := clock()
	conns, err := connectors.Load("", now)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "==> seeding demo tenants: larkspur (fictional company: Larkspur Labs) and globex")
	stats, err := seed.Run(ctx, st, now, pols, seed.DefaultTenants(conns, now))
	if err != nil {
		return err
	}
	for _, ts := range stats {
		discovery, err := ojson.Marshal(ts.Sync.Discovery.Object())
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Seeded Tessera tenant %s: %s usage=%d hris=%d jit=%d\n", ts.Tenant.Slug,
			discovery, ts.Sync.Events.Usage, ts.Sync.Events.Hris, ts.Requests)
	}
	if os.Getenv("TESSERA_READINESS_DEMO") != "off" {
		// The readiness demo is seeded for larkspur only: its Okta (demo)
		// connection matches larkspur's demo connectors; globex is the
		// sentinel tenant and starts with no connections.
		if err := seedReadinessDemo(ctx, st, seed.LarkspurID, clock); err != nil {
			return fmt.Errorf("readiness demo: %w", err)
		}
		fmt.Fprintf(stdout, "Seeded the deployment-readiness demo for tenant %s: Okta (demo) connection validated and dry-run reconciled\n",
			seed.LarkspurSlug)
	}
	if err := keys.EnsureAll(ctx, st, sealer, clock()); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Created the platform and per-tenant signing keys (private keys sealed under the KEK)")
	fmt.Fprintf(stdout, "Seeded Tessera in %.1fs\n", time.Since(start).Seconds())
	return nil
}

// Server timeouts. WriteTimeout exceeds the handler timeout so a timed-out
// handler can still deliver its 503.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = api.DefaultHandlerTimeout + 15*time.Second
	idleTimeout       = 60 * time.Second
	shutdownTimeout   = 10 * time.Second
	sweepInterval     = 30 * time.Second
	keysInterval      = 24 * time.Hour // keys.EnsureAll: rotation runs daily (design §10.6)
)

func serve(ctx context.Context, o options, cfg *config.Config, sealer *seal.Sealer, clock timeutil.Clock,
	loader *policy.Loader, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, err := store.Open(ctx, o.db)
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := loader.Load(); err != nil { // fail fast on broken policy files
		return err
	}
	tenant, err := st.DevDefaultTenant(ctx, os.Getenv("TESSERA_ENV"), envOr("TESSERA_DEV_DEFAULT_TENANT", seed.LarkspurSlug))
	if err != nil {
		return fmt.Errorf("no tenant to serve (authentication arrives in a later release): %w", err)
	}
	// ensure_keys: the platform key and every tenant's signing keys exist and
	// are rotated, and the KEK opens them (fail closed on a wrong KEK).
	if err := keys.EnsureAll(ctx, st, sealer, clock()); err != nil {
		return err
	}
	scenario := os.Getenv("TESSERA_READINESS_SCENARIO")
	if scenario != "" && !slices.Contains(connectors.ScenarioNames(), scenario) {
		return fmt.Errorf("TESSERA_READINESS_SCENARIO: unknown scenario %q (have %v)", scenario, connectors.ScenarioNames())
	}
	srv := api.New(api.Config{Store: st, Tenant: tenant, Clock: clock, Policies: loader, Logger: logger,
		AllowedOrigins: cfg.CORSOrigins, Env: os.Getenv("TESSERA_ENV"), ReadinessScenario: scenario})
	httpSrv := &http.Server{
		Addr:              o.addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		return err
	}
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		srv.RunSweeper(ctx, sweepInterval)
	}()
	keysDone := make(chan struct{})
	go func() {
		defer close(keysDone)
		runKeyRotation(ctx, st, sealer, clock, logger)
	}()
	errc := make(chan error, 1)
	go func() { errc <- httpSrv.Serve(ln) }()
	logger.Info("tessera API listening", "addr", ln.Addr().String())

	select {
	case err := <-errc:
		stop()
		<-sweepDone
		<-keysDone
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err = httpSrv.Shutdown(shutdownCtx)
	<-sweepDone
	<-keysDone
	if serveErr := <-errc; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return err
}

// runKeyRotation runs keys.EnsureAll every keysInterval until ctx ends.
func runKeyRotation(ctx context.Context, st *store.DB, sealer *seal.Sealer, clock timeutil.Clock, logger *slog.Logger) {
	t := time.NewTicker(keysInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := keys.EnsureAll(ctx, st, sealer, clock()); err != nil && ctx.Err() == nil {
				logger.Error("signing key rotation failed", "err", err)
			}
		}
	}
}
