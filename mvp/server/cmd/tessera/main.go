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
//	                      (default: the dev UI on localhost/127.0.0.1, port UI_PORT or 5173)
//	TESSERA_NOW           freeze the clock at an ISO-8601 time (tests and demos)
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
	"strings"
	"syscall"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/api"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
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
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	clock, err := clockFromEnv()
	if err != nil {
		return err
	}
	loader := policy.NewLoader(policyFS())
	switch cmd {
	case "seed":
		return seedDB(ctx, o.db, clock, loader, stdout)
	case "serve":
		if _, err := os.Stat(o.db); o.reseed || errors.Is(err, fs.ErrNotExist) {
			if err := seedDB(ctx, o.db, clock, loader, stdout); err != nil {
				return err
			}
		}
		return serve(ctx, o, clock, loader, logger)
	}
	return fmt.Errorf("unknown command %q (want serve, seed or readiness)", cmd)
}

// dbPath accepts a plain path or the Python backend's sqlite:/// URL form.
func dbPath(v string) string {
	if v == "" {
		return "tessera.db"
	}
	return strings.TrimPrefix(v, "sqlite:///")
}

func clockFromEnv() (timeutil.Clock, error) {
	v := os.Getenv("TESSERA_NOW")
	if v == "" {
		return timeutil.System, nil
	}
	t, err := timeutil.ParseISO(v)
	if err != nil {
		return nil, fmt.Errorf("TESSERA_NOW: %w", err)
	}
	return timeutil.Frozen(t), nil
}

func policyFS() fs.FS {
	if dir := os.Getenv("TESSERA_POLICY_DIR"); dir != "" {
		return os.DirFS(dir)
	}
	return policies.FS
}

func corsOrigins() []string {
	if v := os.Getenv("TESSERA_CORS_ORIGINS"); v != "" {
		var out []string
		for _, o := range strings.Split(v, ",") {
			if o = strings.TrimSpace(o); o != "" {
				out = append(out, o)
			}
		}
		return out
	}
	port := os.Getenv("UI_PORT")
	if port == "" {
		port = "5173"
	}
	return []string{"http://localhost:" + port, "http://127.0.0.1:" + port}
}

func seedDB(ctx context.Context, path string, clock timeutil.Clock, loader *policy.Loader, stdout io.Writer) error {
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
	fmt.Fprintln(stdout, "==> seeding demo data (fictional company: Larkspur Labs)")
	stats, err := seed.Run(ctx, st, conns, now, pols)
	if err != nil {
		return err
	}
	discovery, err := ojson.Marshal(stats.Sync.Discovery.Object())
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Seeded Tessera in %.1fs: %s usage=%d hris=%d jit=%d\n", time.Since(start).Seconds(),
		discovery, stats.Sync.Events.Usage, stats.Sync.Events.Hris, stats.Requests)
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
)

func serve(ctx context.Context, o options, clock timeutil.Clock, loader *policy.Loader, logger *slog.Logger) error {
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
	srv := api.New(api.Config{Store: st, Clock: clock, Policies: loader, Logger: logger, AllowedOrigins: corsOrigins()})
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
	errc := make(chan error, 1)
	go func() { errc <- httpSrv.Serve(ln) }()
	logger.Info("tessera API listening", "addr", ln.Addr().String())

	select {
	case err := <-errc:
		stop()
		<-sweepDone
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err = httpSrv.Shutdown(shutdownCtx)
	<-sweepDone
	if serveErr := <-errc; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return err
}
