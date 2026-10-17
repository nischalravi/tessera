// Command tessera runs the Tessera API server and seeds its database.
//
//	tessera [serve] [-addr 127.0.0.1:8000] [-db tessera.db] [-reseed]
//	tessera seed    [-db tessera.db]
//	tessera check-db [-db tessera.db]   exit 0 if the database opens with this server's schema
//	                                    (run.sh reseeds a database from before sign-in)
//	tessera readiness lint [-dir path]   lint the readiness checklist templates
//	tessera audit verify|checkpoint|export   verify, checkpoint or export the audit ledger (see audit.go)
//	tessera notify seal-password             seal an SMTP password (stdin) for TESSERA_SMTP_PASSWORD_SEALED
//	tessera admin create-tenant|add-idp|invite-admin   operator bootstrap of a tenant (see admin.go)
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
//	TESSERA_ENV           dev (run.sh sets it), test or prod. Every API route except
//	                      the public allow-list needs a signed-in session, and the
//	                      tenant comes from that session (sign-in through the tenant's
//	                      IdP); prod refuses to start with any dev setting (§18.4).
//	TESSERA_DEV_IDP_URL   the dev IdP's issuer: seeding (dev and test) creates a
//	                      dev_mock connection to it with the bootstrap users
//	TESSERA_NOTIFY_EMAIL  off, dev (the dev sink, never in prod) or smtp; default smtp when TESSERA_SMTP_HOST is set,
//	                      else dev outside prod and off in prod. TESSERA_SMTP_HOST/_PORT/_USERNAME/_FROM/_TLS and
//	                      TESSERA_SMTP_PASSWORD_SEALED configure the relay; TESSERA_NOTIFY_MAX_ATTEMPTS and
//	                      TESSERA_NOTIFY_DIGEST_HOUR tune the dispatcher (see internal/config)
//	DEVIDP_CLIENT_SECRET  the dev IdP client's secret, sealed into those connections
//	                      (default tessera-dev-secret, as cmd/tessera-devidp)
//	TESSERA_DEV_IDP_SAML_CERT  the dev IdP's SAML signing certificate (PEM, from
//	                      tessera-devidp -print-saml-cert): seeding also creates a
//	                      dev_mock SAML connection pinning it (run.sh sets it)
//	TESSERA_READINESS_SCENARIO  simulated validation scenario for demo connectors: gaps (default) or happy
//	TESSERA_SAFEDIAL_ALLOW      dev only: host:port or CIDR:port private LDAP targets live checks may dial (see mvp/README.md "Live LDAP checks")
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
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/api"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tessera:", err)
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
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
	if cmd == "audit" {
		return auditCmd(ctx, args, stdout, stderr)
	}
	if cmd == "notify" {
		return notifyCmd(ctx, args, stdout, stderr)
	}
	if cmd == "admin" {
		return adminCmd(ctx, args, stdout, stderr)
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
	if cmd == "check-db" {
		st, err := store.Open(ctx, o.db)
		if err != nil {
			return err
		}
		return st.Close()
	}
	if cmd != "seed" && cmd != "serve" {
		return fmt.Errorf("unknown command %q (want serve, seed, check-db, readiness, audit or admin)", cmd)
	}
	if os.Getenv("TESSERA_ENV") == "" {
		// fail closed: the environment decides the guard rails (§18.4) and
		// whether dev sign-in exists, so it is never implied
		return errors.New("set TESSERA_ENV=dev (run.sh does), TESSERA_ENV=test or TESSERA_ENV=prod")
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	// Typed configuration and the production guard rails come first: an
	// unsafe production setting refuses to start before anything else runs.
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	if cmd == "serve" && !cfg.CookieSecure && !loopbackListen(o.addr) {
		// config allows insecure cookies only in dev on a localhost public
		// URL; the listener must be local too, or the session cookie
		// crosses the network in clear
		return fmt.Errorf("TESSERA_COOKIE_SECURE=false is allowed only with a loopback listen address (got -addr %s)", o.addr)
	}
	clock := cfg.Clock() // TESSERA_NOW, which config refuses in prod
	sealer, err := cfg.Sealer(config.DevKEKPath(o.db))
	if err != nil {
		return err
	}
	loader := policy.NewLoader(policyFS())
	if cmd == "seed" {
		return seedDB(ctx, o.db, cfg, clock, loader, sealer, stdout)
	}
	if _, err := os.Stat(o.db); o.reseed || errors.Is(err, fs.ErrNotExist) {
		if err := seedDB(ctx, o.db, cfg, clock, loader, sealer, stdout); err != nil {
			return err
		}
	}
	return serve(ctx, o, cfg, sealer, clock, loader, logger)
}

// loopbackListen reports whether addr (host:port) listens on loopback only:
// localhost, 127.0.0.0/8 or ::1. An empty host (all interfaces) is not.
func loopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Zone() == "" && a.Unmap().IsLoopback()
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

// devIdPClientSecret is the dev IdP's published default client secret
// (cmd/tessera-devidp); DEVIDP_CLIENT_SECRET overrides both.
const devIdPClientSecret = "tessera-dev-secret" // #nosec G101 -- documented dev-only value of a mock IdP

func seedDB(ctx context.Context, path string, cfg *config.Config, clock timeutil.Clock, loader *policy.Loader,
	sealer *seal.Sealer, stdout io.Writer) error {
	if cfg.IsProd() {
		return errors.New("seed: refusing to seed demo tenants with TESSERA_ENV=prod")
	}
	start := time.Now()
	// Seeding always starts from an empty schema, even over an older database.
	st, err := store.OpenFresh(ctx, path)
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
	tenants := seed.DefaultTenants(conns, now)
	if cfg.DevIdPURL != "" {
		// the dev IdP's client secret (cmd/tessera-devidp reads the same
		// variable), sealed into the dev_mock connections
		secret := os.Getenv("DEVIDP_CLIENT_SECRET")
		if secret == "" {
			secret = devIdPClientSecret
		}
		tenants = seed.WithDevIdPClient(tenants, cfg.DevIdPURL, seed.DevIdPClient{Sealer: sealer, Secret: secret,
			SAMLCert: strings.TrimSpace(os.Getenv("TESSERA_DEV_IDP_SAML_CERT")), GitHub: true})
	}
	keyer := identifiers.NewKeyer(sealer)
	for i := range tenants {
		tenants[i].Identifiers = keyer
	}
	stats, err := seed.Run(ctx, st, now, pols, tenants)
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
	reviewInterval    = 5 * time.Minute  // scheduled access reviews (issue #166)
	notifyInterval    = 15 * time.Second // the notification dispatcher (issue #189)
	keysInterval      = 24 * time.Hour   // keys.EnsureAll: rotation runs daily (design §10.6)
	// checkpointInterval is how often the checkpointer looks for due tenants
	// (each is checkpointed every TESSERA_AUDIT_CHECKPOINT_SECONDS or
	// _EVENTS new events, design §13.6).
	checkpointInterval = 30 * time.Second
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
	if cfg.IsProd() {
		// §18.4: no dev_mock IdP connection may exist in production.
		if err := st.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
			n, err := tx.CountIdPConnectionsByProfile(store.ProfileDevMock)
			if err == nil && n > 0 {
				err = errors.New("refusing to start with TESSERA_ENV=prod: a dev_mock IdP connection exists")
			}
			return err
		}); err != nil {
			return err
		}
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
	anchorURL := cfg.AnchorURL(o.db)
	sink, err := audit.NewSink(anchorURL)
	if err != nil {
		return err
	}
	// Live readiness checks: real LDAP probes open the sealed credential with
	// the KEK and dial through safedial. Private targets need the dev-only
	// allowlist (refused in prod by config) or, later, the Directory Agent.
	templates, err := template.Default()
	if err != nil {
		return err
	}
	allow, err := safedial.ParseAllow(cfg.SafedialAllow)
	if err != nil {
		return fmt.Errorf("TESSERA_SAFEDIAL_ALLOW: %w", err)
	}
	rsvc := readiness.NewService(templates, string(cfg.Env))
	rsvc.Runner.Scenario = scenario
	rsvc.Runner.Live.Sealer, rsvc.Runner.Live.Allow = sealer, allow
	// Outbound calls to IdPs (discovery, JWKS, token) and the kill switch's
	// provider calls (containment) go through safehttp. A test server gets the
	// production client (no loopback exception; ForConfig decides).
	outbound, err := safehttp.ForConfig(cfg)
	if err != nil {
		return err
	}
	srv := api.New(api.Config{Store: st, Clock: clock, Policies: loader, Logger: logger,
		PublicURL: cfg.PublicURL, Sealer: sealer, OutboundHTTP: outbound,
		Containment:    &containment.Service{HTTP: outbound, Sealer: sealer, Clock: clock},
		AllowedOrigins: cfg.CORSOrigins, PublicOrigin: cfg.PublicOrigin(), InsecureCookie: !cfg.CookieSecure,
		HSTS: cfg.IsProd(), Env: cfg.Env, Identifiers: identifiers.NewKeyer(sealer), EmailMode: cfg.Mail.Mode, TrustedProxies: cfg.TrustedProxies, ReadinessScenario: scenario, Readiness: rsvc, AuditAnchor: anchorURL})
	sender, err := notify.NewSender(cfg.Mail, cfg.Env, cfg.OutboundAllowLoopback, sealer, config.DevMailPath(o.db), logger)
	if err != nil {
		return err
	}
	dispatcher := &notify.Dispatcher{DB: st, Sender: sender, Clock: clock, Log: logger, MaxAttempts: cfg.NotifyMaxAttempts,
		DigestHour: cfg.NotifyDigestHour, BaseURL: cfg.PublicURL}
	checkpointer := &audit.Checkpointer{DB: st, Sealer: sealer, Sink: sink, Clock: timeutil.System, Issuer: cfg.PublicURL,
		Every: time.Duration(cfg.AuditCheckpointSeconds) * time.Second, EveryEvents: int64(cfg.AuditCheckpointEvents),
		Log: logger}
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
	reviewsDone := make(chan struct{})
	go func() {
		defer close(reviewsDone)
		srv.RunReviewScheduler(ctx, reviewInterval)
	}()
	keysDone := make(chan struct{})
	go func() {
		defer close(keysDone)
		runKeyRotation(ctx, st, sealer, clock, logger)
	}()
	ckptDone := make(chan struct{})
	go func() {
		defer close(ckptDone)
		checkpointer.Loop(ctx, checkpointInterval)
	}()
	notifyDone := make(chan struct{})
	go func() {
		defer close(notifyDone)
		dispatcher.Loop(ctx, notifyInterval)
	}()
	errc := make(chan error, 1)
	go func() { errc <- httpSrv.Serve(ln) }()
	logger.Info("tessera API listening", "addr", ln.Addr().String())

	select {
	case err := <-errc:
		stop()
		<-sweepDone
		<-reviewsDone
		<-keysDone
		<-ckptDone
		<-notifyDone
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err = httpSrv.Shutdown(shutdownCtx)
	<-sweepDone
	<-reviewsDone
	<-keysDone
	<-ckptDone
	<-notifyDone
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
