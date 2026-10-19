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
//	tessera catalog refresh|compile   fetch and compile the AWS action catalog (see catalog.go)
//	tessera admin gen-rls [-out path] [-check]   render the Postgres row-level-security file (see genrls.go)
//
// Environment:
//
//	TESSERA_DB            database path (or sqlite:///path), or a postgres:// DSN
//	                      (postgres://owner@host/db?sslmode=require&app_role=tessera_app);
//	                      default ./tessera.db
//	TESSERA_AUDIT_ANCHOR  file:///path.jsonl (dev) or s3://bucket/prefix (S3 Object Lock; prod)
//	TESSERA_POLICY_DIR    read policies from this directory instead of the built-in copies
//	TESSERA_CONNECTORS    connector spec, e.g. "demo" (default) or "demo-workday,okta"
//	TESSERA_CORS_ORIGINS  comma-separated browser origins allowed by CORS
//	                      (default: the dev UI on localhost/127.0.0.1, port UI_PORT or 5173;
//	                      must be empty in prod)
//	TESSERA_KEK / TESSERA_KEK_FILE  the key-encryption key (base64 of 32 bytes) that seals
//	                      private keys; in dev it is generated at var/dev-kek next to the database
//	(internal/config lists every setting and the production guard rails that
//	refuse to start with unsafe ones)
//	TESSERA_METRICS_ADDR  host:port of the internal /metrics listener (separate from the API
//	                      listener; default 127.0.0.1:9464 in dev, off in prod; "off" disables;
//	                      prod accepts only a loopback or private IP, see internal/config)
//	TESSERA_READY_MAX_LOOP_LAG_SECONDS  /readyz fails when a background loop has not
//	                      succeeded for this long (default 300)
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

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/api"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/credential"
	"github.com/nischalravi/tessera/mvp/server/internal/health"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
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
	if cmd == "backup" {
		return backupCmd(ctx, args, stdout, stderr)
	}
	if cmd == "notify" {
		return notifyCmd(ctx, args, stdout, stderr)
	}
	if cmd == "admin" {
		return adminCmd(ctx, args, stdout, stderr)
	}
	if cmd == "catalog" {
		return catalogCmd(ctx, args, stdout, stderr)
	}
	fset := flag.NewFlagSet("tessera "+cmd, flag.ContinueOnError)
	fset.SetOutput(stderr)
	var o options
	fset.StringVar(&o.db, "db", dbPath(os.Getenv("TESSERA_DB")), "SQLite database path or postgres:// DSN")
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
		return fmt.Errorf("unknown command %q (want serve, seed, check-db, readiness, audit, backup, admin or catalog)", cmd)
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
	seedNow, err := needsSeed(ctx, o, cfg)
	if err != nil {
		return err
	}
	if seedNow {
		if err := seedDB(ctx, o.db, cfg, clock, loader, sealer, stdout); err != nil {
			return err
		}
	}
	return serve(ctx, o, cfg, sealer, clock, loader, logger)
}

// needsSeed reports whether serve must seed the demo tenants first: on
// --reseed, or when there is nothing yet. For SQLite "nothing" is a missing
// file. A Postgres database always exists, so there it is a database with no
// tenant, and never in production (an empty production database is filled by
// `tessera admin create-tenant`, not by demo data).
func needsSeed(ctx context.Context, o options, cfg *config.Config) (bool, error) {
	if !store.IsPostgresDSN(o.db) {
		_, err := os.Stat(o.db)
		return o.reseed || errors.Is(err, fs.ErrNotExist), nil
	}
	if o.reseed {
		return true, nil
	}
	if cfg.IsProd() {
		return false, nil
	}
	st, err := store.Open(ctx, o.db)
	if err != nil {
		return false, err
	}
	defer st.Close()
	tenants, err := st.ActiveTenants(ctx)
	return len(tenants) == 0, err
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
	provisionInterval = 5 * time.Second  // provisioning worker: sends queued operations and re-reads targets
	keysInterval      = 24 * time.Hour   // keys.EnsureAll: rotation runs daily (design §10.6)
	notifyInterval    = 15 * time.Second // the notification dispatcher (issue #189)
	// checkpointInterval is how often the checkpointer looks for due tenants
	// (each is checkpointed every TESSERA_AUDIT_CHECKPOINT_SECONDS or
	// _EVENTS new events, design §13.6).
	checkpointInterval = 30 * time.Second
	// siemInterval is how often SIEM sinks are pushed what is new in the ledger (#169).
	siemInterval = 15 * time.Second
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
	obs.SetPoolStats(st.PoolStats)
	checker := health.New(st, sealer, obs.DefaultLoops, time.Duration(cfg.ReadyMaxLoopLagSeconds)*time.Second, logger)
	fakeURL, stopFake, err := startFakeTarget(cfg, logger)
	if err != nil {
		return err
	}
	defer stopFake()
	// One shared outbound client: sign-in, containment and provisioning all
	// send through it.
	// One-time secrets (claim links, confirmation codes) go from the API to the
	// dispatcher through memory only.
	secrets := notify.NewSecrets()
	// The guest claim's credential authority: the dev IdP, in development only.
	// Without one (production today) a claim stops at the credential step.
	var authority credential.Authority
	if cfg.Env == config.Dev && cfg.DevIdPURL != "" {
		if authority, err = credential.NewDevIdP(cfg.Env, outbound); err != nil {
			return err
		}
	}
	// The s3:// anchor sink's AWS SDK client uses the same safehttp client.
	anchorURL := cfg.AnchorURL(o.db)
	alertSvc, err := newAlertService(cfg, st, sealer, outbound, clock, logger)
	if err != nil {
		return err
	}
	sink, err := audit.NewSink(anchorURL, audit.WithHTTPClient(outbound))
	if err != nil {
		return err
	}
	siemSvc := &siem.Service{DB: st, Sealer: sealer, HTTP: outbound, Clock: clock, Log: logger,
		Dev: cfg.Env == config.Dev && cfg.OutboundAllowLoopback}
	srv := api.New(api.Config{Health: checker, Store: st, Clock: clock, Policies: loader, Logger: logger,
		Secrets: secrets, Credential: authority,
		PublicURL: cfg.PublicURL, Sealer: sealer, OutboundHTTP: outbound,
		Outbound: outbound, FakeTargetURL: fakeURL,
		Containment:    &containment.Service{HTTP: outbound, Sealer: sealer, Clock: clock},
		AllowedOrigins: cfg.CORSOrigins, PublicOrigin: cfg.PublicOrigin(), InsecureCookie: !cfg.CookieSecure,
		HSTS: cfg.IsProd(), Env: cfg.Env, Identifiers: identifiers.NewKeyer(sealer), EmailMode: cfg.Mail.Mode, TrustedProxies: cfg.TrustedProxies, ReadinessScenario: scenario, Readiness: rsvc, AuditAnchor: anchorURL,
		Siem: siemSvc, Alerts: alertSvc})
	sender, err := notify.NewSender(cfg.Mail, cfg.Env, cfg.OutboundAllowLoopback, sealer, config.DevMailPath(o.db), logger)
	if err != nil {
		return err
	}
	dispatcher := &notify.Dispatcher{DB: st, Sender: sender, Clock: clock, Log: logger, MaxAttempts: cfg.NotifyMaxAttempts,
		DigestHour: cfg.NotifyDigestHour, BaseURL: cfg.PublicURL, Secrets: secrets}
	checkpointer := &audit.Checkpointer{DB: st, Sealer: sealer, Sink: sink, Clock: timeutil.System, Issuer: cfg.PublicURL,
		Every: time.Duration(cfg.AuditCheckpointSeconds) * time.Second, EveryEvents: int64(cfg.AuditCheckpointEvents),
		Log: logger, OnTenant: api.RecordAnchorRun(st)}
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
	metrics, err := newMetricsServer(cfg, o.addr, obs.Default, logger)
	if err != nil {
		_ = ln.Close()
		return err
	}
	if metrics != nil {
		go metrics.serve(logger)
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
	provDone := make(chan struct{})
	go func() {
		defer close(provDone)
		srv.RunProvisioning(ctx, provisionInterval)
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
	siemDone := make(chan struct{})
	go func() {
		defer close(siemDone)
		siemSvc.Run(ctx, siemInterval)
	}()
	alertsDone := make(chan struct{})
	go func() {
		defer close(alertsDone)
		alertSvc.Run(ctx, alertsInterval)
	}()
	backupDone := make(chan struct{})
	go func() {
		defer close(backupDone)
		if cfg.BackupDir != "" {
			logger.Info("scheduled backups on", "dir", cfg.BackupDir, "every_minutes", cfg.BackupEveryMinutes, "keep", cfg.BackupKeep)
			runBackups(ctx, st, sealer, cfg, logger)
		}
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
		if metrics != nil {
			_ = metrics.srv.Close()
		}
		stop()
		<-sweepDone
		<-reviewsDone
		<-provDone
		<-keysDone
		<-ckptDone
		<-siemDone
		<-alertsDone
		<-backupDone
		<-notifyDone
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if metrics != nil {
		_ = metrics.srv.Shutdown(shutdownCtx)
	}
	err = httpSrv.Shutdown(shutdownCtx)
	<-sweepDone
	<-reviewsDone
	<-provDone
	<-keysDone
	<-ckptDone
	<-siemDone
	<-alertsDone
	<-backupDone
	<-notifyDone
	if serveErr := <-errc; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return err
}

// startFakeTarget starts the in-process fake SCIM target on a loopback port
// when TESSERA_DEV_FAKE_TARGET is set (config refuses it in prod) and returns
// its base URL; with it off the URL is empty and the API refuses the "fake"
// target kind.
func startFakeTarget(cfg *config.Config, logger *slog.Logger) (string, func(), error) {
	if !cfg.FakeTarget {
		return "", func() {}, nil
	}
	if cfg.IsProd() || !cfg.OutboundAllowLoopback {
		return "", nil, errors.New("TESSERA_DEV_FAKE_TARGET needs TESSERA_ENV=dev with TESSERA_OUTBOUND_ALLOW_LOOPBACK on")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: fake.New(fake.Options{Lenient: true}).Handler(), ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout: readTimeout, WriteTimeout: readTimeout}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("fake provisioning target stopped", "err", err)
		}
	}()
	url := "http://" + ln.Addr().String()
	logger.Info("dev fake provisioning target listening", "url", url)
	return url, func() { _ = srv.Close() }, nil
}

// runKeyRotation runs keys.EnsureAll every keysInterval until ctx ends.
func runKeyRotation(ctx context.Context, st *store.DB, sealer *seal.Sealer, clock timeutil.Clock, logger *slog.Logger) {
	t := time.NewTicker(keysInterval)
	defer t.Stop()
	// reported to /metrics but not gated: it runs once a day
	obs.DefaultLoops.Register("key_rotation", keysInterval, false)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := obs.DefaultLoops.Run("key_rotation", func() error { return keys.EnsureAll(ctx, st, sealer, clock()) }); err != nil && ctx.Err() == nil {
				logger.Error("signing key rotation failed", "err", err)
			}
		}
	}
}

// alertsInterval is how often the alert engine reads new audit events and
// sends due deliveries (detections run every 15 minutes).
const alertsInterval = time.Minute

// newAlertService builds the alert engine and deliverer (issue #168):
// webhooks through the SSRF-guarded client, email per TESSERA_NOTIFY.
func newAlertService(cfg *config.Config, st *store.DB, sealer *seal.Sealer, client *http.Client, clock timeutil.Clock, logger *slog.Logger) (*alerts.Service, error) {
	mailer, err := alerts.NewMailer(cfg.Notify, logger)
	if err != nil {
		return nil, err
	}
	return &alerts.Service{DB: st, Sealer: sealer, HTTP: client, Mail: mailer, Clock: clock, Log: logger,
		PublicURL: cfg.PublicURL}, nil
}
