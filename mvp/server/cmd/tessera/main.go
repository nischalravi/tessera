// Command tessera runs the Tessera API server and seeds its database.
//
//	tessera [serve] [-addr 127.0.0.1:8000] [-db tessera.db] [-reseed]
//	tessera seed    [-db tessera.db]
//	tessera check-db [-db tessera.db]   exit 0 if the database opens with this server's schema
//	                                    (run.sh reseeds a database from before sign-in)
//	tessera readiness lint [-dir path]   lint the readiness checklist templates
//	tessera groups policy validate [-dir path]   check the policy group files (*.cedar) offline (see groups.go)
//	tessera audit verify|checkpoint|export   verify, checkpoint or export the audit ledger (see audit.go)
//	tessera notify seal-password             seal an SMTP password (stdin) for TESSERA_SMTP_PASSWORD_SEALED
//	tessera archive seal-token               seal the archive store bearer token (stdin) for TESSERA_ARCHIVE_TOKEN_SEALED
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
//	TESSERA_CONNECTORS    connector spec, e.g. "demo" (default) or "demo-workday,okta,entra"
//	                      (okta and entra are the production connectors; see mvp/README.md)
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
//	TESSERA_READINESS_LIVE_CHECK_DAYS  how often live checks re-run on active connections, 1 to 7 days (default 1)
//	TESSERA_READINESS_SCHEDULER "off" stops the scheduled re-runs, drift and Degraded detection
//	TESSERA_SAFEDIAL_ALLOW      dev only: host:port or CIDR:port private LDAP targets live checks may dial (see mvp/README.md "Live LDAP checks")
//	TESSERA_AGENT_ADDR, TESSERA_AGENT_TLS_CERT, TESSERA_AGENT_TLS_KEY  the mutual-TLS listener Directory
//	                      Agents connect to, and its certificate and key (see mvp/README.md "Directory Agent")
//	TESSERA_EXTERNAL_WORKER_KINDS  worker kinds (connector_sync, provision_push) that `tessera worker`
//	                      runs instead of serve; TESSERA_CONNECTOR_SYNC_SCHEDULE schedules connector_sync (see mvp/README.md "Connector workers")
//	TESSERA_ROTATION_FAKE_ADAPTERS  true (the dev and test default) admits the simulated secret-rotation
//	                      adapter, which the demo policies use; prod refuses it
//	TESSERA_STEPUP_ALLOW_WEAKER  dev and test only, default false: lets a tenant's step-up policy replace the code's
//	                      step-up requirements with weaker ones; prod refuses it
//	TESSERA_READINESS_DEMO      "off" skips seeding the demo Okta connection (larkspur only) for Deployment health
package main

import (
	"context"
	"crypto/tls"
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
	"sync"
	"syscall"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agent"
	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/api"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/all"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/attest"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/deprov"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/events/sinks"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/pit"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/provisioning"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/reports"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/rules"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/credential"
	"github.com/nischalravi/tessera/mvp/server/internal/health"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/rotation"
	"github.com/nischalravi/tessera/mvp/server/internal/safedial"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/siem"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/ssf"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
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
	// externalKinds is serve's -external-kinds: worker kinds left to
	// `tessera worker` processes (overrides TESSERA_EXTERNAL_WORKER_KINDS).
	externalKinds string
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	if cmd == "readiness" {
		return readinessCmd(args, stdout, stderr)
	}
	if cmd == "groups" {
		return groupsCmd(args, stdout, stderr)
	}
	if cmd == "audit" {
		return auditCmd(ctx, args, stdout, stderr)
	}
	if cmd == "backup" {
		return backupCmd(ctx, args, stdout, stderr)
	}
	if cmd == "archive" {
		return archiveCmd(ctx, args, stdout, stderr)
	}
	if cmd == "notify" {
		return notifyCmd(ctx, args, stdout, stderr)
	}
	if cmd == "migration" {
		return migrationCmd(args, stdout, stderr)
	}
	if cmd == "admin" {
		return adminCmd(ctx, args, stdout, stderr)
	}
	if cmd == "catalog" {
		return catalogCmd(ctx, args, stdout, stderr)
	}
	if cmd == "worker" {
		return workerCmd(ctx, args, stderr)
	}
	fset := flag.NewFlagSet("tessera "+cmd, flag.ContinueOnError)
	fset.SetOutput(stderr)
	var o options
	fset.StringVar(&o.db, "db", dbPath(os.Getenv("TESSERA_DB")), "SQLite database path or postgres:// DSN")
	if cmd == "serve" {
		fset.StringVar(&o.addr, "addr", "127.0.0.1:8000", "listen address")
		fset.BoolVar(&o.reseed, "reseed", false, "wipe and re-seed the database before serving")
		fset.StringVar(&o.externalKinds, "external-kinds", "", "comma-separated worker kinds ("+strings.Join(worker.Kinds, ", ")+
			") that tessera worker processes run instead of this one (default TESSERA_EXTERNAL_WORKER_KINDS, else none)")
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
		return fmt.Errorf("unknown command %q (want serve, worker, seed, check-db, readiness, audit, backup, migration, admin or catalog)", cmd)
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
	// The okta and entra connectors take the shared outbound client from validated config.
	connClient, err := safehttp.ForConfig(cfg)
	if err != nil {
		return err
	}
	all.Register(connClient, connsync.RuntimeFromConfig(cfg))
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
			SAMLCert: strings.TrimSpace(os.Getenv("TESSERA_DEV_IDP_SAML_CERT")), GitHub: true, CAS: true, WSFed: true})
	}
	keyer := identifiers.NewKeyer(sealer)
	for i := range tenants {
		tenants[i].Identifiers = keyer
		tenants[i].DemoMatching = tenants[i].Slug == seed.LarkspurSlug       // an item for the Identity matches queue
		tenants[i].DemoGuestLifecycle = tenants[i].Slug == seed.LarkspurSlug // rows for Governance → Guest lifecycle
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
	if cfg.RotationFakeAdapters {
		if err := seedRotationDemo(ctx, st, seed.LarkspurID, clock); err != nil {
			return fmt.Errorf("rotation demo: %w", err)
		}
		fmt.Fprintf(stdout, "Seeded the secret-rotation demo for tenant %s: a simulated provider and policies for the demo credentials\n",
			seed.LarkspurSlug)
	}
	if cfg.DevOAuthFakeURL != "" {
		if err := seedOAuthFakeDemo(ctx, st, cfg, sealer, seed.LarkspurID, clock); err != nil {
			return fmt.Errorf("oauth apps demo: %w", err)
		}
		fmt.Fprintf(stdout, "Seeded the OAuth apps demo for tenant %s: four provider connections pointed at the dev fakes (%s); run a sync\n",
			seed.LarkspurSlug, cfg.DevOAuthFakeURL)
	}
	if err := keys.EnsureAll(ctx, st, sealer, clock()); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Created the platform and per-tenant signing keys (private keys sealed under the KEK)")
	if err := oauth.EnsureCLIClients(ctx, st, clock()); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Registered the %s OAuth client in every tenant\n", oauth.CLIClientID)
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
	// rotationInterval is how often the rotation worker looks for due jobs.
	rotationInterval = 30 * time.Second
	// group provisioning calls to customer systems: SCIM and webhook requests
	// may take longer, and a SCIM group lists all its members in one response
	provisioningHTTPTimeout = 30 * time.Second
	provisioningMaxBody     = 16 << 20
)

// ldapPorts are the destination ports the guarded dialer allows for LDAP and AD targets: LDAP,
// LDAPS and the Active Directory global catalog (plain and TLS).
var ldapPorts = []int{389, 636, 3268, 3269}

func serve(ctx context.Context, o options, cfg *config.Config, sealer *seal.Sealer, clock timeutil.Clock,
	loader *policy.Loader, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, err := store.Open(ctx, o.db)
	if err != nil {
		return err
	}
	defer st.Close()
	// #220: move the rows of the two retired credential tables into
	// connection_credentials (a no-op once they are gone). A blob that does not
	// open aborts startup rather than losing a credential.
	if m, err := st.MigrateCredentials(ctx, sealer); err != nil {
		return err
	} else if m != (store.CredentialMigration{}) {
		logger.Info("credentials migrated", "bind", m.Bind, "containment", m.Containment, "orphaned_dropped", m.Orphaned)
	}
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
	// every tenant has the first-party CLI client (tenants created since the
	// last start get it now)
	if err := oauth.EnsureCLIClients(ctx, st, clock()); err != nil {
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
	// Directory Agents (DR-11): private directories are probed through them.
	agents := &agent.Service{DB: st, Hub: agent.NewHub(nil), Clock: clock, Recorder: worker.RecordAgentSync}
	rsvc.Runner.Live.Agents = agents
	if err := configureReadinessSchedule(rsvc); err != nil {
		return err
	}
	// Outbound calls to IdPs (discovery, JWKS, token) and the kill switch's
	// provider calls (containment) go through safehttp. A test server gets the
	// production client (no loopback exception; ForConfig decides).
	outbound, err := safehttp.ForConfig(cfg)
	if err != nil {
		return err
	}
	rsvc.Runner.SCIM.Client = outbound
	all.Register(outbound, connsync.RuntimeFromConfig(cfg)) // okta and entra connectors use the shared client
	obs.SetPoolStats(st.PoolStats)
	checker := health.New(st, sealer, obs.DefaultLoops, time.Duration(cfg.ReadyMaxLoopLagSeconds)*time.Second, logger)
	sinksNet, err := sinks.NewNetwork(cfg) // group event sinks (AWS over HTTPS, RabbitMQ and Kafka through the guarded dialer)
	if err != nil {
		return err
	}
	groupsEngine := &engine.Engine{Budget: cfg.GroupsSyncBudget, Log: logger}
	fakeURL, stopFake, err := startFakeTarget(cfg, logger)
	if err != nil {
		return err
	}
	defer stopFake()
	stopOAuthFakes, err := startOAuthFakes(cfg, logger)
	if err != nil {
		return err
	}
	defer stopOAuthFakes()
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
	containmentSvc := &containment.Service{HTTP: outbound, Sealer: sealer, Clock: clock, DB: st}
	// Secret rotation: the worker calls providers only through the SSRF-guarded
	// client, opens adapter credentials only with the KEK, and the simulated
	// adapter exists only where config allows it (never in prod).
	rotationEngine := &rotation.Engine{DB: st, Clock: clock, Log: logger,
		Service: &rotation.Service{Sealer: sealer, Env: cfg.Env, AllowFake: cfg.RotationFakeAdapters},
		Factory: &rotation.Factory{HTTP: outbound, Sealer: sealer, Now: clock, AllowFake: cfg.RotationFakeAdapters}}
	// group rules: webhooks go through the same safehttp client; email rules log (TESSERA_NOTIFY=log)
	groupsRules := &rules.Runtime{Engine: groupsEngine, HTTP: outbound, Sealer: sealer, AllowHTTP: cfg.OutboundAllowLoopback, Log: logger}
	// Group provisioning reaches customer systems through the same address
	// guard: SCIM and webhooks through its own safehttp client (longer timeout,
	// larger bodies: a SCIM group lists all its members), LDAP through the
	// guarded dialer. Plain LDAP is for the dev directory only.
	provHTTP, err := safehttp.ForConfigLimits(cfg, provisioningHTTPTimeout, provisioningMaxBody)
	if err != nil {
		return err
	}
	provDial, err := safehttp.NewDialer(safehttp.Options{Env: cfg.Env, AllowLoopback: cfg.OutboundAllowLoopback && cfg.Env == config.Dev,
		Timeout: provisioningHTTPTimeout, AllowedPorts: ldapPorts})
	if err != nil {
		return err
	}
	provisioningSvc := &provisioning.Service{DB: st, Sealer: sealer, Clock: clock, Log: logger,
		Deps: provisioning.Deps{HTTP: provHTTP, Dial: provDial, AllowPlainLDAP: cfg.Env == config.Dev, SQLDir: cfg.GroupsProvSQLDir}}
	external := cfg.ExternalWorkerKinds
	if o.externalKinds != "" {
		if external, err = worker.ParseKinds(o.externalKinds); err != nil {
			return fmt.Errorf("-external-kinds: %w", err)
		}
	}
	if len(external) > 0 {
		logger.Info("worker kinds left to tessera worker processes", "kinds", external)
	}
	archiveSvc, err := newArchive(cfg, o.db, st, sealer, clock, logger)
	if err != nil {
		return err
	}
	if archiveSvc.Enabled() {
		logger.Info("archiving on", "location", archiveSvc.Store.Location())
	} else {
		logger.Warn("archiving is off: no archive store is configured (TESSERA_ARCHIVE_DIR or TESSERA_ARCHIVE_URL); nothing is archived or deleted")
	}
	srv := api.New(api.Config{ExternalKinds: external, ConnectorSyncSchedule: cfg.ConnectorSyncSchedule, Health: checker, Store: st, Clock: clock, Policies: loader, Logger: logger, Archive: archiveSvc,
		Secrets: secrets, Credential: authority,
		PublicURL: cfg.PublicURL, RPID: cfg.RPID, Sealer: sealer, OutboundHTTP: outbound, GroupsEngine: groupsEngine, GroupsRules: groupsRules, Provisioning: provisioningSvc, LoaderDataDir: cfg.LoaderDataDir, APIAudience: cfg.APIAudience,
		AccessTokenTTL: time.Duration(cfg.AccessTokenTTLSeconds) * time.Second,
		DeviceCodeTTL:  time.Duration(cfg.DeviceCodeTTLSeconds) * time.Second, DPoPRSNonce: cfg.DPoPRSNonce,
		Outbound: outbound, FakeTargetURL: fakeURL,
		Containment: containmentSvc,
		SSF: &ssf.Service{HTTP: outbound, Sealer: sealer, Clock: clock, Containment: containmentSvc,
			Dev: cfg.Env == config.Dev && cfg.OutboundAllowLoopback},
		AllowedOrigins: cfg.CORSOrigins, PublicOrigin: cfg.PublicOrigin(), InsecureCookie: !cfg.CookieSecure,
		HSTS: cfg.IsProd(), Env: cfg.Env, Identifiers: identifiers.NewKeyer(sealer), EmailMode: cfg.Mail.Mode, TrustedProxies: cfg.TrustedProxies, ReadinessScenario: scenario, Readiness: rsvc, Agents: agents, AuditAnchor: anchorURL,
		Siem: siemSvc, Alerts: alertSvc, AWSCatalog: awsCatalogLoader(cfg),
		SoD:          sod.Settings{MaxDays: cfg.SoDMaxMitigationDays, WarnDays: cfg.SoDWarnDays},
		RotationFake: cfg.RotationFakeAdapters, StepUpAllowWeaker: cfg.StepUpAllowWeaker})
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
	// The Directory Agent listener (DR-11): mutual TLS only, a separate port
	// from the API, serving nothing but the agent protocol.
	var agentSrv *http.Server
	var agentLn net.Listener
	if cfg.AgentAddr != "" {
		tlsCfg, err := agent.ServerTLSConfig(cfg.AgentTLSCert, cfg.AgentTLSKey)
		if err != nil {
			_ = ln.Close()
			return err
		}
		raw, err := net.Listen("tcp", cfg.AgentAddr)
		if err != nil {
			_ = ln.Close()
			return err
		}
		agentLn = tls.NewListener(raw, tlsCfg)
		agentSrv = &http.Server{
			Handler:           agents.Handler(agent.PollWait),
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      agent.PollWait + 15*time.Second,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    16 << 10,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		}
	}
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		// the queue and its health beat: Admin -> Jobs shows this process as a worker
		worker.Serve(ctx, srv.Queue(), &worker.Beater{DB: st, Queue: srv.Queue(), Mode: store.WorkerModeAPI,
			Version: agent.Version, Clock: clock, Log: logger})
	}()
	reviewsDone := make(chan struct{})
	go func() {
		defer close(reviewsDone)
		srv.RunReviewScheduler(ctx, reviewInterval)
	}()
	provDone := make(chan struct{})
	go func() {
		defer close(provDone)
		if srv.ExternalKind(jobs.ProvisionPush) {
			return // a tessera worker sends the provisioning operations
		}
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
	rdyDone := make(chan struct{})
	go func() {
		defer close(rdyDone)
		runReadinessScheduler(ctx, rsvc, st, clock, logger)
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
	// the groups engine's queue worker, time wheel and nightly verification
	groupsDone := make(chan struct{})
	groupsRunner := &engine.Runner{DB: st, Engine: groupsEngine, Clock: clock, Log: logger}
	go func() {
		defer close(groupsDone)
		groupsRunner.Loop(ctx)
	}()
	// group history: the daily Merkle digest (00:05 UTC), retention and the weekly rebuild check
	historyDone := make(chan struct{})
	historyRunner := &pit.Runner{DB: st, Clock: clock, Log: logger, RetentionDays: cfg.GroupsRetentionDays}
	go func() {
		defer close(historyDone)
		historyRunner.Loop(ctx)
	}()
	// group rules: the rules that react to membership and creation events
	rulesDone := make(chan struct{})
	rulesRunner := &rules.Runner{DB: st, Runtime: groupsRules, Clock: clock, Log: logger}
	go func() {
		defer close(rulesDone)
		rulesRunner.Loop(ctx)
	}()
	// group governance: attestation campaigns, deprovisioning and scheduled reports
	govDone := make(chan struct{})
	go func() {
		defer close(govDone)
		var wg sync.WaitGroup
		for _, loop := range []func(context.Context){
			(&attest.Runner{DB: st, Engine: groupsEngine, Clock: clock, Log: logger}).Loop,
			(&deprov.Runner{DB: st, Engine: groupsEngine, Clock: clock, Log: logger}).Loop,
			(&reports.Runner{DB: st, Engine: groupsEngine, Clock: clock, Log: logger}).Loop,
		} {
			wg.Add(1)
			go func(loop func(context.Context)) {
				defer wg.Done()
				loop(ctx)
			}(loop)
		}
		wg.Wait()
	}()
	notifyDone := make(chan struct{})
	go func() {
		defer close(notifyDone)
		dispatcher.Loop(ctx, notifyInterval)
	}()
	rotationDone := make(chan struct{})
	go func() {
		defer close(rotationDone)
		rotationEngine.Loop(ctx, rotationInterval)
	}()
	// group loaders: the scheduler of full and incremental runs (Admin > Jobs)
	loadersDone := make(chan struct{})
	loadersRunner := &loaders.Runner{Svc: &loaders.Service{DB: st, Engine: groupsEngine, Clock: clock, Sealer: sealer, HTTP: outbound,
		DataDir: cfg.LoaderDataDir, Log: logger}}
	go func() {
		defer close(loadersDone)
		loadersRunner.Loop(ctx)
	}()
	// group provisioning: full syncs (daily and on request) and incremental syncs of the group events
	provisioningDone := make(chan struct{})
	provisioningRunner := &provisioning.Runner{Svc: provisioningSvc, Clock: clock, Log: logger}
	go func() {
		defer close(provisioningDone)
		provisioningRunner.Loop(ctx)
	}()
	// group event sinks: SQS, SNS, RabbitMQ and Kafka delivery, through the same guarded network access
	sinksDone := make(chan struct{})
	sinksRunner := &sinks.Runner{DB: st, Svc: &sinks.Service{Sealer: sealer, AllowInsecure: sinksNet.AllowInsecure}, Open: sinksNet.Open,
		Clock: clock, Log: logger}
	go func() {
		defer close(sinksDone)
		sinksRunner.Loop(ctx)
	}()
	errc := make(chan error, 2)
	go func() { errc <- httpSrv.Serve(ln) }()
	logger.Info("tessera API listening", "addr", ln.Addr().String())
	if agentSrv != nil {
		go func() { errc <- agentSrv.Serve(agentLn) }()
		logger.Info("tessera agent listener (mutual TLS)", "addr", agentLn.Addr().String())
	}

	select {
	case err := <-errc:
		if metrics != nil {
			_ = metrics.srv.Close()
		}
		stop()
		if agentSrv != nil {
			_ = agentSrv.Close()
		}
		_ = httpSrv.Close()
		<-sweepDone
		<-reviewsDone
		<-provDone
		<-keysDone
		<-ckptDone
		<-rdyDone
		<-siemDone
		<-alertsDone
		<-backupDone
		<-groupsDone
		<-historyDone
		<-notifyDone
		<-rotationDone
		<-rulesDone
		<-govDone
		<-loadersDone
		<-provisioningDone
		<-sinksDone
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
	if agentSrv != nil {
		if aerr := agentSrv.Shutdown(shutdownCtx); err == nil {
			err = aerr
		}
	}
	<-sweepDone
	<-reviewsDone
	<-provDone
	<-keysDone
	<-ckptDone
	<-rdyDone
	<-siemDone
	<-alertsDone
	<-backupDone
	<-groupsDone
	<-historyDone
	<-notifyDone
	<-rotationDone
	<-rulesDone
	<-govDone
	<-loadersDone
	<-provisioningDone
	<-sinksDone
	for i := 0; i < cap(errc) && (i == 0 || agentSrv != nil); i++ {
		if serveErr := <-errc; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
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
			if err := oauth.EnsureCLIClients(ctx, st, clock()); err != nil && ctx.Err() == nil {
				logger.Error("registering the CLI client failed", "err", err)
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
