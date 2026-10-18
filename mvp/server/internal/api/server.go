// Package api is Tessera's REST API.
//
// The HTTP contract (routes, status codes, JSON bodies, key order and the
// FastAPI/pydantic-style 422 validation errors) is the one the original Python
// backend served; testdata/parity holds the recorded golden responses.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oauth2rp"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oidcrp"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/health"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/reviews"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/internal/transport"
)

// DefaultMaxBodyBytes caps request bodies (every request body is a small JSON object).
const DefaultMaxBodyBytes = 1 << 20

// DefaultHandlerTimeout bounds the time a handler may run.
const DefaultHandlerTimeout = 30 * time.Second

// DefaultStreamTimeout bounds a streamed response (GET /api/audit/export).
// Streams bypass http.TimeoutHandler, which would buffer the whole body in
// memory and cut it at HandlerTimeout; instead the request context gets this
// deadline and the connection's write deadline is extended to match. An
// export that needs longer is split with from_seq/to_seq.
const DefaultStreamTimeout = 15 * time.Minute

// Config configures a Server.
type Config struct {
	Store *store.DB
	// There is no default tenant: every request's tenant comes from its
	// authenticated principal's session row (design §14.2).
	Clock    timeutil.Clock // defaults to timeutil.System
	Policies *policy.Loader // required
	// Connectors returns the configured connectors (defaults to connectors.Load("", now)).
	Connectors func(now time.Time) ([]connectors.Connector, error)
	Logger     *slog.Logger // defaults to slog.Default()
	// AllowedOrigins are the browser origins allowed by CORS (exact match,
	// credentials allowed): TESSERA_CORS_ORIGINS, empty in production.
	AllowedOrigins []string
	// PublicOrigin is the origin of TESSERA_PUBLIC_URL. The CSRF Origin check
	// admits it and AllowedOrigins.
	PublicOrigin string
	// InsecureCookie selects the dev-only cookie without Secure
	// (TESSERA_COOKIE_SECURE=false; config allows it only in dev on localhost).
	InsecureCookie bool
	// HSTS adds Strict-Transport-Security (production).
	HSTS           bool
	MaxBodyBytes   int64         // defaults to DefaultMaxBodyBytes
	HandlerTimeout time.Duration // defaults to DefaultHandlerTimeout; <0 disables
	StreamTimeout  time.Duration // defaults to DefaultStreamTimeout; streamed routes only
	// Readiness is the deployment-readiness service (defaults to the
	// embedded templates and Env).
	Readiness *readiness.Service
	// Env is TESSERA_ENV: "dev" allows activating non-demo connector types,
	// and is otherwise informational.
	Env string
	// ReadinessScenario selects the simulated validation scenario
	// (TESSERA_READINESS_SCENARIO; default "gaps").
	ReadinessScenario string
	// AuditAnchor is TESSERA_AUDIT_ANCHOR: POST /api/audit/verify checks
	// checkpoints against it when it is a file:// URL.
	AuditAnchor string
	// PublicURL is TESSERA_PUBLIC_URL: the base of the OIDC redirect URIs.
	PublicURL string
	// Sealer opens connection client secrets, seals PKCE verifiers, provisioning
	// target credentials and the config bundle signing keys under the KEK.
	// Nil (tests only): sign-in with secrets and config export are unavailable,
	// and provisioning uses a key generated for this process, so its
	// credentials cannot be read after a restart. cmd/tessera always passes
	// the real one.
	Sealer *seal.Sealer
	// OutboundHTTP is the safehttp client for IdP discovery, JWKS and token
	// requests. Nil: browser sign-in through an IdP is unavailable.
	OutboundHTTP *http.Client
	// RateLimits are the per-IP limits on anonymous and /api/auth/*
	// requests (ratelimit.go); the zero value is the defaults.
	RateLimits RateLimits
	// TrustedProxies (TESSERA_TRUSTED_PROXIES) are the peers whose
	// X-Forwarded-For the rate limiter believes.
	TrustedProxies []netip.Prefix
	// Outbound is the safehttp client the provisioning worker sends through.
	// Nil: no outbound client, so every provisioning call fails (as with
	// Containment).
	Outbound *http.Client
	// FakeTargetURL is the base URL of the in-process fake SCIM target
	// (TESSERA_DEV_FAKE_TARGET, dev only). Empty: the "fake" target kind is
	// refused.
	FakeTargetURL string
	// EmailMode is the email delivery (config.MailOff, MailDev or MailSMTP):
	// the preferences page says whether the email channels do anything.
	EmailMode string
	// Identifiers hashes the identifiers of invited guests under per-tenant
	// keys derived from the KEK. Nil: invitations answer 503.
	Identifiers *identifiers.Keyer
	// Containment runs the kill switch's provider calls (revoke sessions and
	// grants). Nil: a service with no outbound client, so every containment
	// step is a manual task.
	Containment *containment.Service
	// Health answers /readyz and the admin platform-health summary. Nil: a
	// checker over Store and Sealer with the default loop-lag threshold.
	Health *health.Checker
	// AuditAppend overrides how the audit middleware writes http.request
	// events (tests inject failures). Nil: the store.
	AuditAppend func(ctx context.Context, t tenancy.ID, e store.AuditEvent) error
}

// Server serves the API.
type Server struct {
	cfg    Config
	store  *store.DB
	clock  timeutil.Clock
	log    *slog.Logger
	routes []*route
	authn  *auth.Authenticator
	limits *limiters
	guests *sponsorship.Service
	rp     *oidcrp.RP
	oauth2 *oauth2rp.RP

	readiness *readiness.Service
	prov      *provision.Engine
	provSeal  *seal.Sealer // cfg.Sealer, or a per-process key when it is nil
	// containment is the kill switch (issue #106); never nil.
	containment *containment.Service
	// admin is the admin-change workflow (design §15); never nil.
	admin *admin.Service
}

// New builds a server.
func New(cfg Config) *Server {
	if cfg.Clock == nil {
		cfg.Clock = timeutil.System
	}
	if cfg.Connectors == nil {
		cfg.Connectors = func(now time.Time) ([]connectors.Connector, error) { return connectors.Load("", now) }
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.HandlerTimeout == 0 {
		cfg.HandlerTimeout = DefaultHandlerTimeout
	}
	if cfg.StreamTimeout <= 0 {
		cfg.StreamTimeout = DefaultStreamTimeout
	}
	if cfg.Readiness == nil {
		reg, err := template.Default()
		if err != nil {
			panic(err) // the embedded templates are linted by TestTemplates_Lint
		}
		cfg.Readiness = readiness.NewService(reg, cfg.Env)
		cfg.Readiness.Runner.Scenario = cfg.ReadinessScenario
	}
	if cfg.Containment == nil {
		cfg.Containment = &containment.Service{}
	}
	if cfg.Containment.Clock == nil {
		cfg.Containment.Clock = cfg.Clock
	}
	if cfg.Health == nil {
		cfg.Health = health.New(cfg.Store, cfg.Sealer, nil, 0, cfg.Logger)
	}
	provSeal := cfg.Sealer
	if provSeal == nil {
		sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
		if err != nil {
			panic(err)
		}
		provSeal = sealer
	}
	s := &Server{cfg: cfg, containment: cfg.Containment, store: cfg.Store, clock: cfg.Clock, log: cfg.Logger, readiness: cfg.Readiness,
		limits: newLimiters(cfg.RateLimits), provSeal: provSeal}
	s.prov = &provision.Engine{DB: cfg.Store, Sealer: provSeal, HTTP: cfg.Outbound,
		Clock: func() time.Time { return s.clock() }, Log: cfg.Logger.With("component", "provisioning")}
	s.admin = &admin.Service{DB: cfg.Store, Clock: func() time.Time { return s.clock() }, Sealer: cfg.Sealer,
		Prod: cfg.Env == "prod", Log: cfg.Logger}
	s.guests = sponsorship.New(cfg.Identifiers)
	if cfg.OutboundHTTP != nil {
		rp, err := oidcrp.New(oidcrp.Config{HTTP: cfg.OutboundHTTP, Now: func() time.Time { return s.clock() }})
		if err != nil {
			panic(err) // HTTP and Now are set
		}
		s.rp = rp
		if s.oauth2, err = oauth2rp.New(cfg.OutboundHTTP); err != nil {
			panic(err) // HTTP is set
		}
	}
	s.authn = &auth.Authenticator{DB: cfg.Store, Clock: func() time.Time { return s.clock() },
		Cookies: auth.Cookies{Insecure: cfg.InsecureCookie}}
	s.registerRoutes()
	s.registerAuditRoutes()
	s.registerReviewScheduleRoutes()
	s.registerCorrelationRoutes()
	s.registerAffiliationRoutes()
	s.registerRequestRoutes()
	s.registerRemovalRoutes()
	s.registerRequestDraftRoutes()
	s.registerOrgRoutes()
	s.registerActivityRoutes()
	s.registerRoleRoutes()
	s.registerAbacRoutes()
	s.registerLifecycleRoutes()
	s.registerGuestRoutes()
	s.registerNotificationRoutes()
	s.registerEmailRoutes()
	s.registerContainmentRoutes()
	s.registerGroupsFolderRoutes()
	s.registerReadinessRoutes()
	s.registerJobRoutes()
	s.registerProvisioningRoutes()
	s.registerTransportRoutes()
	s.registerAuthRoutes()
	s.registerLoginRoutes()
	s.registerSAMLRoutes()
	s.registerOAuth2Routes()
	s.registerStepUpRoutes()
	s.registerAdminRoutes()
	s.registerOpsRoutes()
	s.checkPublicRoutes()
	return s
}

// csrfOrigins are the origins the CSRF Origin check admits.
func (s *Server) csrfOrigins() []string {
	out := slices.Clone(s.cfg.AllowedOrigins)
	if s.cfg.PublicOrigin != "" && !slices.Contains(out, s.cfg.PublicOrigin) {
		out = append(out, s.cfg.PublicOrigin)
	}
	return out
}

// Handler returns the HTTP handler with all middleware applied.
func (s *Server) Handler() http.Handler {
	var h http.Handler = http.HandlerFunc(s.dispatch)
	if s.cfg.HandlerTimeout > 0 {
		h = s.timeouts(h, http.TimeoutHandler(h, s.cfg.HandlerTimeout, `{"detail":"Request timed out"}`))
	}
	h = s.limitBody(h)
	h = s.cors(h)
	h = s.recoverPanics(h)
	// One http.request event per request; reads are buffered and refused
	// with 503 if the event cannot be written (design §13.4).
	// The tenant of an http.request event is the principal's (audit.SetPrincipal
	// in dispatch); unauthenticated requests go to the _platform chain.
	h = audit.Middleware(audit.MiddlewareConfig{DB: s.store, Clock: s.clock, Log: s.log,
		Append: s.cfg.AuditAppend})(h)
	// Per-IP limits on anonymous and /api/auth/* requests, before anything
	// is written to the ledger.
	h = s.rateLimit(h)
	h = s.logRequests(h)
	h = s.securityHeaders(h)
	// The probes /livez and /readyz are answered before the API pipeline
	// (rate limit, audit, sessions): see probes. Metrics wrap everything.
	return obs.Instrument(s.probes(h))
}

// streamDeadlineKey carries a streamed route's deadline to dispatch.
type streamDeadlineKey struct{}

// timeouts sends streamed routes to stream and every other request to timed
// (the HandlerTimeout-bounded handler). A stream gets StreamTimeout on its
// context and on the connection's write deadline (the server's WriteTimeout
// is sized for ordinary responses).
func (s *Server) timeouts(stream, timed http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rt, _, _ := s.find(r.Method, r.URL.Path); rt == nil || !rt.stream {
			timed.ServeHTTP(w, r)
			return
		}
		deadline := time.Now().Add(s.cfg.StreamTimeout)
		// ErrNotSupported (httptest recorders) leaves the server's deadline.
		_ = http.NewResponseController(w).SetWriteDeadline(deadline)
		// The context deadline applies to the handler only (dispatch sets it
		// after authorization), so authentication is not cut short.
		stream.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), streamDeadlineKey{}, deadline)))
	})
}

// RunReviewScheduler launches due review schedules and progresses open
// scheduled campaigns (reminders, escalation, close-out) in every active
// tenant, every interval until ctx is done (issue #166).
func (s *Server) RunReviewScheduler(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	ctx = audit.WithSystemActor(ctx, reviews.Scheduler)
	for {
		if pols, err := s.policies(); err != nil {
			s.log.Error("review scheduler: policies", "err", err)
		} else if err := reviews.TickAll(ctx, s.store, s.clock(), pols); err != nil && ctx.Err() == nil {
			s.log.Error("review scheduler failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SweeperLoops are the loop names RunSweeper reports to obs.DefaultLoops.
var SweeperLoops = []string{"jit_sweep", "request_sweep", "sponsorship_sweep", "lifecycle_sweep", "containment_retries",
	"admin_change_sweep"}

// RunSweeper expires JIT grants, closes due request lines and ends due
// lifecycle terms (warnings first) of every active tenant, each in its own
// tenant transaction, every interval until ctx is done. A failure in one
// tenant is logged and does not stop the others.
func (s *Server) RunSweeper(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	ctx = audit.WithSystemActor(ctx, "jit.sweeper") // jit.expire events name the job
	// Each step is its own tracked loop (obs.DefaultLoops): a step that stalls or
	// keeps failing shows as lag in /metrics, /readyz and Admin -> Platform health.
	loops := obs.DefaultLoops
	for _, name := range SweeperLoops {
		loops.Register(name, interval, true)
	}
	step := func(name, what string, fn func() error) {
		if err := loops.Run(name, fn); err != nil && ctx.Err() == nil {
			s.log.Error(what+" failed", "err", err)
		}
	}
	var maintained time.Time
	for {
		// sweepAndRecord logs its own failures and records the job runs
		step("jit_sweep", "jit sweep", func() error { s.sweepAndRecord(ctx); return nil })
		if now := s.clock(); now.Sub(maintained) >= jobMaintainGap {
			if err := jobs.Maintain(ctx, s.store, now, jobStaleAfter, jobRetention); err != nil && ctx.Err() == nil {
				s.log.Error("job history upkeep failed", "err", err)
			}
			maintained = now
		}
		step("request_sweep", "request sweep", func() error {
			return requests.SweepAll(audit.WithSystemActor(ctx, requests.Sweeper), s.store, s.clock())
		})
		// sponsorships first: the last one to end ends the person, the lifecycle sweep then has nothing left
		step("sponsorship_sweep", "sponsorship sweep", func() error {
			return s.guests.SweepAll(audit.WithSystemActor(ctx, sponsorship.Sweeper), s.store, s.clock())
		})
		step("lifecycle_sweep", "lifecycle sweep", func() error {
			return lifecycle.SweepAll(audit.WithSystemActor(ctx, lifecycle.Sweeper), s.store, s.containment, s.clock())
		})
		step("containment_retries", "containment retry sweep", func() error {
			return s.containment.SweepRetries(audit.WithSystemActor(ctx, "containment.sweeper"), s.store, "containment.sweeper")
		})
		// apply the admin changes whose cooling-off ended and expire the ones
		// nobody approved in 72 hours (design §15.2)
		step("admin_change_sweep", "admin change sweep", func() error {
			_, err := s.admin.Sweep(audit.WithSystemActor(ctx, "admin.sweeper"))
			return err
		})
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// sweepTenant expires one tenant's JIT grants and closes its due request
// lines (requests.Sweep), taking the write lock only when there is work. The
// events name the sweepers, not the principal whose read happened to trigger
// the sweep.
func (s *Server) sweepTenant(ctx context.Context, t tenancy.ID) error {
	now := s.clock()
	var needJIT, needReq bool
	if err := s.store.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		if needJIT, err = jit.NeedsSweep(tx, now); err != nil {
			return err
		}
		needReq, err = requests.NeedsSweep(tx, now)
		return err
	}); err != nil {
		return err
	}
	if needJIT {
		if err := s.store.InTenant(audit.AsSystem(ctx, "jit.sweeper"), t, func(tx *store.TenantTx) error {
			_, err := jit.Sweep(tx, now)
			return err
		}); err != nil {
			return err
		}
	}
	if needReq {
		return s.store.InTenant(audit.AsSystem(ctx, requests.Sweeper), t, func(tx *store.TenantTx) error {
			_, err := requests.Sweep(tx, now)
			return err
		})
	}
	return nil
}

func (s *Server) policies() ([]*policy.Policy, error) { return s.cfg.Policies.Load() }

// ---------------------------------------------------------------- routing

type handlerFunc func(w http.ResponseWriter, r *http.Request, p *params) (any, error)

// tenantMode is how a route reaches tenant data (see registerRoutes).
type tenantMode int

const (
	noTenant tenantMode = iota
	read
	swept
	write
	// phased routes (readiness validation and dry runs) commit in several
	// transactions of the request's tenant: the handler opens them itself
	// through p.scope (readiness.Scope), never through store.TxFrom.
	phased
)

type route struct {
	method  string
	pattern string
	segs    []string
	tenant  tenantMode
	spec    Route
	h       handlerFunc
	// stream: the handler streams its response (StreamTimeout, unbuffered).
	stream bool
	// answersRead: a non-GET route whose response is computed data; it fails
	// closed like a read when its http.request event cannot be written
	// (audit.AnswersRead).
	answersRead bool
	// job: the route runs a job whose runs are recorded (jobs.go).
	job *jobSpec
}

// handle registers a route with its declared requirement (design §12.4). A
// non-public route without a permission, or a public route that is not on
// the allow-list (public_routes.go), or a public route that reaches tenant
// data, panics at startup.
func (s *Server) handle(method, pattern string, mode tenantMode, spec Route, h handlerFunc) *route {
	switch {
	case spec.Public && (spec.Perm != "" || spec.Authn != nil):
		panic(fmt.Sprintf("api: public route %s %s declares a permission", method, pattern))
	case spec.Public && mode != noTenant:
		panic(fmt.Sprintf("api: public route %s %s reaches tenant data", method, pattern))
	case spec.Public && !isPublicRoute(method, pattern):
		panic(fmt.Sprintf("api: %s %s is not on the public route allow-list", method, pattern))
	case !spec.Public && spec.Perm == "":
		panic(fmt.Sprintf("api: route %s %s declares no permission", method, pattern))
	}
	rt := &route{method: method, pattern: pattern, segs: strings.Split(strings.TrimPrefix(pattern, "/"), "/"), tenant: mode,
		spec: spec, h: h}
	s.routes = append(s.routes, rt)
	return rt
}

// RouteInfo describes a registered route.
type RouteInfo struct {
	Method, Pattern string
	// Tenant is true when the route runs inside a tenant transaction.
	Tenant bool
	// Write is true when that transaction can write.
	Write bool
	// Route is the declared requirement: Public, or Perm (and Authn).
	Route
}

// Routes lists every registered route (a plain http.ServeMux cannot list its
// patterns; tests enumerate this table).
func (s *Server) Routes() []RouteInfo {
	out := make([]RouteInfo, len(s.routes))
	for i, rt := range s.routes {
		out[i] = RouteInfo{rt.method, rt.pattern, rt.tenant != noTenant, rt.tenant == write || rt.tenant == phased, rt.spec}
	}
	return out
}

// serve runs the route's handler, inside a transaction of the principal's
// tenant unless the route touches no tenant data. This is the tenant
// middleware of design §5.2: the transaction commits only if the handler
// returns no error and rolls back otherwise, and handlers reach it with
// store.TxFrom. The tenant is the principal's, which comes only from its
// session row; a request without one never gets here.
func (s *Server) serve(rt *route, w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if rt.tenant == noTenant {
		return rt.h(w, r, p)
	}
	var t tenancy.ID
	if pr, ok := auth.PrincipalFrom(r.Context()); ok {
		t = pr.TenantID
	}
	if rt.job != nil && !t.IsZero() {
		return s.serveJob(rt, w, r, p, t)
	}
	return s.serveTenant(rt, w, r, p, t)
}

func (s *Server) serveTenant(rt *route, w http.ResponseWriter, r *http.Request, p *params, t tenancy.ID) (any, error) {
	ctx := r.Context()
	if rt.tenant == phased {
		if t.IsZero() {
			s.store.RecordContextMissing(ctx, r.Method+" "+r.URL.Path)
			return nil, store.ErrNoTenant
		}
		p.scope = readiness.Scope{DB: s.store, Tenant: t}
		return rt.h(w, r, p)
	}
	if rt.tenant == swept && !t.IsZero() {
		if err := s.sweepTenant(ctx, t); err != nil {
			return nil, err
		}
	}
	var out any
	run := func(tx *store.TenantTx) error {
		r := r.WithContext(store.WithTx(ctx, tx))
		p.r = r
		var err error
		out, err = rt.h(w, r, p)
		return err
	}
	var err error
	if rt.tenant == write {
		err = s.store.InTenant(ctx, t, run)
	} else {
		err = s.store.ReadTenant(ctx, t, run)
	}
	return out, err
}

func (rt *route) match(path string) (map[string]string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != len(rt.segs) {
		return nil, false
	}
	var vars map[string]string
	for i, seg := range rt.segs {
		if strings.HasPrefix(seg, "{") {
			if parts[i] == "" {
				return nil, false
			}
			if vars == nil {
				vars = map[string]string{}
			}
			vars[seg[1:len(seg)-1]] = parts[i]
		} else if seg != parts[i] {
			return nil, false
		}
	}
	return vars, true
}

func methodMatches(rm, m string) bool {
	return rm == m || (rm == http.MethodGet && m == http.MethodHead)
}

// find returns the route for method+path, or the methods allowed for the path.
func (s *Server) find(method, path string) (*route, map[string]string, []string) {
	var allowed []string
	for _, rt := range s.routes {
		vars, ok := rt.match(path)
		if !ok {
			continue
		}
		if methodMatches(rt.method, method) {
			return rt, vars, nil
		}
		allowed = append(allowed, rt.method)
		if rt.method == http.MethodGet {
			allowed = append(allowed, http.MethodHead)
		}
	}
	return nil, nil, allowed
}

func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) {
	rt, vars, allowed := s.find(r.Method, r.URL.Path)
	if rt == nil && len(allowed) == 0 && r.URL.Path != "/" {
		// Starlette's redirect_slashes: retry with the trailing slash toggled.
		alt := strings.TrimSuffix(r.URL.Path, "/")
		if alt == r.URL.Path {
			alt += "/"
		}
		// Only same-origin absolute paths that match a registered route are
		// redirected to; "//host" (protocol-relative) targets are refused.
		if strings.HasPrefix(alt, "/") && !strings.HasPrefix(alt, "//") {
			if rt2, _, allowed2 := s.find(r.Method, alt); rt2 != nil || len(allowed2) > 0 {
				u := url.URL{Path: alt, RawQuery: r.URL.RawQuery}
				http.Redirect(w, r, u.RequestURI(), http.StatusTemporaryRedirect) // #nosec G710 -- target is a registered same-origin route
				return
			}
		}
	}
	if rt == nil {
		// No route: nothing runs, but a signed-in caller's probe is still
		// attributed to them (and recorded in their tenant's chain).
		s.attribute(r)
		if len(allowed) > 0 {
			slices.Sort(allowed)
			w.Header().Set("Allow", strings.Join(slices.Compact(allowed), ", "))
			writeJSON(w, http.StatusMethodNotAllowed, detail("Method Not Allowed"))
			return
		}
		writeJSON(w, http.StatusNotFound, detail("Not Found"))
		return
	}
	audit.SetRoute(r.Context(), rt.pattern, vars)
	obs.SetRoute(r.Context(), rt.method+" "+rt.pattern) // the pattern, never the raw path: bounded metric labels
	if rt.answersRead {
		audit.AnswersRead(r.Context())
	}
	r, ok := s.authorize(w, r, rt)
	if !ok {
		return
	}
	if d, ok := r.Context().Value(streamDeadlineKey{}).(time.Time); ok && rt.stream {
		ctx, cancel := context.WithDeadline(r.Context(), d)
		defer cancel()
		r = r.WithContext(ctx)
	}
	p := &params{r: r, path: vars}
	out, err := s.serve(rt, w, r, p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if out == nil {
		return // handler wrote the response itself
	}
	if sb, ok := out.(statusBody); ok {
		writeJSON(w, sb.status, sb.body)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// attribute hands the request's principal, if it has a valid session, to the
// audit middleware without authorizing anything.
func (s *Server) attribute(r *http.Request) {
	p, reason, err := s.authn.Authenticate(r)
	switch {
	case err != nil:
		audit.SetAnonymous(r.Context(), "authentication_error")
	case p == nil:
		audit.SetAnonymous(r.Context(), reason)
	default:
		markAuthenticated(r.Context())
		sid := p.SessionID.String()
		audit.SetPrincipal(r.Context(), audit.Principal{Tenant: p.TenantID, Actor: p.AuditActor(), SessionID: &sid,
			Authn: p.AuditAuthn(s.clock())})
	}
}

// ---------------------------------------------------------------- responses

// httpError is an HTTPException: {"detail": msg} with a status code.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func errStatus(status int, msg string) error { return &httpError{status, msg} }

func detail(msg string) ojson.Object { return ojson.Object{{Key: "detail", Value: msg}} }

// statusBody is a response body sent with a status other than 200. It is
// written after the request's tenant transaction commits.
type statusBody struct {
	status int
	body   any
}

// rawJSON is a pre-encoded JSON response body.
type rawJSON []byte

func writeJSON(w http.ResponseWriter, status int, v any) {
	var body []byte
	if raw, ok := v.(rawJSON); ok {
		body = raw
	} else {
		var err error
		if body, err = ojson.Marshal(v); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body) // #nosec G705 -- JSON-encoded body served as application/json with nosniff, never HTML
}

// timedOut reports whether err comes from the request's deadline passing: the
// error wraps context.DeadlineExceeded, or the driver reported it in its own
// words after the request context expired.
func timedOut(r *http.Request, err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(r.Context().Err(), context.DeadlineExceeded)
}

// writeTimedOut answers with the same 503 http.TimeoutHandler sends, so a
// request whose deadline passed inside the handler gets one answer whichever
// of the two writes first.
func writeTimedOut(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, detail("Request timed out"))
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var he *httpError
	var ve *validationError
	var re *readiness.Error
	var te *transport.Error
	var dn denial
	var ae *admin.Error
	switch {
	case errors.As(err, &dn):
		auth.WriteDenial(w, dn.d)
	case errors.As(err, &ae) && ae.Denial != nil:
		auth.WriteDenial(w, ae.Denial)
	case errors.As(err, &ae):
		writeJSON(w, ae.Status, ojson.Object{{Key: "error", Value: ae.Code}, {Key: "detail", Value: ae.Msg}})
	case errors.As(err, &re):
		writeJSON(w, re.Status, readinessErrorBody(re))
	case errors.As(err, &te):
		writeJSON(w, te.Status, map[string]any{"error": te.Code, "detail": te.Msg})
	case errors.As(err, &he):
		writeJSON(w, he.status, detail(he.msg))
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, ve.body())
	case errors.Is(err, errBodyTooLarge):
		writeJSON(w, http.StatusRequestEntityTooLarge, detail("Request body too large"))
	case errors.Is(err, errBodyUnreadable):
		writeJSON(w, http.StatusBadRequest, detail("There was an error parsing the body"))
	case errors.Is(err, context.Canceled):
		// client went away; nothing useful to send
	case timedOut(r, err):
		writeTimedOut(w)
	default:
		// Never echo internal errors (they may contain SQL or paths) to the client.
		s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// ---------------------------------------------------------------- middleware

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Flush lets a streamed response through (http.Flusher).
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying writer to http.ResponseController.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// logRequests logs one line per request: method, path, status and duration.
// Query strings, headers and bodies are deliberately not logged (they can
// carry search terms, personal data or credentials).
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration_ms", float64(time.Since(start).Microseconds())/1000)
	})
}

func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler {
					panic(p)
				}
				if _, ok := p.(store.MissingTenantContext); ok {
					// A handler reached tenant data without the tenant wrapper:
					// fail closed and record it on the platform tenant.
					s.store.RecordContextMissing(r.Context(), r.Method+" "+r.URL.Path)
				}
				s.log.Error("panic serving request", "method", r.Method, "path", r.URL.Path, "panic", p,
					"stack", string(debug.Stack()))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > s.cfg.MaxBodyBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, detail("Request body too large"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// cors allows the configured UI origins only (exact match, never a wildcard):
// with credentials, so the dev UI on another origin can send its session
// cookie. Production is same-origin and configures no origins (§11).
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Origin")
		allowed := slices.Contains(s.cfg.AllowedOrigins, origin)
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			if !allowed {
				http.Error(w, "Disallowed CORS origin", http.StatusBadRequest)
				return
			}
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			if req := r.Header.Get("Access-Control-Request-Headers"); req != "" {
				h.Set("Access-Control-Allow-Headers", "Content-Type, "+auth.CSRFHeader)
			}
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusOK)
			return
		}
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		next.ServeHTTP(w, r)
	})
}

// Content-Security-Policy values. The API serves JSON, so it allows nothing
// but itself and is never framed. The Swagger UI and ReDoc pages (the
// FastAPI-generated HTML) load their bundles from jsDelivr and inline a
// small bootstrap script, so they get a policy that allows exactly that.
const (
	cspAPI  = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	cspDocs = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
		"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; " +
		"font-src https://fonts.gstatic.com; img-src 'self' data: https://fastapi.tiangolo.com https://cdn.redoc.ly; " +
		"worker-src blob:; frame-ancestors 'none'; base-uri 'none'"
)

// securityHeaders sets the headers of design §5.2 on every response.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		switch r.URL.Path {
		case "/docs", "/redoc", "/docs/oauth2-redirect":
			h.Set("Content-Security-Policy", cspDocs)
		default:
			h.Set("Content-Security-Policy", cspAPI)
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/t/") {
			h.Set("Cache-Control", "no-store")
		}
		if s.cfg.HSTS {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
