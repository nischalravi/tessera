// Package api is Tessera's REST API.
//
// The HTTP contract (routes, status codes, JSON bodies, key order and the
// FastAPI/pydantic-style 422 validation errors) is the one the original Python
// backend served; testdata/parity holds the recorded golden responses.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/jit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/template"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// DefaultMaxBodyBytes caps request bodies (every request body is a small JSON object).
const DefaultMaxBodyBytes = 1 << 20

// DefaultHandlerTimeout bounds the time a handler may run.
const DefaultHandlerTimeout = 30 * time.Second

// Config configures a Server.
type Config struct {
	Store *store.DB
	// Tenant is the tenant every request is served for until authentication
	// lands (Phase 0 PR5): cmd/tessera resolves it with store.DevDefaultTenant,
	// which only works when TESSERA_ENV=dev. The zero value fails closed: every
	// tenant route answers 500 and records tenancy.context_missing.
	Tenant   tenancy.ID
	Clock    timeutil.Clock // defaults to timeutil.System
	Policies *policy.Loader // required
	// Connectors returns the configured connectors (defaults to connectors.Load("", now)).
	Connectors func(now time.Time) ([]connectors.Connector, error)
	Logger     *slog.Logger // defaults to slog.Default()
	// AllowedOrigins are the browser origins allowed by CORS (exact match).
	AllowedOrigins []string
	MaxBodyBytes   int64         // defaults to DefaultMaxBodyBytes
	HandlerTimeout time.Duration // defaults to DefaultHandlerTimeout; <0 disables
	// Readiness is the deployment-readiness service (defaults to the
	// embedded templates and Env).
	Readiness *readiness.Service
	// Env is TESSERA_ENV ("dev" allows activating non-demo connector types).
	Env string
	// ReadinessScenario selects the simulated validation scenario
	// (TESSERA_READINESS_SCENARIO; default "gaps").
	ReadinessScenario string
	// AuditAnchor is TESSERA_AUDIT_ANCHOR: POST /api/audit/verify checks
	// checkpoints against it when it is a file:// URL.
	AuditAnchor string
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

	readiness *readiness.Service
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
	if cfg.Readiness == nil {
		reg, err := template.Default()
		if err != nil {
			panic(err) // the embedded templates are linted by TestTemplates_Lint
		}
		cfg.Readiness = readiness.NewService(reg, cfg.Env)
		cfg.Readiness.Runner.Scenario = cfg.ReadinessScenario
	}
	s := &Server{cfg: cfg, store: cfg.Store, clock: cfg.Clock, log: cfg.Logger, readiness: cfg.Readiness}
	s.registerRoutes()
	s.registerAuditRoutes()
	s.registerReadinessRoutes()
	return s
}

// Handler returns the HTTP handler with all middleware applied.
func (s *Server) Handler() http.Handler {
	var h http.Handler = http.HandlerFunc(s.dispatch)
	if s.cfg.HandlerTimeout > 0 {
		h = http.TimeoutHandler(h, s.cfg.HandlerTimeout, `{"detail":"Request timed out"}`)
	}
	h = s.limitBody(h)
	h = s.cors(h)
	h = s.recoverPanics(h)
	// One http.request event per request; reads are buffered and refused
	// with 503 if the event cannot be written (design §13.4).
	h = audit.Middleware(audit.MiddlewareConfig{DB: s.store, Tenant: s.auditTenant, Clock: s.clock, Log: s.log,
		Append: s.cfg.AuditAppend})(h)
	h = s.logRequests(h)
	return securityHeaders(h)
}

// RunSweeper expires JIT grants of every active tenant, each in its own
// tenant transaction, every interval until ctx is done. A failure in one
// tenant is logged and does not stop the others.
func (s *Server) RunSweeper(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := jit.SweepAll(ctx, s.store, s.clock()); err != nil && ctx.Err() == nil {
			s.log.Error("jit sweep failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// sweepTenant expires one tenant's JIT grants, taking the write lock only
// when there is work.
func (s *Server) sweepTenant(ctx context.Context, t tenancy.ID) error {
	now := s.clock()
	var need bool
	if err := s.store.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		need, err = jit.NeedsSweep(tx, now)
		return err
	}); err != nil || !need {
		return err
	}
	return s.store.InTenant(ctx, t, func(tx *store.TenantTx) error {
		_, err := jit.Sweep(tx, now)
		return err
	})
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
	h       handlerFunc
}

func (s *Server) handle(method, pattern string, mode tenantMode, h handlerFunc) {
	s.routes = append(s.routes, &route{method, pattern, strings.Split(strings.TrimPrefix(pattern, "/"), "/"), mode, h})
}

// RouteInfo describes a registered route.
type RouteInfo struct {
	Method, Pattern string
	// Tenant is true when the route runs inside a tenant transaction.
	Tenant bool
	// Write is true when that transaction can write.
	Write bool
}

// Routes lists every registered route (a plain http.ServeMux cannot list its
// patterns; tests enumerate this table).
func (s *Server) Routes() []RouteInfo {
	out := make([]RouteInfo, len(s.routes))
	for i, rt := range s.routes {
		out[i] = RouteInfo{rt.method, rt.pattern, rt.tenant != noTenant, rt.tenant == write || rt.tenant == phased}
	}
	return out
}

// serve runs the route's handler, inside a transaction of the request's
// tenant unless the route touches no tenant data. This is the tenant
// middleware of design §5.2: the transaction commits only if the handler
// returns no error and rolls back otherwise, and handlers reach it with
// store.TxFrom.
func (s *Server) serve(rt *route, w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if rt.tenant == noTenant {
		return rt.h(w, r, p)
	}
	ctx, t := r.Context(), s.cfg.Tenant
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

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var he *httpError
	var ve *validationError
	var re *readiness.Error
	switch {
	case errors.As(err, &re):
		writeJSON(w, re.Status, readinessErrorBody(re))
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

// cors allows the configured UI origins only (exact match, no credentials).
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
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			if req := r.Header.Get("Access-Control-Request-Headers"); req != "" {
				h.Set("Access-Control-Allow-Headers", "Content-Type")
			}
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusOK)
			return
		}
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
