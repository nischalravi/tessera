package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit/canon"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// The http.request event and fail-closed reads (design §13.4).
//
// Middleware runs the handler against a buffering ResponseWriter, so nothing
// reaches the client yet. It then appends one http.request event in a new
// short transaction of the request's tenant (or _platform). If that append
// fails, a GET or HEAD (a read of customer data) is answered with 503
// {"error":"audit_unavailable"} and the buffered body is dropped: no data
// leaves without a record. Another method gets the same 503 unless its
// domain event already committed with its change (counted through
// store.AuditContext.Committed): then the change is recorded and done, so its
// real response is sent and the failure is logged as critical and counted.
// A POST that records nothing (a validation error, a no-op) therefore fails
// closed like a read, and so does a route marked with AnswersRead (a POST that
// computes an answer, such as a simulation): an incidental event it commits
// on the way (a JIT expiry swept before the analysis) does not record the
// answer.
//
// The actor is the authenticated principal, which the API's authenticator
// hands over with SetPrincipal (with its tenant, session and authn summary),
// or "anonymous" with the reason authentication failed (SetAnonymous). A
// client cannot choose it: nothing in the request body or headers is read to
// attribute the event.

// AnonymousReason is recorded on an anonymous event whose request never
// reached an authenticator (an unknown route, for example).
const AnonymousReason = "unauthenticated"

// MiddlewareConfig configures Middleware.
type MiddlewareConfig struct {
	DB *store.DB
	// Tenant returns the request's tenant; zero means the _platform chain.
	Tenant func(*http.Request) tenancy.ID
	Clock  timeutil.Clock
	Log    *slog.Logger
	// Append writes the event. The default opens DB.InTenant and appends;
	// tests inject failures here.
	Append func(ctx context.Context, t tenancy.ID, e store.AuditEvent) error
	// Excluded reports requests that are not recorded (default: GET
	// /api/health and the public /.well-known documents, which carry no
	// tenant data).
	Excluded func(*http.Request) bool
}

var writeFailures atomic.Int64

// WriteFailures is audit_write_failures_total: http.request events that could
// not be written.
func WriteFailures() int64 { return writeFailures.Load() }

// DefaultExcluded is the design's exclusion list.
func DefaultExcluded(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	p := r.URL.Path
	if p == "/api/health" || strings.HasPrefix(p, "/.well-known/") {
		return true
	}
	if rest, ok := strings.CutPrefix(p, "/t/"); ok {
		if i := strings.IndexByte(rest, '/'); i > 0 && strings.HasPrefix(rest[i:], "/.well-known/") {
			return true
		}
	}
	return false
}

type stateKey struct{}

// reqState is shared between the middleware and the router (SetRoute) and a
// streaming handler (StartStream). The router may run on another goroutine
// (http.TimeoutHandler), so it is locked.
type reqState struct {
	mu        sync.Mutex
	route     *string
	params    map[string]string
	committed atomic.Int64 // domain events this request committed
	read      bool         // AnswersRead: fail closed whatever the method
	recorded  bool
	streaming bool
	start     time.Time
	at        time.Time
	requestID string
	tenant    tenancy.ID
	actor     store.AuditActor
	sessionID *string
	clientID  *string // the OAuth client of a token principal
	authn     json.RawMessage
	anonWhy   string
	cfg       *MiddlewareConfig
	r         *http.Request
	bw        *bufferedWriter
}

// SetRoute tells the middleware which registered route served the request
// (its pattern, never the raw path) and its path parameters.
func SetRoute(ctx context.Context, pattern string, params map[string]string) {
	st, ok := ctx.Value(stateKey{}).(*reqState)
	if !ok {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.route = &pattern
	st.params = make(map[string]string, len(params))
	for k, v := range params {
		st.params[k] = v
	}
}

// Principal is the authenticated caller of a request, as the audit ledger
// records it.
type Principal struct {
	Tenant    tenancy.ID
	Actor     store.AuditActor
	SessionID *string
	ClientID  *string
	Authn     json.RawMessage // canon.Authn
}

// SetPrincipal attributes the request to p: its http.request event goes to
// p.Tenant's chain with p's actor, session and authn summary, and so does
// every domain event written through a transaction opened with the returned
// context. Call it once, after authentication, before the handler runs.
func SetPrincipal(ctx context.Context, p Principal) context.Context {
	st, ok := ctx.Value(stateKey{}).(*reqState)
	if ok {
		st.mu.Lock()
		st.tenant, st.actor, st.sessionID, st.clientID, st.authn, st.anonWhy = p.Tenant, p.Actor, p.SessionID, p.ClientID, p.Authn, ""
		st.mu.Unlock()
	}
	ac, _ := store.AuditContextFrom(ctx)
	ac.Actor, ac.SessionID, ac.ClientID, ac.Authn = p.Actor, p.SessionID, p.ClientID, p.Authn
	return store.WithAuditContext(ctx, ac)
}

// SetAnonymous records why the request is anonymous (public route, no
// session, expired session, ...); it is kept as detail.anonymous_reason.
func SetAnonymous(ctx context.Context, reason string) {
	if st, ok := ctx.Value(stateKey{}).(*reqState); ok {
		st.mu.Lock()
		st.anonWhy = reason
		st.mu.Unlock()
	}
}

// AnswersRead marks the request as a read for the fail-closed rule: its
// response is replaced by 503 audit_unavailable if its http.request event
// cannot be written, whatever its method and whatever it committed. For
// routes such as POST /api/simulate whose response is computed data.
func AnswersRead(ctx context.Context) {
	if st, ok := ctx.Value(stateKey{}).(*reqState); ok {
		st.mu.Lock()
		st.read = true
		st.mu.Unlock()
	}
}

// RequestID returns the request id the middleware assigned.
func RequestID(ctx context.Context) string {
	if st, ok := ctx.Value(stateKey{}).(*reqState); ok {
		return st.requestID
	}
	return ""
}

// ErrUnavailable is returned by StartStream when the event cannot be written.
var ErrUnavailable = errors.New("audit: audit_unavailable")

// StartStream is for handlers that stream a response too large to buffer
// (GET /api/audit/export): it writes the request's http.request event now,
// with status 200 and outcome success, and lets later writes through
// unbuffered. If the event cannot be written it returns ErrUnavailable and
// the handler must answer 503 without data. A failure later in the stream
// is the handler's to record as a second event.
func StartStream(r *http.Request) error {
	st, ok := r.Context().Value(stateKey{}).(*reqState)
	if !ok {
		return nil // not behind the middleware (unit tests of handlers)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.recorded {
		return nil
	}
	if err := st.appendLocked(http.StatusOK); err != nil {
		return ErrUnavailable
	}
	st.recorded, st.streaming = true, true
	if st.bw != nil {
		st.bw.passthrough()
	}
	return nil
}

// Middleware returns the audit middleware.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Clock == nil {
		cfg.Clock = timeutil.System
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Excluded == nil {
		cfg.Excluded = DefaultExcluded
	}
	if cfg.Append == nil {
		db := cfg.DB
		cfg.Append = func(ctx context.Context, t tenancy.ID, e store.AuditEvent) error {
			return db.InTenant(ctx, t, func(tx *store.TenantTx) error {
				_, err := tx.AppendAudit(e)
				return err
			})
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Excluded(r) {
				next.ServeHTTP(w, r)
				return
			}
			st := &reqState{start: time.Now(), at: cfg.Clock(), requestID: uuid.NewString(), cfg: &cfg,
				actor: store.AuditActor{Type: store.ActorAnonymous}, anonWhy: AnonymousReason}
			if cfg.Tenant != nil {
				st.tenant = cfg.Tenant(r)
			}
			if st.tenant.IsZero() {
				st.tenant = tenancy.Platform
			}
			ip, ua := clientIP(r), uaHash(r)
			ctx := context.WithValue(r.Context(), stateKey{}, st)
			ctx = store.WithAuditContext(ctx, store.AuditContext{
				Actor:     store.AuditActor{Type: store.ActorAnonymous},
				RequestID: &st.requestID, IP: ip, UAHash: ua, Committed: &st.committed,
			})
			r = r.WithContext(ctx)
			st.r = r
			bw := &bufferedWriter{under: w, header: http.Header{}}
			st.bw = bw
			bw.header.Set("X-Request-Id", st.requestID)
			next.ServeHTTP(bw, r)

			st.mu.Lock()
			defer st.mu.Unlock()
			if st.recorded {
				bw.flush()
				return
			}
			status := bw.status
			if status == 0 {
				status = http.StatusOK
			}
			if err := st.appendLocked(status); err != nil {
				read := st.read || r.Method == http.MethodGet || r.Method == http.MethodHead
				if read || st.committed.Load() == 0 {
					bw.discard()
					h := w.Header()
					h.Set("Content-Type", "application/json")
					h.Set("Cache-Control", "no-store")
					h.Set("X-Request-Id", st.requestID)
					w.WriteHeader(http.StatusServiceUnavailable)
					body, _ := ojson.Marshal(ojson.Object{{Key: "error", Value: "audit_unavailable"},
						{Key: "request_id", Value: st.requestID}})
					_, _ = w.Write(body)
					return
				}
			}
			bw.flush()
		})
	}
}

// appendLocked builds and writes the http.request event (st.mu held).
func (st *reqState) appendLocked(status int) error {
	r, cfg := st.r, st.cfg
	params := make(map[string]string, len(st.params))
	for k, v := range st.params {
		params[truncate(k, 64)] = truncate(v, 256)
	}
	keys := []string{}
	for k := range r.URL.Query() {
		keys = append(keys, truncate(k, 128))
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	if len(keys) > 64 {
		keys = keys[:64]
	}
	latency := time.Since(st.start).Milliseconds()
	h, err := json.Marshal(canon.HTTP{Method: truncate(r.Method, 16), Route: st.route, PathParams: params,
		QueryKeys: keys, Status: status, LatencyMS: max(latency, 0)})
	if err != nil {
		return err
	}
	ac, _ := store.AuditContextFrom(r.Context())
	d := ojson.Object{}
	if st.actor.Type == store.ActorAnonymous {
		d = append(d, ojson.KV{Key: "anonymous_reason", Value: st.anonWhy})
	}
	detail, err := canon.Detail(d)
	if err != nil {
		return err
	}
	e := store.AuditEvent{OccurredAt: st.at, ActorType: st.actor.Type, ActorID: st.actor.ID, ActorDisplay: st.actor.Display,
		SessionID: st.sessionID, ClientID: st.clientID, Authn: st.authn, Action: store.ActionHTTPRequest,
		Outcome: outcome(status), RequestID: &st.requestID, HTTP: h, IP: ac.IP, UserAgentSHA256: ac.UAHash, Detail: detail}
	if st.route != nil {
		e.TargetType, e.TargetID = target(*st.route, params)
	}
	ctx := context.WithoutCancel(r.Context()) // a client that went away is still recorded
	if err := cfg.Append(ctx, st.tenant, e); err != nil {
		writeFailures.Add(1)
		cfg.Log.ErrorContext(ctx, "audit write failed", "critical", true, "request_id", st.requestID,
			"method", r.Method, "route", deref(st.route), "status", status, "err", err,
			"audit_write_failures_total", writeFailures.Load())
		return err
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func outcome(status int) string {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return store.OutcomeDenied
	case status >= 500:
		return store.OutcomeError
	case status >= 400:
		return store.OutcomeFailure
	}
	return store.OutcomeSuccess
}

// target derives the event target from the route's path parameters: the last
// "<type>_id" parameter, or an "{id}" named by the segment before it
// ("/api/connections/{id}" -> connection).
func target(pattern string, params map[string]string) (*string, *string) {
	segs := strings.Split(strings.Trim(pattern, "/"), "/")
	var typ, id string
	for i, s := range segs {
		if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
			continue
		}
		name := s[1 : len(s)-1]
		switch {
		case strings.HasSuffix(name, "_id"):
			typ, id = strings.TrimSuffix(name, "_id"), params[name]
		case name == "id" && i > 0:
			typ, id = strings.TrimSuffix(segs[i-1], "s"), params[name]
		}
	}
	if typ == "" || id == "" {
		return nil, nil
	}
	return &typ, &id
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// clientIP is the TCP peer address. Forwarding headers are not trusted (the
// trusted-proxy list arrives with deployment behind a load balancer).
func clientIP(r *http.Request) *string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "" {
		return nil
	}
	host = truncate(host, 64)
	return &host
}

// uaHash is the SHA-256 of the User-Agent (it is stored only as a hash).
func uaHash(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(ua))
	s := hex.EncodeToString(sum[:])
	return &s
}

// ---------------------------------------------------------------- buffering

// bufferedWriter holds the response until the event is written. After
// StartStream it passes writes through.
type bufferedWriter struct {
	under   http.ResponseWriter
	header  http.Header
	status  int
	body    bytes.Buffer
	through atomic.Bool
	wrote   bool // headers sent to under
	mu      sync.Mutex
}

func (b *bufferedWriter) Header() http.Header { return b.header }

// Unwrap exposes the underlying writer to http.ResponseController (a stream
// extends its write deadline through it).
func (b *bufferedWriter) Unwrap() http.ResponseWriter { return b.under }

func (b *bufferedWriter) WriteHeader(code int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.status == 0 {
		b.status = code
	}
	if b.through.Load() {
		b.sendHeaderLocked()
	}
}

func (b *bufferedWriter) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.status == 0 {
		b.status = http.StatusOK
	}
	if b.through.Load() {
		b.sendHeaderLocked()
		return b.under.Write(p)
	}
	return b.body.Write(p)
}

// Flush flushes a streaming response.
func (b *bufferedWriter) Flush() {
	if !b.through.Load() {
		return
	}
	b.mu.Lock()
	b.sendHeaderLocked()
	b.mu.Unlock()
	if f, ok := b.under.(http.Flusher); ok {
		f.Flush()
	}
}

func (b *bufferedWriter) sendHeaderLocked() {
	if b.wrote {
		return
	}
	b.wrote = true
	h := b.under.Header()
	for k, v := range b.header {
		h[k] = v
	}
	status := b.status
	if status == 0 {
		status = http.StatusOK
	}
	b.under.WriteHeader(status)
}

// passthrough sends what is buffered and lets later writes through.
func (b *bufferedWriter) passthrough() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.through.Store(true)
	if b.status != 0 || b.body.Len() > 0 {
		b.sendHeaderLocked()
		_, _ = b.under.Write(b.body.Bytes()) // #nosec G705 -- replays the handler's own response bytes and headers unchanged
		b.body.Reset()
	}
}

func (b *bufferedWriter) flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.through.Load() {
		if !b.wrote && b.status != 0 {
			b.sendHeaderLocked()
		}
		return
	}
	b.sendHeaderLocked()
	if b.body.Len() > 0 {
		_, _ = b.under.Write(b.body.Bytes()) // #nosec G705 -- replays the handler's own response bytes and headers unchanged
	}
}

func (b *bufferedWriter) discard() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.body.Reset()
}
