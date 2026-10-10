package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

const secretData = `{"identities":["ZZ-SECRET-ROW"]}`

type capture struct {
	mu     sync.Mutex
	events []store.AuditEvent
	fail   error
}

func (c *capture) append(_ context.Context, _ tenancy.ID, e store.AuditEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	c.events = append(c.events, e)
	return nil
}

func mw(c *capture, h http.Handler) http.Handler {
	return audit.Middleware(audit.MiddlewareConfig{Append: c.append, Clock: timeutil.Frozen(t0),
		Tenant: func(*http.Request) tenancy.ID { return tenantA }})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		audit.SetRoute(r.Context(), "/api/things/{thing_id}", map[string]string{"thing_id": "7"})
		h.ServeHTTP(w, r)
	}))
}

var dataHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Leaky", "1")
	_, _ = w.Write([]byte(secretData))
})

// TestReadFailsClosed (E2.4): when the event cannot be written, a GET or
// HEAD gets 503 audit_unavailable and none of the handler's body or headers;
// a POST (whose domain event committed with its change) gets its response.
func TestReadFailsClosed(t *testing.T) {
	c := &capture{fail: errors.New("database is locked")}
	h := mw(c, dataHandler)
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/api/things/7", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d, want 503", m, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "ZZ-SECRET-ROW") || rec.Header().Get("X-Leaky") != "" {
			t.Errorf("%s leaked the buffered response: %q %v", m, rec.Body.String(), rec.Header())
		}
		if m == http.MethodGet {
			var body struct {
				Error     string `json:"error"`
				RequestID string `json:"request_id"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error != "audit_unavailable" ||
				body.RequestID == "" || body.RequestID != rec.Header().Get("X-Request-Id") {
				t.Errorf("503 body %q", rec.Body.String())
			}
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/things/7", strings.NewReader("{}")))
	if rec.Code != http.StatusOK || rec.Body.String() != secretData {
		t.Errorf("POST: %d %q, want the real response", rec.Code, rec.Body.String())
	}
	c.fail = nil
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/things/7", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != secretData || rec.Header().Get("X-Leaky") != "1" {
		t.Errorf("healthy GET: %d %q", rec.Code, rec.Body.String())
	}
}

// TestMiddleware_ActorNeverFromClient: whatever identity headers or bodies a
// client sends, the event's actor is anonymous until PR5.
func TestMiddleware_ActorNeverFromClient(t *testing.T) {
	c := &capture{}
	var seen store.AuditContext
	h := mw(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = store.AuditContextFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/things/7?b=2&a=1&a=3", strings.NewReader(`{"actor":"root"}`))
	for k, v := range map[string]string{"X-Tessera-User": "root", "Authorization": "Bearer x", "X-Forwarded-For": "10.0.0.1",
		"X-Request-Id": "attacker-chosen", "User-Agent": "curl/8"} {
		req.Header.Set(k, v)
	}
	req.RemoteAddr = "192.0.2.10:5555"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if len(c.events) != 1 {
		t.Fatalf("%d events", len(c.events))
	}
	e := c.events[0]
	if e.ActorType != store.ActorAnonymous || e.ActorID != nil || e.ActorDisplay != nil || seen.Actor.Type != store.ActorAnonymous {
		t.Errorf("actor %s %v", e.ActorType, e.ActorID)
	}
	if e.IP == nil || *e.IP != "192.0.2.10" {
		t.Errorf("ip %v (forwarding headers must not be trusted)", e.IP)
	}
	if e.RequestID == nil || *e.RequestID == "attacker-chosen" {
		t.Error("client chose the request id")
	}
	if e.UserAgentSHA256 == nil || strings.Contains(*e.UserAgentSHA256, "curl") || len(*e.UserAgentSHA256) != 64 {
		t.Errorf("user agent not hashed: %v", e.UserAgentSHA256)
	}
	var hf struct {
		Route     string
		QueryKeys []string `json:"query_keys"`
		Status    int
	}
	if err := json.Unmarshal(e.HTTP, &hf); err != nil {
		t.Fatal(err)
	}
	if hf.Route != "/api/things/{thing_id}" || strings.Join(hf.QueryKeys, ",") != "a,b" || hf.Status != 204 {
		t.Errorf("http %s", e.HTTP)
	}
	if e.TargetType == nil || *e.TargetType != "thing" || *e.TargetID != "7" || e.Outcome != store.OutcomeSuccess {
		t.Errorf("target %v %v outcome %s", e.TargetType, e.TargetID, e.Outcome)
	}
	if !strings.Contains(string(e.Detail), audit.AnonymousReason) {
		t.Errorf("detail %s", e.Detail)
	}
}

func TestMiddleware_ExcludedAndOutcomes(t *testing.T) {
	c := &capture{}
	status := http.StatusOK
	h := mw(c, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
	for _, p := range []string{"/api/health", "/.well-known/oauth-protected-resource", "/t/acme/.well-known/jwks.json"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}
	if len(c.events) != 0 {
		t.Errorf("excluded paths wrote %d events", len(c.events))
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/health", nil))
	if len(c.events) != 1 {
		t.Error("only GET /api/health is excluded")
	}
	for st, want := range map[int]string{200: "success", 401: "denied", 403: "denied", 404: "failure", 422: "failure", 500: "error", 503: "error"} {
		c.events, status = nil, st
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/things/7", nil))
		if len(c.events) != 1 || c.events[0].Outcome != want {
			t.Errorf("status %d: %v", st, c.events)
		}
	}
}

// TestStartStream: a streaming handler's event is written before its first
// byte, once; if it cannot be, the handler gets ErrUnavailable.
func TestStartStream(t *testing.T) {
	c := &capture{}
	var during int
	h := mw(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := audit.StartStream(r); err != nil {
			http.Error(w, `{"error":"audit_unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		during = len(c.events)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("line1\n"))
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("line2\n"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/things/7", nil))
	if during != 1 || len(c.events) != 1 || rec.Body.String() != "line1\nline2\n" || !rec.Flushed {
		t.Errorf("events before streaming %d, after %d, body %q flushed %v", during, len(c.events), rec.Body.String(), rec.Flushed)
	}
	c.fail = errors.New("down")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/things/7", nil))
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "line") {
		t.Errorf("stream with a failing ledger: %d %q", rec.Code, rec.Body.String())
	}
}
