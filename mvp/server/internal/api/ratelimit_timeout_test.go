package api

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// TestRateLimit_AuthenticatedFlagOutlivesTimeout (#270): http.TimeoutHandler
// returns when the timeout fires while its handler goroutine keeps running, so
// the handler can mark the request authenticated while rateLimit reads the
// flag. Under -race this failed when the flag was a plain bool.
func TestRateLimit_AuthenticatedFlagOutlivesTimeout(t *testing.T) {
	srv, _ := seededServer(t)
	srv.limits = newLimiters(noRateLimits)
	done := make(chan struct{})
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		defer func() { done <- struct{}{} }()
		<-r.Context().Done() // the timeout has fired; the middleware is returning
		markAuthenticated(r.Context())
	})
	h := srv.rateLimit(http.TimeoutHandler(inner, time.Millisecond, `{"detail":"Request timed out"}`))
	for i := 0; i < 50; i++ {
		req := fromIP(httptest.NewRequest("GET", "/api/identities", nil), "198.51.100.7:1000")
		req.AddCookie(auth.Cookies{}.Session(auth.NewSecret()))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		<-done
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("request %d: status %d, want 503", i, rec.Code)
		}
	}
}

// TestHandlerTimeout_NeverInternalError (#270): a signed-in request that
// outlives HandlerTimeout answers the documented 503, never 500, however the
// timeout races the handler's authentication.
func TestHandlerTimeout_NeverInternalError(t *testing.T) {
	st, _ := testkit.Tiny(t)
	srv := New(Config{Store: st.DB, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), HandlerTimeout: 5 * time.Millisecond,
		RateLimits: noRateLimits})
	srv.handle("GET", "/api/slow", read, need(auth.PermGraphRead), func(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	h := signIn(t, st.DB, st.Tenant, testAdmin, authtest.Phr, testkit.Now).Handler(srv.Handler())
	for i := 0; i < 20; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/slow", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("request %d: status %d, want 503; body %q", i, rec.Code, rec.Body.String())
		}
	}
}

// TestClientAbort_NotAnAuthFailure (#310): a client that hangs up while its
// session is being checked is logged as neither an authentication failure nor
// an audit write failure, and the answer is not a 503 (which reads as an
// outage). A request whose deadline passed keeps the documented 503.
func TestClientAbort_NotAnAuthFailure(t *testing.T) {
	st, _ := testkit.Tiny(t)
	var logs bytes.Buffer
	srv := New(Config{Store: st.DB, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(&logs, nil)), RateLimits: noRateLimits})
	srv.handle("GET", "/api/abort", read, need(auth.PermGraphRead), func(_ http.ResponseWriter, _ *http.Request, _ *params) (any, error) {
		return map[string]string{"ok": "1"}, nil
	})
	h := signIn(t, st.DB, st.Tenant, testAdmin, authtest.Phr, testkit.Now).Handler(srv.Handler())

	for _, c := range []struct {
		name     string
		deadline bool
		wantCode int
	}{
		{"client abort", false, statusClientClosed},
		{"deadline", true, http.StatusServiceUnavailable},
	} {
		t.Run(c.name, func(t *testing.T) {
			logs.Reset()
			ctx, cancel := context.WithCancel(context.Background())
			if c.deadline {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			} else {
				cancel()
			}
			defer cancel()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/abort", nil).WithContext(ctx))
			if rec.Code != c.wantCode {
				t.Errorf("status %d, want %d; body %q", rec.Code, c.wantCode, rec.Body.String())
			}
			for _, bad := range []string{"authentication failed", "audit write failed", "audit_unavailable"} {
				if strings.Contains(logs.String(), bad) || strings.Contains(rec.Body.String(), bad) {
					t.Errorf("reported %q for a request the client gave up on: %s", bad, logs.String())
				}
			}
		})
	}
}
