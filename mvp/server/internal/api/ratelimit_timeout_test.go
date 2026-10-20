package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
