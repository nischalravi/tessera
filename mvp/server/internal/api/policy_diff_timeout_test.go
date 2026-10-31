package api

import (
	"context"
	"errors"
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
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// A preview that outlives its deadline or its client stops (#766): 503 or a closed connection, no partial answer, the
// work ends at its next step, and the request is still audited.

var diffAWSBody = diffBody(nil, diffWidenOps)

func diffHooksServer(t *testing.T, timeout time.Duration) (*Server, *storetest.Fixture, authtest.Login, chan error) {
	t.Helper()
	f := storetest.TwoTenants(t)
	persistEstate(t, f.DB, f.B.ID, nil)
	srv := newIsolationServerWith(f, func(c *Config) { withAWSCatalog(c); c.PolicyDiffTimeout = timeout })
	ended := make(chan error, 1)
	srv.policyDiffHooks.before = func(ctx context.Context) { <-ctx.Done() } // a long preview: it runs until stopped
	srv.policyDiffHooks.end = func(err error) { ended <- err }
	return srv, f, reqLogin(t, f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, ""), ended
}

func waitEnded(t *testing.T, ended chan error) error {
	t.Helper()
	select {
	case err := <-ended:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the preview kept running after its deadline")
		return nil
	}
}

func TestPolicyDiffAPI_DeadlineStopsTheWork(t *testing.T) {
	srv, f, pa, ended := diffHooksServer(t, 300*time.Millisecond)
	start := time.Now()
	rec := reqDo(srv.Handler(), pa, "POST", "/api/policy/diff", diffAWSBody)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "Request timed out") || strings.Contains(rec.Body.String(), "diff_sha256") {
		t.Fatalf("status %d body %q, want the 503 timeout and no answer", rec.Code, rec.Body)
	}
	if d := time.Since(start); d < 250*time.Millisecond || d > 5*time.Second {
		t.Errorf("answered after %s, want about the 300ms route deadline", d)
	}
	if err := waitEnded(t, ended); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the handler ended with %v, want the deadline", err)
	}
	// the request is audited all the same
	if evs := httpEvents(ledger(t, f.DB, f.B.ID)); len(evs) == 0 || evs[0].Outcome != store.OutcomeError {
		t.Errorf("no audit event of the timed-out preview: %v", evs)
	}
}

func TestPolicyDiffAPI_ClientDisconnectStopsTheWork(t *testing.T) {
	srv, _, pa, ended := diffHooksServer(t, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	srv.policyDiffHooks.before = func(ctx context.Context) { cancel(); <-ctx.Done() }
	req := httptest.NewRequest("POST", "/api/policy/diff", strings.NewReader(diffAWSBody)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	pa.Apply(req)
	rec := serve(srv.Handler(), req)
	if strings.Contains(rec.Body.String(), "diff_sha256") {
		t.Errorf("a disconnected client got an answer: %d %q", rec.Code, rec.Body)
	}
	if err := waitEnded(t, ended); !errors.Is(err, context.Canceled) {
		t.Errorf("the handler ended with %v, want the cancellation", err)
	}
}

// A route's own timeout replaces HandlerTimeout for that route alone.
func TestRouteTimeout_OtherRoutesKeepTheDefault(t *testing.T) {
	st, _ := testkit.Tiny(t)
	srv := New(Config{Store: st.DB, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), HandlerTimeout: 50 * time.Millisecond, PolicyDiffTimeout: time.Minute})
	nap := func(d time.Duration) handlerFunc {
		return func(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
			select {
			case <-time.After(d):
				return map[string]string{"ok": "yes"}, nil
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
	}
	srv.handle("GET", "/api/nap-default", read, need(auth.PermGraphRead), nap(time.Second))
	srv.handle("GET", "/api/nap-long", read, need(auth.PermGraphRead), nap(300*time.Millisecond)).timeout = time.Minute
	srv.handle("GET", "/api/nap-short", read, need(auth.PermGraphRead), nap(time.Second)).timeout = 100 * time.Millisecond
	h := asAdmin(t, srv, st.DB, st.Tenant, testkit.Now).Handler()
	for path, want := range map[string]int{"/api/nap-default": 503, "/api/nap-long": 200, "/api/nap-short": 503} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("%s: %d, want %d (%s)", path, rec.Code, want, rec.Body)
		}
	}
	// only the preview route, the GitHub check that runs it (plus the time to post, AC-10) and the right-sizing pull request (LP-9) carry the longer deadline
	for _, rt := range srv.routes {
		if rt.pattern == "/api/policy/github/check" && rt.timeout != time.Minute+60*time.Second {
			t.Errorf("the GitHub check route's timeout is %s, want the preview's plus a minute", rt.timeout)
		}
		if rt.pattern == "/api/lp/recommendations/{id}/pull-request" && rt.timeout != time.Minute+90*time.Second {
			t.Errorf("the right-sizing pull request route's timeout is %s, want the preview's plus 90 seconds", rt.timeout)
		}
		if rt.timeout != 0 && rt.pattern != "/api/policy/diff" && rt.pattern != "/api/policy/github/check" && rt.pattern != "/api/lp/recommendations/{id}/pull-request" && rt.pattern != "/api/nap-long" && rt.pattern != "/api/nap-short" {
			t.Errorf("route %s %s has timeout %s", rt.method, rt.pattern, rt.timeout)
		}
		if rt.pattern == "/api/policy/diff" && rt.timeout != time.Minute {
			t.Errorf("the preview route's timeout is %s, want the configured minute", rt.timeout)
		}
	}
}

func TestPolicyDiffTimeoutDefault(t *testing.T) {
	st, _ := testkit.Tiny(t)
	srv := New(Config{Store: st.DB, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if srv.cfg.HandlerTimeout != DefaultHandlerTimeout || srv.cfg.PolicyDiffTimeout != DefaultPolicyDiffTimeout || DefaultPolicyDiffTimeout <= DefaultHandlerTimeout {
		t.Errorf("timeouts: handler %s, preview %s", srv.cfg.HandlerTimeout, srv.cfg.PolicyDiffTimeout)
	}
}
