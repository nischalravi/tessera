package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seed"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// noRateLimits is for tests that send many anonymous requests on purpose.
var noRateLimits = RateLimits{Anonymous: RateLimit{Every: time.Nanosecond, Burst: 1 << 20},
	Auth: RateLimit{Every: time.Nanosecond, Burst: 1 << 20}}

func fromIP(r *http.Request, addr string) *http.Request {
	r.RemoteAddr = addr
	return r
}

func countHTTPEvents(t *testing.T, db *store.DB) int {
	t.Helper()
	n := 0
	for _, id := range []tenancy.ID{tenancy.Platform, seed.LarkspurID} {
		for _, e := range ledger(t, db, id) {
			if e.Action == "http.request" {
				n++
			}
		}
	}
	return n
}

// TestRateLimit_AnonymousPerIP: anonymous requests are limited per IP (an
// IPv6 peer by its /64) before the audit middleware: a refused request is
// 429 with Retry-After and writes nothing to the ledger; another IP and a
// signed-in session are unaffected; made-up cookies count as anonymous.
func TestRateLimit_AnonymousPerIP(t *testing.T) {
	srv, db := seededServer(t)
	srv.limits = newLimiters(RateLimits{Anonymous: RateLimit{Every: time.Hour, Burst: 3}, Auth: RateLimit{Every: time.Hour, Burst: 100}})
	h := srv.Handler()
	alice := signIn(t, db, seed.LarkspurID, testAdmin, authtest.Phr, testkit.Now)
	for i := 0; i < 3; i++ {
		if rec := serve(h, fromIP(httptest.NewRequest("GET", "/api/identities", nil), "198.51.100.7:1000")); rec.Code != 401 {
			t.Fatalf("anonymous %d: %d", i, rec.Code)
		}
	}
	before := countHTTPEvents(t, db)
	rec := serve(h, fromIP(httptest.NewRequest("GET", "/api/identities", nil), "198.51.100.7:2000"))
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), "rate_limited") {
		t.Fatalf("over the limit: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	if after := countHTTPEvents(t, db); after != before {
		t.Errorf("a refused request wrote %d http.request events", after-before)
	}
	// a made-up cookie from the same IP is refused too
	bogus := fromIP(httptest.NewRequest("GET", "/api/identities", nil), "198.51.100.7:3000")
	bogus.AddCookie(auth.Cookies{}.Session(auth.NewSecret()))
	if rec := serve(h, bogus); rec.Code != 429 {
		t.Errorf("made-up cookie: %d", rec.Code)
	}
	// another IP is not affected
	if rec := serve(h, fromIP(httptest.NewRequest("GET", "/api/health", nil), "203.0.113.9:1000")); rec.Code != 200 {
		t.Errorf("other IP: %d", rec.Code)
	}
	// IPv6: one /64 shares a bucket
	for i, addr := range []string{"[2001:db8:1:2::1]:1", "[2001:db8:1:2::2]:1", "[2001:db8:1:2:ffff::3]:1", "[2001:db8:1:2::4]:1"} {
		code := serve(h, fromIP(httptest.NewRequest("GET", "/api/health", nil), addr)).Code
		if want := map[bool]int{true: 200, false: 429}[i < 3]; code != want {
			t.Errorf("%s: %d, want %d", addr, code, want)
		}
	}
	// made-up cookies drain the bucket: three bad cookies, then the IP is limited
	for i := 0; i < 4; i++ {
		r := fromIP(httptest.NewRequest("GET", "/api/identities", nil), "192.0.2.50:1")
		r.AddCookie(auth.Cookies{}.Session(auth.NewSecret()))
		if code := serve(h, r).Code; (i < 3 && code != 401) || (i == 3 && code != 429) {
			t.Errorf("bad cookie %d: %d", i, code)
		}
	}
	// a valid session is not counted against the anonymous bucket
	for i := 0; i < 10; i++ {
		r := fromIP(authed(alice, "GET", "/api/identities", ""), "192.0.2.60:1")
		if code := serve(h, r).Code; code != 200 {
			t.Fatalf("signed-in request %d: %d", i, code)
		}
	}
}

// TestRateLimit_AuthRoutes: every /api/auth/* request takes a token from the
// IP's auth bucket, signed in or not.
func TestRateLimit_AuthRoutes(t *testing.T) {
	srv, db := seededServer(t)
	srv.limits = newLimiters(RateLimits{Anonymous: RateLimit{Every: time.Hour, Burst: 100}, Auth: RateLimit{Every: time.Hour, Burst: 2}})
	h := srv.Handler()
	alice := signIn(t, db, seed.LarkspurID, testAdmin, authtest.Phr, testkit.Now)
	for i, want := range []int{200, 200, 429} {
		r := fromIP(httptest.NewRequest("GET", "/api/auth/discover?tenant=larkspur", nil), "198.51.100.8:1")
		if code := serve(h, r).Code; code != want {
			t.Errorf("discover %d: %d, want %d", i, code, want)
		}
	}
	// Reading your own session is not a sign-in attempt: the UI does it on every page load (UAT #308).
	for _, path := range []string{"/api/auth/session", "/api/auth/sessions"} {
		if code := serve(h, fromIP(authed(alice, "GET", path, ""), "198.51.100.8:1")).Code; code != 200 {
			t.Errorf("signed-in %s from a limited IP: %d", path, code)
		}
	}
	// ... and does not use up the sign-in budget of a fresh IP.
	for i := 0; i < 40; i++ {
		if code := serve(h, fromIP(authed(alice, "GET", "/api/auth/session", ""), "198.51.100.9:1")).Code; code != 200 {
			t.Fatalf("session read %d: %d", i, code)
		}
	}
	if code := serve(h, fromIP(httptest.NewRequest("GET", "/api/auth/discover?tenant=larkspur", nil), "198.51.100.9:1")).Code; code != 200 {
		t.Errorf("discover after 40 session reads: %d", code)
	}
	if code := serve(h, fromIP(authed(alice, "GET", "/api/identities", ""), "198.51.100.8:1")).Code; code != 200 {
		t.Errorf("other routes of a signed-in user from that IP: %d", code)
	}
}

// TestRateLimit_ClientBehindTrustedProxy: behind a trusted proxy the key is
// the rightmost untrusted X-Forwarded-For hop; from any other peer the header
// is ignored.
func TestRateLimit_ClientBehindTrustedProxy(t *testing.T) {
	s := &Server{cfg: Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}}
	for _, tc := range []struct{ peer, xff, want string }{
		{"10.1.2.3:443", "198.51.100.1, 10.9.9.9", "198.51.100.1"},
		{"10.1.2.3:443", "6.6.6.6, 198.51.100.1", "198.51.100.1"}, // a client-supplied hop to the left is ignored
		{"10.1.2.3:443", "", "10.1.2.3"},
		{"10.1.2.3:443", "junk, 198.51.100.2", "198.51.100.2"},
		{"10.1.2.3:443", "[::1], junk", "10.1.2.3"},
		{"10.1.2.3:443", "2001:db8:1:2::7", "2001:db8:1:2::/64"},
		{"10.1.2.3:443", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"}, // same /64, same bucket
		{"10.1.2.3:443", "fe80::1%eth0", "fe80::/64"},                             // zone dropped
		{"10.1.2.3:443", "::ffff:198.51.100.3", "198.51.100.3"},
		{"[2001:db8:9:9::1]:443", "", "2001:db8:9:9::/64"},
		{"203.0.113.5:443", "198.51.100.1", "203.0.113.5"}, // untrusted peer: header ignored
		{"not-an-address", "", "invalid"},
	} {
		r := httptest.NewRequest("GET", "/api/health", nil)
		r.RemoteAddr = tc.peer
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got := s.rateKey(r).String(); got != tc.want {
			t.Errorf("peer %s XFF %q: key %s, want %s", tc.peer, tc.xff, got, tc.want)
		}
	}
}

// seededServer is a server over a seed with the dev IdP connections and
// their bootstrap users.
func seededServer(t *testing.T) (*Server, *store.DB) {
	t.Helper()
	db := testkit.Open(t)
	tenants := seed.WithDevIdP([]seed.Tenant{
		{ID: seed.LarkspurID, Slug: seed.LarkspurSlug, Name: "Larkspur Labs", Connectors: []connectors.Connector{connectors.Tiny{Now: testkit.Now}}},
		{ID: seed.GlobexID, Slug: seed.GlobexSlug, Name: "Globex", Connectors: []connectors.Connector{connectors.Tiny{Now: testkit.Now, Sentinel: "G"}}},
	}, "http://127.0.0.1:8001")
	if _, err := seed.Run(context.Background(), db, testkit.Now, testkit.Policies(t), tenants); err != nil {
		t.Fatal(err)
	}
	return New(Config{Store: db, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS), Env: "test",
		AllowedOrigins: []string{authtest.Origin}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}), db
}
