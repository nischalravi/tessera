package connsync_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

func TestDecide(t *testing.T) {
	old := t0.Add(-48 * time.Hour)
	recent := t0.Add(-time.Hour)
	good := func(full *time.Time) *connsync.Checkpoint {
		return &connsync.Checkpoint{Cursor: "c", State: []byte("s"), FullSyncAt: full}
	}
	tests := []struct {
		name     string
		mode     connsync.Mode
		noStore  bool
		cp       *connsync.Checkpoint
		maxAge   time.Duration
		wantFull bool
		reason   string
	}{
		{"no store", connsync.Incremental, true, nil, 0, true, "no checkpoint store"},
		{"none stored", connsync.Incremental, false, nil, 0, true, "no checkpoint"},
		{"empty cursor", connsync.Incremental, false, &connsync.Checkpoint{State: []byte("s")}, 0, true, "checkpoint is empty"},
		{"empty state", connsync.Incremental, false, &connsync.Checkpoint{Cursor: "c"}, 0, true, "checkpoint is empty"},
		{"usable", connsync.Incremental, false, good(&recent), 24 * time.Hour, false, ""},
		{"usable without max age", connsync.Incremental, false, good(nil), 0, false, ""},
		{"too old", connsync.Incremental, false, good(&old), 24 * time.Hour, true, "last full sync is too old"},
		{"never full", connsync.Incremental, false, good(nil), 24 * time.Hour, true, "last full sync is too old"},
		{"on demand", connsync.Full, false, good(&recent), 24 * time.Hour, true, "requested"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := connsync.WithMode(context.Background(), tc.mode)
			if !tc.noStore {
				ms := &connsync.MemoryStore{}
				if tc.cp != nil {
					_ = ms.Save(ctx, "okta", "discover", tc.cp)
				}
				ctx = connsync.WithStore(ctx, ms)
			}
			p, err := connsync.Decide(ctx, "okta", "discover", t0, tc.maxAge)
			if err != nil || p.Full != tc.wantFull || p.Reason != tc.reason {
				t.Errorf("Decide = %+v, %v; want full=%v reason=%q", p, err, tc.wantFull, tc.reason)
			}
		})
	}
}

func TestModeDefaultsToIncremental(t *testing.T) {
	if m := connsync.ModeFrom(context.Background()); m != connsync.Incremental || m.String() != "incremental" {
		t.Errorf("default mode = %v", m)
	}
	if m := connsync.ModeFrom(connsync.WithMode(context.Background(), connsync.Full)); m.String() != "full" {
		t.Errorf("mode = %v", m)
	}
}

func TestStateRoundTripAndBounds(t *testing.T) {
	type snap struct{ A []string }
	in := snap{A: []string{"x", "y"}}
	b, err := connsync.EncodeState(in)
	if err != nil {
		t.Fatal(err)
	}
	var out snap
	if err := connsync.DecodeState(b, &out); err != nil || len(out.A) != 2 {
		t.Fatalf("DecodeState = %v, %v", out, err)
	}
	for name, bad := range map[string][]byte{"not gzip": []byte("plain"), "empty": nil} {
		if err := connsync.DecodeState(bad, &out); err == nil {
			t.Errorf("%s: DecodeState accepted garbage", name)
		}
	}
}

func TestBackoffDelay(t *testing.T) {
	b := connsync.Backoff{Base: time.Second, Max: 10 * time.Second}
	tests := []struct {
		attempt int
		server  time.Duration
		want    time.Duration
	}{
		{0, 0, time.Second},
		{1, 0, 2 * time.Second},
		{2, 0, 4 * time.Second},
		{10, 0, 10 * time.Second},             // capped
		{0, 3 * time.Second, 3 * time.Second}, // Retry-After wins
		{5, 3 * time.Second, 3 * time.Second}, // ... over the schedule
		{0, time.Hour, 10 * time.Second},      // ... but is bounded
		{0, -time.Second, time.Second},        // nonsense is ignored
	}
	for _, tc := range tests {
		if got := b.Delay(tc.attempt, tc.server); got != tc.want {
			t.Errorf("Delay(%d, %v) = %v, want %v", tc.attempt, tc.server, got, tc.want)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		in     string
		want   time.Duration
		wantOK bool
	}{
		{"7", 7 * time.Second, true},
		{" 0 ", 0, true},
		{"-3", 0, false},
		{"", 0, false},
		{"soon", 0, false},
		{t0.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second, true},
		{t0.Add(-time.Minute).Format(http.TimeFormat), 0, true},
		{"99999999999999", (1 << 31) * time.Second, true},
	}
	for _, tc := range tests {
		got, ok := connsync.ParseRetryAfter(tc.in, t0)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("ParseRetryAfter(%q) = %v, %v; want %v, %v", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func newClient(t *testing.T, h http.HandlerFunc, maxBody int64) (*connsync.Client, *connsynctest.Server, *connsynctest.NoSleep) {
	t.Helper()
	srv := connsynctest.New(t, h)
	ns := &connsynctest.NoSleep{}
	return &connsync.Client{HC: testClient(t, srv, maxBody), Now: func() time.Time { return t0 },
		Backoff: connsync.Backoff{Base: time.Second, Max: 30 * time.Second, MaxAttempts: 4, Sleep: ns.Sleep}}, srv, ns
}

func TestClientRetriesOn429HonouringRetryAfter(t *testing.T) {
	calls := 0
	c, srv, ns := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls++; calls <= 2 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}, 0)
	var v struct{ OK bool }
	if _, err := c.GetJSON(context.Background(), srv.URL+"/x", nil, &v); err != nil || !v.OK {
		t.Fatalf("GetJSON = %v, %v", v, err)
	}
	if len(ns.Waits) != 2 || ns.Waits[0] != 3*time.Second || ns.Waits[1] != 3*time.Second {
		t.Errorf("waits = %v, want two of 3s", ns.Waits)
	}
}

func TestClientRetriesGoogleRateLimit403(t *testing.T) {
	body := func(reason string) string {
		return `{"error":{"code":403,"message":"leaky message","errors":[{"reason":"` + reason + `","message":"leaky"}],"status":"PERMISSION_DENIED"}}`
	}
	for _, tc := range []struct {
		reason   string
		retried  bool
		rateLim  bool
		wantCall int
	}{
		{"rateLimitExceeded", true, true, 4},
		{"userRateLimitExceeded", true, true, 4},
		{"insufficientPermissions", false, false, 1},
		{"dailyLimitExceeded", false, false, 1},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			calls := 0
			c, srv, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, body(tc.reason))
			}, 0)
			c.RetryOn = connsync.IsGoogleRateLimit
			_, err := c.GetJSON(context.Background(), srv.URL+"/x", nil, &struct{}{})
			if connsync.Status(err) != 403 || errors.Is(err, connsync.ErrRateLimited) != tc.rateLim || calls != tc.wantCall {
				t.Errorf("err = %v, calls = %d", err, calls)
			}
			if err != nil && strings.Contains(err.Error(), "leaky") {
				t.Errorf("error %q carries the body", err)
			}
		})
	}
}

func TestClientHonoursOktaResetHeaderAndBoundsTheWait(t *testing.T) {
	calls := 0
	c, srv, ns := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls++; calls == 1 {
			w.Header().Set("X-Rate-Limit-Reset", fmt.Sprint(t0.Add(10*time.Second).Unix()))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, `{}`)
	}, 0)
	var v map[string]any
	if _, err := c.GetJSON(context.Background(), srv.URL+"/x", nil, &v); err != nil {
		t.Fatal(err)
	}
	if len(ns.Waits) != 1 || ns.Waits[0] != 11*time.Second {
		t.Errorf("waits = %v, want 11s (reset in 10s plus 1s)", ns.Waits)
	}
	// A hostile Retry-After is capped at Backoff.Max.
	c2, srv2, ns2 := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "86400")
		w.WriteHeader(http.StatusTooManyRequests)
	}, 0)
	_, err := c2.GetJSON(context.Background(), srv2.URL+"/x", nil, &v)
	if !errors.Is(err, connsync.ErrRateLimited) || connsync.Status(err) != 429 {
		t.Fatalf("exhausted 429 = %v, want ErrRateLimited", err)
	}
	if len(ns2.Waits) != 3 {
		t.Fatalf("waits = %v, want 3 retries (MaxAttempts 4)", ns2.Waits)
	}
	for _, w := range ns2.Waits {
		if w != 30*time.Second {
			t.Errorf("wait %v not bounded to 30s", w)
		}
	}
}

func TestClientPausesWhenQuotaIsExhausted(t *testing.T) {
	c, srv, ns := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Rate-Limit-Remaining", "0")
		w.Header().Set("X-Rate-Limit-Reset", fmt.Sprint(t0.Add(5*time.Second).Unix()))
		fmt.Fprint(w, `{}`)
	}, 0)
	var v map[string]any
	if _, err := c.GetJSON(context.Background(), srv.URL+"/x", nil, &v); err != nil {
		t.Fatal(err)
	}
	if len(ns.Waits) != 1 || ns.Waits[0] != 5*time.Second {
		t.Errorf("waits = %v, want one of 5s", ns.Waits)
	}
}

func TestClientErrorsNeverCarryTheBody(t *testing.T) {
	c, srv, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"errorCode":"E0000006","errorSummary":"secret-token-abc is not allowed for alice@example.com"}`)
	}, 0)
	_, err := c.GetJSON(context.Background(), srv.URL+"/api/v1/users?search=alice%40example.com", nil, &struct{}{})
	if connsync.Status(err) != 403 || err == nil {
		t.Fatalf("err = %v", err)
	}
	for _, leak := range []string{"secret-token-abc", "alice", "search"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q contains %q", err, leak)
		}
	}
	if !strings.Contains(err.Error(), "E0000006") {
		t.Errorf("error %q lacks the provider error code", err)
	}
}

func TestClientOversizedAndMalformedBodies(t *testing.T) {
	big := `{"pad":"` + strings.Repeat("x", 4096) + `"}`
	c, srv, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			fmt.Fprint(w, big)
		case "/chunked":
			// no Content-Length: the limit has to hold while reading
			w.Header().Set("Transfer-Encoding", "chunked")
			fl := w.(http.Flusher)
			for i := 0; i < 8; i++ {
				fmt.Fprint(w, strings.Repeat("y", 1024))
				fl.Flush()
			}
		case "/truncated":
			fmt.Fprint(w, `{"a":[1,2`)
		case "/trailing":
			fmt.Fprint(w, `{"a":1} {"b":2}`)
		case "/wrongtype":
			fmt.Fprint(w, `{"a":"text"}`)
		case "/empty":
		}
	}, 1024)
	var v struct{ A []int }
	for _, p := range []string{"/big", "/chunked"} {
		if _, err := c.GetJSON(context.Background(), srv.URL+p, nil, &v); !errors.Is(err, safehttp.ErrTooLarge) {
			t.Errorf("%s: err = %v, want ErrTooLarge", p, err)
		}
	}
	for _, p := range []string{"/truncated", "/trailing", "/wrongtype", "/empty"} {
		_, err := c.GetJSON(context.Background(), srv.URL+p, nil, &v)
		if !errors.Is(err, connsync.ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", p, err)
		}
		if err != nil && strings.Contains(err.Error(), "text") {
			t.Errorf("%s: error quotes the body: %v", p, err)
		}
	}
}

func TestClientReauthorizesOnceOn401(t *testing.T) {
	var invalidated int
	calls := 0
	c, srv, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls++; r.Header.Get("Authorization") != "Bearer fresh" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{}`)
	}, 0)
	tok := "stale"
	c.Authorize = func(context.Context) (string, error) { return "Bearer " + tok, nil }
	c.OnUnauthorized = func() { invalidated++; tok = "fresh" }
	if _, err := c.GetJSON(context.Background(), srv.URL+"/x", nil, &struct{}{}); err != nil || invalidated != 1 || calls != 2 {
		t.Fatalf("err = %v, invalidated = %d, calls = %d", err, invalidated, calls)
	}
	// A permanent 401 is returned after one retry, not looped.
	c.OnUnauthorized = func() {}
	tok = "stale"
	if _, err := c.GetJSON(context.Background(), srv.URL+"/x", nil, &struct{}{}); connsync.Status(err) != 401 {
		t.Fatalf("permanent 401 = %v", err)
	}
}

func TestClientStopsWhenContextEnds(t *testing.T) {
	c, srv, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }, 0)
	c.Backoff.Sleep = connsync.SleepCtx
	c.Backoff.Base = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.GetJSON(ctx, srv.URL+"/x", nil, &struct{}{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
}

func TestValidDomainAndParseBaseURL(t *testing.T) {
	dev := connsync.Runtime{Env: "dev", AllowLoopback: true}
	prod := connsync.Runtime{Env: "prod"}
	tests := []struct {
		raw  string
		rt   connsync.Runtime
		ok   bool
		note string
	}{
		{"https://example.okta.com", prod, true, "plain"},
		{"https://example.okta.com/", prod, true, "trailing slash"},
		{"https://login.example-corp.co.uk", prod, true, "multi label"},
		{"http://example.okta.com", prod, false, "http in prod"},
		{"http://example.okta.com", dev, false, "http to a name in dev"},
		{"https://127.0.0.1:8443", prod, false, "loopback in prod"},
		{"https://127.0.0.1:8443", dev, true, "loopback in dev"},
		{"http://127.0.0.1:8443", dev, true, "http loopback in dev"},
		{"https://169.254.169.254", dev, false, "metadata address"},
		{"https://10.0.0.5", prod, false, "ip literal"},
		{"https://localhost", prod, false, "no dot"},
		{"https://exa_mple.okta.com", prod, false, "underscore"},
		{"https://-bad.okta.com", prod, false, "leading hyphen"},
		{"https://example.okta.com:8443", prod, true, "port"},
		{"https://user:pw@example.okta.com", prod, false, "user info"},
		{"https://example.okta.com?x=1", prod, false, "query"},
		{"https://example.okta.com#f", prod, false, "fragment"},
		{"ftp://example.okta.com", prod, false, "scheme"},
		{"https://", prod, false, "no host"},
		{"example.okta.com", prod, false, "no scheme"},
		{"https://" + strings.Repeat("a", 64) + ".com", prod, false, "label too long"},
		{"https://example.123", prod, false, "numeric tld"},
	}
	for _, tc := range tests {
		_, err := connsync.ParseBaseURL(tc.raw, tc.rt)
		if (err == nil) != tc.ok {
			t.Errorf("%s: ParseBaseURL(%q) = %v, want ok=%v", tc.note, tc.raw, err, tc.ok)
		}
	}
}

func TestSameOriginAndWalk(t *testing.T) {
	base, _ := url.Parse("https://example.okta.com")
	for raw, ok := range map[string]bool{
		"https://example.okta.com/api/v1/users?after=1": true,
		"https://EXAMPLE.okta.com:443/x":                true,
		"https://evil.example.com/api/v1/users":         false,
		"http://example.okta.com/x":                     false,
		"https://example.okta.com:8443/x":               false,
		"https://user@example.okta.com/x":               false,
		"/relative":                                     false,
	} {
		if _, err := connsync.SameOrigin(base, raw); (err == nil) != ok {
			t.Errorf("SameOrigin(%q) = %v, want ok=%v", raw, err, ok)
		}
	}
	// A page that links to another host stops the walk before it is followed.
	err := connsync.Walk(context.Background(), base, "https://example.okta.com/a", func(_ context.Context, u string) (string, error) {
		return "https://evil.example.com/b", nil
	})
	if err == nil || !strings.Contains(err.Error(), "leaves the configured host") {
		t.Errorf("off-host link = %v", err)
	}
	// A cycle is cut.
	err = connsync.Walk(context.Background(), base, "https://example.okta.com/a", func(_ context.Context, u string) (string, error) {
		return "https://example.okta.com/a", nil
	})
	if !errors.Is(err, connsync.ErrPaging) {
		t.Errorf("cycle = %v, want ErrPaging", err)
	}
	// A normal chain is followed in order.
	var seen []string
	next := map[string]string{"https://example.okta.com/1": "https://example.okta.com/2", "https://example.okta.com/2": ""}
	err = connsync.Walk(context.Background(), base, "https://example.okta.com/1", func(_ context.Context, u string) (string, error) {
		seen = append(seen, u)
		return next[u], nil
	})
	if err != nil || len(seen) != 2 {
		t.Errorf("chain: %v, %v", seen, err)
	}
}

func TestSecretNeverPrints(t *testing.T) {
	s := connsync.NewSecret("hunter2-super-secret")
	j, _ := json.Marshal(map[string]any{"s": s})
	for name, out := range map[string]string{"%v": fmt.Sprintf("%v", s), "%s": fmt.Sprintf("%s", s), "%+v": fmt.Sprintf("%+v", s),
		"%#v": fmt.Sprintf("%#v", s), "struct": fmt.Sprintf("%+v", struct{ S connsync.Secret }{s}), "json": string(j)} {
		if strings.Contains(out, "hunter2") {
			t.Errorf("%s leaked the secret: %s", name, out)
		}
	}
	if s.Reveal() != "hunter2-super-secret" || s.Empty() || !connsync.NewSecret("").Empty() {
		t.Error("Reveal/Empty are wrong")
	}
}

func TestResolveSecret(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "key")
	if err := os.WriteFile(file, []byte("  from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	huge := filepath.Join(dir, "huge")
	_ = os.WriteFile(huge, []byte(strings.Repeat("a", 70<<10)), 0o600)
	env := func(k string) string { return map[string]string{"TOK": " from-env ", "BLANK": " "}[k] }
	tests := []struct {
		ref  string
		want string
		ok   bool
	}{
		{"env:TOK", "from-env", true},
		{"env:BLANK", "", false},
		{"env:MISSING", "", false},
		{"file:" + file, "from-file", true},
		{"file:" + empty, "", false},
		{"file:" + huge, "", false},
		{"file:relative/path", "", false},
		{"file:" + filepath.Join(dir, "nope"), "", false},
		{"literal-secret-value", "", false},
		{"vault:kv/okta", "", false},
		{"env:", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		got, err := connsync.ResolveSecret(tc.ref, env)
		if (err == nil) != tc.ok || got.Reveal() != tc.want {
			t.Errorf("ResolveSecret(%q) = %q, %v; want %q ok=%v", tc.ref, got.Reveal(), err, tc.want, tc.ok)
		}
		if err != nil && strings.Contains(err.Error(), "literal-secret-value") {
			t.Errorf("error for %q echoes the reference value", tc.ref)
		}
	}
}

func TestRuntimeFromConfig(t *testing.T) {
	load := func(env map[string]string) *config.Config {
		t.Helper()
		c, err := config.Load(func(k string) string { return env[k] })
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if r := connsync.RuntimeFromConfig(load(map[string]string{"TESSERA_ENV": "dev", "TESSERA_OUTBOUND_ALLOW_LOOPBACK": "1"})); r.Env != "dev" || !r.AllowLoopback {
		t.Errorf("dev runtime = %+v", r)
	}
	if r := connsync.RuntimeFromConfig(load(map[string]string{"TESSERA_ENV": "dev", "TESSERA_OUTBOUND_ALLOW_LOOPBACK": "0"})); r.Env != "dev" || r.AllowLoopback {
		t.Errorf("dev runtime without the exception = %+v", r)
	}
	// A Config that config.Load did not return gets the production rules.
	if r := connsync.RuntimeFromConfig(&config.Config{Env: "dev"}); r.Env != "prod" || r.AllowLoopback {
		t.Errorf("hand-built runtime = %+v: loopback must never be on", r)
	}
	if r := connsync.RuntimeFromConfig(nil); r.Env != "prod" || r.AllowLoopback {
		t.Errorf("nil runtime = %+v", r)
	}
}

func TestSharedClientRefusesPrivateAddresses(t *testing.T) {
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"https://127.0.0.1/x", "https://169.254.169.254/latest", "https://10.1.2.3/x", "http://example.com/x"} {
		_, err := safehttp.Get(context.Background(), hc, u)
		if err == nil {
			t.Errorf("GET %s succeeded through the connector client", u)
		}
	}
}

func testClient(t testing.TB, srv *connsynctest.Server, maxBody int64) *http.Client {
	t.Helper()
	hc, err := safehttp.NewForTest(t, srv.Options(maxBody))
	if err != nil {
		t.Fatal(err)
	}
	return hc
}
