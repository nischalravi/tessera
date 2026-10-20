package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/api"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

func TestMain(m *testing.M) { testkit.Main(m) }

// The CLI against an in-process Tessera API (design §19 PR10): the real
// router, the real authorization server and a real store, a fake clock that
// the CLI's sleeps advance, and a "browser" that approves the device code
// with an authtest session.

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// syncBuf is a bytes.Buffer safe for a writer goroutine and a reader.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type world struct {
	t      *testing.T
	db     *testkit.DB
	srv    *httptest.Server
	clock  *fakeClock
	dir    string
	tenant tenancy.ID
	slug   string
	// answered, while login waits for the browser, is closed once the browser
	// has answered the device code. The CLI's polling sleeps wait for it before
	// moving the fake clock on, so a slow machine (-race) cannot expire the code
	// before it is approved.
	answered atomic.Pointer[chan struct{}]
	ids      testkit.IDs
}

const slug = "tiny"

func newWorld(t *testing.T) *world {
	t.Helper()
	db, ids := testkit.Tiny(t)
	w := &world{t: t, db: db, ids: ids, clock: &fakeClock{t: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)},
		dir:    filepath.Join(t.TempDir(), "tessera"), // the CLI creates it (mode 0700)
		tenant: testkit.TinyTenant, slug: slug}
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	sealer, err := seal.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := keys.EnsureAll(ctx, db.DB, sealer, w.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := oauth.EnsureCLIClients(ctx, db.DB, w.clock.Now()); err != nil {
		t.Fatal(err)
	}
	var handler http.Handler
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { handler.ServeHTTP(rw, r) }))
	t.Cleanup(w.srv.Close)
	lots := api.RateLimit{Every: time.Microsecond, Burst: 1 << 20}
	handler = api.New(api.Config{
		Store: db.DB, Clock: w.clock.Now, Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AllowedOrigins: []string{authtest.Origin}, Env: "test",
		RateLimits: api.RateLimits{Anonymous: lots, Auth: lots}, PublicURL: w.srv.URL, Sealer: sealer,
		GroupsEngine: engine.New(5000),
	}).Handler()
	return w
}

// cli is one command-line invocation's result.
type result struct {
	code           int
	stdout, stderr string
}

// run runs tessera-cli with this world's config dir and a clock that its
// sleeps advance (with a short real pause so the "browser" can act).
func (w *world) run(args ...string) result {
	w.t.Helper()
	return w.runWith(nil, args...)
}

func (w *world) runWith(stdout *syncBuf, args ...string) result {
	w.t.Helper()
	var out, errb syncBuf
	if stdout != nil {
		out = syncBuf{}
	}
	var o io.Writer = &out
	if stdout != nil {
		o = stdout
	}
	env := map[string]string{"TESSERA_CONFIG_DIR": w.dir, "TESSERA_ENV": "dev"}
	code := run(context.Background(), args, runEnv{getenv: func(k string) string { return env[k] }, stdin: strings.NewReader(""),
		stdout: o, stderr: &errb, now: w.clock.Now,
		sleep: func(ctx context.Context, d time.Duration) error {
			time.Sleep(10 * time.Millisecond)
			if ch := w.answered.Load(); ch != nil {
				// The 30s cap only bounds a browser step that never answers; past
				// it the clock moves on and the code can expire as it did before.
				select {
				case <-*ch:
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(30 * time.Second):
				}
			}
			w.clock.Advance(d)
			return ctx.Err()
		}})
	return result{code: code, stdout: o.(interface{ String() string }).String(), stderr: errb.String()}
}

// browser signs the user in (a fresh phishing-resistant sign-in) and answers
// the device code the CLI printed.
func (w *world) browser(email string, roles []auth.Role, userCode, decision string) {
	w.t.Helper()
	l := authtest.LoginAs(w.t, w.db.DB, w.tenant, authtest.User{Email: email, Roles: roles}, authtest.Phr, w.clock.Now())
	body, _ := json.Marshal(map[string]string{"user_code": userCode, "decision": decision})
	req, _ := http.NewRequest(http.MethodPost, w.srv.URL+"/api/auth/device/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	l.Apply(req)
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		w.t.Fatalf("approve: %d %s", res.StatusCode, b)
	}
}

var codeRE = regexp.MustCompile(`[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}`)

// login runs `tessera-cli login` and has the browser answer it.
func (w *world) login(email string, roles []auth.Role, decision string, extra ...string) result {
	w.t.Helper()
	var out syncBuf
	answered := make(chan struct{})
	w.answered.Store(&answered)
	defer w.answered.Store(nil)
	release := sync.OnceFunc(func() { close(answered) })
	defer release() // on every exit path, so the CLI never waits out the cap
	done := make(chan result, 1)
	go func() {
		args := append([]string{"login", "--server", w.srv.URL, "--tenant", w.slug}, extra...)
		done <- w.runWith(&out, args...)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if code := codeRE.FindString(out.String()); code != "" {
			w.browser(email, roles, code, decision)
			release()
			break
		}
		select {
		case r := <-done: // the command ended without printing a code
			return r
		default:
		}
		if time.Now().After(deadline) {
			w.t.Fatalf("no user code in %q", out.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
	return <-done
}

var operator = []auth.Role{auth.RoleOperator}

func (w *world) credsPath() string { return filepath.Join(w.dir, "credentials.json") }

func (w *world) creds() map[string]any {
	w.t.Helper()
	b, err := os.ReadFile(w.credsPath())
	if err != nil {
		w.t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		w.t.Fatal(err)
	}
	return m
}

func (w *world) events(action string) []*store.AuditEvent {
	w.t.Helper()
	var out []*store.AuditEvent
	if err := w.db.ReadTenant(context.Background(), w.tenant, func(tx *store.TenantTx) error {
		all, err := tx.AuditEventsRange(1, 0, 0)
		for _, e := range all {
			if e.Action == action {
				out = append(out, e)
			}
		}
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
	return out
}

// TestE2E_Lifecycle: sign in, call the API, refresh, step up, sign in again,
// sign out.
func TestE2E_Lifecycle(t *testing.T) {
	w := newWorld(t)

	t.Run("login", func(t *testing.T) {
		r := w.login("alice@tiny.example", operator, "approve")
		if r.code != 0 {
			t.Fatalf("login exited %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
		}
		// the code and the page, a warning, and no pre-filled link
		if !strings.Contains(r.stdout, w.srv.URL+"/device") || !codeRE.MatchString(r.stdout) ||
			!strings.Contains(r.stdout, "Only approve if you just ran this command yourself") {
			t.Errorf("instructions: %s", r.stdout)
		}
		for _, bad := range []string{"verification_uri_complete", "?user_code", "&user_code", "code="} {
			if strings.Contains(r.stdout, bad) {
				t.Errorf("the output has %q: %s", bad, r.stdout)
			}
		}
		// credentials: mode 0600 in a 0700 directory, the DPoP key and the refresh token
		st, err := os.Stat(w.credsPath())
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("credentials file: %v %v", st, err)
		}
		if ds, _ := os.Stat(w.dir); ds.Mode().Perm()&0o077 != 0 {
			// t.TempDir is created 0700 by the testing package; Save only creates missing directories
			t.Errorf("config directory mode %v", ds.Mode().Perm())
		}
		c := w.creds()
		if !strings.HasPrefix(c["refresh_token"].(string), "trt_") || c["server"] != w.srv.URL || c["tenant"] != slug ||
			c["issuer"] != w.srv.URL+"/t/"+slug || !strings.Contains(string(mustJSON(c["dpop_key"])), `"d"`) {
			t.Errorf("credentials: %v", c)
		}
		// the server side: one CLI session for alice, the approval and the issuance audited
		if n := len(w.events("oauth.device.approved")); n != 1 {
			t.Errorf("%d approvals audited", n)
		}
		if n := len(w.events("oauth.token.issued")); n != 1 {
			t.Errorf("%d issuances audited", n)
		}
	})

	t.Run("whoami", func(t *testing.T) {
		r := w.run("whoami")
		if r.code != 0 || !strings.Contains(r.stdout, "alice@tiny.example") || !strings.Contains(r.stdout, "operator") ||
			!strings.Contains(r.stdout, "graph.read") {
			t.Errorf("whoami exited %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
		}
	})

	t.Run("api reads", func(t *testing.T) {
		r := w.run("api", "GET", "/api/summary")
		if r.code != 0 || !json.Valid([]byte(r.stdout)) {
			t.Fatalf("api exited %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
		}
		// audited as the user, through the CLI client, in the tenant's chain
		var found *store.AuditEvent
		for _, e := range w.events("http.request") {
			if strings.Contains(string(e.HTTP), `"/api/summary"`) {
				found = e
			}
		}
		if found == nil || found.ActorType != store.ActorUser || found.ClientID == nil || *found.ClientID != oauth.CLIClientID ||
			found.SessionID == nil || found.Outcome != store.OutcomeSuccess {
			t.Errorf("the summary call was not audited as the CLI user: %+v", found)
		}
	})

	t.Run("api honours roles and scopes", func(t *testing.T) {
		// an operator may not sweep JIT grants (policy_admin only)
		r := w.run("api", "-d", "{}", "POST", "/api/jit/sweep")
		if r.code != 1 || !strings.Contains(r.stdout, `"forbidden"`) || !strings.Contains(r.stderr, "HTTP 403") {
			t.Errorf("sweep: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
		}
	})

	t.Run("an access token expires and is refreshed", func(t *testing.T) {
		before := w.creds()["refresh_token"]
		w.clock.Advance(11 * time.Minute)
		r := w.run("api", "GET", "/api/summary")
		if r.code != 0 {
			t.Fatalf("api exited %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
		}
		if after := w.creds()["refresh_token"]; after == before {
			t.Error("the refresh token was not rotated")
		}
		if n := len(w.events("oauth.refresh.rotated")); n != 1 {
			t.Errorf("%d rotations audited", n)
		}
	})

	t.Run("concurrent invocations refresh once", func(t *testing.T) {
		w.clock.Advance(11 * time.Minute)
		var wg sync.WaitGroup
		codes := make([]int, 4)
		for i := range codes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[i] = w.run("api", "GET", "/api/summary").code
			}()
		}
		wg.Wait()
		for i, c := range codes {
			if c != 0 {
				t.Errorf("invocation %d exited %d", i, c)
			}
		}
		if n := len(w.events("oauth.refresh.rotated")); n != 2 {
			t.Errorf("%d rotations after the second expiry, want 2 in total", n)
		}
		if n := len(w.events("oauth.refresh.reuse_detected")); n != 0 {
			t.Errorf("%d reuse detections: concurrent CLIs presented one token twice", n)
		}
		if r := w.run("whoami"); r.code != 0 {
			t.Errorf("the session did not survive: %d %s", r.code, r.stderr)
		}
	})

	t.Run("an action that needs a fresh sign-in", func(t *testing.T) {
		w.clock.Advance(20 * time.Minute) // past the 15 minutes STEP_UP_POLICY allows
		r := w.run("api", "-d", "{}", "POST", "/api/jit/requests/1/approve")
		if r.code != 3 || !strings.Contains(r.stderr, "phishing-resistant sign-in") ||
			!strings.Contains(r.stderr, "tessera-cli login --acr urn:tessera:acr:phr --max-age 900") ||
			!strings.Contains(r.stderr, "was not repeated") {
			t.Errorf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
		}
	})

	t.Run("signing in again replaces and revokes the old session", func(t *testing.T) {
		old := w.creds()
		r := w.login("alice@tiny.example", operator, "approve", "--acr", "urn:tessera:acr:phr", "--max-age", "60")
		if r.code != 0 {
			t.Fatalf("login exited %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
		}
		if w.creds()["refresh_token"] == old["refresh_token"] {
			t.Error("the stored token did not change")
		}
		// the step-up now passes the freshness check (the handler then finds no such request)
		r = w.run("api", "-d", "{}", "POST", "/api/jit/requests/999999/approve")
		if r.code == 3 {
			t.Errorf("still asked for a step-up after signing in again: %s", r.stderr)
		}
		var active int
		_ = w.db.ReadTenant(context.Background(), w.tenant, func(tx *store.TenantTx) error {
			users, _ := tx.PlatformUsers()
			for _, u := range users {
				ss, _ := tx.SessionsForUser(u.ID)
				for _, s := range ss {
					if s.Kind == store.SessionCLI && s.Status == store.SessionActive {
						active++
					}
				}
			}
			return nil
		})
		if active != 1 {
			t.Errorf("%d active CLI sessions, want only the new one", active)
		}
		if n := len(w.events("oauth.token.revoked")); n != 1 {
			t.Errorf("%d revocations audited", n)
		}
	})

	t.Run("api only talks to the signed-in server", func(t *testing.T) {
		for _, p := range []string{"https://evil.example/api/summary", "//evil.example/api/summary", "api/summary", `/\evil.example`} {
			if r := w.run("api", "GET", p); r.code != 1 || !strings.Contains(r.stderr, "not an API path") {
				t.Errorf("%q: exit %d\nstderr: %s", p, r.code, r.stderr)
			}
		}
	})

	t.Run("logout", func(t *testing.T) {
		r := w.run("logout")
		if r.code != 0 || !strings.Contains(r.stdout, "Signed out") {
			t.Fatalf("logout exited %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
		}
		if _, err := os.Stat(w.credsPath()); !os.IsNotExist(err) {
			t.Errorf("the credentials file is still there: %v", err)
		}
		if r := w.run("whoami"); r.code != 1 || !strings.Contains(r.stderr, "not signed in") {
			t.Errorf("whoami after logout: %d %s", r.code, r.stderr)
		}
		if r := w.run("logout"); r.code != 0 || !strings.Contains(r.stderr, "not signed in") {
			t.Errorf("second logout: %d %s", r.code, r.stderr)
		}
		if n := len(w.events("oauth.token.revoked")); n != 2 {
			t.Errorf("%d revocations audited, want 2", n)
		}
	})
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestE2E_ReadOnlyScope(t *testing.T) {
	w := newWorld(t)
	if r := w.login("alice@tiny.example", operator, "approve", "--scope", "tessera:read"); r.code != 0 {
		t.Fatalf("login: %d %s %s", r.code, r.stdout, r.stderr)
	}
	// operators may request JIT access, but this token only reads
	r := w.run("api", "-d", `{"identity_id":1,"group_id":1,"justification":"x"}`, "POST", "/api/jit/requests")
	if r.code != 1 || !strings.Contains(r.stdout, `"forbidden"`) || !strings.Contains(r.stderr, "HTTP 403") {
		t.Errorf("a write with a read-only token: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if r := w.run("api", "GET", "/api/summary"); r.code != 0 {
		t.Errorf("a read: %d %s", r.code, r.stderr)
	}
}

func TestE2E_Denied(t *testing.T) {
	w := newWorld(t)
	r := w.login("alice@tiny.example", operator, "deny")
	if r.code != 1 || !strings.Contains(r.stderr, "denied") {
		t.Errorf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if _, err := os.Stat(w.credsPath()); !os.IsNotExist(err) {
		t.Error("credentials were saved after a denial")
	}
}

func TestE2E_Expired(t *testing.T) {
	w := newWorld(t)
	r := w.run("login", "--server", w.srv.URL, "--tenant", w.slug) // nobody approves
	if r.code != 1 || !strings.Contains(r.stderr, "expired") {
		t.Errorf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
}

func TestE2E_DeviceGrantOff(t *testing.T) {
	w := newWorld(t)
	if err := w.db.InSystem(context.Background(), "test", func(s *store.SystemTx) error {
		return s.SetTenantSettings(w.tenant, `{"device_grant_enabled": false}`)
	}); err != nil {
		t.Fatal(err)
	}
	r := w.run("login", "--server", w.srv.URL, "--tenant", w.slug)
	if r.code != 1 || !strings.Contains(r.stderr, "turned off") {
		t.Errorf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
}

func TestE2E_SessionEnded(t *testing.T) {
	w := newWorld(t)
	if r := w.login("alice@tiny.example", operator, "approve"); r.code != 0 {
		t.Fatalf("login: %d %s", r.code, r.stderr)
	}
	// an administrator revokes the session
	if err := w.db.InTenant(context.Background(), w.tenant, func(tx *store.TenantTx) error {
		users, _ := tx.PlatformUsers()
		for _, u := range users {
			if _, err := tx.RevokeUserSessions(u.ID, auth.RevokedAdmin, w.clock.Now()); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r := w.run("api", "GET", "/api/summary")
	if r.code != 1 || !strings.Contains(r.stderr, "session has ended") {
		t.Errorf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if _, err := os.Stat(w.credsPath()); !os.IsNotExist(err) {
		t.Error("the dead credentials were kept")
	}
}

// TestE2E_StaleTokenIsTheft: restoring an old credentials file (a copy of the
// disk from before a refresh) presents a used refresh token: the server
// revokes the session and the CLI says so.
func TestE2E_StaleTokenIsTheft(t *testing.T) {
	w := newWorld(t)
	if r := w.login("alice@tiny.example", operator, "approve"); r.code != 0 {
		t.Fatalf("login: %d %s", r.code, r.stderr)
	}
	stale, err := os.ReadFile(w.credsPath())
	if err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(11 * time.Minute)
	if r := w.run("api", "GET", "/api/summary"); r.code != 0 {
		t.Fatalf("refresh: %d %s", r.code, r.stderr)
	}
	good, _ := os.ReadFile(w.credsPath())
	if err := os.WriteFile(w.credsPath(), stale, 0o600); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(11 * time.Minute)
	if r := w.run("api", "GET", "/api/summary"); r.code != 1 || !strings.Contains(r.stderr, "session has ended") {
		t.Errorf("a stale token: exit %d\nstderr: %s", r.code, r.stderr)
	}
	if evs := w.events("oauth.refresh.reuse_detected"); len(evs) != 1 || !strings.Contains(string(evs[0].Detail), `"severity":"critical"`) {
		t.Errorf("reuse events: %+v", evs)
	}
	// the genuine client's token died with the family
	if err := os.WriteFile(w.credsPath(), good, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := w.run("whoami"); r.code != 1 {
		t.Errorf("the family survived the reuse: %d %s", r.code, r.stdout)
	}
}

func TestE2E_CredentialsMustBePrivate(t *testing.T) {
	w := newWorld(t)
	if r := w.login("alice@tiny.example", operator, "approve"); r.code != 0 {
		t.Fatalf("login: %d %s", r.code, r.stderr)
	}
	if err := os.Chmod(w.credsPath(), 0o644); err != nil {
		t.Fatal(err)
	}
	r := w.run("whoami")
	if r.code != 1 || !strings.Contains(r.stderr, "mode 0644") || !strings.Contains(r.stderr, "chmod 600") {
		t.Errorf("exit %d\nstderr: %s", r.code, r.stderr)
	}
	if err := os.Chmod(w.credsPath(), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := w.run("whoami"); r.code != 0 {
		t.Errorf("after chmod 600: %d %s", r.code, r.stderr)
	}
}

// TestE2E_ServerMustBeWhoItSays: the CLI refuses a server whose metadata
// names another issuer or sends it to another origin.
func TestE2E_ServerMustBeWhoItSays(t *testing.T) {
	w := newWorld(t)
	for name, doc := range map[string]func(base string) map[string]any{
		"another issuer": func(base string) map[string]any {
			return map[string]any{"issuer": "https://evil.example/t/tiny"}
		},
		"an endpoint on another origin": func(base string) map[string]any {
			iss := base + "/t/tiny"
			return map[string]any{"issuer": iss, "token_endpoint": "https://evil.example/token",
				"device_authorization_endpoint": iss + "/oauth/device_authorization", "revocation_endpoint": iss + "/oauth/revoke",
				"grant_types_supported": []string{"urn:ietf:params:oauth:grant-type:device_code"}, "dpop_signing_alg_values_supported": []string{"ES256"}}
		},
		"no device grant": func(base string) map[string]any {
			iss := base + "/t/tiny"
			return map[string]any{"issuer": iss, "token_endpoint": iss + "/oauth/token",
				"device_authorization_endpoint": iss + "/oauth/device_authorization", "revocation_endpoint": iss + "/oauth/revoke",
				"grant_types_supported": []string{"refresh_token"}, "dpop_signing_alg_values_supported": []string{"ES256"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var base string
			stub := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server") {
					_ = json.NewEncoder(rw).Encode(doc(base))
					return
				}
				t.Errorf("the CLI went on to %s", r.URL.Path)
				rw.WriteHeader(http.StatusInternalServerError)
			}))
			defer stub.Close()
			base = stub.URL
			if r := w.run("login", "--server", stub.URL, "--tenant", "tiny"); r.code != 1 {
				t.Errorf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
			}
		})
	}
}

func TestE2E_Usage(t *testing.T) {
	w := newWorld(t)
	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"no command":           {nil, 2},
		"unknown command":      {[]string{"frobnicate"}, 2},
		"login needs a tenant": {[]string{"login", "--server", w.srv.URL}, 2},
		"api needs a path":     {[]string{"api", "GET"}, 2},
		"api method":           {[]string{"api", "TRACE", "/api/summary"}, 2},
		"api bad JSON":         {[]string{"api", "-d", "{", "POST", "/api/x"}, 2},
		"whoami takes none":    {[]string{"whoami", "x"}, 2},
		"help":                 {[]string{"help"}, 0},
	} {
		if r := w.run(tc.args...); r.code != tc.code {
			t.Errorf("%s: exit %d, want %d (%s)", name, r.code, tc.code, r.stderr)
		}
	}
	// a bad tenant name and a bad server are refused before any request
	if r := w.run("login", "--server", w.srv.URL, "--tenant", "Not A Slug"); r.code != 1 {
		t.Errorf("bad tenant: %d %s", r.code, r.stderr)
	}
	if r := w.run("login", "--server", "ftp://x", "--tenant", "tiny"); r.code != 1 {
		t.Errorf("bad server: %d %s", r.code, r.stderr)
	}
}

// TestHTTPClientIsSafehttp: production allows neither http nor loopback;
// development does.
func TestHTTPClientIsSafehttp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte("ok")) }))
	defer srv.Close()
	prod, err := newHTTPClient("prod")
	if err != nil {
		t.Fatal(err)
	}
	if res, err := prod.Get(srv.URL); err == nil { // #nosec G107 -- the test server
		_ = res.Body.Close()
		t.Error("the production client reached a loopback http server")
	}
	dev, err := newHTTPClient("dev")
	if err != nil {
		t.Fatal(err)
	}
	res, err := dev.Get(srv.URL) // #nosec G107 -- the test server
	if err != nil {
		t.Fatalf("the development client could not reach loopback: %v", err)
	}
	_ = res.Body.Close()
	for _, env := range []string{"", "test", "staging"} {
		if _, err := newHTTPClient(env); err != nil {
			t.Errorf("env %q: %v", env, err)
		}
	}
}
