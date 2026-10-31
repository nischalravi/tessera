package ghapp_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/ghapp"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func key(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

func pkcs1(k *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

func pkcs8(t testing.TB, k *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

var t0 = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// verifyJWT checks the App JWT's RS256 signature and returns its header and claims.
func verifyJWT(t testing.TB, jwt string, pub *rsa.PublicKey) (hdr map[string]any, claims map[string]any) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("jwt signature does not verify: %v", err)
	}
	for i, dst := range []*map[string]any{&hdr, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(raw, dst) != nil {
			t.Fatalf("jwt part %d unreadable: %v", i, err)
		}
	}
	return hdr, claims
}

func TestAppJWTClaims(t *testing.T) {
	k := key(t)
	jwt, err := ghapp.AppJWT("123456", k, t0)
	if err != nil {
		t.Fatal(err)
	}
	hdr, c := verifyJWT(t, jwt, &k.PublicKey)
	if hdr["alg"] != "RS256" || hdr["typ"] != "JWT" {
		t.Errorf("header = %v", hdr)
	}
	iat, exp := int64(c["iat"].(float64)), int64(c["exp"].(float64))
	if iat != t0.Unix()-60 {
		t.Errorf("iat = %d, want now-60s (%d)", iat, t0.Unix()-60)
	}
	if exp <= t0.Unix() || exp-t0.Unix() > 600 {
		t.Errorf("exp = now+%ds, want within (0, 600]", exp-t0.Unix())
	}
	if c["iss"] != "123456" {
		t.Errorf("iss = %v, want the App id as a string", c["iss"])
	}
	if len(c) != 3 {
		t.Errorf("claims = %v, want iat, exp and iss only", c)
	}
	for _, bad := range []string{"", "abc", "12 3", "-1", strings.Repeat("1", 21)} {
		if _, err := ghapp.AppJWT(bad, k, t0); !errors.Is(err, ghapp.ErrAppID) {
			t.Errorf("AppJWT(%q) = %v, want ErrAppID", bad, err)
		}
	}
	if _, err := ghapp.AppJWT("1", nil, t0); !errors.Is(err, ghapp.ErrKey) {
		t.Errorf("AppJWT with no key = %v", err)
	}
}

func TestParseKey(t *testing.T) {
	k := key(t)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		pem  string
		ok   bool
	}{
		{"pkcs1", pkcs1(k), true},
		{"pkcs8", pkcs8(t, k), true},
		{"pkcs1 with surrounding space", "\n" + pkcs1(k) + "\n\n", true},
		{"1024 bits", pkcs1(small), false},
		{"empty", "", false},
		{"not pem", "hello", false},
		{"two blocks", pkcs1(k) + pkcs1(k), false},
		{"public key block", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}})), false},
		{"garbage der", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}})), false},
		{"too large", pkcs1(k) + strings.Repeat("\n", ghapp.MaxKeyPEMBytes), false},
	} {
		got, err := ghapp.ParseKey([]byte(tc.pem))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
		if err != nil && len(tc.pem) > 20 && strings.Contains(err.Error(), strings.TrimSpace(tc.pem)[:20]) {
			t.Errorf("%s: the error carries the input", tc.name)
		}
		if tc.ok && got.N.Cmp(k.N) != 0 {
			t.Errorf("%s: parsed a different key", tc.name)
		}
	}
	// the fingerprint is GitHub's: base64 of SHA-256 over the PKCS#8 DER, and does not reveal the key
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	sum := sha256.Sum256(der)
	want := "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
	if fp := ghapp.Fingerprint(k); fp != want || len(fp) > 64 {
		t.Errorf("Fingerprint = %q, want %q", fp, want)
	}
}

// fakeGitHub replays the parts of the GitHub API the client uses and records what it was sent.
type fakeGitHub struct {
	t   *testing.T
	srv *httptest.Server
	pub *rsa.PublicKey

	mu         sync.Mutex
	now        time.Time
	mints      int
	lifetime   time.Duration
	current    string // the token the API accepts
	mintStatus int    // non-zero: the mint answers this
	mintBodies []map[string]any
	checks     map[int64]map[string]any
	comments   map[int64]string
	nextID     int64
	log        []string
	// fail makes the next requests matching "METHOD path" answer with the given reply, in order
	fail map[string][]reply
}

type reply struct {
	status int
	header map[string]string
	body   string
}

func newFake(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{t: t, pub: &key(t).PublicKey, now: t0, lifetime: time.Hour, checks: map[int64]map[string]any{}, comments: map[int64]string{}, nextID: 100,
		fail: map[string][]reply{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeGitHub) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func (f *fakeGitHub) failNext(route string, r ...reply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[route] = append(f.fail[route], r...)
}

func (f *fakeGitHub) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, l := range f.log {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	route := r.Method + " " + r.URL.Path
	f.log = append(f.log, route)
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") == "" || r.Header.Get("User-Agent") == "" {
		f.t.Errorf("%s: missing GitHub headers: %v", route, r.Header)
	}
	if q := f.fail[route]; len(q) > 0 {
		f.fail[route] = q[1:]
		for k, v := range q[0].header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(q[0].status)
		_, _ = io.WriteString(w, q[0].body)
		return
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	send := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/app/installations/") && strings.HasSuffix(r.URL.Path, "/access_tokens"):
		_, claims := verifyJWT(f.t, bearer, f.pub)
		if iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64)); iat > f.now.Unix() || exp <= f.now.Unix() || exp-f.now.Unix() > 600 {
			f.t.Errorf("mint JWT out of window: iat=%d exp=%d now=%d", iat, exp, f.now.Unix())
		}
		f.mintBodies = append(f.mintBodies, body)
		if f.mintStatus != 0 {
			send(f.mintStatus, map[string]string{"message": "x"})
			return
		}
		f.mints++
		f.current = "ghs_token" + strconv.Itoa(f.mints)
		send(http.StatusCreated, map[string]any{"token": f.current, "expires_at": f.now.Add(f.lifetime).UTC().Format(time.RFC3339),
			"permissions": body["permissions"], "repository_selection": "selected"})
		return
	}
	if bearer != f.current || f.current == "" {
		send(http.StatusUnauthorized, map[string]string{"message": "Bad credentials", "echo": bearer})
		return
	}
	switch {
	case route == "POST /repos/o/policy/check-runs":
		f.nextID++
		f.checks[f.nextID] = body
		send(http.StatusCreated, map[string]any{"id": f.nextID, "html_url": "https://github.com/o/policy/runs/" + strconv.FormatInt(f.nextID, 10)})
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/repos/o/policy/check-runs/"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/repos/o/policy/check-runs/"), 10, 64)
		if _, ok := f.checks[id]; !ok {
			send(http.StatusNotFound, map[string]string{"message": "Not Found"})
			return
		}
		f.checks[id] = body
		send(http.StatusOK, map[string]any{"id": id})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/repos/o/policy/issues/") && strings.HasSuffix(r.URL.Path, "/comments"):
		f.nextID++
		f.comments[f.nextID], _ = body["body"].(string)
		send(http.StatusCreated, map[string]any{"id": f.nextID, "html_url": "https://github.com/o/policy/pull/5#issuecomment-" + strconv.FormatInt(f.nextID, 10)})
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/repos/o/policy/issues/comments/"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/repos/o/policy/issues/comments/"), 10, 64)
		if _, ok := f.comments[id]; !ok {
			send(http.StatusNotFound, map[string]string{"message": "Not Found"})
			return
		}
		f.comments[id], _ = body["body"].(string)
		send(http.StatusOK, map[string]any{"id": id, "html_url": "https://github.com/o/policy/pull/5#issuecomment-" + strconv.FormatInt(id, 10)})
	default:
		send(http.StatusNotFound, map[string]string{"message": "Not Found"})
	}
}

func (f *fakeGitHub) client(t *testing.T) (*ghapp.Client, *[]time.Duration) {
	t.Helper()
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	var slept []time.Duration
	c := &ghapp.Client{HTTP: hc, APIBase: f.srv.URL, Cache: ghapp.NewTokenCache(), Now: f.clock,
		Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); f.advance(d); return nil }}
	return c, &slept
}

func creds(t testing.TB) *ghapp.Credentials {
	return &ghapp.Credentials{AppID: "4242", InstallationID: 77, Repo: "o/policy", Key: key(t), Scope: "tenant-a", KeyID: "fp1"}
}

const sha1c = "0123456789abcdef0123456789abcdef01234567"

func okCheck() ghapp.Check {
	return ghapp.Check{HeadSHA: sha1c, Conclusion: "success", Title: "Policy preview: no new violations", Summary: "all good"}
}

func TestTokenExchangeAndCache(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t)
	cr := creds(t)
	if _, _, err := c.CreateComment(context.Background(), cr, 5, "one"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.CreateComment(context.Background(), cr, 5, "two"); err != nil {
		t.Fatal(err)
	}
	if f.mints != 1 {
		t.Fatalf("mints = %d after two calls, want 1 (cached)", f.mints)
	}
	// the exchange asks for the least: the one repository and checks + pull_requests write
	b := f.mintBodies[0]
	repos, _ := b["repositories"].([]any)
	perms, _ := b["permissions"].(map[string]any)
	if len(repos) != 1 || repos[0] != "policy" || len(perms) != 2 || perms["checks"] != "write" || perms["pull_requests"] != "write" {
		t.Errorf("mint body = %v, want repositories [policy] and permissions checks+pull_requests write only", b)
	}
	if f.count("POST /app/installations/77/access_tokens") != 1 {
		t.Errorf("mint route calls = %v", f.log)
	}

	// still cached shortly before the refresh margin, replaced after it
	f.advance(time.Hour - ghapp.RefreshMargin - time.Minute)
	if _, _, err := c.CreateComment(context.Background(), cr, 5, "three"); err != nil || f.mints != 1 {
		t.Fatalf("1 minute before the margin: err = %v, mints = %d, want the cached token", err, f.mints)
	}
	f.advance(2 * time.Minute)
	if _, _, err := c.CreateComment(context.Background(), cr, 5, "four"); err != nil || f.mints != 2 {
		t.Fatalf("past the margin: err = %v, mints = %d, want a new token", err, f.mints)
	}

	// another tenant or another key never shares a token
	other := *cr
	other.Scope = "tenant-b"
	if _, _, err := c.CreateComment(context.Background(), &other, 5, "x"); err != nil || f.mints != 3 {
		t.Fatalf("other tenant: err = %v, mints = %d, want its own token", err, f.mints)
	}
	rotated := *cr
	rotated.KeyID = "fp2"
	if _, _, err := c.CreateComment(context.Background(), &rotated, 5, "x"); err != nil || f.mints != 4 {
		t.Fatalf("rotated key: err = %v, mints = %d, want its own token", err, f.mints)
	}
}

func TestExpiredTokenRefreshesOnce(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t)
	cr := creds(t)
	if _, _, err := c.CreateComment(context.Background(), cr, 5, "one"); err != nil {
		t.Fatal(err)
	}
	// GitHub revokes the cached token early: the next call gets 401, mints a new token and succeeds
	f.mu.Lock()
	f.current = "ghs_revoked_elsewhere"
	f.mu.Unlock()
	if _, _, err := c.CreateComment(context.Background(), cr, 5, "two"); err != nil {
		t.Fatalf("after one 401: %v", err)
	}
	if f.mints != 2 {
		t.Errorf("mints = %d, want 2 (one refresh)", f.mints)
	}
	if n := f.count("POST /repos/o/policy/issues/5/comments"); n != 3 {
		t.Errorf("comment posts = %d, want 3 (ok, 401, retry)", n)
	}

	// a second 401 in a row is an error, not a loop
	f.failNext("POST /repos/o/policy/issues/5/comments", reply{status: 401}, reply{status: 401})
	_, _, err := c.CreateComment(context.Background(), cr, 5, "three")
	if !ghapp.IsStatus(err, 401) {
		t.Fatalf("two 401s: err = %v, want a 401 status error", err)
	}
	if f.mints != 3 {
		t.Errorf("mints = %d, want 3 (one refresh for the failing call, none more)", f.mints)
	}
	if ghapp.ErrCode(err) != "github_401" {
		t.Errorf("ErrCode = %q", ghapp.ErrCode(err))
	}
}

func TestMintFailures(t *testing.T) {
	for _, tc := range []struct {
		status int
		is     error
		code   string
	}{
		{http.StatusNotFound, ghapp.ErrInstallationNotFound, "installation_not_found"},
		{http.StatusUnauthorized, ghapp.ErrAppAuth, "app_auth_failed"},
		{http.StatusUnprocessableEntity, ghapp.ErrRepoAccess, "repository_not_accessible"},
	} {
		f := newFake(t)
		f.mintStatus = tc.status
		c, _ := f.client(t)
		_, _, err := c.CreateComment(context.Background(), creds(t), 5, "x")
		if !errors.Is(err, tc.is) || ghapp.ErrCode(err) != tc.code {
			t.Errorf("mint %d: err = %v (%q), want %v", tc.status, err, ghapp.ErrCode(err), tc.is)
		}
		if n := f.count("POST /app/installations"); n != 1 {
			t.Errorf("mint %d: %d mint calls, want 1 (no retry)", tc.status, n)
		}
		if f.count("POST /repos/") != 0 {
			t.Errorf("mint %d: an API call was made without a token", tc.status)
		}
	}
	// a 500 on the mint is a status error, never retried
	f := newFake(t)
	f.mintStatus = 500
	c, _ := f.client(t)
	if _, _, err := c.CreateComment(context.Background(), creds(t), 5, "x"); !ghapp.IsStatus(err, 500) {
		t.Errorf("mint 500: err = %v", err)
	}
}

func TestRateLimits(t *testing.T) {
	post := "POST /repos/o/policy/issues/5/comments"
	run := func(t *testing.T, f *fakeGitHub, replies ...reply) (error, []time.Duration) {
		c, slept := f.client(t)
		if len(replies) > 0 {
			// warm the cache so only the API call is limited
			if _, _, err := c.CreateComment(context.Background(), creds(t), 5, "warm"); err != nil {
				t.Fatal(err)
			}
			f.failNext(post, replies...)
		}
		_, _, err := c.CreateComment(context.Background(), creds(t), 5, "x")
		return err, *slept
	}

	t.Run("Retry-After is waited out", func(t *testing.T) {
		f := newFake(t)
		err, slept := run(t, f, reply{status: 403, header: map[string]string{"Retry-After": "2"}, body: `{"message":"You have exceeded a secondary rate limit"}`})
		if err != nil || len(slept) != 1 || slept[0] != 2*time.Second {
			t.Errorf("err = %v, slept = %v; want one 2s wait then success", err, slept)
		}
	})
	t.Run("X-RateLimit-Reset is waited out", func(t *testing.T) {
		f := newFake(t)
		reset := strconv.FormatInt(t0.Add(7*time.Second).Unix(), 10)
		err, slept := run(t, f, reply{status: 403, header: map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset}})
		if err != nil || len(slept) != 1 || slept[0] != 7*time.Second {
			t.Errorf("err = %v, slept = %v; want one 7s wait then success", err, slept)
		}
	})
	t.Run("429 is a rate limit", func(t *testing.T) {
		f := newFake(t)
		err, slept := run(t, f, reply{status: 429, header: map[string]string{"Retry-After": "1"}})
		if err != nil || len(slept) != 1 {
			t.Errorf("err = %v, slept = %v", err, slept)
		}
	})
	t.Run("a long window is reported, not slept", func(t *testing.T) {
		f := newFake(t)
		err, slept := run(t, f, reply{status: 403, header: map[string]string{"Retry-After": "3600"}})
		var rl *ghapp.RateLimitError
		if !errors.As(err, &rl) || rl.RetryAfter != time.Hour || len(slept) != 0 || ghapp.ErrCode(err) != "rate_limited" {
			t.Errorf("err = %v, slept = %v; want RateLimitError{1h} and no sleep", err, slept)
		}
	})
	t.Run("retries are bounded", func(t *testing.T) {
		f := newFake(t)
		lim := reply{status: 403, header: map[string]string{"Retry-After": "1"}}
		err, slept := run(t, f, lim, lim, lim, lim)
		var rl *ghapp.RateLimitError
		if !errors.As(err, &rl) || len(slept) != ghapp.MaxRetries {
			t.Errorf("err = %v, slept = %v; want RateLimitError after %d waits", err, slept, ghapp.MaxRetries)
		}
		if n := f.count(post); n != 1+ghapp.MaxRetries+1 {
			t.Errorf("posts = %d, want warm-up + %d attempts", n, ghapp.MaxRetries+1)
		}
	})
	t.Run("a secondary limit without a time is not retried", func(t *testing.T) {
		f := newFake(t)
		err, slept := run(t, f, reply{status: 403, body: `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes"}`})
		var rl *ghapp.RateLimitError
		if !errors.As(err, &rl) || rl.RetryAfter != 0 || len(slept) != 0 {
			t.Errorf("err = %v, slept = %v", err, slept)
		}
	})
	t.Run("a plain 403 is a permission error, not retried", func(t *testing.T) {
		f := newFake(t)
		err, slept := run(t, f, reply{status: 403, body: `{"message":"Resource not accessible by integration"}`})
		if !ghapp.IsStatus(err, 403) || len(slept) != 0 || f.count(post) != 2 {
			t.Errorf("err = %v, slept = %v, posts = %d", err, slept, f.count(post))
		}
	})
	t.Run("a rate limit on the mint is waited out too", func(t *testing.T) {
		f := newFake(t)
		f.failNext("POST /app/installations/77/access_tokens", reply{status: 403, header: map[string]string{"Retry-After": "3"}})
		c, slept := f.client(t)
		if _, _, err := c.CreateComment(context.Background(), creds(t), 5, "x"); err != nil || len(*slept) != 1 || (*slept)[0] != 3*time.Second {
			t.Errorf("err = %v, slept = %v", err, *slept)
		}
	})
	t.Run("a cancelled context stops the wait", func(t *testing.T) {
		f := newFake(t)
		c, _ := f.client(t)
		c.Sleep = func(ctx context.Context, d time.Duration) error { return context.Canceled }
		f.failNext("POST /app/installations/77/access_tokens", reply{status: 403, header: map[string]string{"Retry-After": "3"}})
		if _, _, err := c.CreateComment(context.Background(), creds(t), 5, "x"); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestPublishCreatesThenUpdatesInPlace(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t)
	cr := creds(t)
	ctx := context.Background()

	// first run: a check run and a comment are created
	pub, err := c.Publish(ctx, cr, 5, okCheck(), "comment v1", ghapp.Previous{})
	if err != nil {
		t.Fatal(err)
	}
	if !pub.CheckCreated || !pub.CommentCreated || pub.CheckRunID == 0 || pub.CommentID == 0 || !strings.HasPrefix(pub.CommentURL, "https://") {
		t.Fatalf("first publish = %+v", pub)
	}
	chk := f.checks[pub.CheckRunID]
	out, _ := chk["output"].(map[string]any)
	if chk["name"] != ghapp.CheckName || chk["head_sha"] != sha1c || chk["status"] != "completed" || chk["conclusion"] != "success" ||
		out["title"] != "Policy preview: no new violations" || out["summary"] != "all good" || chk["completed_at"] == "" {
		t.Errorf("created check run = %v", chk)
	}

	// second run on the same commit: both are updated in place
	k2 := okCheck()
	k2.Conclusion, k2.Summary = "failure", "worse"
	prev := ghapp.Previous{HeadSHA: sha1c, CheckRunID: pub.CheckRunID, CommentID: pub.CommentID}
	pub2, err := c.Publish(ctx, cr, 5, k2, "comment v2", prev)
	if err != nil {
		t.Fatal(err)
	}
	if pub2.CheckCreated || pub2.CommentCreated || pub2.CheckRunID != pub.CheckRunID || pub2.CommentID != pub.CommentID {
		t.Fatalf("second publish = %+v, want updates in place", pub2)
	}
	if len(f.comments) != 1 || f.comments[pub.CommentID] != "comment v2" {
		t.Errorf("comments = %v, want the one comment updated", f.comments)
	}
	if len(f.checks) != 1 || f.checks[pub.CheckRunID]["conclusion"] != "failure" {
		t.Errorf("check runs = %v, want the one check run updated", f.checks)
	}
	if _, ok := f.checks[pub.CheckRunID]["head_sha"]; ok {
		t.Error("the check run update re-sent head_sha")
	}

	// a new commit: a new check run, the same comment
	k3 := okCheck()
	k3.HeadSHA = "fedcba9876543210fedcba9876543210fedcba98"
	pub3, err := c.Publish(ctx, cr, 5, k3, "comment v3", ghapp.Previous{HeadSHA: sha1c, CheckRunID: pub.CheckRunID, CommentID: pub.CommentID})
	if err != nil {
		t.Fatal(err)
	}
	if !pub3.CheckCreated || pub3.CommentCreated || pub3.CheckRunID == pub.CheckRunID || pub3.CommentID != pub.CommentID || len(f.checks) != 2 || len(f.comments) != 1 {
		t.Errorf("third publish = %+v; checks = %d, comments = %d", pub3, len(f.checks), len(f.comments))
	}

	// a deleted comment (and check run) is created again, once
	delete(f.comments, pub.CommentID)
	delete(f.checks, pub3.CheckRunID)
	pub4, err := c.Publish(ctx, cr, 5, k3, "comment v4", ghapp.Previous{HeadSHA: k3.HeadSHA, CheckRunID: pub3.CheckRunID, CommentID: pub.CommentID})
	if err != nil {
		t.Fatal(err)
	}
	if !pub4.CheckCreated || !pub4.CommentCreated || len(f.comments) != 1 {
		t.Errorf("fourth publish = %+v; comments = %d", pub4, len(f.comments))
	}
	if f.mints != 1 {
		t.Errorf("mints = %d over the whole sequence, want 1", f.mints)
	}
}

func TestPublishPartialFailureKeepsTheCheck(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t)
	f.failNext("POST /repos/o/policy/issues/5/comments", reply{status: 422, body: `{"message":"Validation Failed"}`})
	pub, err := c.Publish(context.Background(), creds(t), 5, okCheck(), "c", ghapp.Previous{})
	if !ghapp.IsStatus(err, 422) || pub == nil || pub.CheckRunID == 0 || pub.CommentID != 0 {
		t.Errorf("pub = %+v, err = %v; want the check run reported and the comment error returned", pub, err)
	}
}

func TestInputValidation(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t)
	ctx := context.Background()
	for _, repo := range []string{"", "o", "o/", "/p", "o/p/q", "o/..", "../p", "o/p?x=1", "o/p#f", "o p/q", "o/p\n", strings.Repeat("a", 101) + "/p"} {
		cr := creds(t)
		cr.Repo = repo
		if _, _, err := c.CreateComment(ctx, cr, 5, "x"); !errors.Is(err, ghapp.ErrBadInput) {
			t.Errorf("repo %q: err = %v, want ErrBadInput", repo, err)
		}
	}
	cr := creds(t)
	if _, _, err := c.CreateComment(ctx, cr, 0, "x"); !errors.Is(err, ghapp.ErrBadInput) {
		t.Errorf("pull 0: %v", err)
	}
	if _, _, err := c.CreateComment(ctx, cr, 5, ""); !errors.Is(err, ghapp.ErrBadInput) {
		t.Errorf("empty comment: %v", err)
	}
	bad := okCheck()
	bad.HeadSHA = "main"
	if _, _, err := c.CreateCheckRun(ctx, cr, bad); !errors.Is(err, ghapp.ErrBadInput) {
		t.Errorf("branch name as sha: %v", err)
	}
	bad = okCheck()
	bad.Conclusion = "cancelled"
	if _, _, err := c.CreateCheckRun(ctx, cr, bad); !errors.Is(err, ghapp.ErrBadInput) {
		t.Errorf("conclusion cancelled: %v", err)
	}
	if f.count("") != 0 {
		t.Errorf("requests were made for invalid input: %v", f.log)
	}
	if !ghapp.ValidAPIBase("https://ghe.example.com/api/v3") || ghapp.ValidAPIBase("ftp://x") || ghapp.ValidAPIBase("https://u:p@x/") || ghapp.ValidAPIBase("https://x/?a=1") || ghapp.ValidAPIBase("x") {
		t.Error("ValidAPIBase")
	}
}

// Nothing secret reaches an error: not the App key, the JWT, the installation token, nor a response body that echoes them.
func TestSecretsNeverInErrorsOrLogs(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t)
	cr := creds(t)
	keyPEM := pkcs1(cr.Key)
	ctx := context.Background()
	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	// a mint that echoes the JWT, then an API call whose 401 and 500 bodies echo the token
	if _, _, err := c.CreateComment(ctx, cr, 5, "warm"); err != nil {
		t.Fatal(err)
	}
	tok := f.current
	f.failNext("POST /repos/o/policy/issues/5/comments", reply{status: 500, body: `{"message":"` + tok + `"}`})
	_, _, err := c.CreateComment(ctx, cr, 5, "x")
	collect(err)
	f.failNext("POST /repos/o/policy/check-runs", reply{status: 401, body: tok}, reply{status: 401, body: tok})
	_, _, err = c.CreateCheckRun(ctx, cr, okCheck())
	collect(err)
	f.mintStatus = 401
	c.Cache = ghapp.NewTokenCache()
	_, _, err = c.CreateComment(ctx, cr, 5, "x")
	collect(err)
	// an unreachable API: the URL (which names the repository) is dropped
	c.APIBase = "http://127.0.0.1:1"
	_, _, err = c.CreateComment(ctx, cr, 5, "x")
	collect(err)
	_, _, err = c.CreateComment(ctx, cr, 5, "x")
	collect(err)
	// a bad PEM
	_, err = ghapp.ParseKey([]byte("-----BEGIN RSA PRIVATE KEY-----\nSECRETSECRET\n-----END RSA PRIVATE KEY-----\n"))
	collect(err)

	jwt, _ := ghapp.AppJWT(cr.AppID, cr.Key, t0)
	if len(errs) < 6 {
		t.Fatalf("collected %d errors, want 6", len(errs))
	}
	for _, e := range errs {
		msg := e.Error() + " " + ghapp.ErrCode(e)
		for name, secret := range map[string]string{"token": tok, "jwt": jwt, "key": keyPEM, "key body": "SECRETSECRET", "repo": "o/policy"} {
			if strings.Contains(msg, secret) {
				t.Errorf("error %q carries the %s", e, name)
			}
		}
	}
	// the cache holds the token only in memory: a fresh cache knows nothing
	if ghapp.NewTokenCache().Len() != 0 {
		t.Error("a new cache is not empty")
	}
}

func TestErrCodes(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, ""},
		{context.DeadlineExceeded, "timeout"},
		{fmt.Errorf("wrapped: %w", &ghapp.StatusError{Status: 404}), "github_404"},
		{&ghapp.RateLimitError{}, "rate_limited"},
		{ghapp.ErrBadInput, "invalid_settings"},
		{errors.New("dial tcp"), "unreachable"},
	} {
		if got := ghapp.ErrCode(tc.err); got != tc.want {
			t.Errorf("ErrCode(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
