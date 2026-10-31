package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/ghapp"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The GitHub App check run (issue #656, AC-10): the settings route keeps the App's private key sealed and never returns
// it, and POST /api/policy/github/check runs the preview and posts a check run and one comment, updated in place.

var (
	ghKeyOnce sync.Once
	ghKey     *rsa.PrivateKey
)

func ghTestKey(t testing.TB) (*rsa.PrivateKey, string) {
	t.Helper()
	ghKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		ghKey = k
	})
	return ghKey, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ghKey)}))
}

// syncBuf is a log sink the server and the test can both touch.
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

// appGitHub is a local TLS stand-in for the GitHub App API: it checks the App JWT of a token exchange, accepts only the
// installation token it minted last, and keeps the check runs and comments it was given.
type appGitHub struct {
	mu       sync.Mutex
	pub      *rsa.PublicKey
	mints    int
	current  string
	tokens   []string
	jwts     []string
	checks   map[int64]map[string]any
	comments map[int64]string
	nextID   int64
	got      []string
	mintBody []map[string]any // the body of each token request
	repo     *gitRepo         // the repository routes of the right-sizing pull request (lp_rec_pr_test.go); nil: none
	head     string           // the pull request's head; ghHead when empty
	// fail answers the next request of a route ("METHOD path") with the status and headers
	fail map[string]ghFail
	// delay holds a check run create open, to widen the window in which requests for one pull request overlap
	delay time.Duration
}

type ghFail struct {
	status int
	header map[string]string
}

func (g *appGitHub) calls(prefix string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, r := range g.got {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func newAppGitHub(t *testing.T, logs *syncBuf) (*appGitHub, func(*Config)) {
	t.Helper()
	k, _ := ghTestKey(t)
	g := &appGitHub{pub: &k.PublicKey, checks: map[int64]map[string]any{}, comments: map[int64]string{}, nextID: 1000, fail: map[string]ghFail{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(g.serve))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(storetest.IdentityKEK)
	if err != nil {
		t.Fatal(err)
	}
	return g, func(c *Config) {
		c.OutboundHTTP, c.GitHubAPIBase, c.Sealer = hc, srv.URL, sealer
		withAWSCatalog(c)
		if logs != nil {
			c.Logger = slog.New(slog.NewTextHandler(logs, nil))
		}
	}
}

func (g *appGitHub) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	route := r.Method + " " + r.URL.Path
	g.got = append(g.got, route)
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	send := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if f, ok := g.fail[route]; ok {
		delete(g.fail, route)
		for k, v := range f.header {
			w.Header().Set(k, v)
		}
		send(f.status, map[string]string{"message": "replayed failure"})
		return
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if r.Method == http.MethodGet && r.URL.Path == "/app" { // the App itself, read with the App JWT (LP-9: the login of its pull requests)
		send(http.StatusOK, map[string]any{"slug": "tessera-app"})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/access_tokens") && r.Method == http.MethodPost {
		parts := strings.Split(bearer, ".")
		sig, err := base64.RawURLEncoding.DecodeString(parts[len(parts)-1])
		sum := sha256.Sum256([]byte(strings.Join(parts[:len(parts)-1], ".")))
		if len(parts) != 3 || err != nil || rsa.VerifyPKCS1v15(g.pub, crypto.SHA256, sum[:], sig) != nil {
			send(http.StatusUnauthorized, map[string]string{"message": "A JSON web token could not be decoded"})
			return
		}
		g.jwts = append(g.jwts, bearer)
		g.mintBody = append(g.mintBody, body)
		g.mints++
		g.current = "ghs_apptoken" + strconv.Itoa(g.mints)
		g.tokens = append(g.tokens, g.current)
		send(http.StatusCreated, map[string]any{"token": g.current, "expires_at": "2099-01-01T00:00:00Z", "permissions": body["permissions"]})
		return
	}
	if bearer != g.current || g.current == "" {
		send(http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
		return
	}
	if g.repo != nil && g.repo.serve(r, body, send) {
		return
	}
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/o/policy/pulls/"):
		h := g.head
		if h == "" {
			h = ghHead
		}
		send(http.StatusOK, map[string]any{"head": map[string]string{"sha": h}})
	case route == "POST /repos/o/policy/check-runs":
		time.Sleep(g.delay)
		g.nextID++
		g.checks[g.nextID] = body
		send(http.StatusCreated, map[string]any{"id": g.nextID, "html_url": "https://github.com/o/policy/runs/1"})
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/repos/o/policy/check-runs/"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/repos/o/policy/check-runs/"), 10, 64)
		g.checks[id] = body
		send(http.StatusOK, map[string]any{"id": id})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/comments"):
		g.nextID++
		g.comments[g.nextID], _ = body["body"].(string)
		send(http.StatusCreated, map[string]any{"id": g.nextID, "html_url": "https://github.com/o/policy/pull/7#issuecomment-1"})
	case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/issues/comments/"):
		id, _ := strconv.ParseInt(r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:], 10, 64)
		g.comments[id], _ = body["body"].(string)
		send(http.StatusOK, map[string]any{"id": id, "html_url": "https://github.com/o/policy/pull/7#issuecomment-1"})
	default:
		send(http.StatusNotFound, map[string]string{"message": "Not Found"})
	}
}

func (g *appGitHub) onlyComment(t *testing.T) string {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.comments) != 1 {
		t.Fatalf("GitHub holds %d comments, want 1", len(g.comments))
	}
	for _, c := range g.comments {
		return c
	}
	return ""
}

func ghAdmin(t *testing.T, f *storetest.Fixture, tn storetest.Tenant, email string) authtest.Login {
	t.Helper()
	return signIn(t, f.DB, tn.ID, authtest.User{Email: email, Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
}

func putApp(t *testing.T, h http.Handler, l authtest.Login, pemKey string, enabled bool) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"enabled": enabled, "app_id": "4242", "installation_id": 77, "repo": "o/policy", "private_key": pemKey})
	rec := reqDo(h, l, "PUT", "/api/policy/github/app", string(body))
	if rec.Code != 200 {
		t.Fatalf("PUT /api/policy/github/app = %d %s", rec.Code, rec.Body)
	}
	return rec.Body.String()
}

const ghHead = "0123456789abcdef0123456789abcdef01234567"

func checkBody(t *testing.T, head string, pull int, change map[string]any) string {
	t.Helper()
	m := map[string]any{"repo": "o/policy", "pull_number": pull, "head_sha": head}
	for k, v := range change {
		m[k] = v
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestGitHubApp_SettingsSealTheKeyAndNeverReturnIt(t *testing.T) {
	f := storetest.TwoTenants(t)
	logs := &syncBuf{}
	_, withGH := newAppGitHub(t, logs)
	h := newIsolationServerWith(f, withGH).Handler()
	admin := ghAdmin(t, f, f.B, "admin@b.example")
	key, pemKey := ghTestKey(t)

	rec := reqDo(h, admin, "GET", "/api/policy/github/app", "")
	var v map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 || v["enabled"] != false || v["key_set"] != false || v["key_fingerprint"] != "" || v["repo"] != "" {
		t.Fatalf("default = %d %s", rec.Code, rec.Body)
	}
	if p := v["permissions"].(map[string]any); len(p) != 2 || p["checks"] != "write" || p["pull_requests"] != "write" {
		t.Errorf("permissions = %v, want checks and pull_requests write only", p)
	}
	if p := v["contents_permissions"].(map[string]any); len(p) != 3 || p["contents"] != "write" || p["checks"] != "write" || p["pull_requests"] != "write" {
		t.Errorf("contents_permissions = %v, want checks, pull_requests and contents write", p)
	}

	for name, body := range map[string]string{
		"no body":               ``,
		"unknown field":         `{"enabled":false,"extra":1}`,
		"app id not digits":     `{"enabled":false,"app_id":"12a"}`,
		"negative installation": `{"enabled":false,"installation_id":-1}`,
		"bad repo":              `{"enabled":false,"repo":"o/../x"}`,
		"not a key":             `{"enabled":false,"private_key":"hello"}`,
		"public key":            `{"enabled":false,"private_key":"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"}`,
		"key and remove":        `{"enabled":false,"remove_key":true,"private_key":` + strconv.Quote(pemKey) + `}`,
		"enable with nothing":   `{"enabled":true}`,
		"enable with no key":    `{"enabled":true,"app_id":"1","installation_id":2,"repo":"o/r"}`,
	} {
		if rec := reqDo(h, admin, "PUT", "/api/policy/github/app", body); rec.Code != 422 {
			t.Errorf("%s: %d %.200s, want 422", name, rec.Code, rec.Body)
		}
	}

	out := putApp(t, h, admin, pemKey, true)
	fp := ghapp.Fingerprint(key)
	for _, body := range []string{out, reqDo(h, admin, "GET", "/api/policy/github/app", "").Body.String()} {
		for _, secret := range []string{"BEGIN", "PRIVATE KEY", "key_enc", base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key))[:40]} {
			if strings.Contains(body, secret) {
				t.Errorf("a response holds %q: %s", secret, body)
			}
		}
		if !strings.Contains(body, `"key_set":true`) || !strings.Contains(body, fp) || !strings.Contains(body, `"app_id":"4242"`) || !strings.Contains(body, `"installation_id":77`) {
			t.Errorf("response = %s", body)
		}
	}

	// stored sealed, bound to the tenant; the ledger and the logs hold no key
	sealer, _ := seal.New(storetest.IdentityKEK)
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		st, err := tx.GitHubAppSettings()
		if err != nil || !st.Enabled || len(st.KeyEnc) == 0 || strings.Contains(string(st.KeyEnc), "PRIVATE") || st.KeyFingerprint != fp {
			t.Errorf("stored = %+v, %v", st, err)
		}
		if got, err := sealer.Open(st.KeyEnc, githubKeyAAD(f.B.ID)); err != nil || string(got) != pemKey {
			t.Errorf("the key does not open with its own tenant's AAD: %v", err)
		}
		if _, err := sealer.Open(st.KeyEnc, githubKeyAAD(f.A.ID)); err == nil {
			t.Error("the sealed key opens under another tenant's AAD")
		}
		if _, err := sealer.Open(st.KeyEnc, seal.AAD(f.B.ID, "aws_pr_comment_settings", "token_enc")); err == nil {
			t.Error("the sealed key opens under another column's AAD")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var settings int
	for _, e := range ledger(t, f.DB, f.B.ID) {
		if strings.Contains(string(e.Detail), "PRIVATE KEY") || strings.Contains(string(e.Detail), "BEGIN") {
			t.Errorf("audit event %s holds the key: %s", e.Action, e.Detail)
		}
		if e.Action == "policy.github_app.settings" {
			settings++
			if !strings.Contains(string(e.Detail), fp) || !strings.Contains(string(e.Detail), `"key_changed":true`) {
				t.Errorf("settings event = %s", e.Detail)
			}
		}
	}
	if settings != 1 {
		t.Errorf("%d settings events, want 1", settings)
	}

	// omitting the key keeps it; a new key rotates it; remove_key deletes it and the feature is refused again
	if rec := reqDo(h, admin, "PUT", "/api/policy/github/app", `{"enabled":true,"app_id":"4242","installation_id":78,"repo":"o/policy"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), fp) {
		t.Errorf("PUT without a key = %d %s", rec.Code, rec.Body)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, other)}))
	if out := putApp(t, h, admin, otherPEM, true); !strings.Contains(out, ghapp.Fingerprint(other)) || strings.Contains(out, fp) {
		t.Errorf("rotation = %s", out)
	}
	if rec := reqDo(h, admin, "PUT", "/api/policy/github/app", `{"enabled":false,"app_id":"4242","installation_id":78,"repo":"o/policy","remove_key":true}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"key_set":false`) {
		t.Errorf("remove_key = %d %s", rec.Code, rec.Body)
	}
	if rec := reqDo(h, admin, "POST", "/api/policy/github/check", checkBody(t, ghHead, 7, map[string]any{"files": map[string]string{"x": "y"}})); rec.Code != 409 || !strings.Contains(rec.Body.String(), "github_app_disabled") {
		t.Errorf("check with the key removed = %d %s", rec.Code, rec.Body)
	}

	// tenant A never saw any of it
	adminA := ghAdmin(t, f, f.A, "admin@a.example")
	if rec := reqDo(h, adminA, "GET", "/api/policy/github/app", ""); !strings.Contains(rec.Body.String(), `"key_set":false`) || strings.Contains(rec.Body.String(), "o/policy") {
		t.Errorf("tenant A sees %s", rec.Body)
	}

	// the permission and the step-up
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	for _, rq := range [][2]string{{"GET", ""}, {"PUT", `{"enabled":false}`}} {
		if rec := reqDo(h, viewer, rq[0], "/api/policy/github/app", rq[1]); rec.Code != 403 {
			t.Errorf("viewer %s = %d", rq[0], rec.Code)
		}
	}
	weak := signIn(t, f.DB, f.B.ID, authtest.User{Email: "w@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	if rec := reqDo(h, weak, "PUT", "/api/policy/github/app", `{"enabled":false}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("weak sign-in PUT = %d %.200s", rec.Code, rec.Body)
	}
	if strings.Contains(logs.String(), "PRIVATE KEY") || strings.Contains(logs.String(), pemKey[40:80]) {
		t.Errorf("the key reached the logs:\n%s", logs.String())
	}
}

func mustPKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

const sodFile = `schema: tessera.sod/v1
ruleset:
  key: payments
  name: Payments controls
  enabled: true
functions:
  - key: create
    name: Create a payment
    selectors: [{name_pattern: "payments:create*"}]
  - key: approve
    name: Approve a payment
    selectors: [{name_pattern: "payments:approve*"}]
risks:
  - key: pay-create-approve
    name: Create and approve a payment
    priority: high
    functions: [create, approve]
`

func TestGitHubCheck_ConclusionsAndInPlaceUpdates(t *testing.T) {
	f := storetest.TwoTenants(t)
	persistEstate(t, f.DB, f.B.ID, nil)
	logs := &syncBuf{}
	gh, withGH := newAppGitHub(t, logs)
	h := newIsolationServerWith(f, withGH).Handler()
	admin := ghAdmin(t, f, f.B, "admin@b.example")
	_, pemKey := ghTestKey(t)

	noop := map[string]any{"files": map[string]string{"tessera.yaml": fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n    roles: partial\n", f.B.Slug)}}
	sod := map[string]any{"files": map[string]string{
		"tessera.yaml":      fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n  sod: partial\n", f.B.Slug),
		"sod/payments.yaml": sodFile}}
	conditional := map[string]any{"terraform_plan": json.RawMessage(`{"format_version":"1.2","planned_values":{},"resource_changes":[
	 {"address":"aws_iam_user_group_membership.m","mode":"managed","type":"aws_iam_user_group_membership","name":"m","change":{"actions":["create"],"before":null,"after":{"user":"mallory","groups":["admins"]},"after_unknown":{}}}]}`)}

	// not configured: refused, nothing sent
	if rec := reqDo(h, admin, "POST", "/api/policy/github/check", checkBody(t, ghHead, 7, noop)); rec.Code != 409 || !strings.Contains(rec.Body.String(), "github_app_disabled") || len(gh.got) != 0 {
		t.Fatalf("unconfigured = %d %s (%d GitHub calls)", rec.Code, rec.Body, len(gh.got))
	}
	putApp(t, h, admin, pemKey, true)

	post := func(head string, pull int, change map[string]any, want int) map[string]any {
		t.Helper()
		rec := reqDo(h, admin, "POST", "/api/policy/github/check", checkBody(t, head, pull, change))
		if rec.Code != want {
			t.Fatalf("POST /api/policy/github/check = %d, want %d: %.600s", rec.Code, want, rec.Body)
		}
		var v map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	// 1. success: a no-op bundle introduces nothing
	v := post(ghHead, 7, noop, 200)
	if v["conclusion"] != "success" || v["status"] != "posted" || v["check_created"] != true || v["comment_created"] != true {
		t.Fatalf("no-op = %v", v)
	}
	checkID, commentID := int64(v["check_run_id"].(float64)), int64(v["comment_id"].(float64))
	if gh.mints != 1 || gh.calls("POST /repos/o/policy/check-runs") != 1 || gh.calls("POST /repos/o/policy/issues/7/comments") != 1 {
		t.Errorf("GitHub calls = %v", gh.got)
	}
	chk := gh.checks[checkID]
	if chk["conclusion"] != "success" || chk["head_sha"] != ghHead || chk["name"] != ghapp.CheckName {
		t.Errorf("check run = %v", chk)
	}
	if c := gh.onlyComment(t); !strings.HasPrefix(c, ghapp.CommentMarker) || !strings.Contains(c, "SUCCESS") {
		t.Errorf("comment = %s", c)
	}

	// 2. failure: an SoD rule that someone already breaks introduces a finding; same commit, so both are updated in place
	v = post(ghHead, 7, sod, 200)
	if v["conclusion"] != "failure" || v["check_created"] != false || v["comment_created"] != false ||
		int64(v["check_run_id"].(float64)) != checkID || int64(v["comment_id"].(float64)) != commentID {
		t.Fatalf("sod = %v", v)
	}
	if gh.checks[checkID]["conclusion"] != "failure" || len(gh.checks) != 1 {
		t.Errorf("check runs = %v, want the one updated", gh.checks)
	}
	if c := gh.onlyComment(t); !strings.Contains(c, "FAILURE") || !strings.Contains(c, "pay-create-approve") || !strings.Contains(c, "separation-of-duties") {
		t.Errorf("comment = %s", c)
	}
	if gh.mints != 1 {
		t.Errorf("mints = %d, want the cached token reused", gh.mints)
	}

	// 3. neutral: a Terraform change that is unsupported but access relevant makes the answer conditional; a new commit gets a
	// new check run and the same comment
	newHead := strings.Repeat("ab", 20)
	gh.mu.Lock()
	gh.head = newHead
	gh.mu.Unlock()
	v = post(newHead, 7, conditional, 200)
	gh.mu.Lock()
	gh.head = ""
	gh.mu.Unlock()
	if v["conclusion"] != "neutral" || v["check_created"] != true || v["comment_created"] != false || int64(v["comment_id"].(float64)) != commentID {
		t.Fatalf("conditional = %v", v)
	}
	if len(gh.checks) != 2 || len(gh.comments) != 1 {
		t.Errorf("GitHub holds %d check runs and %d comments, want 2 and 1", len(gh.checks), len(gh.comments))
	}
	if c := gh.onlyComment(t); !strings.Contains(c, "NEUTRAL") || !strings.Contains(c, "aws_iam_user_group_membership.m") {
		t.Errorf("comment = %s", c)
	}

	// another pull request gets its own comment
	post(ghHead, 8, noop, 200)
	if len(gh.comments) != 2 {
		t.Errorf("%d comments after a second pull request, want 2", len(gh.comments))
	}

	// the record of what was posted, and the audit events (with no key or token in them)
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		rec, err := tx.GitHubPRCheck("o/policy", 7)
		if err != nil || rec == nil || rec.HeadSHA != newHead || rec.Conclusion != "neutral" || rec.CommentID != commentID {
			t.Errorf("record = %+v, %v", rec, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	posted := 0
	for _, e := range ledger(t, f.DB, f.B.ID) {
		d := string(e.Detail)
		for _, tok := range gh.tokens {
			if strings.Contains(d, tok) {
				t.Errorf("audit event %s holds an installation token", e.Action)
			}
		}
		for _, jwt := range gh.jwts {
			if strings.Contains(d, jwt) {
				t.Errorf("audit event %s holds an App JWT", e.Action)
			}
		}
		if e.Action == "policy.github_check.posted" {
			posted++
			if !strings.Contains(d, `"repo":"o/policy"`) || !strings.Contains(d, "diff_sha256") || !strings.Contains(d, "conclusion") {
				t.Errorf("posted event = %s", d)
			}
		}
	}
	if posted != 4 {
		t.Errorf("%d posted events, want 4", posted)
	}
	for _, secret := range append(append([]string{"PRIVATE KEY"}, gh.tokens...), gh.jwts...) {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("a secret reached the logs: %.40s", secret)
		}
	}

	// input and configuration limits
	for name, tc := range map[string]struct {
		body string
		want int
		code string
	}{
		"other repository": {strings.Replace(checkBody(t, ghHead, 7, noop), "o/policy", "o/other", 1), 422, "repo_not_configured"},
		"bad repo":         {strings.Replace(checkBody(t, ghHead, 7, noop), "o/policy", "o/../x", 1), 422, "invalid_repo"},
		"pull zero":        {checkBody(t, ghHead, 0, noop), 422, "invalid_pull_number"},
		"branch as sha":    {checkBody(t, "main", 7, noop), 422, "invalid_head_sha"},
		"upper-case sha":   {checkBody(t, strings.ToUpper(ghHead), 7, noop), 422, "invalid_head_sha"},
		"no change":        {checkBody(t, ghHead, 7, nil), 422, "empty_change"},
		"stale head":       {checkBody(t, strings.Repeat("cd", 20), 7, noop), 409, "stale_head_sha"},
		"unknown field":    {checkBody(t, ghHead, 7, map[string]any{"token": "x"}), 422, "invalid_body"},
	} {
		if rec := reqDo(h, admin, "POST", "/api/policy/github/check", tc.body); rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("%s: %d %.200s, want %d %s", name, rec.Code, rec.Body, tc.want, tc.code)
		}
	}
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	if rec := reqDo(h, viewer, "POST", "/api/policy/github/check", checkBody(t, ghHead, 7, noop)); rec.Code != 403 {
		t.Errorf("viewer = %d", rec.Code)
	}

	// tenant A has not configured the App: it cannot use B's, and sees none of B's checks
	adminA := ghAdmin(t, f, f.A, "admin@a.example")
	before := len(gh.got)
	if rec := reqDo(h, adminA, "POST", "/api/policy/github/check", checkBody(t, ghHead, 7, noop)); rec.Code != 409 || !strings.Contains(rec.Body.String(), "github_app_disabled") || len(gh.got) != before {
		t.Errorf("tenant A = %d %.200s (%d new GitHub calls)", rec.Code, rec.Body, len(gh.got)-before)
	}
	if err := f.DB.ReadTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
		if rec, err := tx.GitHubPRCheck("o/policy", 7); err != nil || rec != nil {
			t.Errorf("tenant A sees B's record: %+v, %v", rec, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// and when A configures the same App and installation, it gets its own token and its own comment
	putApp(t, h, adminA, pemKey, true)
	mints := gh.mints
	if v := func() map[string]any {
		rec := reqDo(h, adminA, "POST", "/api/policy/github/check", checkBody(t, ghHead, 7, map[string]any{"files": map[string]string{
			"tessera.yaml": fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n    roles: partial\n", f.A.Slug)}}))
		var v map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		if rec.Code != 200 {
			t.Fatalf("tenant A post = %d %s", rec.Code, rec.Body)
		}
		return v
	}(); v["comment_created"] != true || gh.mints != mints+1 {
		t.Errorf("tenant A = %v, mints %d -> %d; want a new comment and its own token", v, mints, gh.mints)
	}
}

func TestGitHubCheck_GitHubFailuresAreReportedAndAudited(t *testing.T) {
	f := storetest.TwoTenants(t)
	gh, withGH := newAppGitHub(t, nil)
	h := newIsolationServerWith(f, withGH).Handler()
	admin := ghAdmin(t, f, f.B, "admin@b.example")
	_, pemKey := ghTestKey(t)
	putApp(t, h, admin, pemKey, true)
	body := checkBody(t, ghHead, 7, map[string]any{"files": map[string]string{"tessera.yaml": fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n    roles: partial\n", f.B.Slug)}})
	tokenRoute := "POST /app/installations/77/access_tokens"

	for name, tc := range map[string]struct {
		route  string
		fail   ghFail
		status int
		code   string
		reason string
	}{
		"installation gone":  {tokenRoute, ghFail{status: 404}, 502, "github_failed", "installation_not_found"},
		"App key refused":    {tokenRoute, ghFail{status: 401}, 502, "github_failed", "app_auth_failed"},
		"repo not installed": {tokenRoute, ghFail{status: 422}, 502, "github_failed", "installation_scope_mismatch"},
		"rate limited":       {"POST /repos/o/policy/check-runs", ghFail{status: 403, header: map[string]string{"Retry-After": "3600"}}, 503, "github_rate_limited", "rate_limited"},
		"no permission":      {"POST /repos/o/policy/check-runs", ghFail{status: 403}, 502, "github_failed", "github_403"},
	} {
		gh.mu.Lock()
		gh.fail[tc.route] = tc.fail
		gh.current = "" // no usable token is cached upstream: force an exchange where one is expected
		gh.mu.Unlock()
		rec := reqDo(h, admin, "POST", "/api/policy/github/check", body)
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.code) || !strings.Contains(rec.Body.String(), `"reason":"`+tc.reason+`"`) {
			t.Errorf("%s: %d %.300s, want %d %s/%s", name, rec.Code, rec.Body, tc.status, tc.code, tc.reason)
		}
	}
	failed := 0
	for _, e := range ledger(t, f.DB, f.B.ID) {
		if e.Action == "policy.github_check.failed" {
			failed++
			if !strings.Contains(string(e.Detail), `"error":"`) {
				t.Errorf("failed event = %s", e.Detail)
			}
		}
	}
	if failed != 5 {
		t.Errorf("%d failed events, want 5", failed)
	}
	// a failed first post leaves no record, so a retry creates the check and comment
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		if rec, err := tx.GitHubPRCheck("o/policy", 7); err != nil || rec != nil {
			t.Errorf("record after failures = %+v, %v", rec, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	gh.mu.Lock()
	gh.current = ""
	gh.mu.Unlock()
	if rec := reqDo(h, admin, "POST", "/api/policy/github/check", body); rec.Code != 200 {
		t.Errorf("retry = %d %.300s", rec.Code, rec.Body)
	}
}

// The deprecated stored personal token is refused where the operator turned it off (prod always does).
func TestPersonalTokenDisabled(t *testing.T) {
	_, withGH := newFakeGitHub(t)
	c := newAWSEval(t, nil, withGH, func(c *Config) { c.DisablePersonalToken = true })
	rec := c.do("PUT", "/api/aws/pr-comment", `{"enabled":true,"repo":"o/r","token":"`+prToken+`"}`)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "personal_token_disabled") || strings.Contains(rec.Body.String(), prToken) {
		t.Errorf("PUT with a token = %d %s", rec.Code, rec.Body.String())
	}
	// settings without a token still work, and a stored token is not used
	if rec := c.do("PUT", "/api/aws/pr-comment", `{"enabled":false,"repo":"o/r"}`); rec.Code != 200 {
		t.Errorf("PUT without a token = %d %s", rec.Code, rec.Body.String())
	}
}

// CI is a machine client: it cannot meet a step-up, so the trigger is a scope-only permission it can hold
// (tessera:policy-github-check), and that scope gives it nothing else, least of all the App's settings.
func TestGitHubCheck_MachineClient(t *testing.T) {
	gh, withGH := newAppGitHub(t, nil)
	e := newOAuthEnv(t, withGH)
	_, pemKey := ghTestKey(t)
	adminA := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "admin@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	putApp(t, e.h, adminA, pemKey, true)
	body := checkBody(t, ghHead, 7, map[string]any{"files": map[string]string{"tessera.yaml": fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n    roles: partial\n", e.f.A.Slug)}})

	ci := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:policy-github-check"}, true)
	tok := e.machineToken(ci, "tenant-a", "tessera:policy-github-check")
	rec := e.call(tok, "POST", "/api/policy/github/check", body)
	if rec.Code != 200 || body_(rec)["conclusion"] != "success" || body_(rec)["status"] != "posted" {
		t.Fatalf("CI check = %d %s", rec.Code, rec.Body)
	}
	if len(gh.comments) != 1 || len(gh.checks) != 1 {
		t.Errorf("GitHub holds %d comments and %d check runs", len(gh.comments), len(gh.checks))
	}
	// the scope gives it nothing else: not the settings, not the graph
	if rec := e.call(tok, "PUT", "/api/policy/github/app", `{"enabled":false}`); rec.Code != 403 {
		t.Errorf("CI PUT settings = %d %s", rec.Code, rec.Body)
	}
	if rec := e.call(tok, "GET", "/api/policy/github/app", ""); rec.Code != 403 {
		t.Errorf("CI GET settings = %d", rec.Code)
	}
	if rec := e.call(tok, "GET", "/api/summary", ""); rec.Code != 403 {
		t.Errorf("CI GET /api/summary = %d", rec.Code)
	}
	// a client without the scope is refused, even with a role that reads
	reader := e.addMachine("tenant-a", []string{"viewer"}, []string{"tessera:read"}, true)
	rtok := e.machineToken(reader, "tenant-a", "tessera:read")
	if rec := e.call(rtok, "POST", "/api/policy/github/check", body); rec.Code != 403 {
		t.Errorf("read-scope client = %d %s", rec.Code, rec.Body)
	}
	// the head must be the pull request's now
	gh.mu.Lock()
	gh.head = strings.Repeat("ef", 20)
	gh.mu.Unlock()
	before := len(gh.comments)
	if rec := e.call(tok, "POST", "/api/policy/github/check", body); rec.Code != 409 || !strings.Contains(rec.Body.String(), "stale_head_sha") || len(gh.comments) != before {
		t.Errorf("stale head = %d %s", rec.Code, rec.Body)
	}
}

func body_(rec *httptest.ResponseRecorder) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return m
}

// Concurrent first checks of one pull request create one check run and one comment (issue #781): the others either update
// them or are refused 409 check_in_progress, and once the claim is released a later check is accepted.
func TestGitHubCheck_ConcurrentChecksCreateOnce(t *testing.T) {
	f := storetest.TwoTenants(t)
	persistEstate(t, f.DB, f.B.ID, nil)
	gh, withGH := newAppGitHub(t, nil)
	gh.delay = 300 * time.Millisecond
	h := newIsolationServerWith(f, withGH).Handler()
	admin := ghAdmin(t, f, f.B, "admin@b.example")
	_, pemKey := ghTestKey(t)
	putApp(t, h, admin, pemKey, true)
	noop := map[string]any{"files": map[string]string{"tessera.yaml": fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n    roles: partial\n", f.B.Slug)}}

	const n = 6
	codes := make([]int, n)
	bodies := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := reqDo(h, admin, "POST", "/api/policy/github/check", checkBody(t, ghHead, 9, noop))
			codes[i], bodies[i] = rec.Code, rec.Body.String()
		}(i)
	}
	wg.Wait()
	ok, busy := 0, 0
	for i, c := range codes {
		switch {
		case c == 200:
			ok++
		case c == 409 && strings.Contains(bodies[i], "check_in_progress"):
			busy++
		default:
			t.Errorf("request %d = %d %.300s", i, c, bodies[i])
		}
	}
	if ok < 1 || busy < 1 {
		t.Errorf("%d accepted, %d refused as in progress; want at least one of each", ok, busy)
	}
	if c := gh.calls("POST /repos/o/policy/check-runs"); c != 1 {
		t.Errorf("%d check run creates, want 1", c)
	}
	if c := gh.calls("POST /repos/o/policy/issues/9/comments"); c != 1 {
		t.Errorf("%d comment creates, want 1", c)
	}
	gh.onlyComment(t)

	// the claim was released: the next check updates in place
	gh.delay = 0
	rec := reqDo(h, admin, "POST", "/api/policy/github/check", checkBody(t, ghHead, 9, noop))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"check_created":false`) || !strings.Contains(rec.Body.String(), `"comment_created":false`) {
		t.Errorf("later check = %d %.300s, want an in-place update", rec.Code, rec.Body)
	}
	if c := gh.calls("POST /repos/o/policy/check-runs"); c != 1 {
		t.Errorf("%d check run creates after the later check, want 1", c)
	}
}

// PUT with enabled:false only toggles: the other fields and the sealed key stay, and omitted fields stay on any PUT.
func TestGitHubApp_PutKeepsOmittedFields(t *testing.T) {
	f := storetest.TwoTenants(t)
	_, withGH := newAppGitHub(t, nil)
	h := newIsolationServerWith(f, withGH).Handler()
	admin := ghAdmin(t, f, f.B, "admin@b.example")
	_, pemKey := ghTestKey(t)
	putApp(t, h, admin, pemKey, true)
	get := func() map[string]any {
		t.Helper()
		var v map[string]any
		if err := json.Unmarshal(reqDo(h, admin, "GET", "/api/policy/github/app", "").Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := get()
	if rec := reqDo(h, admin, "PUT", "/api/policy/github/app", `{"enabled":false}`); rec.Code != 200 {
		t.Fatalf("disable = %d %s", rec.Code, rec.Body)
	}
	off := get()
	if off["enabled"] != false || off["app_id"] != "4242" || off["installation_id"] != float64(77) || off["repo"] != "o/policy" ||
		off["key_set"] != true || off["key_fingerprint"] != before["key_fingerprint"] {
		t.Errorf("after disabling = %v, want only enabled changed", off)
	}
	// enabling again needs nothing else, and a field sent replaces the stored one
	if rec := reqDo(h, admin, "PUT", "/api/policy/github/app", `{"enabled":true,"repo":"o/other"}`); rec.Code != 200 {
		t.Fatalf("enable = %d %s", rec.Code, rec.Body)
	}
	on := get()
	if on["enabled"] != true || on["app_id"] != "4242" || on["installation_id"] != float64(77) || on["repo"] != "o/other" || on["key_set"] != true {
		t.Errorf("after enabling = %v", on)
	}
}
