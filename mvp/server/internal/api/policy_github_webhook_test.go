package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/ratelimit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The GitHub pull_request webhook (issue #771, AC-10 follow-up): signature, tenant binding, replay, body cap, ignored
// actions, the pull request's own bundle, stale heads, concurrency, and where the secret may appear.

type hookWorld struct {
	t      *testing.T
	e      *oauthEnv
	gh     *appGitHub
	repo   *gitRepo
	logs   *syncBuf
	admin  authtest.Login
	secret string
	files  map[string]string
	sha    string // the head commit (the pull request's head)
	n      int
}

const hookPull = 7

func hookSetup(t *testing.T) *hookWorld {
	t.Helper()
	logs := &syncBuf{}
	gh, withGH := newAppGitHub(t, logs)
	e := newOAuthEnv(t, withGH)
	w := &hookWorld{t: t, e: e, gh: gh, logs: logs, admin: ghAdmin(t, e.f, e.f.B, "ta@b.example")}
	_, pemKey := ghTestKey(t)
	putApp(t, e.h, w.admin, pemKey, true)
	w.files = map[string]string{"tessera.yaml": fmt.Sprintf("schema: tessera.repo/v1\ntenant: %s\nmanage:\n    roles: partial\n", e.f.B.Slug)}
	w.repo = newGitRepo(w.files)
	w.repo.extra = syncExtra(map[string]string{}, map[string]map[string]string{})
	w.sha = w.repo.branches["main"]
	gh.mu.Lock()
	gh.repo, gh.head = w.repo, w.sha
	gh.mu.Unlock()
	w.secret = w.rotate()
	return w
}

// rotate makes a new webhook secret through the settings route and returns it.
func (w *hookWorld) rotate() string {
	w.t.Helper()
	rec := reqDo(w.e.h, w.admin, "PUT", "/api/policy/github/app", `{"enabled":true,"rotate_webhook_secret":true}`)
	var v struct {
		Secret string `json:"webhook_secret"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &v) != nil || !strings.HasPrefix(v.Secret, "whsec_") {
		w.t.Fatalf("rotate = %d %s", rec.Code, rec.Body)
	}
	return v.Secret
}

func hookSig(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// payload is a pull_request event for pull request hookPull of the configured installation and repository.
func (w *hookWorld) payload(action, head string) []byte {
	b, _ := json.Marshal(map[string]any{"action": action, "number": hookPull, "installation": map[string]any{"id": 77},
		"repository":   map[string]any{"full_name": "o/policy"},
		"pull_request": map[string]any{"number": hookPull, "head": map[string]any{"sha": head, "repo": map[string]any{"full_name": "o/policy"}}}})
	return b
}

type hookReq struct {
	slug, event, delivery, sig string
	secret                     string // signs the body when sig is empty and secret is not "-"
	body                       []byte
}

func (w *hookWorld) deliver(h hookReq) *httptest.ResponseRecorder {
	w.t.Helper()
	if h.slug == "" {
		h.slug = w.e.f.B.Slug
	}
	if h.event == "" {
		h.event = "pull_request"
	}
	if h.delivery == "" {
		w.n++
		h.delivery = fmt.Sprintf("d-%d", w.n)
	}
	if h.sig == "" && h.secret != "-" {
		h.sig = hookSig(firstNonEmpty(h.secret, w.secret), h.body)
	}
	req := httptest.NewRequest("POST", "/public/t/"+h.slug+"/github/webhook", strings.NewReader(string(h.body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", h.event)
	req.Header.Set("X-GitHub-Delivery", h.delivery)
	if h.sig != "" {
		req.Header.Set("X-Hub-Signature-256", h.sig)
	}
	return serve(w.e.h, req)
}

func (w *hookWorld) ok(action, head string) *httptest.ResponseRecorder {
	return w.deliver(hookReq{body: w.payload(action, head)})
}

func (w *hookWorld) actions(tn tenancy.ID) map[string]int {
	w.t.Helper()
	return reqAuditActions(w.t, w.e.f, tn)
}

func TestGitHubWebhook_ChecksThePullRequestsOwnBundle(t *testing.T) {
	w := hookSetup(t)
	rec := w.ok("opened", w.sha)
	if rec.Code != 202 || !strings.Contains(rec.Body.String(), `"outcome":"checked"`) || !strings.Contains(rec.Body.String(), `"conclusion":"success"`) {
		t.Fatalf("delivery = %d %s", rec.Code, rec.Body)
	}
	// the bundle was read from the commit with a contents:read token, and the check run was posted with the checks token
	if w.gh.calls("GET /repos/o/policy/git/trees/") == 0 || w.gh.calls("POST /repos/o/policy/check-runs") != 1 {
		t.Errorf("GitHub calls = %v", w.gh.got)
	}
	var readTokens, writeTokens int
	for _, m := range w.gh.mintBody {
		perms, _ := m["permissions"].(map[string]any)
		switch {
		case len(perms) == 1 && perms["contents"] == "read":
			readTokens++
		case perms["checks"] == "write":
			writeTokens++
		}
	}
	if readTokens != 1 || writeTokens != 1 {
		t.Errorf("tokens minted: %d contents:read, %d checks:write; want one each (%v)", readTokens, writeTokens, w.gh.mintBody)
	}
	w.gh.onlyComment(t)
	// a re-run for the same commit updates in place
	if rec := w.ok("synchronize", w.sha); rec.Code != 202 {
		t.Fatalf("second delivery = %d %s", rec.Code, rec.Body)
	}
	if w.gh.calls("POST /repos/o/policy/check-runs") != 1 || w.gh.calls("POST /repos/o/policy/issues/7/comments") != 1 {
		t.Errorf("a re-run created again: %v", w.gh.got)
	}
	a := w.actions(w.e.f.B.ID)
	if a["policy.github_check.posted"] != 2 {
		t.Errorf("audit actions = %v, want two posted events", a)
	}
	var trig bool
	for _, ev := range ledger(t, w.e.f.DB, w.e.f.B.ID) {
		if ev.Action == "policy.github_check.posted" && strings.Contains(string(ev.Detail), `"trigger":"webhook"`) && strings.Contains(string(ev.Detail), `"delivery_id":"d-1"`) {
			trig = true
		}
	}
	if !trig {
		t.Error("no posted event names the webhook trigger and the delivery")
	}
}

func TestGitHubWebhook_Signature(t *testing.T) {
	w := hookSetup(t)
	body := w.payload("opened", w.sha)
	good := hookSig(w.secret, body)
	other := hookSig("whsec_other", body)
	// every refusal is the same 401, after the same work: nothing says what was wrong
	var want string
	for name, h := range map[string]hookReq{
		"wrong secret":      {sig: other, body: body},
		"missing signature": {secret: "-", body: body},
		"no prefix":         {sig: strings.TrimPrefix(good, "sha256="), body: body},
		"sha1 prefix":       {sig: "sha1=" + strings.TrimPrefix(good, "sha256="), body: body},
		"not hex":           {sig: "sha256=zz", body: body},
		"short":             {sig: good[:20], body: body},
		"other body":        {sig: good, body: append(append([]byte{}, body...), ' ')},
		"unknown slug":      {slug: "no-such-tenant", sig: good, body: body},
		"bad slug":          {slug: "Not_A_Slug!", sig: good, body: body},
	} {
		rec := w.deliver(h)
		if rec.Code != 401 {
			t.Errorf("%s: %d %s, want 401", name, rec.Code, rec.Body)
			continue
		}
		if want == "" {
			want = rec.Body.String()
		}
		if rec.Body.String() != want {
			t.Errorf("%s: body %q differs from %q", name, rec.Body, want)
		}
	}
	if w.gh.calls("POST /repos/o/policy/check-runs") != 0 || len(w.gh.got) != 0 {
		t.Errorf("a refused delivery reached GitHub: %v", w.gh.got)
	}
	// refusals are in the platform chain's request events, not the tenant's
	if n := w.actions(w.e.f.B.ID)["policy.github_webhook.rejected"]; n != 0 {
		t.Errorf("%d tenant events for unauthenticated deliveries", n)
	}
	if rec := w.deliver(hookReq{sig: good, body: body}); rec.Code != 202 {
		t.Errorf("the right signature = %d %s", rec.Code, rec.Body)
	}
}

// The comparison is hmac.Equal and nothing else touches the digest.
func TestGitHubWebhook_ConstantTimeCompare(t *testing.T) {
	src, err := os.ReadFile("policy_github_webhook.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "hmac.Equal(got, want)") {
		t.Error("the signature is not compared with hmac.Equal")
	}
	for _, bad := range []string{"bytes.Equal", "subtle.", "== want", "!= want", "string(want)", "string(got)"} {
		if strings.Contains(s, bad) {
			t.Errorf("policy_github_webhook.go contains %q", bad)
		}
	}
	body := []byte(`{"a":1}`)
	for _, tc := range []struct {
		name, hdr string
		ok        bool
	}{
		{"good", hookSig("s", body), true},
		{"wrong key", hookSig("t", body), false},
		{"empty", "", false},
		{"prefix only", "sha256=", false},
		{"upper-case hex", "sha256=" + strings.ToUpper(strings.TrimPrefix(hookSig("s", body), "sha256=")), false}, // GitHub sends lower-case hex (issue #809)
		{"truncated", hookSig("s", body)[:40], false},
	} {
		if got := githubSignatureOK([]byte("s"), body, tc.hdr); got != tc.ok {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.ok)
		}
	}
}

func TestGitHubWebhook_ReplayedDeliveryIsRefused(t *testing.T) {
	w := hookSetup(t)
	body := w.payload("opened", w.sha)
	if rec := w.deliver(hookReq{delivery: "abc-1", body: body}); rec.Code != 202 {
		t.Fatalf("first = %d %s", rec.Code, rec.Body)
	}
	for i := 0; i < 2; i++ {
		rec := w.deliver(hookReq{delivery: "abc-1", body: body})
		if rec.Code != 409 || !strings.Contains(rec.Body.String(), "replayed_delivery") {
			t.Errorf("replay %d = %d %s", i, rec.Code, rec.Body)
		}
	}
	if w.gh.calls("PATCH /repos/o/policy/check-runs/") != 0 || w.gh.calls("POST /repos/o/policy/check-runs") != 1 {
		t.Errorf("a replay reached GitHub: %v", w.gh.got)
	}
	if n := w.actions(w.e.f.B.ID)["policy.github_webhook.rejected"]; n != 2 {
		t.Errorf("%d rejected events, want 2", n)
	}
	// a fresh id is handled; a delivery id that is not an id is refused
	if rec := w.deliver(hookReq{delivery: "abc-2", body: body}); rec.Code != 202 {
		t.Errorf("fresh id = %d %s", rec.Code, rec.Body)
	}
	if rec := w.deliver(hookReq{delivery: "bad id!", body: body}); rec.Code != 422 {
		t.Errorf("bad id = %d %s", rec.Code, rec.Body)
	}
	// the same id in another tenant is another delivery (retention is per tenant): only B's table holds it
	err := w.e.f.DB.InTenant(t.Context(), w.e.f.A.ID, func(c *store.TenantTx) error {
		fresh, err := c.RecordGitHubDelivery("abc-1", storetest.Now.Add(time.Hour), storetest.Now)
		if err == nil && !fresh {
			t.Error("A's delivery id was seen as B's")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A delivery that fails for a reason that may pass is forgotten, so GitHub's redelivery of it is handled.
func TestGitHubWebhook_FailedDeliveryCanBeRedelivered(t *testing.T) {
	w := hookSetup(t)
	w.gh.mu.Lock()
	w.gh.fail["POST /repos/o/policy/check-runs"] = ghFail{status: 502}
	w.gh.mu.Unlock()
	body := w.payload("opened", w.sha)
	if rec := w.deliver(hookReq{delivery: "retry-1", body: body}); rec.Code != 502 {
		t.Fatalf("first = %d %s", rec.Code, rec.Body)
	}
	if rec := w.deliver(hookReq{delivery: "retry-1", body: body}); rec.Code != 202 {
		t.Errorf("redelivery = %d %s, want it handled", rec.Code, rec.Body)
	}
}

func TestGitHubWebhook_BodyCap(t *testing.T) {
	w := hookSetup(t)
	big := append(w.payload("opened", w.sha)[:0:0], make([]byte, githubHookBody+1)...)
	for i := range big {
		big[i] = ' '
	}
	if rec := w.deliver(hookReq{body: big}); rec.Code != 413 {
		t.Errorf("oversized = %d %.200s, want 413", rec.Code, rec.Body)
	}
	// exactly the cap is read (and is then refused as not JSON, not as too large)
	if rec := w.deliver(hookReq{body: big[:githubHookBody]}); rec.Code != 422 {
		t.Errorf("at the cap = %d %.200s, want 422 invalid_body", rec.Code, rec.Body)
	}
	if len(w.gh.got) != 0 {
		t.Errorf("GitHub was called: %v", w.gh.got)
	}
}

func TestGitHubWebhook_InstallationAndRepositoryMustMatchTheSlugsTenant(t *testing.T) {
	w := hookSetup(t)
	mk := func(inst int, repo string) []byte {
		b, _ := json.Marshal(map[string]any{"action": "opened", "installation": map[string]any{"id": inst}, "repository": map[string]any{"full_name": repo},
			"pull_request": map[string]any{"number": hookPull, "head": map[string]any{"sha": w.sha, "repo": map[string]any{"full_name": "o/policy"}}}})
		return b
	}
	for name, body := range map[string][]byte{"other installation": mk(78, "o/policy"), "other repository": mk(77, "o/other"), "no installation": mk(0, "o/policy")} {
		rec := w.deliver(hookReq{body: body})
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), "installation_mismatch") {
			t.Errorf("%s = %d %s, want 403 installation_mismatch", name, rec.Code, rec.Body)
		}
	}
	if rec := w.deliver(hookReq{body: mk(77, "O/Policy")}); rec.Code != 202 {
		t.Errorf("repository in another case = %d %s", rec.Code, rec.Body)
	}
	if n := w.actions(w.e.f.B.ID)["policy.github_webhook.rejected"]; n != 3 {
		t.Errorf("%d rejected events, want 3", n)
	}
}

// A pull request from a fork is never previewed: "repository" is the base, so the installation and repository binding passes,
// and only the head's repository says whose files these are (issue #805).
func TestGitHubWebhook_PullRequestFromAForkIsIgnored(t *testing.T) {
	w := hookSetup(t)
	mk := func(head any) []byte {
		pr := map[string]any{"number": hookPull, "head": map[string]any{"sha": w.sha}}
		if head != nil {
			pr["head"].(map[string]any)["repo"] = head
		}
		b, _ := json.Marshal(map[string]any{"action": "opened", "installation": map[string]any{"id": 77}, "repository": map[string]any{"full_name": "o/policy"}, "pull_request": pr})
		return b
	}
	repo := func(name string) any { return map[string]any{"full_name": name} }
	for name, body := range map[string][]byte{
		"fork of another owner":     mk(repo("evil/policy")),
		"same name, other owner":    mk(repo("o2/policy")),
		"same owner, other name":    mk(repo("o/policy-fork")),
		"deleted fork (null repo)":  mk(nil),
		"empty repository name":     mk(repo("")),
		"suffix of the tenant repo": mk(repo("evil/o/policy")),
		"prefix of the tenant repo": mk(repo("o/policy/x")),
	} {
		rec := w.deliver(hookReq{body: body})
		if rec.Code != 202 || !strings.Contains(rec.Body.String(), `"outcome":"ignored"`) || !strings.Contains(rec.Body.String(), "fork_pull_request") {
			t.Errorf("%s = %d %s, want ignored as fork_pull_request", name, rec.Code, rec.Body)
		}
	}
	if len(w.gh.got) != 0 {
		t.Errorf("a pull request from a fork reached GitHub: %v", w.gh.got)
	}
	if got := w.actions(w.e.f.B.ID); got["policy.github_webhook.ignored"] != 7 || got["policy.github_check.posted"] != 0 {
		t.Errorf("audit actions = %v, want 7 ignored events and no check", got)
	}
	// the pull request's own repository, in another case, is checked; and the delivery ids of the ignored ones were not spent
	if rec := w.deliver(hookReq{body: mk(repo("O/Policy"))}); rec.Code != 202 || !strings.Contains(rec.Body.String(), `"outcome":"checked"`) {
		t.Errorf("same repository = %d %s", rec.Code, rec.Body)
	}
}

// B's valid signature on A's slug, and A's own secret, never reach the other tenant.
func TestGitHubWebhook_OtherTenantsSlug(t *testing.T) {
	w := hookSetup(t)
	body := w.payload("opened", w.sha)
	// A has no secret: B's signature on A's slug is refused like any other
	if rec := w.deliver(hookReq{slug: w.e.f.A.Slug, body: body}); rec.Code != 401 {
		t.Errorf("A without a secret = %d %s", rec.Code, rec.Body)
	}
	// A configures the same installation and its own secret; B's secret still does not open A
	adminA := ghAdmin(t, w.e.f, w.e.f.A, "ta@a.example")
	_, pemKey := ghTestKey(t)
	putApp(t, w.e.h, adminA, pemKey, true)
	rec := reqDo(w.e.h, adminA, "PUT", "/api/policy/github/app", `{"rotate_webhook_secret":true,"enabled":true}`)
	var v struct {
		Secret string `json:"webhook_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 || v.Secret == "" || v.Secret == w.secret {
		t.Fatalf("A rotate = %d %s", rec.Code, rec.Body)
	}
	if rec := w.deliver(hookReq{slug: w.e.f.A.Slug, body: body}); rec.Code != 401 {
		t.Errorf("B's secret on A's slug = %d %s", rec.Code, rec.Body)
	}
	if rec := w.deliver(hookReq{slug: w.e.f.B.Slug, secret: v.Secret, body: body}); rec.Code != 401 {
		t.Errorf("A's secret on B's slug = %d %s", rec.Code, rec.Body)
	}
	if w.gh.calls("POST /repos/o/policy/check-runs") != 0 {
		t.Error("a cross-tenant delivery posted a check")
	}
	// A's own secret works for A, and the delivery is audited in A's ledger only
	before := w.actions(w.e.f.B.ID)
	rec = w.deliver(hookReq{slug: w.e.f.A.Slug, secret: v.Secret, event: "ping", body: []byte(`{}`)})
	if rec.Code != 202 || w.actions(w.e.f.A.ID)["policy.github_webhook.ignored"] != 1 || w.actions(w.e.f.B.ID)["policy.github_webhook.ignored"] != before["policy.github_webhook.ignored"] {
		t.Errorf("A's ping = %d %s", rec.Code, rec.Body)
	}
}

func TestGitHubWebhook_IgnoredEventsAndActions(t *testing.T) {
	w := hookSetup(t)
	for _, action := range []string{"closed", "labeled", "edited", "assigned", "ready_for_review", "converted_to_draft", ""} {
		rec := w.ok(action, w.sha)
		if rec.Code != 202 || !strings.Contains(rec.Body.String(), `"outcome":"ignored"`) || !strings.Contains(rec.Body.String(), "action_not_handled") {
			t.Errorf("action %q = %d %s", action, rec.Code, rec.Body)
		}
	}
	for event, reason := range map[string]string{"ping": "ping", "push": "event_not_handled", "issues": "event_not_handled", "pull_request_review": "event_not_handled"} {
		rec := w.deliver(hookReq{event: event, body: w.payload("opened", w.sha)})
		if rec.Code != 202 || !strings.Contains(rec.Body.String(), reason) {
			t.Errorf("event %s = %d %s", event, rec.Code, rec.Body)
		}
	}
	if len(w.gh.got) != 0 {
		t.Errorf("an ignored delivery reached GitHub: %v", w.gh.got)
	}
	if n := w.actions(w.e.f.B.ID)["policy.github_webhook.ignored"]; n != 11 {
		t.Errorf("%d ignored events, want 11", n)
	}
	for _, action := range []string{"opened", "synchronize", "reopened"} {
		if rec := w.ok(action, w.sha); rec.Code != 202 || !strings.Contains(rec.Body.String(), "checked") {
			t.Errorf("action %s = %d %s", action, rec.Code, rec.Body)
		}
	}
	// a malformed event, and a commit that holds no policy bundle
	if rec := w.deliver(hookReq{body: []byte(`{"action":`)}); rec.Code != 422 {
		t.Errorf("malformed = %d", rec.Code)
	}
	if rec := w.deliver(hookReq{body: w.payload("opened", "nothex")}); rec.Code != 422 {
		t.Errorf("bad head = %d", rec.Code)
	}
	empty := w.repo.push(map[string]string{"README.md": "hello"})
	w.gh.mu.Lock()
	w.gh.head = empty
	w.gh.mu.Unlock()
	if rec := w.ok("synchronize", empty); rec.Code != 202 || !strings.Contains(rec.Body.String(), "no_policy_bundle") {
		t.Errorf("no bundle = %d %s", rec.Code, rec.Body)
	}
}

// A re-run for an older head never overwrites the result of the newer one.
func TestGitHubWebhook_OlderHeadDoesNotOverwriteANewerOne(t *testing.T) {
	w := hookSetup(t)
	older := w.sha
	newer := w.repo.push(w.files)
	w.gh.mu.Lock()
	w.gh.head = newer
	w.gh.mu.Unlock()
	if rec := w.ok("synchronize", newer); rec.Code != 202 || !strings.Contains(rec.Body.String(), "checked") {
		t.Fatalf("newer = %d %s", rec.Code, rec.Body)
	}
	posts, patches := w.gh.calls("POST /repos/o/policy/check-runs"), w.gh.calls("PATCH /repos/o/policy/check-runs/")
	rec := w.ok("synchronize", older)
	if rec.Code != 202 || !strings.Contains(rec.Body.String(), "stale_head") {
		t.Errorf("older = %d %s, want ignored as stale_head", rec.Code, rec.Body)
	}
	if w.gh.calls("POST /repos/o/policy/check-runs") != posts || w.gh.calls("PATCH /repos/o/policy/check-runs/") != patches {
		t.Errorf("an older head posted: %v", w.gh.got)
	}
	err := w.e.f.DB.ReadTenant(t.Context(), w.e.f.B.ID, func(c *store.TenantTx) error {
		rec, err := c.GitHubPRCheck("o/policy", hookPull)
		if err == nil && (rec == nil || rec.HeadSHA != newer) {
			t.Errorf("recorded = %+v, want the newer head %s", rec, newer)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGitHubWebhook_ConcurrentDeliveriesForOnePullRequestCheckOnce(t *testing.T) {
	w := hookSetup(t)
	w.gh.delay = 300 * time.Millisecond
	const n = 5
	codes := make([]int, n)
	bodies := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := w.deliver(hookReq{delivery: fmt.Sprintf("conc-%d", i), body: w.payload("synchronize", w.sha)})
			codes[i], bodies[i] = rec.Code, rec.Body.String()
		}(i)
	}
	wg.Wait()
	for i := range codes {
		if codes[i] != 202 || !strings.Contains(bodies[i], "checked") {
			t.Errorf("delivery %d = %d %.200s", i, codes[i], bodies[i])
		}
	}
	if c := w.gh.calls("POST /repos/o/policy/check-runs"); c != 1 {
		t.Errorf("%d check run creates, want 1", c)
	}
	if c := w.gh.calls("POST /repos/o/policy/issues/7/comments"); c != 1 {
		t.Errorf("%d comment creates, want 1", c)
	}
	w.gh.onlyComment(t)
}

func TestGitHubWebhook_RateLimitPerTenant(t *testing.T) {
	w := hookSetup(t)
	w.e.srv.ghHookLimit = ratelimit.New(ratelimit.ClassTenant, time.Hour, 2, 100)
	var codes []int
	for i := 0; i < 4; i++ {
		codes = append(codes, w.deliver(hookReq{event: "ping", body: []byte(`{}`)}).Code)
	}
	if fmt.Sprint(codes) != "[202 202 429 429]" {
		t.Errorf("codes = %v, want two accepted then 429", codes)
	}
	// bad signatures do not use up the tenant's allowance
	w.e.srv.ghHookLimit = ratelimit.New(ratelimit.ClassTenant, time.Hour, 1, 100)
	for i := 0; i < 5; i++ {
		w.deliver(hookReq{secret: "whsec_wrong", body: []byte(`{}`)})
	}
	if rec := w.deliver(hookReq{event: "ping", body: []byte(`{}`)}); rec.Code != 202 {
		t.Errorf("after bad signatures = %d, want 202", rec.Code)
	}
}

func TestGitHubWebhook_SecretSettingsAndNeverLeaks(t *testing.T) {
	w := hookSetup(t)
	e := w.e
	secret := w.secret
	slug := e.f.B.Slug
	get := reqDo(e.h, w.admin, "GET", "/api/policy/github/app", "")
	var v map[string]any
	if err := json.Unmarshal(get.Body.Bytes(), &v); err != nil || get.Code != 200 || v["webhook_secret_set"] != true || v["webhook_path"] != "/public/t/"+slug+"/github/webhook" || v["webhook_secret_set_at"] == nil {
		t.Fatalf("GET = %d %s", get.Code, get.Body)
	}
	if _, has := v["webhook_secret"]; has {
		t.Error("GET returns webhook_secret")
	}
	// a later PUT neither returns nor changes it
	rec := reqDo(e.h, w.admin, "PUT", "/api/policy/github/app", `{"enabled":true}`)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "webhook_secret\"") || !strings.Contains(rec.Body.String(), `"webhook_secret_set":true`) {
		t.Errorf("PUT = %d %s", rec.Code, rec.Body)
	}
	if rec := w.ok("opened", w.sha); rec.Code != 202 {
		t.Errorf("the secret changed: %d %s", rec.Code, rec.Body)
	}
	// stored sealed, bound to tenant, table and column
	err := e.f.DB.ReadTenant(t.Context(), e.f.B.ID, func(c *store.TenantTx) error {
		hs, err := c.GitHubWebhookSecret()
		if err != nil || hs == nil || strings.Contains(string(hs.SecretEnc), secret) {
			t.Errorf("stored = %+v, %v", hs, err)
			return nil
		}
		if got, err := e.sealer.Open(hs.SecretEnc, githubWebhookAAD(e.f.B.ID)); err != nil || string(got) != secret {
			t.Errorf("does not open under its own AAD: %v", err)
		}
		if _, err := e.sealer.Open(hs.SecretEnc, githubWebhookAAD(e.f.A.ID)); err == nil {
			t.Error("opens under another tenant's AAD")
		}
		if _, err := e.sealer.Open(hs.SecretEnc, githubKeyAAD(e.f.B.ID)); err == nil {
			t.Error("opens under another purpose's AAD")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// every response and record so far, including the refusals
	bad := w.deliver(hookReq{secret: "whsec_wrong", body: w.payload("opened", w.sha)})
	mismatch := w.deliver(hookReq{body: []byte(`{"action":"opened","installation":{"id":1},"repository":{"full_name":"x/y"},"pull_request":{"number":1,"head":{"sha":"` + w.sha + `"}}}`)})
	for _, body := range []string{get.Body.String(), bad.Body.String(), mismatch.Body.String(), w.logs.String()} {
		if strings.Contains(body, secret) || strings.Contains(body, strings.TrimPrefix(secret, "whsec_")) {
			t.Errorf("the secret leaked: %.300s", body)
		}
	}
	for _, tn := range []tenancy.ID{e.f.B.ID, tenancy.Platform} {
		for _, ev := range ledger(t, e.f.DB, tn) {
			if strings.Contains(string(ev.Detail), secret) || strings.Contains(string(ev.Detail), strings.TrimPrefix(secret, "whsec_")) {
				t.Errorf("audit event %s holds the secret: %s", ev.Action, ev.Detail)
			}
		}
	}
	var rotated int
	for _, ev := range ledger(t, e.f.DB, e.f.B.ID) {
		if ev.Action == "policy.github_app.settings" && strings.Contains(string(ev.Detail), `"webhook_secret_rotated":true`) {
			rotated++
		}
	}
	if rotated != 1 {
		t.Errorf("%d rotation events, want 1", rotated)
	}

	// rotating replaces it: the old secret stops working at once, the new one works
	newSecret := w.rotate()
	if newSecret == secret {
		t.Fatal("rotation returned the same secret")
	}
	if rec := w.deliver(hookReq{secret: secret, body: w.payload("opened", w.sha)}); rec.Code != 401 {
		t.Errorf("old secret = %d", rec.Code)
	}
	w.secret = newSecret
	if rec := w.ok("opened", w.sha); rec.Code != 202 {
		t.Errorf("new secret = %d %s", rec.Code, rec.Body)
	}
	// removing it turns the receiver off for everyone
	if rec := reqDo(e.h, w.admin, "PUT", "/api/policy/github/app", `{"enabled":true,"remove_webhook_secret":true}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"webhook_secret_set":false`) {
		t.Errorf("remove = %d %s", rec.Code, rec.Body)
	}
	if rec := w.ok("opened", w.sha); rec.Code != 401 {
		t.Errorf("after remove = %d, want 401", rec.Code)
	}
	if rec := reqDo(e.h, w.admin, "PUT", "/api/policy/github/app", `{"enabled":true,"remove_webhook_secret":true,"rotate_webhook_secret":true}`); rec.Code != 422 {
		t.Errorf("both = %d", rec.Code)
	}
}

func TestGitHubWebhook_PermissionsAndDisabledApp(t *testing.T) {
	w := hookSetup(t)
	e := w.e
	viewer := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, storetest.Now)
	pa := reqLogin(t, e.f, "pa@b.example", []auth.Role{auth.RolePolicyAdmin}, "")
	for _, l := range []authtest.Login{viewer, pa} {
		if rec := reqDo(e.h, l, "PUT", "/api/policy/github/app", `{"rotate_webhook_secret":true}`); rec.Code != 403 {
			t.Errorf("rotate without connections.manage = %d", rec.Code)
		}
	}
	weak := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "w@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
	if rec := reqDo(e.h, weak, "PUT", "/api/policy/github/app", `{"rotate_webhook_secret":true}`); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("rotate without step-up = %d %.200s", rec.Code, rec.Body)
	}
	if rec := w.ok("opened", w.sha); rec.Code != 202 {
		t.Fatalf("the secret was changed by a refused request: %d", rec.Code)
	}
	// the App turned off: an authentic delivery is refused and audited, with no GitHub call
	if rec := reqDo(e.h, w.admin, "PUT", "/api/policy/github/app", `{"enabled":false}`); rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	before := len(w.gh.got)
	if rec := w.ok("opened", w.sha); rec.Code != 409 || !strings.Contains(rec.Body.String(), "github_app_disabled") {
		t.Errorf("disabled = %d %s", rec.Code, rec.Body)
	}
	if len(w.gh.got) != before {
		t.Error("a delivery for a disabled App reached GitHub")
	}
	// an unauthenticated caller cannot use the settings route; a public caller sees no session behavior on the webhook
	req := httptest.NewRequest(http.MethodPut, "/api/policy/github/app", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if rec := serve(e.h, req); rec.Code != 401 {
		t.Errorf("anonymous PUT = %d", rec.Code)
	}
}

// A bundle with validation findings gets a failing check that lists them, not a bare 422 and no check (issue #808).
func TestGitHubWebhook_BundleWithFindingsPostsAFailingCheck(t *testing.T) {
	w := hookSetup(t)
	files := map[string]string{}
	for k, v := range w.files {
		files[k] = v
	}
	files["roles/bad.yaml"] = "schema: tessera.repo/v1\nnot_a_field: `ping @everyone`\n"
	head := w.repo.push(files)
	w.gh.mu.Lock()
	w.gh.head = head
	w.gh.mu.Unlock()
	rec := w.ok("opened", head)
	if rec.Code != 202 || !strings.Contains(rec.Body.String(), `"outcome":"checked"`) || !strings.Contains(rec.Body.String(), `"conclusion":"failure"`) {
		t.Fatalf("delivery = %d %.300s, want 202 checked failure", rec.Code, rec.Body)
	}
	if w.gh.calls("POST /repos/o/policy/check-runs") != 1 {
		t.Fatalf("GitHub calls = %v, want one check run", w.gh.got)
	}
	w.gh.mu.Lock()
	var chk map[string]any
	for _, c := range w.gh.checks {
		chk = c
	}
	w.gh.mu.Unlock()
	out, _ := chk["output"].(map[string]any)
	summary, _ := out["summary"].(string)
	if chk["conclusion"] != "failure" || !strings.Contains(summary, "roles/bad.yaml") || strings.Contains(summary, "`ping @everyone`") {
		t.Errorf("check = %v, want a failure naming roles/bad.yaml with the text escaped", chk)
	}
	if !strings.Contains(w.gh.onlyComment(t), "roles/bad.yaml") {
		t.Error("the comment does not list the findings")
	}
	if n := w.actions(w.e.f.B.ID)["policy.github_check.posted"]; n != 1 {
		t.Errorf("posted events = %d, want 1", n)
	}
	// the delivery is handled: a redelivery of the same id is a replay, not a second check
	if rec := w.deliver(hookReq{delivery: "d-1", body: w.payload("opened", head)}); rec.Code != 409 {
		t.Errorf("replay = %d %s, want 409", rec.Code, rec.Body)
	}
}

func TestGitHubWebhook_SmallDeviations(t *testing.T) {
	w := hookSetup(t)
	body := w.payload("opened", w.sha)

	// an upper-case digest of the right MAC is not what GitHub sends
	good := hookSig(w.secret, body)
	upper := "sha256=" + strings.ToUpper(strings.TrimPrefix(good, "sha256="))
	if rec := w.deliver(hookReq{sig: upper, body: body}); rec.Code != 401 {
		t.Errorf("upper-case hex = %d, want 401", rec.Code)
	}
	if rec := w.deliver(hookReq{sig: good, body: body}); rec.Code != 202 {
		t.Errorf("lower-case hex = %d %s, want 202", rec.Code, rec.Body)
	}

	// a chunked body over the cap has no Content-Length: 413, not 422
	req := httptest.NewRequest("POST", "/public/t/"+w.e.f.B.Slug+"/github/webhook", io.NopCloser(strings.NewReader(strings.Repeat(" ", 3<<20))))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-GitHub-Delivery", "chunked-1")
	req.Header.Set("X-Hub-Signature-256", good)
	if rec := serve(w.e.h, req); rec.Code != 413 {
		t.Errorf("chunked 3 MiB = %d %.200s, want 413", rec.Code, rec.Body)
	}

	// the per-tenant 429 says when to retry in the header too
	w.e.srv.ghHookLimit = ratelimit.New(ratelimit.ClassTenant, time.Hour, 1, 100)
	w.deliver(hookReq{event: "ping", body: []byte(`{}`)})
	if rec := w.deliver(hookReq{event: "ping", body: []byte(`{}`)}); rec.Code != 429 || rec.Header().Get("Retry-After") != "2" {
		t.Errorf("rate limited = %d Retry-After %q, want 429 and 2", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// Rotating or removing the webhook secret changes only the secret: an omitted enabled keeps its value (issue #807).
func TestGitHubWebhook_SecretChangesKeepEnabled(t *testing.T) {
	w := hookSetup(t)
	enabled := func() any {
		rec := reqDo(w.e.h, w.admin, "GET", "/api/policy/github/app", "")
		var v map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v["enabled"]
	}
	for _, body := range []string{`{"rotate_webhook_secret":true}`, `{"remove_webhook_secret":true}`, `{}`} {
		if rec := reqDo(w.e.h, w.admin, "PUT", "/api/policy/github/app", body); rec.Code != 200 || enabled() != true {
			t.Errorf("%s: %d, enabled = %v, want 200 and true", body, rec.Code, enabled())
		}
	}
	if rec := reqDo(w.e.h, w.admin, "PUT", "/api/policy/github/app", `{"enabled":false}`); rec.Code != 200 || enabled() != false {
		t.Errorf("enabled:false = %d, enabled = %v", rec.Code, enabled())
	}
}
