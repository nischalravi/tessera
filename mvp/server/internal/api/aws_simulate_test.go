package api

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

const prToken = "ghp_ExampleTokenValue0123456789abcdef"

func simBody(changes, extra string) string {
	return `{"changes":[` + changes + `]` + extra + `}`
}

const widenPolicy = `{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::prod-pii/*\"}]}`

func putS3Read() string {
	return `{"op":"put_policy_version","target_arn":"` + awstest.EstateS3Read + `","document":"` + widenPolicy + `"}`
}

func changesOf(v map[string]any) []map[string]any {
	var out []map[string]any
	for _, c := range v["changes"].([]any) {
		out = append(out, c.(map[string]any))
	}
	return out
}

func has(xs any, want string) bool {
	for _, x := range xs.([]any) {
		if x == want {
			return true
		}
	}
	return false
}

func TestAWSSimulateShowsWhoGainsAndLoses(t *testing.T) {
	c := newAWSEval(t, nil)

	v := c.json("POST", "/api/aws/simulate-policy-change", simBody(putS3Read(), ""), 200)
	if v["base_snapshot"] != c.snapshot || v["head_snapshot"] == c.snapshot || v["head_snapshot"] == "" || v["profile"] != "default" ||
		v["catalog_version"] != "awstest-1" {
		t.Fatalf("view = %v", v)
	}
	gained := false
	for _, ch := range changesOf(v) {
		if ch["kind"] == "gained" && has(ch["principals"], awstest.EstateAlice) && has(ch["actions"], "s3:PutObject") {
			gained = true
			if a := ch["after"].(map[string]any); a["outcome"] != "allow" || a["fidelity"] != "exact" {
				t.Errorf("after = %v", a)
			}
			if ch["before"] != nil || len(ch["trace"].([]any)) == 0 || ch["gap"] != false {
				t.Errorf("change = %v", ch)
			}
		}
		for _, p := range ch["principals"].([]any) {
			if p != awstest.EstateAlice {
				t.Errorf("the pull request reaches %v", p)
			}
		}
	}
	sum := v["summary"].(map[string]any)
	if !gained || sum["gained"].(float64) < 1 || sum["lost"].(float64) != 0 || sum["principals_affected"].(float64) != 1 {
		t.Errorf("summary = %v, gained=%v", sum, gained)
	}
	comment := v["comment"].(string)
	for _, want := range []string{"<!-- tessera-access-diff -->", "```text", "GAIN", "user/alice (111111111111)", "s3:PutObject", "[EXACT]", "catalog awstest-1"} {
		if !strings.Contains(comment, want) {
			t.Errorf("the comment lacks %q:\n%s", want, comment)
		}
	}
	if pr := v["pr_comment"].(map[string]any); pr["status"] != "not_requested" {
		t.Errorf("pr_comment = %v", pr)
	}

	// an SCP that denies s3:GetObject takes it away from the principals under it
	deny := `{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"},{\"Effect\":\"Deny\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}`
	v = c.json("POST", "/api/aws/simulate-policy-change",
		simBody(`{"op":"put_scp","target_arn":"`+awstest.EstateFullSCP+`","document":"`+deny+`"}`, `,"head":"PR #7"`), 200)
	lost := false
	for _, ch := range changesOf(v) {
		lost = lost || (ch["kind"] == "lost" && has(ch["principals"], awstest.EstateAlice) && has(ch["actions"], "s3:GetObject"))
	}
	if !lost || v["summary"].(map[string]any)["lost"].(float64) < 1 || !strings.Contains(v["comment"].(string), "LOSES") ||
		!strings.Contains(v["comment"].(string), "PR #7") {
		t.Errorf("SCP simulation = %v", v["summary"])
	}
}

func TestAWSSimulateRefusesBadInput(t *testing.T) {
	c := newAWSEval(t, nil)
	many := strings.Repeat(putS3Read()+",", awsMaxPolicyChanges) + putS3Read()
	for name, tc := range map[string]struct {
		body string
		want int
		code string
	}{
		"no body":             {``, 422, "invalid_body"},
		"no changes":          {`{"changes":[]}`, 422, "invalid_changes"},
		"too many changes":    {simBody(many, ""), 422, "invalid_changes"},
		"unknown op":          {simBody(`{"op":"drop_table","target_arn":"x"}`, ""), 422, "invalid_body"},
		"unknown field":       {simBody(putS3Read(), `,"extra":1`), 422, "invalid_body"},
		"trailing data":       {simBody(putS3Read(), "") + `{}`, 422, "invalid_body"},
		"bad change":          {simBody(putS3Read()+`,{"op":"detach","target_arn":"`+awstest.EstateDevUser+`","policy_arn":"`+awstest.EstateS3Read+`"}`, ""), 422, "invalid_change"},
		"missing document":    {simBody(`{"op":"put_resource_policy","target_arn":"`+awstest.EstateBucket+`"}`, ""), 422, "invalid_change"},
		"bad head":            {simBody(putS3Read(), `,"head":"a\nb"`), 422, "invalid_head"},
		"long head":           {simBody(putS3Read(), `,"head":"`+strings.Repeat("h", 81)+`"`), 422, "invalid_head"},
		"bad profile":         {simBody(putS3Read(), `,"profile":"moon"`), 422, "invalid_profile"},
		"bad pull number":     {simBody(putS3Read(), `,"comment":{"pull_number":0}`), 422, "invalid_pull_number"},
		"unknown base":        {simBody(putS3Read(), `,"base_snapshot":"`+strings.Repeat("0", 64)+`"`), 404, "not_found"},
		"malformed base":      {simBody(putS3Read(), `,"base_snapshot":"x"`), 404, "not_found"},
		"unknown comment key": {simBody(putS3Read(), `,"comment":{"repo":"o/r"}`), 422, "invalid_body"},
	} {
		rec := c.do("POST", "/api/aws/simulate-policy-change", tc.body)
		if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("%s: %d %.200s, want %d %s", name, rec.Code, rec.Body.String(), tc.want, tc.code)
		}
	}
	// the failing change is named
	rec := c.do("POST", "/api/aws/simulate-policy-change", simBody(putS3Read()+`,{"op":"detach","target_arn":"`+awstest.EstateDevUser+`","policy_arn":"`+awstest.EstateS3Read+`"}`, ""))
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v["change_index"] != float64(1) || !strings.Contains(v["detail"].(string), "change 1") {
		t.Errorf("error body = %s", rec.Body.String())
	}
}

// fakeGitHub is a local TLS stand-in for api.github.com.
type fakeGitHub struct {
	mu     sync.Mutex
	status int
	got    []ghRequest
}

type ghRequest struct{ method, path, auth, body string }

func (g *fakeGitHub) requests() []ghRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]ghRequest(nil), g.got...)
}

func newFakeGitHub(t *testing.T) (*fakeGitHub, func(*Config)) {
	t.Helper()
	g := &fakeGitHub{status: http.StatusCreated}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		g.mu.Lock()
		g.got = append(g.got, ghRequest{r.Method, r.URL.Path, r.Header.Get("Authorization"), string(b)})
		status := g.status
		g.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"id":99,"html_url":"https://github.com/o/r/pull/12#issuecomment-99","message":"` + r.Header.Get("Authorization") + `"}`))
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return g, func(c *Config) { c.OutboundHTTP, c.GitHubAPIBase, c.Sealer = hc, srv.URL, sealer }
}

func TestAWSPRCommentSettings(t *testing.T) {
	_, withGH := newFakeGitHub(t)
	c := newAWSEval(t, nil, withGH)

	// off by default
	if v := c.get("/api/aws/pr-comment", 200); v["enabled"] != false || v["token_set"] != false || v["repo"] != "" {
		t.Errorf("default = %v", v)
	}
	for name, body := range map[string]string{
		"no body":              ``,
		"unknown field":        `{"enabled":false,"extra":1}`,
		"bad repo":             `{"enabled":false,"repo":"o/../x"}`,
		"repo with a query":    `{"enabled":false,"repo":"o/r?x=1"}`,
		"bad token":            `{"enabled":false,"repo":"o/r","token":"a b"}`,
		"header injection":     `{"enabled":false,"repo":"o/r","token":"abc\r\nX: 1"}`,
		"enable with no token": `{"enabled":true,"repo":"o/r"}`,
		"enable with no repo":  `{"enabled":true,"token":"` + prToken + `"}`,
	} {
		if rec := c.do("PUT", "/api/aws/pr-comment", body); rec.Code != 422 {
			t.Errorf("%s: %d %.200s, want 422", name, rec.Code, rec.Body.String())
		}
	}

	rec := c.do("PUT", "/api/aws/pr-comment", `{"enabled":true,"repo":"o/r","token":"`+prToken+`"}`)
	if rec.Code != 200 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	// the token is never returned, by any route
	for _, body := range []string{rec.Body.String(), c.do("GET", "/api/aws/pr-comment", "").Body.String()} {
		if strings.Contains(body, prToken) || strings.Contains(body, "token_enc") {
			t.Errorf("a response holds the token: %s", body)
		}
		if !strings.Contains(body, `"token_set":true`) || !strings.Contains(body, `"repo":"o/r"`) {
			t.Errorf("response = %s", body)
		}
	}
	// the stored token is sealed, bound to the tenant, and not in the audit ledger
	c.read(func(tx *store.TenantTx) error {
		st, err := tx.AWSPRCommentSettings()
		if err != nil || !st.Enabled || len(st.TokenEnc) == 0 || strings.Contains(string(st.TokenEnc), prToken) {
			t.Errorf("stored settings = %+v, %v", st, err)
		}
		evs, err := tx.AuditLog(0)
		if err != nil {
			return err
		}
		found := false
		for _, e := range evs {
			if strings.Contains(string(e.Detail), prToken) {
				t.Errorf("audit event %s holds the token: %s", e.Action, e.Detail)
			}
			found = found || e.Action == "aws.pr_comment.settings"
		}
		if !found {
			t.Error("the settings change is not in the audit ledger")
		}
		return nil
	})

	// keeping the token: omit it
	if rec := c.do("PUT", "/api/aws/pr-comment", `{"enabled":true,"repo":"o/other"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"token_set":true`) {
		t.Errorf("PUT without a token = %d %s", rec.Code, rec.Body.String())
	}
	// turning it off keeps the settings and is visible
	if rec := c.do("PUT", "/api/aws/pr-comment", `{"enabled":false,"repo":"o/other"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Errorf("PUT off = %d %s", rec.Code, rec.Body.String())
	}
}

func TestAWSPRCommentIsPostedOnlyWhenEnabled(t *testing.T) {
	gh, withGH := newFakeGitHub(t)
	c := newAWSEval(t, nil, withGH)
	withComment := simBody(putS3Read(), `,"comment":{"pull_number":12}`)

	// 1. off by default: the diff is returned, nothing is posted
	v := c.json("POST", "/api/aws/simulate-policy-change", withComment, 200)
	if pr := v["pr_comment"].(map[string]any); pr["status"] != "disabled" || len(gh.requests()) != 0 {
		t.Fatalf("pr_comment = %v, %d requests", pr, len(gh.requests()))
	}

	// 2. enabled: posted, with the rendered diff, the sealed token and nothing else
	c.json("PUT", "/api/aws/pr-comment", `{"enabled":true,"repo":"o/r","token":"`+prToken+`"}`, 200)
	v = c.json("POST", "/api/aws/simulate-policy-change", withComment, 200)
	pr := v["pr_comment"].(map[string]any)
	if pr["status"] != "posted" || pr["url"] != "https://github.com/o/r/pull/12#issuecomment-99" {
		t.Fatalf("pr_comment = %v", pr)
	}
	reqs := gh.requests()
	if len(reqs) != 1 || reqs[0].method != "POST" || reqs[0].path != "/repos/o/r/issues/12/comments" || reqs[0].auth != "Bearer "+prToken {
		t.Fatalf("GitHub saw %+v", reqs)
	}
	var posted map[string]string
	if err := json.Unmarshal([]byte(reqs[0].body), &posted); err != nil || posted["body"] != v["comment"] || !strings.HasPrefix(posted["body"], "<!-- tessera-access-diff -->") {
		t.Errorf("posted body = %q (%v)", reqs[0].body, err)
	}
	// without a comment in the request nothing is posted
	c.json("POST", "/api/aws/simulate-policy-change", simBody(putS3Read(), ""), 200)
	if n := len(gh.requests()); n != 1 {
		t.Errorf("%d requests after a simulation that asked for none", n)
	}
	// the post is audited, without the token
	c.read(func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(0)
		if err != nil {
			return err
		}
		n := 0
		for _, e := range evs {
			if strings.Contains(string(e.Detail), prToken) {
				t.Errorf("audit event %s holds the token", e.Action)
			}
			if e.Action == "aws.pr_comment.posted" {
				n++
				if !strings.Contains(string(e.Detail), `"pull_number":12`) || !strings.Contains(string(e.Detail), `"repo":"o/r"`) {
					t.Errorf("event detail = %s", e.Detail)
				}
			}
		}
		if n != 1 {
			t.Errorf("%d aws.pr_comment.posted events, want 1", n)
		}
		return nil
	})

	// 3. GitHub refuses: reported as failed with a short code, audited, and the token and body never leak
	gh.mu.Lock()
	gh.status = http.StatusForbidden
	gh.mu.Unlock()
	rec := c.do("POST", "/api/aws/simulate-policy-change", withComment)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), prToken) {
		t.Fatalf("failed post = %d (token in the answer: %v)", rec.Code, strings.Contains(rec.Body.String(), prToken))
	}
	var fv map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &fv)
	if pr := fv["pr_comment"].(map[string]any); pr["status"] != "failed" || pr["error"] != "github_403" {
		t.Errorf("pr_comment = %v", pr)
	}
	c.read(func(tx *store.TenantTx) error {
		evs, _ := tx.AuditLog(0)
		failed := false
		for _, e := range evs {
			failed = failed || (e.Action == "aws.pr_comment.failed" && strings.Contains(string(e.Detail), "github_403"))
		}
		if !failed {
			t.Error("the failed post is not in the audit ledger")
		}
		return nil
	})

	// 4. turned off again: nothing more is posted
	c.json("PUT", "/api/aws/pr-comment", `{"enabled":false,"repo":"o/r"}`, 200)
	before := len(gh.requests())
	if v := c.json("POST", "/api/aws/simulate-policy-change", withComment, 200); v["pr_comment"].(map[string]any)["status"] != "disabled" ||
		len(gh.requests()) != before {
		t.Errorf("a post was made with the comment turned off")
	}
}

// With no outbound client the comment cannot be sent, and says so.
func TestAWSPRCommentUnavailableWithoutOutboundClient(t *testing.T) {
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	c := newAWSEval(t, nil, func(cfg *Config) { cfg.Sealer = sealer })
	c.json("PUT", "/api/aws/pr-comment", `{"enabled":true,"repo":"o/r","token":"`+prToken+`"}`, 200)
	v := c.json("POST", "/api/aws/simulate-policy-change", simBody(putS3Read(), `,"comment":{"pull_number":3}`), 200)
	if v["pr_comment"].(map[string]any)["status"] != "unavailable" {
		t.Errorf("pr_comment = %v", v["pr_comment"])
	}
}

// Saving a token needs the KEK that seals it.
func TestAWSPRCommentTokenNeedsASealer(t *testing.T) {
	c := newAWSEval(t, nil)
	rec := c.do("PUT", "/api/aws/pr-comment", `{"enabled":false,"repo":"o/r","token":"`+prToken+`"}`)
	if rec.Code != 503 || strings.Contains(rec.Body.String(), prToken) {
		t.Errorf("PUT with no sealer = %d %s", rec.Code, rec.Body.String())
	}
	// no secret, no sealer needed
	if rec := c.do("PUT", "/api/aws/pr-comment", `{"enabled":false,"repo":"o/r"}`); rec.Code != 200 {
		t.Errorf("PUT without a token = %d %s", rec.Code, rec.Body.String())
	}
}
