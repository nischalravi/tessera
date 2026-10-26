package api

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	policies "github.com/nischalravi/tessera/mvp/server/policies"
)

// The production shadow agreement (issue #641) over the awsorg recordings: the
// collection fixtures give the snapshot, and a stand-in for the simulator
// answers iam:SimulatePrincipalPolicy as the test says.

// shadowDoer answers SimulatePrincipalPolicy with sim and sends everything
// else to the recordings.
type shadowDoer struct {
	*collectDoer
	mu    sync.Mutex
	sim   func(principal, action, resource string) (status int, body string)
	asked []url.Values
}

func simResult(decision string, missing ...string) string {
	m := ""
	if len(missing) > 0 {
		m = "<MissingContextValues><member>" + strings.Join(missing, "</member><member>") + "</member></MissingContextValues>"
	}
	return `<SimulatePrincipalPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><SimulatePrincipalPolicyResult><IsTruncated>false</IsTruncated>` +
		`<EvaluationResults><member><EvalActionName>%A%</EvalActionName><EvalDecision>` + decision + `</EvalDecision>` + m +
		`</member></EvaluationResults></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>`
}

func (d *shadowDoer) Do(req *http.Request) (*http.Response, error) {
	var b []byte
	if req.Body != nil {
		b, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(b))
	}
	form, _ := url.ParseQuery(string(b))
	if form.Get("Action") != "SimulatePrincipalPolicy" {
		return d.collectDoer.Do(req)
	}
	d.mu.Lock()
	d.asked = append(d.asked, form)
	d.mu.Unlock()
	status, body := d.sim(form.Get("PolicySourceArn"), form.Get("ActionNames.member.1"), form.Get("ResourceArns.member.1"))
	body = strings.ReplaceAll(body, "%A%", form.Get("ActionNames.member.1"))
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"text/xml"}}, Body: io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)), Request: req}, nil
}

func (d *shadowDoer) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.asked)
}

// newShadowEnv collects the fixture estate (so there is a snapshot and an ok
// connector) and then replaces the AWS client with the shadow doer.
func newShadowEnv(t *testing.T, sim func(p, a, r string) (int, string)) (*collectEnv, *shadowDoer) {
	t.Helper()
	old := awsShadowGap
	awsShadowGap = 0
	t.Cleanup(func() { awsShadowGap = old })
	var sd *shadowDoer
	e := newCollectEnv(t, func(c *Config) {
		sd = &shadowDoer{collectDoer: &collectDoer{}, sim: sim}
		sd.collectDoer.next(nil)
		c.AWSHTTP = sd
	})
	e.pause(t)
	e.collect(t)
	e.drain(t)
	return e, sd
}

func (e *collectEnv) runShadow(t *testing.T) (any, error) {
	t.Helper()
	return e.srv.queueAWSShadow(context.Background(), queue.Job{Tenant: e.c.st.Tenant})
}

func (e *collectEnv) shadowChecks(t *testing.T, query string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, x := range e.c.json("GET", "/api/aws/shadow/checks"+query, "", 200)["items"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

func always(decision string, missing ...string) func(p, a, r string) (int, string) {
	return func(string, string, string) (int, string) { return 200, simResult(decision, missing...) }
}

func TestAWSShadowSettingsAPI(t *testing.T) {
	c := newRD(t)
	v := c.json("GET", "/api/aws/shadow", "", 200)
	if v["enabled"] != false || v["daily_k"] != float64(20) || v["agreement"] != nil {
		t.Errorf("default = %v", v)
	}
	for _, body := range []string{`{"enabled":true,"daily_k":0}`, `{"enabled":true,"daily_k":201}`, `{"enabled":true,"daily_k":"x"}`, `{"enabled":true,"extra":1}`} {
		if rec := c.do("PUT", "/api/aws/shadow", body); rec.Code != 400 && rec.Code != 422 {
			t.Errorf("PUT %s = %d %s", body, rec.Code, rec.Body.String())
		}
	}
	v = c.json("PUT", "/api/aws/shadow", `{"enabled":true,"daily_k":7}`, 200)
	if v["enabled"] != true || v["daily_k"] != float64(7) || v["updated_by"] == "" {
		t.Errorf("after PUT = %v", v)
	}
	today := v["today"].(map[string]any)
	if today["sampled"] != float64(0) || today["remaining"] != float64(7) {
		t.Errorf("today = %v", today)
	}
	// omitting daily_k keeps it
	if v = c.json("PUT", "/api/aws/shadow", `{"enabled":false}`, 200); v["enabled"] != false || v["daily_k"] != float64(7) {
		t.Errorf("opt out = %v", v)
	}
	// a tenant that opted in shows on Deployment health, with no checks yet
	c.json("PUT", "/api/aws/shadow", `{"enabled":true}`, 200)
	h := c.json("GET", "/api/insights/deployment-health", "", 200)
	if ag, _ := h["aws_shadow"].(map[string]any); ag == nil || ag["enabled"] != true || ag["compared"] != float64(0) || ag["rate"] != nil {
		t.Errorf("health aws_shadow = %v", h["aws_shadow"])
	}
	c.read(func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(0)
		n := 0
		for _, ev := range evs {
			if ev.Action == "aws.shadow.settings" {
				n++
			}
		}
		if n != 3 {
			t.Errorf("%d aws.shadow.settings events, want 3", n)
		}
		return err
	})
}

func TestAWSShadowHealthAbsentWhenNeverUsed(t *testing.T) {
	c := newRD(t)
	if h := c.json("GET", "/api/insights/deployment-health", "", 200); h["aws_shadow"] != nil {
		t.Errorf("a tenant that never opted in has aws_shadow = %v", h["aws_shadow"])
	}
}

func TestAWSShadowJobOffDoesNothing(t *testing.T) {
	e, sd := newShadowEnv(t, always("allowed"))
	if _, err := e.runShadow(t); err != nil {
		t.Fatal(err)
	}
	if sd.calls() != 0 || len(e.shadowChecks(t, "")) != 0 {
		t.Errorf("a tenant that did not opt in had %d simulator calls", sd.calls())
	}
}

func TestAWSShadowJobAgreesAndDisagrees(t *testing.T) {
	e, sd := newShadowEnv(t, always("implicitDeny"))
	e.c.json("PUT", "/api/aws/shadow", `{"enabled":true,"daily_k":6}`, 200)
	res, err := e.runShadow(t)
	if err != nil {
		t.Fatal(err)
	}
	checks := e.shadowChecks(t, "")
	if len(checks) == 0 || len(checks) > 6 || len(checks) != sd.calls() {
		t.Fatalf("%d checks for %d simulator calls (K = 6): %v", len(checks), sd.calls(), res)
	}
	var open string
	for _, ck := range checks {
		allow := ck["tessera_outcome"] == "allow"
		want := "agree"
		if allow { // the simulator said implicitDeny
			want = "disagree"
		}
		if ck["verdict"] != want || ck["aws_decision"] != "implicitDeny" || ck["tessera_fidelity"] != "exact" || ck["explanation_id"] == "" ||
			ck["principal_arn"] == "" || ck["resource_arn"] == "" {
			t.Errorf("check = %v, want verdict %s", ck, want)
		}
		if want == "disagree" {
			if ck["triage_status"] != "open" || !strings.Contains(ck["detail"].(string), "Tessera says allowed") {
				t.Errorf("disagreement = %v", ck)
			}
			open = ck["id"].(string)
		} else if ck["triage_status"] != "none" {
			t.Errorf("agreement = %v", ck)
		}
	}
	if open == "" {
		t.Fatalf("no disagreement among %v: the fixture estate has allowed decisions the simulator was told to deny", checks)
	}
	// the simulator was asked for the principal's own account, with no context keys
	for _, f := range sd.asked {
		if !strings.HasPrefix(f.Get("PolicySourceArn"), "arn:aws:iam::") || f.Get("ContextEntries.member.1.ContextKeyName") != "" {
			t.Errorf("simulator question = %v", f)
		}
	}

	// the metric: Deployment health and the settings route agree
	v := e.c.json("GET", "/api/aws/shadow", "", 200)
	ag := v["agreement"].(map[string]any)
	dis := 0
	for _, ck := range checks {
		if ck["verdict"] == "disagree" {
			dis++
		}
	}
	if ag["disagree"] != float64(dis) || ag["agree"] != float64(len(checks)-dis) || ag["open_disagreements"] != float64(dis) || ag["last_checked_at"] == nil ||
		ag["rate"] != float64(len(checks)-dis)/float64(len(checks)) {
		t.Errorf("agreement = %v (%d of %d disagree)", ag, dis, len(checks))
	}
	h := e.c.json("GET", "/api/insights/deployment-health", "", 200)
	if hs, _ := h["aws_shadow"].(map[string]any); hs == nil || hs["rate"] != ag["rate"] || hs["open_disagreements"] != ag["open_disagreements"] {
		t.Errorf("deployment health aws_shadow = %v, want %v", h["aws_shadow"], ag)
	}
	if today := v["today"].(map[string]any); today["sampled"] != float64(len(checks)) || today["remaining"] != float64(6-len(checks)) {
		t.Errorf("today = %v", today)
	}

	// triage: records, state, audit
	if rec := e.c.do("POST", "/api/aws/shadow/checks/"+open+"/triage", `{"status":"nonsense"}`); rec.Code != 400 && rec.Code != 422 {
		t.Errorf("bad status = %d", rec.Code)
	}
	if rec := e.c.do("POST", "/api/aws/shadow/checks/"+open+"/triage", `{"status":"engine_bug","note":"`+strings.Repeat("x", 501)+`"}`); rec.Code != 400 && rec.Code != 422 {
		t.Errorf("long note = %d", rec.Code)
	}
	e.c.json("POST", "/api/aws/shadow/checks/"+open+"/triage", `{"status":"investigating","note":"looking"}`, 200)
	got := e.c.json("POST", "/api/aws/shadow/checks/"+open+"/triage", `{"status":"engine_bug","note":"ticket 12"}`, 200)
	if got["triage_status"] != "engine_bug" {
		t.Errorf("triaged = %v", got)
	}
	one := e.c.json("GET", "/api/aws/shadow/checks/"+open, "", 200)
	steps := one["triage"].([]any)
	notes := map[string]string{} // the clock is frozen, so the two steps share a time: compare as a set
	for _, st := range steps {
		m := st.(map[string]any)
		notes[m["status"].(string)] = m["note"].(string)
		if m["actor"] == "" || m["created_at"] == "" {
			t.Errorf("triage record = %v", m)
		}
	}
	if len(steps) != 2 || notes["investigating"] != "looking" || notes["engine_bug"] != "ticket 12" {
		t.Errorf("triage records = %v", steps)
	}
	if v := e.c.json("GET", "/api/aws/shadow", "", 200)["agreement"].(map[string]any); v["open_disagreements"] != float64(dis-1) {
		t.Errorf("open after triage = %v, want %d", v["open_disagreements"], dis-1)
	}
	if got := e.shadowChecks(t, "?verdict=disagree&triage=engine_bug"); len(got) != 1 || got[0]["id"] != open {
		t.Errorf("filter = %v", got)
	}
	e.c.read(func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(0)
		n := map[string]int{}
		for _, ev := range evs {
			n[ev.Action]++
		}
		if n["aws.shadow.checked"] != 1 || n["aws.shadow.triaged"] != 2 {
			t.Errorf("audit events = %v", n)
		}
		return err
	})
	// an agreement is not triaged
	for _, ck := range checks {
		if ck["verdict"] == "agree" {
			if rec := e.c.do("POST", "/api/aws/shadow/checks/"+ck["id"].(string)+"/triage", `{"status":"resolved"}`); rec.Code != 404 {
				t.Errorf("triage of an agreement = %d", rec.Code)
			}
			break
		}
	}
	for _, bad := range []string{"?verdict=x", "?triage=x", "?limit=0", "?limit=501"} {
		if rec := e.c.do("GET", "/api/aws/shadow/checks"+bad, ""); rec.Code != 400 && rec.Code != 422 {
			t.Errorf("GET checks%s = %d", bad, rec.Code)
		}
	}
}

// The daily quota is the rate limit: the rows are the counter, so another run
// of the job the same day spends only what is left, and none once it is spent.
func TestAWSShadowJobDailyQuota(t *testing.T) {
	e, sd := newShadowEnv(t, always("allowed"))
	e.c.json("PUT", "/api/aws/shadow", `{"enabled":true,"daily_k":4}`, 200)
	for i := 0; i < 3; i++ {
		if _, err := e.runShadow(t); err != nil {
			t.Fatal(err)
		}
	}
	n := len(e.shadowChecks(t, ""))
	if n == 0 || n > 4 || sd.calls() != n {
		t.Errorf("%d checks and %d simulator calls after three runs with K = 4", n, sd.calls())
	}
	if v := e.c.json("GET", "/api/aws/shadow", "", 200)["today"].(map[string]any); v["remaining"] != float64(4-n) {
		t.Errorf("today = %v", v)
	}
	// raising K allows more the same day; a new day starts a new count
	e.c.json("PUT", "/api/aws/shadow", `{"enabled":true,"daily_k":200}`, 200)
	before := sd.calls()
	if _, err := e.runShadow(t); err != nil {
		t.Fatal(err)
	}
	if sd.calls() <= before || sd.calls() > awsShadowPerRun+n {
		t.Errorf("%d calls after raising K (had %d); a run takes at most %d", sd.calls(), before, awsShadowPerRun)
	}
	days := map[string]bool{}
	e.c.read(func(tx *store.TenantTx) error {
		cks, err := tx.AWSShadowChecks("", "", 500)
		for _, c := range cks {
			days[c.SampleDay] = true
		}
		return err
	})
	if len(days) != 1 || !days[testkit.Now.UTC().Format("2006-01-02")] {
		t.Errorf("sample days = %v", days)
	}
}

func TestAWSShadowJobInconclusiveAndErrors(t *testing.T) {
	t.Run("missing context keys are inconclusive and out of the rate", func(t *testing.T) {
		e, _ := newShadowEnv(t, always("implicitDeny", "aws:SourceIp"))
		e.c.json("PUT", "/api/aws/shadow", `{"enabled":true,"daily_k":4}`, 200)
		if _, err := e.runShadow(t); err != nil {
			t.Fatal(err)
		}
		checks := e.shadowChecks(t, "")
		if len(checks) == 0 {
			t.Fatal("no checks")
		}
		for _, ck := range checks {
			if ck["verdict"] != "inconclusive" || ck["triage_status"] != "none" || !strings.Contains(ck["detail"].(string), "aws:SourceIp") {
				t.Errorf("check = %v", ck)
			}
		}
		ag := e.c.json("GET", "/api/aws/shadow", "", 200)["agreement"].(map[string]any)
		if ag["rate"] != nil || ag["compared"] != float64(0) || ag["inconclusive"] != float64(len(checks)) || ag["open_disagreements"] != float64(0) {
			t.Errorf("agreement = %v", ag)
		}
	})
	t.Run("a reader role that cannot simulate is asked three times, then the run stops", func(t *testing.T) {
		denied := func(string, string, string) (int, string) {
			return 403, `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not authorized to perform iam:SimulatePrincipalPolicy</Message></Error></ErrorResponse>`
		}
		e, sd := newShadowEnv(t, denied)
		e.c.json("PUT", "/api/aws/shadow", `{"enabled":true,"daily_k":20}`, 200)
		_, err := e.runShadow(t)
		if err == nil || !strings.Contains(err.Error(), "in a row failed") {
			t.Errorf("run error = %v", err)
		}
		checks := e.shadowChecks(t, "")
		if len(checks) != awsShadowMaxFailures || sd.calls() != awsShadowMaxFailures {
			t.Fatalf("%d checks, %d calls; want %d", len(checks), sd.calls(), awsShadowMaxFailures)
		}
		for _, ck := range checks {
			if ck["verdict"] != "error" || !strings.Contains(ck["detail"].(string), "AccessDenied") || ck["aws_decision"] != "" {
				t.Errorf("check = %v", ck)
			}
		}
		if ag := e.c.json("GET", "/api/aws/shadow", "", 200)["agreement"].(map[string]any); ag["errors"] != float64(3) || ag["rate"] != nil {
			t.Errorf("agreement = %v", ag)
		}
	})
}

// A tenant's checks are its own: another tenant cannot read, list or triage them.
func TestAWSShadowTenantIsolation(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := New(Config{Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Env: "test", RateLimits: noRateLimits,
		AllowedOrigins: []string{"http://localhost:5173"}})
	h := srv.Handler()
	la := signIn(t, f.DB, f.A.ID, testAdmin, authtest.Phr, storetest.Now)
	lb := signIn(t, f.DB, f.B.ID, testAdmin, authtest.Phr, storetest.Now)
	id := store.NewID()
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.InsertAWSShadowCheck(&store.AWSShadowCheck{ID: id, ConnectorID: "c", SnapshotID: "s", SampleDay: "2026-01-01",
			PrincipalARN: "arn:aws:iam::111111111111:role/a", Action: "s3:GetObject", ResourceARN: "arn:aws:s3:::b",
			TesseraOutcome: "allow", TesseraFidelity: "exact", AWSDecision: "implicitDeny", Verdict: store.AWSShadowDisagree, CheckedAt: storetest.Now})
	}); err != nil {
		t.Fatal(err)
	}
	a := func(m, p, b string) *httptest.ResponseRecorder { return serve(h, authed(la, m, p, b)) }
	b := func(m, p, b string) *httptest.ResponseRecorder { return serve(h, authed(lb, m, p, b)) }
	if rec := a("GET", "/api/aws/shadow/checks/"+id, ""); rec.Code != 200 {
		t.Fatalf("A GET own check = %d %s", rec.Code, rec.Body.String())
	}
	if rec := b("GET", "/api/aws/shadow/checks/"+id, ""); rec.Code != 404 {
		t.Errorf("B GET A's check = %d", rec.Code)
	}
	if rec := b("POST", "/api/aws/shadow/checks/"+id+"/triage", `{"status":"resolved"}`); rec.Code != 404 {
		t.Errorf("B triage A's check = %d", rec.Code)
	}
	if rec := b("GET", "/api/aws/shadow/checks", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Errorf("B list = %d %s", rec.Code, rec.Body.String())
	}
	if rec := b("GET", "/api/aws/shadow", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), `"open_disagreements":1`) {
		t.Errorf("B settings = %d %s", rec.Code, rec.Body.String())
	}
	if rec := a("GET", "/api/aws/shadow/checks/"+id, ""); !strings.Contains(rec.Body.String(), `"triage_status":"open"`) {
		t.Errorf("A's check changed: %s", rec.Body.String())
	}
}
