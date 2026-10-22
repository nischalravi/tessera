package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/helpdesk"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// Verified help-desk resets (issue #108). The fixture identities: alice is not
// privileged and her manager is carol; carol holds ProdAdmin through the
// platform group (a privileged identity).

type helpdeskEnv struct {
	t      *testing.T
	f      *storetest.Fixture
	h      http.Handler
	now    *time.Time
	fake   *helpdesk.FakeExecutor
	agent  authtest.Login // operator who starts and verifies
	other  authtest.Login // a second operator
	mgr    authtest.Login // operator linked to carol's identity (alice's manager)
	alice  int64
	carol  int64
	signin func(email string, id *int64) authtest.Login
}

func newHelpdeskEnv(t *testing.T, svc func(*helpdesk.Service)) *helpdeskEnv {
	t.Helper()
	f := storetest.TwoTenants(t)
	e := &helpdeskEnv{t: t, f: f, now: new(time.Time), fake: &helpdesk.FakeExecutor{}, alice: f.A.IDs["alice"], carol: f.A.IDs["carol"]}
	*e.now = storetest.Now
	hs := &helpdesk.Service{Simulated: true, Executors: map[string]helpdesk.ResetExecutor{"okta": e.fake}}
	if svc != nil {
		svc(hs)
	}
	e.h = New(Config{
		Store: f.DB, Clock: timeutil.Clock(func() time.Time { return *e.now }), Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Helpdesk: hs, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Env: "test", RateLimits: noRateLimits, AllowedOrigins: []string{"http://localhost:5173"},
	}).Handler()
	e.signin = func(email string, id *int64) authtest.Login {
		return signIn(t, f.DB, f.A.ID, authtest.User{Email: email, Roles: []auth.Role{auth.RoleOperator}, IdentityID: id},
			authtest.Phr, *e.now)
	}
	// operators are linked to (grant-less) people: an unlinked one is refused (#446)
	link := func(xid string) *int64 { return ensureIdentity(t, f.DB, f.A.ID, "none", xid, *e.now) }
	e.agent = e.signin("agent@a.example", link("op-agent"))
	e.other = e.signin("other@a.example", link("op-other"))
	e.mgr = e.signin("carol@a.example", &e.carol)
	return e
}

func (e *helpdeskEnv) do(l authtest.Login, method, path, body string) (int, string) {
	e.t.Helper()
	rec := corrDo(e.h, l, method, path, body)
	return rec.Code, rec.Body.String()
}

func (e *helpdeskEnv) start(l authtest.Login, identity int64, kind string) helpdesk.CaseView {
	e.t.Helper()
	code, body := e.do(l, "POST", "/api/helpdesk/cases",
		fmt.Sprintf(`{"identity_id":%d,"kind":%q,"system":"okta","reason":"locked out after phone loss"}`, identity, kind))
	if code != http.StatusCreated {
		e.t.Fatalf("start: %d %s", code, body)
	}
	var v helpdesk.CaseView
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		e.t.Fatal(err)
	}
	return v
}

func (e *helpdeskEnv) view(id string) helpdesk.CaseView {
	e.t.Helper()
	code, body := e.do(e.agent, "GET", "/api/helpdesk/cases/"+id, "")
	var v helpdesk.CaseView
	if code != 200 || json.Unmarshal([]byte(body), &v) != nil {
		e.t.Fatalf("view: %d %s", code, body)
	}
	return v
}

func (e *helpdeskEnv) verify(l authtest.Login, id, body string) (int, string) {
	return e.do(l, "POST", "/api/helpdesk/cases/"+id+"/verifications", body)
}

const callbackBody = `{"method":"callback","number_source":"hr","evidence":"called the number in the HR record"}`

func TestHelpdeskUnverifiedCaseCannotExecute(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	v := e.start(e.agent, e.alice, "mfa")
	if v.Status != "open" || v.Privileged || v.Policy.Satisfied || v.Policy.Required != 1 {
		t.Fatalf("started case: %+v", v)
	}
	path := "/api/helpdesk/cases/" + v.ID + "/execute"

	// nothing verified: refused, with the policy in the body, and the IdP is never called
	code, body := e.do(e.other, "POST", path, "")
	if code != http.StatusConflict || !strings.Contains(body, `"verification_required"`) || !strings.Contains(body, `"policy"`) {
		t.Fatalf("unverified execute: %d %s", code, body)
	}
	// a failed verification does not unlock it either (IDV is for privileged identities only)
	if code, body = e.verify(e.agent, v.ID, `{"method":"idv","session_ref":"s1"}`); code != 422 {
		t.Errorf("IDV for a non-privileged identity: %d %s", code, body)
	}
	if code, body = e.do(e.other, "POST", path, ""); code != http.StatusConflict {
		t.Fatalf("execute after a refused verification: %d %s", code, body)
	}
	// the number must come from HR, never from the caller
	if code, body = e.verify(e.other, v.ID, `{"method":"callback","number_source":"caller","evidence":"they gave me a number"}`); code != 422 {
		t.Errorf("call-back to a caller-supplied number: %d %s", code, body)
	}
	if code, body = e.verify(e.other, v.ID, `{"method":"callback","number_source":"hr"}`); code != 422 {
		t.Errorf("call-back without evidence: %d %s", code, body)
	}
	if code, body = e.verify(e.agent, v.ID, `{"method":"sms"}`); code != 422 {
		t.Errorf("unknown method: %d %s", code, body)
	}
	if got := e.fake.Calls(); len(got) != 0 {
		t.Fatalf("the IdP was called for an unverified case: %v", got)
	}
	if e.view(v.ID).Status != "open" {
		t.Error("the unverified case changed state")
	}

	// verified: it runs once, through the executor, and is audited
	if code, body = e.verify(e.other, v.ID, callbackBody); code != 200 {
		t.Fatalf("callback: %d %s", code, body)
	}
	code, body = e.do(e.other, "POST", path, "")
	if code != 200 || strings.Contains(body, "temporary_access_pass") {
		t.Fatalf("execute: %d %s", code, body)
	}
	calls := e.fake.Calls()
	if len(calls) != 1 || calls[0].UserID != "alice" || calls[0].Kind != "mfa" || calls[0].System != "okta" {
		t.Fatalf("executor calls: %+v", calls)
	}
	done := e.view(v.ID)
	if done.Status != "executed" || done.ExecutedAt == nil || done.ExecutedBy == nil || len(done.Result) == 0 {
		t.Errorf("executed case: %+v", done)
	}
	got := auditActions(t, e.f, e.f.A.ID)
	for _, a := range []string{"helpdesk.case.started", "helpdesk.case.verification", "helpdesk.reset.started", "helpdesk.reset.executed"} {
		if got[a] == 0 {
			t.Errorf("no %s audit event: %v", a, got)
		}
	}
	// it cannot run twice, and a closed case takes no more verifications
	if code, body = e.do(e.other, "POST", path, ""); code != http.StatusConflict {
		t.Errorf("second execute: %d %s", code, body)
	}
	if code, body = e.verify(e.other, v.ID, callbackBody); code != http.StatusConflict {
		t.Errorf("verify a closed case: %d %s", code, body)
	}
	if len(e.fake.Calls()) != 1 {
		t.Errorf("the IdP was called again: %v", e.fake.Calls())
	}
}

func TestHelpdeskPushNeedsPhishingResistantAuthenticator(t *testing.T) {
	e := newHelpdeskEnv(t, func(s *helpdesk.Service) { s.Push = weakPush{} })
	v := e.start(e.agent, e.alice, "password")
	if code, body := e.verify(e.agent, v.ID, `{"method":"push"}`); code != 200 {
		t.Fatalf("push: %d %s", code, body)
	}
	got := e.view(v.ID)
	if len(got.Verifications) != 1 || got.Verifications[0].Outcome != "failed" || got.Policy.Satisfied {
		t.Errorf("a push to a weak authenticator must not count: %+v", got)
	}
	if code, body := e.do(e.other, "POST", "/api/helpdesk/cases/"+v.ID+"/execute", ""); code != http.StatusConflict {
		t.Errorf("execute: %d %s", code, body)
	}
	if len(e.fake.Calls()) != 0 {
		t.Error("the IdP was called")
	}
}

type weakPush struct{}

func (weakPush) SendPush(_ context.Context, _ helpdesk.PushRequest) (helpdesk.PushResult, error) {
	return helpdesk.PushResult{Approved: true, PhishingResistant: false, Authenticator: "sms", Ref: "w1"}, nil
}

func TestHelpdeskPrivilegedNeedsTwoVerificationsAndSecondApprover(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	v := e.start(e.agent, e.carol, "mfa")
	if !v.Privileged || v.Policy.Required != 2 || !v.Policy.NeedsSecondApprover {
		t.Fatalf("carol's case: %+v", v)
	}
	exec := "/api/helpdesk/cases/" + v.ID + "/execute"
	second := "/api/helpdesk/cases/" + v.ID + "/second-approval"

	// IDV works for a privileged identity, but one method is not enough
	if code, body := e.verify(e.agent, v.ID, `{"method":"idv","session_ref":"idv-123"}`); code != 200 {
		t.Fatalf("idv: %d %s", code, body)
	}
	if code, _ := e.do(e.other, "POST", exec, ""); code != http.StatusConflict {
		t.Errorf("one verification: %d", code)
	}
	if code, body := e.verify(e.agent, v.ID, `{"method":"idv","session_ref":"fail-1"}`); code != 200 || e.view(v.ID).Policy.Satisfied {
		t.Errorf("a failed IDV: %d %s", code, body)
	}
	// the same method twice still counts once
	if code, body := e.verify(e.agent, v.ID, `{"method":"idv","session_ref":"idv-456"}`); code != 200 {
		t.Fatalf("idv again: %d %s", code, body)
	}
	if got := e.view(v.ID); len(got.Policy.Counted) != 1 {
		t.Errorf("counted: %v", got.Policy.Counted)
	}
	if code, body := e.verify(e.other, v.ID, callbackBody); code != 200 {
		t.Fatalf("callback: %d %s", code, body)
	}
	// two methods, no second approver
	code, body := e.do(e.other, "POST", exec, "")
	if code != http.StatusConflict || !strings.Contains(body, "second approver") {
		t.Fatalf("no second approver: %d %s", code, body)
	}
	// the requester cannot be the second approver
	if code, body = e.do(e.agent, "POST", second, ""); code != http.StatusForbidden {
		t.Errorf("requester as second approver: %d %s", code, body)
	}
	if code, _ = e.do(e.other, "POST", exec, ""); code != http.StatusConflict {
		t.Errorf("execute after a refused approval: %d", code)
	}
	// a viewer cannot approve at all
	viewer := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, *e.now)
	if code, _ = e.do(viewer, "POST", second, ""); code != http.StatusForbidden {
		t.Errorf("viewer approving: %d", code)
	}
	// the carol-linked user is the subject: she cannot approve her own reset
	if code, body = e.do(e.mgr, "POST", second, ""); code != http.StatusForbidden {
		t.Errorf("subject as second approver: %d %s", code, body)
	}
	if code, body = e.do(e.other, "POST", second, ""); code != 200 {
		t.Fatalf("second approval: %d %s", code, body)
	}
	if code, body = e.do(e.other, "POST", second, ""); code != http.StatusConflict {
		t.Errorf("second approval twice: %d %s", code, body)
	}
	if code, body = e.do(e.other, "POST", exec, ""); code != 200 {
		t.Fatalf("execute: %d %s", code, body)
	}
	if got := e.fake.Calls(); len(got) != 1 || got[0].UserID != "carol" {
		t.Errorf("executor calls: %+v", got)
	}
	if got := auditActions(t, e.f, e.f.A.ID); got["helpdesk.case.second_approval"] != 1 {
		t.Errorf("audit: %v", got)
	}
}

func TestHelpdeskSecondApprovalOnlyForPrivileged(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	v := e.start(e.agent, e.alice, "mfa")
	if code, body := e.do(e.other, "POST", "/api/helpdesk/cases/"+v.ID+"/second-approval", ""); code != http.StatusConflict {
		t.Errorf("second approval of a non-privileged case: %d %s", code, body)
	}
}

func TestHelpdeskManagerApproval(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	v := e.start(e.agent, e.alice, "password")
	mgr := "/api/helpdesk/cases/" + v.ID + "/manager-approval"
	// it is not a verification an agent can record
	if code, body := e.verify(e.agent, v.ID, `{"method":"manager_approval"}`); code != http.StatusForbidden {
		t.Errorf("agent recording a manager approval: %d %s", code, body)
	}
	// someone who is not the manager
	if code, body := e.do(e.other, "POST", mgr, ""); code != http.StatusForbidden {
		t.Errorf("non-manager: %d %s", code, body)
	}
	// the requester, even if they were the manager, cannot give it
	if code, body := e.do(e.agent, "POST", mgr, ""); code != http.StatusForbidden {
		t.Errorf("requester: %d %s", code, body)
	}
	if e.view(v.ID).Policy.Satisfied {
		t.Fatal("a refused approval satisfied the policy")
	}
	// carol is alice's manager
	if code, body := e.do(e.mgr, "POST", mgr, `{"evidence":"confirmed in person"}`); code != 200 {
		t.Fatalf("manager approval: %d %s", code, body)
	}
	if got := e.view(v.ID); !got.Policy.Satisfied || got.Policy.Counted[0] != "manager_approval" {
		t.Errorf("policy after the manager approval: %+v", got.Policy)
	}
	if code, body := e.do(e.other, "POST", "/api/helpdesk/cases/"+v.ID+"/execute", ""); code != 200 {
		t.Fatalf("execute: %d %s", code, body)
	}
}

func TestHelpdeskFailedResetCanBeRetried(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	v := e.start(e.agent, e.alice, "mfa")
	if code, body := e.verify(e.other, v.ID, callbackBody); code != 200 {
		t.Fatal(code, body)
	}
	exec := "/api/helpdesk/cases/" + v.ID + "/execute"
	e.fake.Err = fmt.Errorf("POST /x: status 500")
	code, body := e.do(e.other, "POST", exec, "")
	if code != http.StatusBadGateway || !strings.Contains(body, `"provider_failed"`) {
		t.Fatalf("failed reset: %d %s", code, body)
	}
	if got := e.view(v.ID); got.Status != "failed" || got.Error == "" || len(got.Result) != 0 {
		t.Errorf("failed case: %+v", got)
	}
	if got := auditActions(t, e.f, e.f.A.ID); got["helpdesk.reset.failed"] != 1 || got["helpdesk.reset.executed"] != 0 {
		t.Errorf("audit: %v", got)
	}
	e.fake.Err = nil
	e.fake.TAP = "Tap-secret-xyz"
	rec := corrDo(e.h, e.other, "POST", exec, "")
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "Tap-secret-xyz") {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body)
	}
	// the pass is shown once: not in the case, the audit ledger or a later read
	if _, body := e.do(e.agent, "GET", "/api/helpdesk/cases/"+v.ID, ""); strings.Contains(body, "Tap-secret-xyz") {
		t.Error("the temporary access pass was stored")
	}
	if err := e.f.DB.ReadTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		evs, err := c.AuditLog(-1) // every event, http.request included
		if len(evs) == 0 {
			t.Error("no audit events to check")
		}
		for _, ev := range evs {
			if strings.Contains(string(ev.Detail), "Tap-secret-xyz") {
				t.Errorf("the temporary access pass reached the audit ledger: %s", ev.Action)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := auditActions(t, e.f, e.f.A.ID); got["helpdesk.reset.executed"] != 1 {
		t.Errorf("audit: %v", got)
	}
}

func TestHelpdeskStartValidation(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	dave := e.f.A.IDs["dave"] // terminated
	self := e.signin("alice@a.example", &e.alice)
	for name, tc := range map[string]struct {
		login authtest.Login
		body  string
		want  int
	}{
		"bad kind":        {e.agent, fmt.Sprintf(`{"identity_id":%d,"kind":"pin","system":"okta","reason":"locked out after phone loss"}`, e.alice), 422},
		"bad system":      {e.agent, fmt.Sprintf(`{"identity_id":%d,"kind":"mfa","system":"ldap","reason":"locked out after phone loss"}`, e.alice), 422},
		"short reason":    {e.agent, fmt.Sprintf(`{"identity_id":%d,"kind":"mfa","system":"okta","reason":"x"}`, e.alice), 422},
		"unknown field":   {e.agent, fmt.Sprintf(`{"identity_id":%d,"kind":"mfa","system":"okta","reason":"locked out after phone loss","x":1}`, e.alice), 422},
		"unknown person":  {e.agent, `{"identity_id":99999,"kind":"mfa","system":"okta","reason":"locked out after phone loss"}`, 404},
		"no account":      {e.agent, fmt.Sprintf(`{"identity_id":%d,"kind":"mfa","system":"entra","reason":"locked out after phone loss"}`, e.alice), 422},
		"terminated":      {e.agent, fmt.Sprintf(`{"identity_id":%d,"kind":"mfa","system":"okta","reason":"locked out after phone loss"}`, dave), 409},
		"own identity":    {self, fmt.Sprintf(`{"identity_id":%d,"kind":"mfa","system":"okta","reason":"locked out after phone loss"}`, e.alice), 403},
		"B's identity":    {e.agent, fmt.Sprintf(`{"identity_id":%d,"kind":"mfa","system":"okta","reason":"locked out after phone loss"}`, e.f.B.IDs["alice"]+100000), 404},
		"viewer":          {signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, *e.now), fmt.Sprintf(`{"identity_id":%d,"kind":"mfa","system":"okta","reason":"locked out after phone loss"}`, e.alice), 403},
		"tenant admin":    {signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, *e.now), fmt.Sprintf(`{"identity_id":%d,"kind":"mfa","system":"okta","reason":"locked out after phone loss"}`, e.alice), 403},
		"password system": {e.agent, fmt.Sprintf(`{"identity_id":%d,"kind":"password","system":"simulated","reason":"locked out after phone loss"}`, e.alice), 201},
	} {
		if code, body := e.do(tc.login, "POST", "/api/helpdesk/cases", tc.body); code != tc.want {
			t.Errorf("%s: %d %s, want %d", name, code, body, tc.want)
		}
	}
}

// The simulated executor and providers are refused when the service is not simulated (production).
func TestHelpdeskSimulationRefusedInProduction(t *testing.T) {
	e := newHelpdeskEnv(t, func(s *helpdesk.Service) { s.Simulated = false })
	if code, body := e.do(e.agent, "POST", "/api/helpdesk/cases",
		fmt.Sprintf(`{"identity_id":%d,"kind":"mfa","system":"simulated","reason":"locked out after phone loss"}`, e.alice)); code != 422 {
		t.Errorf("simulated case: %d %s", code, body)
	}
	v := e.start(e.agent, e.alice, "mfa")
	if code, body := e.verify(e.agent, v.ID, `{"method":"push"}`); code != http.StatusServiceUnavailable {
		t.Errorf("push without a provider: %d %s", code, body)
	}
	if code, body := e.do(e.other, "POST", "/api/helpdesk/signals",
		`{"identity_id":1,"kind":"sign_in","location":"x","occurred_at":"2026-01-01T00:00:00Z"}`); code != 404 {
		t.Errorf("signal feed: %d %s", code, body)
	}
	// with no live connection the okta executor is unavailable, not faked
	e2 := newHelpdeskEnv(t, func(s *helpdesk.Service) { s.Simulated = false; s.Executors = nil })
	v2 := e2.start(e2.agent, e2.alice, "mfa")
	if code, body := e2.verify(e2.other, v2.ID, callbackBody); code != 200 {
		t.Fatal(code, body)
	}
	if code, body := e2.do(e2.other, "POST", "/api/helpdesk/cases/"+v2.ID+"/execute", ""); code != http.StatusServiceUnavailable {
		t.Errorf("execute without an executor: %d %s", code, body)
	}
	if got := e2.view(v2.ID); got.Status != "open" {
		t.Errorf("a refused execute must leave the case open: %s", got.Status)
	}
}

func TestHelpdeskTakeoverDetection(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	t0 := storetest.Now
	v := e.start(e.agent, e.alice, "mfa")
	if code, body := e.verify(e.other, v.ID, callbackBody); code != 200 {
		t.Fatal(code, body)
	}
	if code, body := e.do(e.other, "POST", "/api/helpdesk/cases/"+v.ID+"/execute", ""); code != 200 {
		t.Fatal(code, body)
	}
	*e.now = t0.Add(3 * time.Hour)
	ops := e.signin("agent@a.example", nil) // the earlier session is stale after the clock moves
	e.agent = ops
	signal := func(kind, loc string, at time.Time) (int, string) {
		return e.do(ops, "POST", "/api/helpdesk/signals", fmt.Sprintf(
			`{"identity_id":%d,"kind":%q,"location":%q,"device":"Pixel 9","occurred_at":%q}`, e.alice, kind, loc, at.Format(time.RFC3339)))
	}
	findings := func() int {
		_, body := e.do(ops, "GET", "/api/helpdesk/findings", "")
		var out struct {
			Findings []helpdesk.FindingView `json:"findings"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err, body)
		}
		return len(out.Findings)
	}
	// history before the reset, then each signal alone does not fire
	if code, body := signal("sign_in", "Oslo", t0.Add(-48*time.Hour)); code != 201 {
		t.Fatal(code, body)
	}
	if code, body := signal("mfa_device_added", "", t0.Add(time.Hour)); code != 201 || strings.Contains(body, "post_reset") {
		t.Fatalf("device alone: %d %s", code, body)
	}
	if code, body := signal("sign_in", "Oslo", t0.Add(90*time.Minute)); code != 201 || strings.Contains(body, "post_reset") {
		t.Fatalf("known location: %d %s", code, body)
	}
	if findings() != 0 {
		t.Fatal("fired without a new location")
	}
	// a new location within 24h of the reset, after a new device: it fires
	code, body := signal("sign_in", "Lagos", t0.Add(2*time.Hour))
	if code != 201 || !strings.Contains(body, helpdesk.RuleResetTakeover) {
		t.Fatalf("new location: %d %s", code, body)
	}
	if findings() != 1 || len(e.view(v.ID).Findings) != 1 {
		t.Error("the finding is not listed")
	}
	// the case raises it once
	if code, body = signal("sign_in", "Accra", t0.Add(150*time.Minute)); code != 201 || strings.Contains(body, helpdesk.RuleResetTakeover) {
		t.Fatalf("second location: %d %s", code, body)
	}
	if findings() != 1 {
		t.Error("the finding was raised twice")
	}
	if got := auditActions(t, e.f, e.f.A.ID); got["helpdesk.detection.fired"] != 1 {
		t.Errorf("audit: %v", got)
	}
	// bad input
	for name, b := range map[string]string{
		"kind":     fmt.Sprintf(`{"identity_id":%d,"kind":"login","location":"x","occurred_at":"2026-01-01T00:00:00Z"}`, e.alice),
		"location": fmt.Sprintf(`{"identity_id":%d,"kind":"sign_in","occurred_at":"2026-01-01T00:00:00Z"}`, e.alice),
		"future":   fmt.Sprintf(`{"identity_id":%d,"kind":"sign_in","location":"x","occurred_at":"2099-01-01T00:00:00Z"}`, e.alice),
		"identity": `{"identity_id":99999,"kind":"sign_in","location":"x","occurred_at":"2026-01-01T00:00:00Z"}`,
	} {
		if code, body := e.do(ops, "POST", "/api/helpdesk/signals", b); code != 422 && code != 404 {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	// a viewer cannot feed signals
	viewer := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, *e.now)
	if code, _ := e.do(viewer, "POST", "/api/helpdesk/signals", `{}`); code != 403 {
		t.Errorf("viewer feeding signals: %d", code)
	}
}

func TestHelpdeskTenantIsolation(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	v := e.start(e.agent, e.alice, "mfa")
	b := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "agent@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, *e.now)
	base := "/api/helpdesk/cases/" + v.ID
	for name, tc := range map[string]struct{ method, path, body string }{
		"get":       {"GET", base, ""},
		"verify":    {"POST", base + "/verifications", callbackBody},
		"second":    {"POST", base + "/second-approval", ""},
		"manager":   {"POST", base + "/manager-approval", ""},
		"execute":   {"POST", base + "/execute", ""},
		"cancel":    {"POST", base + "/cancel", ""},
		"bad id":    {"GET", "/api/helpdesk/cases/not-a-uuid", ""},
		"start (A)": {"POST", "/api/helpdesk/cases", fmt.Sprintf(`{"identity_id":%d,"kind":"mfa","system":"okta","reason":"locked out after phone loss"}`, e.alice)},
	} {
		code, body := e.do(b, tc.method, tc.path, tc.body)
		if code != 404 && code != 422 && code != 403 {
			t.Errorf("%s: %d %s", name, code, body)
		}
		if code == 200 || code == 201 {
			t.Errorf("%s crossed tenants", name)
		}
	}
	if _, body := e.do(b, "GET", "/api/helpdesk/cases", ""); strings.Contains(body, v.ID) {
		t.Error("B lists A's case")
	}
	if len(e.fake.Calls()) != 0 {
		t.Error("B's requests reached the IdP")
	}
	if e.view(v.ID).Status != "open" {
		t.Error("A's case changed")
	}
}

func TestHelpdeskCancel(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	v := e.start(e.agent, e.alice, "mfa")
	if code, body := e.verify(e.other, v.ID, callbackBody); code != 200 {
		t.Fatal(code, body)
	}
	if code, body := e.do(e.agent, "POST", "/api/helpdesk/cases/"+v.ID+"/cancel", ""); code != 200 {
		t.Fatalf("cancel: %d %s", code, body)
	}
	if code, _ := e.do(e.other, "POST", "/api/helpdesk/cases/"+v.ID+"/execute", ""); code != http.StatusConflict {
		t.Errorf("execute a cancelled case: %d", code)
	}
	if len(e.fake.Calls()) != 0 {
		t.Error("a cancelled case reached the IdP")
	}
}

// Four eyes (#358): the operator who opens a case cannot record the call-back
// (it is their own word) or execute it, and nobody verifies or executes a
// reset of their own identity.
func TestHelpdeskFourEyes(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	self := e.signin("alice@a.example", &e.alice) // an operator linked to the subject
	v := e.start(e.agent, e.alice, "mfa")
	exec := "/api/helpdesk/cases/" + v.ID + "/execute"
	refused := func(name string, code int, body, want string) {
		t.Helper()
		if code != http.StatusForbidden || !strings.Contains(body, `"`+want+`"`) {
			t.Errorf("%s: %d %s, want 403 %s", name, code, body, want)
		}
	}
	code, body := e.verify(e.agent, v.ID, callbackBody)
	refused("requester call-back", code, body, helpdesk.ReasonRequesterVerify)
	code, body = e.verify(self, v.ID, callbackBody)
	refused("subject call-back", code, body, helpdesk.ReasonSelfReset)
	code, body = e.verify(self, v.ID, `{"method":"push"}`)
	refused("subject push", code, body, helpdesk.ReasonSelfReset)
	if got := e.view(v.ID); got.Policy.Satisfied || len(got.Verifications) != 0 {
		t.Fatalf("a refused verification was recorded: %+v", got)
	}
	if code, body = e.verify(e.other, v.ID, callbackBody); code != 200 {
		t.Fatalf("second operator call-back: %d %s", code, body)
	}
	if !e.view(v.ID).Policy.Satisfied {
		t.Fatal("a second operator's call-back does not satisfy the policy")
	}
	code, body = e.do(e.agent, "POST", exec, "")
	refused("requester execute", code, body, helpdesk.ReasonRequesterExecute)
	code, body = e.do(self, "POST", exec, "")
	refused("subject execute", code, body, helpdesk.ReasonSelfReset)
	if len(e.fake.Calls()) != 0 || e.view(v.ID).Status != "open" {
		t.Fatal("a refused execute reached the IdP or changed the case")
	}
	if code, body = e.do(e.other, "POST", exec, ""); code != 200 {
		t.Fatalf("second operator execute: %d %s", code, body)
	}
	if len(e.fake.Calls()) != 1 {
		t.Errorf("executor calls: %v", e.fake.Calls())
	}
}

// A requester with two sign-in users linked to one identity cannot use the
// second as the independent verifier, second approver or executor (#431).
func TestHelpdeskRequesterLinkedUserIsNotIndependent(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	bob := e.f.A.IDs["bob"]
	req := e.signin("bob1@a.example", &bob)
	req2 := e.signin("bob2@a.example", &bob) // the same person's second sign-in
	v := e.start(req, e.alice, "mfa")
	refused := func(name string, code int, body, want string) {
		t.Helper()
		if code != http.StatusForbidden || !strings.Contains(body, `"`+want+`"`) {
			t.Errorf("%s: %d %s, want 403 %s", name, code, body, want)
		}
	}
	code, body := e.verify(req2, v.ID, callbackBody)
	refused("linked-user call-back", code, body, helpdesk.ReasonRequesterVerify)
	code, body = e.verify(req2, v.ID, `{"method":"manager_approval"}`)
	if code != http.StatusForbidden {
		t.Errorf("linked-user manager approval: %d %s", code, body)
	}
	code, body = e.do(req2, "POST", "/api/helpdesk/cases/"+v.ID+"/execute", "")
	refused("linked-user execute", code, body, helpdesk.ReasonRequesterExecute)
	if got := e.view(v.ID); got.Policy.Satisfied || len(got.Verifications) != 0 {
		t.Fatalf("a refused verification was recorded: %+v", got)
	}
	if code, body = e.verify(e.other, v.ID, callbackBody); code != 200 {
		t.Fatalf("an unrelated operator's call-back: %d %s", code, body)
	}
	if !e.view(v.ID).Policy.Satisfied {
		t.Fatal("an unrelated operator's call-back does not satisfy the policy")
	}
}

// An operator whose platform user has no linked identity cannot open or verify
// a reset case: the self-reset check cannot place them (#446).
func TestHelpdeskUnlinkedOperatorIsRefused(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	unlinked := e.signin("unlinked@a.example", nil)
	code, body := e.do(unlinked, "POST", "/api/helpdesk/cases",
		fmt.Sprintf(`{"identity_id":%d,"kind":"mfa","system":"okta","reason":"locked out after phone loss"}`, e.alice))
	if code != http.StatusForbidden || !strings.Contains(body, `"`+helpdesk.ReasonActorUnlinked+`"`) {
		t.Errorf("open: %d %s, want 403 actor_unlinked", code, body)
	}
	v := e.start(e.agent, e.alice, "mfa")
	code, body = e.verify(unlinked, v.ID, callbackBody)
	if code != http.StatusForbidden || !strings.Contains(body, `"`+helpdesk.ReasonActorUnlinked+`"`) {
		t.Errorf("verify: %d %s, want 403 actor_unlinked", code, body)
	}
	if got := e.view(v.ID); len(got.Verifications) != 0 {
		t.Fatalf("a refused verification was recorded: %+v", got)
	}
	if code, body = e.verify(e.other, v.ID, callbackBody); code != 200 {
		t.Fatalf("linked unrelated operator: %d %s", code, body)
	}
}

// An operator with no linked identity can neither second-approve nor execute a reset (#449); a
// linked unrelated operator still can.
func TestHelpdeskUnlinkedOperatorCannotApproveOrExecute(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	v := e.start(e.agent, e.carol, "mfa")
	if code, body := e.verify(e.agent, v.ID, `{"method":"idv","session_ref":"idv-123"}`); code != 200 {
		t.Fatalf("idv: %d %s", code, body)
	}
	if code, body := e.verify(e.other, v.ID, callbackBody); code != 200 {
		t.Fatalf("callback: %d %s", code, body)
	}
	unlinked := e.signin("unlinked@a.example", nil)
	base := "/api/helpdesk/cases/" + v.ID
	for name, path := range map[string]string{"second approval": base + "/second-approval", "execute": base + "/execute"} {
		code, body := e.do(unlinked, "POST", path, "")
		if code != http.StatusForbidden || !strings.Contains(body, `"`+helpdesk.ReasonActorUnlinked+`"`) {
			t.Errorf("%s: %d %s, want 403 actor_unlinked", name, code, body)
		}
	}
	if code, body := e.do(e.other, "POST", base+"/second-approval", ""); code != 200 {
		t.Fatalf("linked second approval: %d %s", code, body)
	}
	if code, body := e.do(e.other, "POST", base+"/execute", ""); code != 200 {
		t.Fatalf("linked execute: %d %s", code, body)
	}
	if got := e.fake.Calls(); len(got) != 1 {
		t.Errorf("executor calls: %+v", got)
	}
}
