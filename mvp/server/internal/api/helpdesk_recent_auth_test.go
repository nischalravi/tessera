package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Recently added authentication methods and the verified help-desk reset
// (issue #477).

// addMethod registers an authentication method of alice's Okta account that was
// enrolled `daysAgo` days before now (nil: the IdP reported no enrolment date).
func (e *helpdeskEnv) addMethod(daysAgo *int) {
	e.t.Helper()
	var at *time.Time
	if daysAgo != nil {
		v := e.now.Add(-time.Duration(*daysAgo) * 24 * time.Hour)
		at = &v
	}
	err := e.f.DB.InTenant(context.Background(), e.f.A.ID, func(c *store.TenantTx) error {
		return c.ReplaceAuthMethods("okta", []store.AuthMethod{{AccountID: e.f.A.IDs["acct:okta:alice"], ExternalID: "factor-1",
			Strength: "otp", Kind: "totp", Label: "Pixel 8", EnrolledAt: at, ObservedAt: *e.now}})
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func days(n int) *int { return &n }

func (e *helpdeskEnv) setRecent(l authtest.Login, n int, action string) (int, string) {
	return e.do(l, "PUT", "/api/helpdesk/settings", fmt.Sprintf(`{"recent_method_days":%d,"recent_method_action":%q}`, n, action))
}

func TestHelpdeskRecentMethodNeedsSecondApprover(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	e.addMethod(days(2))
	v := e.start(e.agent, e.alice, "mfa")
	if v.Privileged || v.Policy.RecentAuthMethod == nil || !v.Policy.NeedsSecondApprover || v.Policy.Blocked ||
		len(v.Policy.RecentAuthMethod.Reasons) != 1 || !strings.Contains(v.Policy.RecentAuthMethod.Reasons[0], "Pixel 8") {
		t.Fatalf("started case: %+v", v.Policy)
	}
	if got := auditActions(t, e.f, e.f.A.ID); got["helpdesk.case.recent_auth_method"] != 1 {
		t.Errorf("audit: %v", got)
	}
	exec, second := "/api/helpdesk/cases/"+v.ID+"/execute", "/api/helpdesk/cases/"+v.ID+"/second-approval"
	if code, body := e.verify(e.other, v.ID, callbackBody); code != 200 {
		t.Fatalf("callback: %d %s", code, body)
	}
	// verified, but the extra approval is missing
	if code, body := e.do(e.other, "POST", exec, ""); code != http.StatusConflict || !strings.Contains(body, "second approver") {
		t.Fatalf("no second approver: %d %s", code, body)
	}
	if code, body := e.do(e.agent, "POST", second, ""); code != http.StatusForbidden {
		t.Errorf("the requester as second approver: %d %s", code, body)
	}
	if len(e.fake.Calls()) != 0 {
		t.Fatalf("the IdP was called before the approval: %v", e.fake.Calls())
	}
	if code, body := e.do(e.other, "POST", second, ""); code != 200 {
		t.Fatalf("second approval: %d %s", code, body)
	}
	if code, body := e.do(e.other, "POST", exec, ""); code != 200 {
		t.Fatalf("execute: %d %s", code, body)
	}
	if got := e.fake.Calls(); len(got) != 1 || got[0].UserID != "alice" {
		t.Errorf("executor calls: %+v", got)
	}
}

func TestHelpdeskRecentMethodWindow(t *testing.T) {
	for name, tc := range map[string]struct {
		daysAgo *int
		days    int
		trigger bool
	}{
		"inside the window":            {days(6), 7, true},
		"on the edge of the window":    {days(7), 7, true},
		"outside the window":           {days(8), 7, false},
		"a longer configured window":   {days(20), 30, true},
		"no enrolment date is unknown": {nil, 7, false},
	} {
		t.Run(name, func(t *testing.T) {
			e := newHelpdeskEnv(t, nil)
			if code, body := e.setRecent(e.agent, tc.days, "require_approval"); code != 200 {
				t.Fatalf("settings: %d %s", code, body)
			}
			e.addMethod(tc.daysAgo)
			v := e.start(e.agent, e.alice, "mfa")
			if got := v.Policy.RecentAuthMethod != nil; got != tc.trigger || v.Policy.NeedsSecondApprover != tc.trigger {
				t.Errorf("policy = %+v, want trigger %v", v.Policy, tc.trigger)
			}
		})
	}
}

func TestHelpdeskRecentMethodBlock(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	if code, body := e.setRecent(e.agent, 7, "block"); code != 200 {
		t.Fatalf("settings: %d %s", code, body)
	}
	e.addMethod(days(2))
	v := e.start(e.agent, e.alice, "mfa")
	if !v.Policy.Blocked || v.Policy.Satisfied {
		t.Fatalf("policy = %+v", v.Policy)
	}
	exec := "/api/helpdesk/cases/" + v.ID + "/execute"
	if code, body := e.verify(e.other, v.ID, callbackBody); code != 200 {
		t.Fatalf("callback: %d %s", code, body)
	}
	// an approval does not lift a block
	if code, body := e.do(e.other, "POST", "/api/helpdesk/cases/"+v.ID+"/second-approval", ""); code != http.StatusConflict {
		t.Fatalf("second approval of a blocked case: %d %s", code, body)
	}
	if code, body := e.do(e.other, "POST", exec, ""); code != http.StatusConflict || !strings.Contains(body, "blocked") {
		t.Fatalf("blocked execute: %d %s", code, body)
	}
	if len(e.fake.Calls()) != 0 {
		t.Fatalf("the IdP was called for a blocked case: %v", e.fake.Calls())
	}
	// the window no longer covers the method (an admin shortens it): the case can run
	if code, body := e.setRecent(e.agent, 1, "block"); code != 200 {
		t.Fatalf("settings: %d %s", code, body)
	}
	if got := e.view(v.ID).Policy; got.Blocked || got.RecentAuthMethod != nil {
		t.Fatalf("after the window: %+v", got)
	}
	if code, body := e.do(e.other, "POST", exec, ""); code != 200 {
		t.Fatalf("execute after the window: %d %s", code, body)
	}
}

func TestHelpdeskRecentMethodOff(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	if code, body := e.setRecent(e.agent, 7, "off"); code != 200 {
		t.Fatalf("settings: %d %s", code, body)
	}
	e.addMethod(days(1))
	v := e.start(e.agent, e.alice, "mfa")
	if v.Policy.RecentAuthMethod != nil || v.Policy.NeedsSecondApprover {
		t.Fatalf("policy = %+v", v.Policy)
	}
	if code, body := e.verify(e.other, v.ID, callbackBody); code != 200 {
		t.Fatalf("callback: %d %s", code, body)
	}
	if code, body := e.do(e.other, "POST", "/api/helpdesk/cases/"+v.ID+"/execute", ""); code != 200 {
		t.Fatalf("execute: %d %s", code, body)
	}
}

func TestHelpdeskIdPRiskSignal(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	when := e.now.Add(-3 * time.Hour).Format(time.RFC3339)
	body := func(id int64, at string) string {
		return fmt.Sprintf(`{"identity_id":%d,"source":"Entra ID","detail":"suspicious authentication method added","occurred_at":%q}`, id, at)
	}
	admin := func(email string, roles ...auth.Role) authtest.Login {
		return signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: email, Roles: roles}, authtest.Phr, *e.now)
	}
	tenantAdmin, policyAdmin := admin("ta@a.example", auth.RoleTenantAdmin), admin("pa@a.example", auth.RolePolicyAdmin)
	// issue #510: an operator (helpdesk.approve) and a viewer cannot post or dismiss a signal; an admin without a
	// fresh passkey sign-in cannot either
	viewer := admin("v@a.example", auth.RoleViewer)
	for name, l := range map[string]authtest.Login{"viewer": viewer, "operator": e.other, "help-desk agent": e.agent} {
		if code, _ := e.do(l, "POST", "/api/helpdesk/risk-signals", body(e.alice, when)); code != http.StatusForbidden {
			t.Errorf("%s ingesting a risk signal: %d", name, code)
		}
		if code, _ := e.do(l, "GET", "/api/helpdesk/risk-signals", ""); code != http.StatusForbidden {
			t.Errorf("%s listing risk signals: %d", name, code)
		}
	}
	stale := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "stale@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: e.now.Add(-20 * time.Minute)}, *e.now)
	if code, out := e.do(stale, "POST", "/api/helpdesk/risk-signals", body(e.alice, when)); code != http.StatusUnauthorized || !strings.Contains(out, "step_up_required") {
		t.Errorf("an admin without step-up: %d %s", code, out)
	}
	for name, b := range map[string]string{
		"future":    body(e.alice, e.now.Add(time.Hour).Format(time.RFC3339)),
		"backdated": body(e.alice, e.now.Add(-8*24*time.Hour).Format(time.RFC3339)), // the window is 7 days
		"long ago":  body(e.alice, e.now.Add(-80*24*time.Hour).Format(time.RFC3339)),
		"no src":    fmt.Sprintf(`{"identity_id":%d,"source":"","occurred_at":%q}`, e.alice, when),
		"long":      fmt.Sprintf(`{"identity_id":%d,"source":"entra","detail":%q,"occurred_at":%q}`, e.alice, strings.Repeat("x", 201), when),
		"no time":   fmt.Sprintf(`{"identity_id":%d,"source":"entra"}`, e.alice),
	} {
		if code, out := e.do(tenantAdmin, "POST", "/api/helpdesk/risk-signals", b); code != 422 {
			t.Errorf("%s: %d %s", name, code, out)
		}
	}
	if code, out := e.do(tenantAdmin, "POST", "/api/helpdesk/risk-signals", body(999999, when)); code != 404 {
		t.Errorf("unknown identity: %d %s", code, out)
	}
	// tenant B cannot signal on A's identity
	loginB := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, *e.now)
	if code, out := e.do(loginB, "POST", "/api/helpdesk/risk-signals", body(e.alice, when)); code != 404 {
		t.Errorf("tenant B on A's identity: %d %s", code, out)
	}
	before := e.start(e.agent, e.alice, "mfa")
	if before.Policy.RecentAuthMethod != nil {
		t.Fatalf("no signal yet: %+v", before.Policy)
	}
	code, out := e.do(tenantAdmin, "POST", "/api/helpdesk/risk-signals", body(e.alice, when))
	if code != http.StatusCreated {
		t.Fatalf("ingest: %d %s", code, out)
	}
	var created struct {
		ID         string `json:"id"`
		ReportedBy string `json:"reported_by"`
	}
	if err := json.Unmarshal([]byte(out), &created); err != nil || created.ID == "" {
		t.Fatalf("ingest body: %s %v", out, err)
	}
	// the open case now shows it as the poster's report with an unverified label, and cannot run without the extra approval
	after := e.view(before.ID)
	reasons := ""
	if after.Policy.RecentAuthMethod != nil {
		reasons = strings.Join(after.Policy.RecentAuthMethod.Reasons, ";")
	}
	if after.Policy.RecentAuthMethod == nil || !after.Policy.NeedsSecondApprover || !strings.Contains(reasons, "reported by ") ||
		!strings.Contains(reasons, "(manual") || !strings.Contains(reasons, "unverified") || strings.HasPrefix(reasons, "Entra ID reported") {
		t.Fatalf("after the signal: %+v", after.Policy)
	}
	if code, out := e.verify(e.other, before.ID, callbackBody); code != 200 {
		t.Fatalf("callback: %d %s", code, out)
	}
	if code, out := e.do(e.other, "POST", "/api/helpdesk/cases/"+before.ID+"/execute", ""); code != http.StatusConflict {
		t.Errorf("execute with an IdP risk signal and no approval: %d %s", code, out)
	}
	// dismissal: a reason is required, the poster cannot dismiss, an operator cannot, a different admin can
	dismiss := "/api/helpdesk/risk-signals/" + created.ID + "/dismiss"
	if code, out := e.do(policyAdmin, "POST", dismiss, `{"reason":""}`); code != 422 {
		t.Errorf("dismiss without a reason: %d %s", code, out)
	}
	if code, out := e.do(tenantAdmin, "POST", dismiss, `{"reason":"it was mine"}`); code != http.StatusForbidden || !strings.Contains(out, "different_admin_required") {
		t.Errorf("the poster dismissing: %d %s", code, out)
	}
	if code, _ := e.do(e.other, "POST", dismiss, `{"reason":"not an admin"}`); code != http.StatusForbidden {
		t.Errorf("an operator dismissing: %d", code)
	}
	if code, out := e.do(policyAdmin, "POST", "/api/helpdesk/risk-signals/nope/dismiss", `{"reason":"x"}`); code != 404 {
		t.Errorf("unknown signal: %d %s", code, out)
	}
	if code, out := e.do(loginB, "POST", dismiss, `{"reason":"another tenant"}`); code != 404 {
		t.Errorf("tenant B dismissing A's signal: %d %s", code, out)
	}
	if code, out := e.do(policyAdmin, "POST", dismiss, `{"reason":"raised in error"}`); code != 200 || !strings.Contains(out, `"dismissed":true`) {
		t.Fatalf("dismiss: %d %s", code, out)
	}
	if code, out := e.do(policyAdmin, "POST", dismiss, `{"reason":"again"}`); code != http.StatusConflict {
		t.Errorf("dismissing twice: %d %s", code, out)
	}
	if v := e.view(before.ID); v.Policy.RecentAuthMethod != nil && len(v.Policy.RecentAuthMethod.Reasons) > 0 {
		t.Errorf("a dismissed signal still counts: %+v", v.Policy.RecentAuthMethod)
	}
	if code, out := e.do(policyAdmin, "GET", "/api/helpdesk/risk-signals", ""); code != 200 || !strings.Contains(out, `"reported_by":"`) || !strings.Contains(out, `"dismissed":true`) {
		t.Errorf("list: %d %s", code, out)
	}
	got := auditActions(t, e.f, e.f.A.ID)
	if got["helpdesk.risk_signal.ingested"] != 1 || got["helpdesk.risk_signal.dismissed"] != 1 {
		t.Errorf("audit: %v", got)
	}
}

func TestHelpdeskSettingsAPI(t *testing.T) {
	e := newHelpdeskEnv(t, nil)
	code, body := e.do(e.agent, "GET", "/api/helpdesk/settings", "")
	if code != 200 || !strings.Contains(body, `"recent_method_days":7`) || !strings.Contains(body, `"recent_method_action":"require_approval"`) {
		t.Fatalf("defaults: %d %s", code, body)
	}
	for name, b := range map[string]string{
		"zero days":  `{"recent_method_days":0,"recent_method_action":"block"}`,
		"91 days":    `{"recent_method_days":91,"recent_method_action":"block"}`,
		"bad action": `{"recent_method_days":7,"recent_method_action":"ignore"}`,
		"no action":  `{"recent_method_days":7}`,
	} {
		if code, out := e.do(e.agent, "PUT", "/api/helpdesk/settings", b); code != 422 {
			t.Errorf("%s: %d %s", name, code, out)
		}
	}
	viewer := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "v@a.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, *e.now)
	if code, _ := e.do(viewer, "PUT", "/api/helpdesk/settings", `{"recent_method_days":3,"recent_method_action":"off"}`); code != http.StatusForbidden {
		t.Errorf("viewer changing the settings: %d", code)
	}
	if code, out := e.do(viewer, "GET", "/api/helpdesk/settings", ""); code != 200 {
		t.Errorf("viewer reading the settings: %d %s", code, out)
	}
	if code, out := e.setRecent(e.agent, 14, "block"); code != 200 || !strings.Contains(out, `"recent_method_days":14`) {
		t.Fatalf("update: %d %s", code, out)
	}
	if got := auditActions(t, e.f, e.f.A.ID); got["helpdesk.settings.updated"] != 1 {
		t.Errorf("audit: %v", got)
	}
	// per tenant: B still has the defaults
	loginB := signIn(t, e.f.DB, e.f.B.ID, authtest.User{Email: "ops@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, *e.now)
	if code, out := e.do(loginB, "GET", "/api/helpdesk/settings", ""); code != 200 || !strings.Contains(out, `"recent_method_days":7`) {
		t.Errorf("tenant B settings: %d %s", code, out)
	}
}
