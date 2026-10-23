package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

type notifyRig struct {
	f                                 *storetest.Fixture
	h                                 http.Handler
	admin, stale, auditor, viewer, ta authtest.Login
}

func newNotifyRig(t *testing.T, mutate func(*Config)) *notifyRig {
	t.Helper()
	f := storetest.TwoTenants(t)
	h := newIsolationServerWith(f, func(c *Config) {
		c.Sealer = testSealer()
		if mutate != nil {
			mutate(c)
		}
	}).Handler()
	now := storetest.Now
	return &notifyRig{f: f, h: h,
		admin:   signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now),
		stale:   signIn(t, f.DB, f.B.ID, authtest.User{Email: "stale@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Ctx{AAL: 2, Phr: true, AuthTime: now.Add(-20 * time.Minute)}, now),
		auditor: signIn(t, f.DB, f.B.ID, authtest.User{Email: "au@b.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, now),
		viewer:  signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now),
		ta:      signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)}
}

func (r *notifyRig) do(l authtest.Login, method, path, body string) *httptest.ResponseRecorder {
	return reqDo(r.h, l, method, path, body)
}

func mustCode(t *testing.T, what string, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("%s: %d %s, want %d", what, rec.Code, rec.Body, want)
	}
}

// ---- relay

func TestMailRelayAPI(t *testing.T) {
	r := newNotifyRig(t, nil)
	body := `{"version":0,"enabled":true,"host":"93.184.216.34","port":587,"tls":"starttls","username":"tessera","password":"hunter2-relay-password","from":"Tessera <tessera@larkspur.example>"}`

	var v relayView
	rec := r.do(r.auditor, "GET", "/api/admin/mail-relay", "")
	mustCode(t, "GET before", rec, 200)
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || v.Configured || v.Version != 0 || v.Port != 587 || v.CanManage {
		t.Errorf("defaults: %s", rec.Body)
	}
	if rec := r.do(r.viewer, "GET", "/api/admin/mail-relay", ""); rec.Code != 403 {
		t.Errorf("viewer GET: %d", rec.Code)
	}
	for who, l := range map[string]authtest.Login{"viewer": r.viewer, "auditor": r.auditor} {
		if rec := r.do(l, "PUT", "/api/admin/mail-relay", body); rec.Code != 403 {
			t.Errorf("%s PUT: %d", who, rec.Code)
		}
	}
	if rec := r.do(r.stale, "PUT", "/api/admin/mail-relay", body); rec.Code != 401 && rec.Code != 403 {
		t.Errorf("PUT without a fresh sign-in: %d", rec.Code)
	}
	for name, tc := range map[string]struct {
		body string
		code int
	}{
		"private address":   {strings.Replace(body, "93.184.216.34", "10.0.0.5", 1), 422},
		"metadata address":  {strings.Replace(body, "93.184.216.34", "169.254.169.254", 1), 422},
		"loopback":          {strings.Replace(body, "93.184.216.34", "127.0.0.1", 1), 422},
		"localhost":         {strings.Replace(body, "93.184.216.34", "localhost", 1), 422},
		"no login password": {strings.Replace(body, `"password":"hunter2-relay-password",`, "", 1), 422},
		"bad tls":           {strings.Replace(body, "starttls", "ssl", 1), 422},
		"bad from":          {strings.Replace(body, "Tessera <tessera@larkspur.example>", "nope", 1), 422},
		"unknown field":     {strings.Replace(body, `"port":587`, `"port":587,"bcc":"x"`, 1), 422},
		"stale version":     {strings.Replace(body, `"version":0`, `"version":4`, 1), 409},
	} {
		if rec := r.do(r.admin, "PUT", "/api/admin/mail-relay", tc.body); rec.Code != tc.code {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body, tc.code)
		}
	}
	rec = r.do(r.admin, "PUT", "/api/admin/mail-relay", body)
	mustCode(t, "PUT", rec, 200)
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), "password_sealed") {
		t.Fatalf("the password is in the response: %s", rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || !v.Configured || !v.Enabled || !v.HasPassword || v.Host != "93.184.216.34" || v.Version != 1 || !v.CanManage {
		t.Errorf("after PUT: %s", rec.Body)
	}
	// the password is sealed in the table and not readable through GET either
	if rec := r.do(r.auditor, "GET", "/api/admin/mail-relay", ""); strings.Contains(rec.Body.String(), "hunter2") {
		t.Errorf("GET shows the password: %s", rec.Body)
	}
	if err := r.f.DB.ReadTenant(t.Context(), r.f.B.ID, func(tx *store.TenantTx) error {
		row, err := tx.MailRelay()
		if err != nil || len(row.PasswordSealed) == 0 || strings.Contains(string(row.PasswordSealed), "hunter2") {
			t.Errorf("stored row = %+v, %v", row, err)
		}
		log, _ := tx.AuditLog(-1)
		for _, e := range log {
			if strings.Contains(string(e.Detail), "hunter2") {
				t.Errorf("the password is in the audit log: %s", e.Detail)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// another tenant has none
	var a relayView
	rec = r.do(r.ta, "GET", "/api/admin/mail-relay", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil || a.Configured || a.Host != "" {
		t.Errorf("tenant A sees B's relay: %s", rec.Body)
	}
	// a test message needs a relay that can connect: a public address is not reachable from the test, so it fails visibly
	if rec := r.do(r.ta, "POST", "/api/admin/mail-relay/test", `{}`); rec.Code != 404 {
		t.Errorf("test without a relay: %d %s", rec.Code, rec.Body)
	}
	// delete
	if rec := r.do(r.admin, "DELETE", "/api/admin/mail-relay", `{"version":9}`); rec.Code != 409 {
		t.Errorf("stale delete: %d", rec.Code)
	}
	rec = r.do(r.admin, "DELETE", "/api/admin/mail-relay", `{"version":1}`)
	mustCode(t, "DELETE", rec, 200)
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || v.Configured {
		t.Errorf("after DELETE: %s", rec.Body)
	}
	if rec := r.do(r.admin, "DELETE", "/api/admin/mail-relay", `{"version":0}`); rec.Code != 404 {
		t.Errorf("second delete: %d", rec.Code)
	}
	if rec := r.do(r.auditor, "GET", "/api/audit", ""); !strings.Contains(rec.Body.String(), "mail.relay.update") || !strings.Contains(rec.Body.String(), "mail.relay.delete") {
		t.Errorf("relay changes are not audited: %.300s", rec.Body)
	}
}

// ---- chat

type hookRecorder struct {
	mu    sync.Mutex
	posts []string
}

func (h *hookRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.posts = append(h.posts, string(b))
	h.mu.Unlock()
}

func TestChatAPI(t *testing.T) {
	rec := &hookRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "dev", AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	r := newNotifyRig(t, func(c *Config) { c.Env, c.OutboundHTTP = "dev", hc })
	hook := srv.URL + "/services/T000/B000/SECRET-WEBHOOK-TOKEN"
	body := func(mod string) string {
		return `{"version":0,"provider":"slack","enabled":true,"webhook_url":` + jsonStr(hook) + `,"kinds":["request.approval_needed","security.alert"]` + mod + `}`
	}
	var v chatView
	res := r.do(r.auditor, "GET", "/api/admin/chat", "")
	mustCode(t, "GET before", res, 200)
	if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil || v.Configured || v.Provider != "slack" || len(v.Kinds) == 0 || len(v.ChatState.Kinds) != 3 {
		t.Errorf("defaults: %s", res.Body)
	}
	if res := r.do(r.viewer, "PUT", "/api/admin/chat", body("")); res.Code != 403 {
		t.Errorf("viewer PUT: %d", res.Code)
	}
	if res := r.do(r.stale, "PUT", "/api/admin/chat", body("")); res.Code != 401 && res.Code != 403 {
		t.Errorf("PUT without a fresh sign-in: %d", res.Code)
	}
	for name, tc := range map[string]struct {
		body string
		code int
	}{
		"unknown provider": {strings.Replace(body(""), `"slack"`, `"discord"`, 1), 422},
		"unknown kind":     {strings.Replace(body(""), "security.alert", "nope", 1), 422},
		"a secret kind":    {strings.Replace(body(""), "security.alert", "claim.code", 1), 422},
		"no URL":           {`{"version":0,"provider":"slack","enabled":true,"kinds":["security.alert"]}`, 422},
		"ftp":              {strings.Replace(body(""), srv.URL, "ftp://127.0.0.1", 1), 422},
		"stale":            {strings.Replace(body(""), `"version":0`, `"version":2`, 1), 409},
	} {
		if res := r.do(r.admin, "PUT", "/api/admin/chat", tc.body); res.Code != tc.code {
			t.Errorf("%s: %d %s, want %d", name, res.Code, res.Body, tc.code)
		}
	}
	res = r.do(r.admin, "PUT", "/api/admin/chat", body(""))
	mustCode(t, "PUT", res, 200)
	if strings.Contains(res.Body.String(), "SECRET-WEBHOOK-TOKEN") {
		t.Fatalf("the webhook URL is in the response: %s", res.Body)
	}
	if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil || !v.Configured || !v.HasWebhook || v.Host != "127.0.0.1" || v.Version != 1 || len(v.ChatState.Kinds) != 2 {
		t.Errorf("after PUT: %s", res.Body)
	}
	if res := r.do(r.auditor, "GET", "/api/admin/chat", ""); strings.Contains(res.Body.String(), "SECRET-WEBHOOK-TOKEN") {
		t.Errorf("GET shows the webhook: %s", res.Body)
	}
	// keeping the URL: an empty one on a second save
	res = r.do(r.admin, "PUT", "/api/admin/chat", `{"version":1,"provider":"slack","enabled":true,"kinds":["security.alert"]}`)
	mustCode(t, "PUT keeping the URL", res, 200)
	// test message goes through the saved webhook
	res = r.do(r.admin, "POST", "/api/admin/chat/test", `{}`)
	mustCode(t, "test", res, 200)
	rec.mu.Lock()
	if len(rec.posts) != 1 || !strings.Contains(rec.posts[0], "Test message from Tessera") {
		t.Errorf("posts = %v", rec.posts)
	}
	rec.mu.Unlock()
	if res := r.do(r.ta, "POST", "/api/admin/chat/test", `{}`); res.Code != 404 {
		t.Errorf("tenant A's test: %d", res.Code)
	}
	var a chatView
	res = r.do(r.ta, "GET", "/api/admin/chat", "")
	if err := json.Unmarshal(res.Body.Bytes(), &a); err != nil || a.Configured {
		t.Errorf("tenant A sees B's webhook: %s", res.Body)
	}
	res = r.do(r.admin, "DELETE", "/api/admin/chat", `{"version":2}`)
	mustCode(t, "DELETE", res, 200)
	if aud := r.do(r.auditor, "GET", "/api/audit", ""); strings.Contains(aud.Body.String(), "SECRET-WEBHOOK-TOKEN") || !strings.Contains(aud.Body.String(), "chat.webhook.update") ||
		!strings.Contains(aud.Body.String(), "chat.webhook.test") {
		t.Errorf("audit: %.400s", aud.Body)
	}
}

// In production the webhook must be on the provider's own host, whatever the URL says.
func TestChatAPIHostAllowList(t *testing.T) {
	r := newNotifyRig(t, nil) // Env "test": the provider host list applies
	put := func(provider, u string) int {
		return r.do(r.admin, "PUT", "/api/admin/chat", `{"version":0,"provider":"`+provider+`","enabled":false,"webhook_url":`+jsonStr(u)+`,"kinds":["security.alert"]}`).Code
	}
	if c := put("slack", "https://hooks.slack.com/services/T/B/X"); c != 200 {
		t.Errorf("slack host: %d", c)
	}
	r2 := newNotifyRig(t, nil)
	put2 := func(provider, u string) int {
		return r2.do(r2.admin, "PUT", "/api/admin/chat", `{"version":0,"provider":"`+provider+`","enabled":false,"webhook_url":`+jsonStr(u)+`,"kinds":["security.alert"]}`).Code
	}
	for _, u := range []string{"https://example.com/x", "http://hooks.slack.com/x", "https://169.254.169.254/x", "https://hooks.slack.com.evil.example/x"} {
		if c := put2("slack", u); c != 422 {
			t.Errorf("%s: %d", u, c)
		}
	}
	if c := put2("teams", "https://contoso.webhook.office.com/webhookb2/a/IncomingWebhook/b/c"); c != 200 {
		t.Errorf("teams host: %d", c)
	}
}

// ---- policy and templates

func TestNotificationPolicyAPI(t *testing.T) {
	r := newNotifyRig(t, nil)
	var v notifyPolicyView
	res := r.do(r.auditor, "GET", "/api/admin/notification-policy", "")
	if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil || res.Code != 200 || v.Version != 0 || v.EscalateAfterHours != 48 || v.ReviewRemindAfterDays != 7 || v.CanManage {
		t.Fatalf("defaults: %d %s", res.Code, res.Body)
	}
	good := `{"version":0,"review_remind_after_days":3,"review_remind_every_days":2,"request_warn_hours":48,"jit_warn_minutes":15,"escalate_after_hours":12}`
	if res := r.do(r.viewer, "PUT", "/api/admin/notification-policy", good); res.Code != 403 {
		t.Errorf("viewer: %d", res.Code)
	}
	if res := r.do(r.stale, "PUT", "/api/admin/notification-policy", good); res.Code != 401 && res.Code != 403 {
		t.Errorf("no fresh sign-in: %d", res.Code)
	}
	for name, tc := range map[string]struct {
		body string
		code int
	}{
		"zero escalation": {strings.Replace(good, `"escalate_after_hours":12`, `"escalate_after_hours":0`, 1), 422},
		"jit too small":   {strings.Replace(good, `"jit_warn_minutes":15`, `"jit_warn_minutes":1`, 1), 422},
		"missing field":   {`{"version":0,"review_remind_after_days":3}`, 422},
		"stale":           {strings.Replace(good, `"version":0`, `"version":5`, 1), 409},
	} {
		if res := r.do(r.admin, "PUT", "/api/admin/notification-policy", tc.body); res.Code != tc.code {
			t.Errorf("%s: %d %s, want %d", name, res.Code, res.Body, tc.code)
		}
	}
	res = r.do(r.admin, "PUT", "/api/admin/notification-policy", good)
	if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil || res.Code != 200 || v.Version != 1 || v.EscalateAfterHours != 12 || v.JITWarnMinutes != 15 || !v.CanManage || v.Defaults.EscalateAfterHours != 48 {
		t.Fatalf("PUT: %d %s", res.Code, res.Body)
	}
	// the escalation SLA applies to an item with no approval policy of its own
	err := r.f.DB.ReadTenant(t.Context(), r.f.B.ID, func(tx *store.TenantTx) error {
		p, _, err := notify.LoadPolicy(tx)
		if p.EscalateAfterHours != 12 {
			t.Errorf("loaded %+v", p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var a notifyPolicyView
	res = r.do(r.ta, "GET", "/api/admin/notification-policy", "")
	if err := json.Unmarshal(res.Body.Bytes(), &a); err != nil || a.Version != 0 || a.EscalateAfterHours != 48 {
		t.Errorf("tenant A sees B's policy: %s", res.Body)
	}
}

func TestNotificationTemplatesAPI(t *testing.T) {
	r := newNotifyRig(t, nil)
	var v templatesView
	res := r.do(r.auditor, "GET", "/api/admin/notification-templates", "")
	if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil || res.Code != 200 || len(v.Templates) != len(notify.Kinds) || len(v.Vars) != len(notify.TemplateVars) || v.CanManage {
		t.Fatalf("GET: %d %.300s", res.Code, res.Body)
	}
	for _, tpl := range v.Templates {
		if tpl.Customized {
			t.Errorf("%s is customized before any save", tpl.Kind)
		}
	}
	put := func(l authtest.Login, kind, body string) *httptest.ResponseRecorder {
		return r.do(l, "PUT", "/api/admin/notification-templates/"+url.PathEscape(kind), body)
	}
	good := `{"subject_tpl":"Please decide: {{subject}}","body_tpl":"{{body}}\n{{link}}"}`
	if res := put(r.viewer, "request.approval_needed", good); res.Code != 403 {
		t.Errorf("viewer: %d", res.Code)
	}
	if res := put(r.stale, "request.approval_needed", good); res.Code != 401 && res.Code != 403 {
		t.Errorf("no fresh sign-in: %d", res.Code)
	}
	for name, tc := range map[string]struct {
		kind, body string
		code       int
	}{
		"unknown kind":        {"nope", good, 404},
		"a secret kind":       {"claim.code", good, 404},
		"unknown placeholder": {"request.approval_needed", `{"subject_tpl":"{{password}}","body_tpl":"x"}`, 422},
		"empty":               {"request.approval_needed", `{"subject_tpl":"","body_tpl":""}`, 422},
		"two lines":           {"request.approval_needed", `{"subject_tpl":"a\nb","body_tpl":"x"}`, 422},
		"unknown field":       {"request.approval_needed", `{"subject_tpl":"a","body_tpl":"x","html":"<b>"}`, 422},
	} {
		if res := put(r.admin, tc.kind, tc.body); res.Code != tc.code {
			t.Errorf("%s: %d %s, want %d", name, res.Code, res.Body, tc.code)
		}
	}
	res = put(r.admin, "request.approval_needed", good)
	mustCode(t, "PUT", res, 200)
	if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil || !v.CanManage {
		t.Fatal(err)
	}
	custom := 0
	for _, tpl := range v.Templates {
		if tpl.Customized {
			custom++
			if tpl.Kind != "request.approval_needed" || !strings.Contains(tpl.Subject, "{{subject}}") {
				t.Errorf("customized = %+v", tpl)
			}
		}
	}
	if custom != 1 {
		t.Errorf("%d customized kinds", custom)
	}
	var a templatesView
	res = r.do(r.ta, "GET", "/api/admin/notification-templates", "")
	_ = json.Unmarshal(res.Body.Bytes(), &a)
	for _, tpl := range a.Templates {
		if tpl.Customized {
			t.Errorf("tenant A sees B's template of %s", tpl.Kind)
		}
	}
	if res := r.do(r.admin, "DELETE", "/api/admin/notification-templates/request.approval_needed", ""); res.Code != 200 {
		t.Errorf("reset: %d %s", res.Code, res.Body)
	}
	if res := r.do(r.admin, "DELETE", "/api/admin/notification-templates/request.approval_needed", ""); res.Code != 404 {
		t.Errorf("second reset: %d", res.Code)
	}
}

// ---- suppressions and DSN

func TestSuppressionsAndDSNAPI(t *testing.T) {
	r := newNotifyRig(t, nil)
	res := r.do(r.auditor, "GET", "/api/email/suppressions", "")
	mustCode(t, "list", res, 200)
	for who, l := range map[string]authtest.Login{"viewer": r.viewer, "auditor": r.auditor} {
		if res := r.do(l, "POST", "/api/email/suppressions", `{"address":"x@example.com"}`); res.Code != 403 {
			t.Errorf("%s POST: %d", who, res.Code)
		}
	}
	for name, body := range map[string]string{"not an address": `{"address":"nope"}`, "display name": `{"address":"A <a@b.example>"}`,
		"unknown field": `{"address":"a@b.example","reason":"bounce"}`, "long note": `{"address":"a@b.example","note":"` + strings.Repeat("x", 301) + `"}`} {
		if res := r.do(r.admin, "POST", "/api/email/suppressions", body); res.Code != 422 {
			t.Errorf("%s: %d %s", name, res.Code, res.Body)
		}
	}
	res = r.do(r.admin, "POST", "/api/email/suppressions", `{"address":"Left.Company@Example.com","note":"left"}`)
	mustCode(t, "add", res, 200)
	if !strings.Contains(res.Body.String(), `"left.company@example.com"`) || !strings.Contains(res.Body.String(), `"manual"`) {
		t.Errorf("list = %s", res.Body)
	}
	var other struct {
		Suppressions []suppressionView `json:"suppressions"`
	}
	res = r.do(r.ta, "GET", "/api/email/suppressions", "")
	_ = json.Unmarshal(res.Body.Bytes(), &other)
	if len(other.Suppressions) != 0 {
		t.Errorf("tenant A sees B's suppressions: %s", res.Body)
	}
	if res := r.do(r.ta, "DELETE", "/api/email/suppressions/"+url.PathEscape("left.company@example.com"), ""); res.Code != 404 {
		t.Errorf("tenant A lifts B's suppression: %d", res.Code)
	}
	// the UI sends the address fully encoded (%40 for @, %2B for +)
	res = r.do(r.admin, "POST", "/api/email/suppressions", `{"address":"Plus+Tag@Example.com"}`)
	mustCode(t, "add a plus address", res, 200)
	res = r.do(r.admin, "DELETE", "/api/email/suppressions/Plus%2BTag%40Example.com", "")
	mustCode(t, "lift a plus address", res, 200)
	if strings.Contains(res.Body.String(), "plus+tag") {
		t.Errorf("still listed: %s", res.Body)
	}
	res = r.do(r.admin, "DELETE", "/api/email/suppressions/"+url.PathEscape("LEFT.company@example.com"), "")
	mustCode(t, "lift", res, 200)
	if strings.Contains(res.Body.String(), "left.company") {
		t.Errorf("still listed: %s", res.Body)
	}
	if res := r.do(r.admin, "DELETE", "/api/email/suppressions/"+url.PathEscape("left.company@example.com"), ""); res.Code != 404 {
		t.Errorf("second lift: %d", res.Code)
	}

	// a delivery status report
	dsn := strings.Join([]string{"Content-Type: message/delivery-status", "", "Reporting-MTA: dns; relay.example", "",
		"Final-Recipient: rfc822; nobody@example.com", "Action: failed", "Status: 5.1.1", ""}, "\r\n")
	if res := r.do(r.viewer, "POST", "/api/email/dsn", dsn); res.Code != 403 {
		t.Errorf("viewer DSN: %d", res.Code)
	}
	res = r.do(r.admin, "POST", "/api/email/dsn", dsn)
	mustCode(t, "DSN", res, 200)
	if !strings.Contains(res.Body.String(), `"outcome":"not_matched"`) {
		t.Errorf("DSN result = %s", res.Body)
	}
	// issue #513: the real RFC 3464 media types are accepted, and text/plain (CORS-safelisted) is not
	for ct, want := range map[string]int{"multipart/report; report-type=delivery-status; boundary=b": 200, "message/delivery-status": 200,
		"message/rfc822": 200, "text/plain": 415, "text/csv": 415} {
		req := httptest.NewRequest("POST", "/api/email/dsn", strings.NewReader(dsn))
		req.Header.Set("Content-Type", ct)
		r.admin.Apply(req)
		if res := serve(r.h, req); res.Code != want {
			t.Errorf("DSN as %s: %d %s, want %d", ct, res.Code, res.Body, want)
		}
	}
	if res := r.do(r.admin, "POST", "/api/email/dsn", "this is not a report"); res.Code != 422 {
		t.Errorf("garbage DSN: %d %s", res.Code, res.Body)
	}
	if res := r.do(r.admin, "POST", "/api/email/dsn", strings.Repeat("a", notify.MaxDSNBytes+10)); res.Code != 413 && res.Code != 422 {
		t.Errorf("huge DSN: %d", res.Code)
	}
	if aud := r.do(r.auditor, "GET", "/api/audit", ""); !strings.Contains(aud.Body.String(), "email.suppression.add") || !strings.Contains(aud.Body.String(), "email.dsn") {
		t.Errorf("audit: %.300s", aud.Body)
	}
}

// "Send again" is on offer for a deferred, failed or bounced message and for one skipped because its address was
// suppressed; a message the relay refused stays final.
func TestEmailRetryableFlag(t *testing.T) {
	r := newNotifyRig(t, nil)
	now := storetest.Now
	mk := func(key, status, delivery string) string {
		var id string
		if err := r.f.DB.InTenant(t.Context(), r.f.B.ID, func(tx *store.TenantTx) error {
			email := "someone@b.example"
			n := &store.Notification{ID: "n-" + key, Kind: "request.approval_needed", Subject: "s", Body: "b", DedupeKey: key, InApp: true, CreatedAt: now,
				Delivery: delivery, Email: &email}
			if _, err := tx.InsertNotification(n); err != nil {
				return err
			}
			m := &store.EmailMessage{ID: "m-" + key, NotificationID: n.ID, Kind: n.Kind, Recipient: email, Subject: "s", CreatedAt: now}
			if err := tx.EnsureEmailMessage(m); err != nil {
				return err
			}
			m.Status, m.UpdatedAt = status, now
			id = m.ID
			return tx.SaveEmailMessage(m)
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	for _, tc := range []struct {
		key, status, delivery string
		want                  bool
	}{
		{"a", store.EmailDeferred, store.DeliveryPending, true},
		{"b", store.EmailFailed, store.DeliveryDead, true},
		{"c", store.EmailBounced, store.DeliverySent, true},
		{"d", store.EmailRejected, store.DeliverySkipped, true},
		{"e", store.EmailRejected, store.DeliveryDead, false},
		{"f", store.EmailAccepted, store.DeliverySent, false},
	} {
		id := mk(tc.key, tc.status, tc.delivery)
		var v emailView
		res := r.do(r.auditor, "GET", "/api/email/messages/"+id, "")
		if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil || res.Code != 200 || v.Retryable != tc.want {
			t.Errorf("%s/%s: retryable = %v (%d %s), want %v", tc.status, tc.delivery, v.Retryable, res.Code, res.Body, tc.want)
		}
	}
	// a bounced message is sent again through the API, and a suppressed address blocks it
	id := mk("g", store.EmailBounced, store.DeliverySent)
	mustCode(t, "suppress", r.do(r.admin, "POST", "/api/email/suppressions", `{"address":"someone@b.example"}`), 200)
	if res := r.do(r.admin, "POST", "/api/email/messages/"+id+"/retry", `{}`); res.Code != 409 || !strings.Contains(res.Body.String(), "suppressed") {
		t.Errorf("retry while suppressed: %d %s", res.Code, res.Body)
	}
	mustCode(t, "lift", r.do(r.admin, "DELETE", "/api/email/suppressions/someone@b.example", ""), 200)
	res := r.do(r.admin, "POST", "/api/email/messages/"+id+"/retry", `{}`)
	mustCode(t, "retry", res, 200)
	var v emailView
	if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil || v.Status != store.EmailQueued {
		t.Errorf("after retry: %s", res.Body)
	}
}
