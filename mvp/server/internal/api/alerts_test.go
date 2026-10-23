package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// seedAlert raises a break-glass alert in tenant t and returns its id.
func seedAlert(t *testing.T, db *store.DB, tn tenancy.ID, tag string) string {
	t.Helper()
	id := "alert-" + tag + "-" + fmt.Sprint(len(tag))
	err := db.InTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		return tx.InsertAlert(&store.Alert{ID: id, RuleID: "break_glass_used", DedupKey: "k-" + tag, Severity: "critical",
			Title: "Break-glass access used " + tag, Detail: json.RawMessage(`{}`), Count: 1, FirstSeenAt: storetest.Now,
			LastSeenAt: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func alertsDo(h http.Handler, l authtest.Login, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	l.Apply(req)
	return serve(h, req)
}

func alertsServer(t *testing.T, f *storetest.Fixture) http.Handler {
	t.Helper()
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	srv := newIsolationServer(f)
	srv.cfg.Alerts = &alerts.Service{DB: f.DB, Sealer: sealer, Mail: alerts.LogMailer{}}
	return srv.Handler()
}

func TestAlertsAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := alertsServer(t, f)
	now := storetest.Now
	op := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, now)
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	id := seedAlert(t, f.DB, f.B.ID, "b")

	if rec := alertsDo(h, viewer, "GET", "/api/alerts", ""); rec.Code != 403 {
		t.Errorf("viewer lists alerts: %d", rec.Code)
	}
	rec := alertsDo(h, op, "GET", "/api/alerts?status=live", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"rule_name":"Break-glass access used"`) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if rec := alertsDo(h, op, "GET", "/api/alerts?status=bogus", ""); rec.Code != 422 {
		t.Errorf("bad status filter: %d", rec.Code)
	}
	if rec := alertsDo(h, op, "GET", "/api/alerts/summary", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"critical":1`) {
		t.Errorf("summary: %d %s", rec.Code, rec.Body)
	}
	rec = alertsDo(h, op, "POST", "/api/alerts/"+id+"/acknowledge", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"acknowledged"`) || !strings.Contains(rec.Body.String(), `"assignee":{"id":`) {
		t.Fatalf("ack: %d %s", rec.Code, rec.Body)
	}
	if rec := alertsDo(h, op, "POST", "/api/alerts/"+id+"/acknowledge", ""); rec.Code != 409 {
		t.Errorf("second ack: %d", rec.Code)
	}
	rec = alertsDo(h, op, "POST", "/api/alerts/"+id+"/resolve", `{"note":"drill"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"resolution":"drill"`) {
		t.Fatalf("resolve: %d %s", rec.Code, rec.Body)
	}
	if rec := alertsDo(h, op, "GET", "/api/alerts/"+id, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"deliveries":[]`) {
		t.Errorf("get: %d %s", rec.Code, rec.Body)
	}

	// rules: anyone with alerts.read lists; only tenant admins change them
	if rec := alertsDo(h, op, "GET", "/api/alerts/rules", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"id":"signin_failures"`) {
		t.Errorf("rules: %d %s", rec.Code, rec.Body)
	}
	rule := `{"enabled":true,"severity":"high","threshold":3,"window_minutes":10}`
	if rec := alertsDo(h, op, "PUT", "/api/alerts/rules/signin_failures", rule); rec.Code != 403 {
		t.Errorf("operator changes a rule: %d", rec.Code)
	}
	if rec := alertsDo(h, admin, "PUT", "/api/alerts/rules/signin_failures", rule); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"customized":true`) {
		t.Errorf("admin changes a rule: %d %s", rec.Code, rec.Body)
	}
	if rec := alertsDo(h, admin, "PUT", "/api/alerts/rules/nope", rule); rec.Code != 404 {
		t.Errorf("unknown rule: %d", rec.Code)
	}

	// channels: tenant admins only; the webhook secret is shown once and the URL redacted
	if rec := alertsDo(h, op, "GET", "/api/alerts/channels", ""); rec.Code != 403 {
		t.Errorf("operator lists channels: %d", rec.Code)
	}
	hook := `{"name":"Slack #sec","kind":"webhook","target":"https://hooks.slack.com/services/T0/B0/abcdefSECRET","min_severity":"high"}`
	rec = alertsDo(h, admin, "POST", "/api/alerts/channels", hook)
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"secret":"whsec_`) || strings.Contains(rec.Body.String(), "abcdef") {
		t.Fatalf("create webhook: %d %s", rec.Code, rec.Body)
	}
	var ch channelView
	_ = json.Unmarshal(rec.Body.Bytes(), &ch)
	if ch.Target != "https://hooks.slack.com/…" { // no tail of the secret path (#333)
		t.Errorf("redacted target %q", ch.Target)
	}
	rec = alertsDo(h, admin, "GET", "/api/alerts/channels", "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "whsec_") || strings.Contains(rec.Body.String(), "abcdef") {
		t.Errorf("list channels leaks: %s", rec.Body)
	}
	if rec := alertsDo(h, admin, "POST", "/api/alerts/channels", `{"name":"x","kind":"webhook","target":"http://10.0.0.1/x"}`); rec.Code != 422 {
		t.Errorf("plain-http webhook: %d %s", rec.Code, rec.Body)
	}
	// an update without a target keeps it; the kind cannot change
	rec = alertsDo(h, admin, "PUT", "/api/alerts/channels/"+ch.ID, `{"name":"Slack #security","min_severity":"critical"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"min_severity":"critical"`) || strings.Contains(rec.Body.String(), `"secret"`) {
		t.Errorf("update: %d %s", rec.Code, rec.Body)
	}
	if rec := alertsDo(h, admin, "PUT", "/api/alerts/channels/"+ch.ID, `{"name":"x","kind":"email"}`); rec.Code != 422 {
		t.Errorf("kind change: %d", rec.Code)
	}
	rec = alertsDo(h, admin, "POST", "/api/alerts/channels", `{"name":"SecOps mail","kind":"email","target":"secops@b.example","min_severity":"low"}`)
	if rec.Code != 201 {
		t.Fatalf("create email: %d %s", rec.Code, rec.Body)
	}
	var mail channelView
	_ = json.Unmarshal(rec.Body.Bytes(), &mail)
	rec = alertsDo(h, admin, "POST", "/api/alerts/channels/"+mail.ID+"/test", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Errorf("test email channel: %d %s", rec.Code, rec.Body)
	}
	acts := map[string]int{}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{})
		for _, e := range evs {
			acts[e.Action]++
		}
		return err
	})
	for _, a := range []string{"alert.acknowledged", "alert.resolved", "alert.rule.updated", "alert.channel.created", "alert.channel.updated", "alert.channel.tested"} {
		if acts[a] == 0 {
			t.Errorf("%s not audited (%v)", a, acts)
		}
	}
}

// TestAlertsAPI_CrossTenant: as tenant B, tenant A's alerts and channels
// answer exactly like ids that do not exist, and nothing of A changes.
func TestAlertsAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := alertsServer(t, f)
	now := storetest.Now
	aAlert := seedAlert(t, f.DB, f.A.ID, "a")
	var aChan string
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
		c := &store.AlertChannel{ID: "chan-a", Name: "A mail", Kind: "email", Target: "a@a.example", MinSeverity: "low", Enabled: true,
			CreatedAt: now, UpdatedAt: now}
		aChan = c.ID
		return tx.InsertAlertChannel(c)
	}); err != nil {
		t.Fatal(err)
	}
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin, auth.RoleOperator}},
		authtest.Phr, now)
	before := storetest.Dump(t, f.DB, f.A.ID)
	cases := []struct{ method, path, missing, body string }{
		{"GET", "/api/alerts/" + aAlert, "/api/alerts/nope", ""},
		{"POST", "/api/alerts/" + aAlert + "/acknowledge", "/api/alerts/nope/acknowledge", ""},
		{"POST", "/api/alerts/" + aAlert + "/resolve", "/api/alerts/nope/resolve", `{"note":"x"}`},
		{"POST", "/api/alerts/" + aAlert + "/assign", "/api/alerts/nope/assign", `{"assignee_user_id":null}`},
		{"PUT", "/api/alerts/channels/" + aChan, "/api/alerts/channels/nope", `{"name":"x","target":"x@b.example"}`},
		{"POST", "/api/alerts/channels/" + aChan + "/test", "/api/alerts/channels/nope/test", ""},
	}
	for _, c := range cases {
		got := alertsDo(h, admin, c.method, c.path, c.body)
		want := alertsDo(h, admin, c.method, c.missing, c.body)
		if got.Code != want.Code || got.Code == 200 || got.Body.String() != want.Body.String() {
			t.Errorf("%s %s: %d %s; missing id: %d %s", c.method, c.path, got.Code, got.Body, want.Code, want.Body)
		}
	}
	// rules are per tenant: B's change does not touch A
	if rec := alertsDo(h, admin, "PUT", "/api/alerts/rules/access_drift", `{"enabled":false,"severity":"low","threshold":1,"window_minutes":5}`); rec.Code != 200 {
		t.Fatalf("B's rule change: %d %s", rec.Code, rec.Body)
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
}
