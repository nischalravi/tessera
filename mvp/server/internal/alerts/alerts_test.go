package alerts_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

func ev(action, outcome string, detail string) *store.AuditEvent {
	actor := "Ivan"
	return &store.AuditEvent{Action: action, Outcome: outcome, ActorType: "user", ActorDisplay: &actor, Detail: json.RawMessage(detail)}
}

func TestRuleMatching(t *testing.T) {
	cases := []struct {
		rule  string
		e     *store.AuditEvent
		match bool
		key   string
	}{
		{"break_glass_used", ev("auth.break_glass.used", "success", `{}`), true, "Ivan"},
		{"break_glass_used", ev("breakglass.action", "success", `{}`), true, "Ivan"},
		{"break_glass_used", ev("auth.login.success", "success", `{}`), false, ""},
		{"admin_role_granted", ev("auth.role.granted", "success", `{"role":"tenant_admin","user":"pat@x"}`), true, "pat@x/tenant_admin"},
		{"admin_role_granted", ev("auth.role.granted", "success", `{"role":"viewer","user":"pat@x"}`), false, ""},
		{"admin_role_granted", ev("auth.role.granted", "failure", `{"role":"tenant_admin"}`), false, ""},
		{"admin_role_granted", ev("admin.change.applied", "success", `{"kind":"role.grant","target_role":"tenant_admin","user":"o@x"}`), true, "o@x/tenant_admin"},
		{"admin_role_granted", ev("admin.change.applied", "success", `{"kind":"idp.update"}`), false, ""},
		{"mfa_bypass", ev("auth.mfa.bypassed", "success", `{"email":"v@x"}`), true, "v@x"},
		{"signin_failures", ev("auth.login.failure", "failure", `{"email":"a@x"}`), true, "a@x"},
		{"signin_failures", ev("auth.login.failure", "failure", `{}`), true, "unknown"},
		{"provisioning_failed", ev("connectors.sync", "error", `{}`), true, "connectors.sync"},
		{"provisioning_failed", ev("connectors.sync", "success", `{}`), false, ""},
		{"provisioning_failed", ev("job.failed", "success", `{}`), true, "job.failed"},
		{"provisioning_failed", ev("jml.leaver", "failure", `{}`), true, "jml.leaver"},
		{"provisioning_failed", ev("grant.revoke", "failure", `{}`), false, ""},
		{"access_drift", ev("drift.remediate", "success", `{"drift_id":"d1","class":"rogue","system":"okta","action":"owner_task"}`), true, "d1"},
		{"access_drift", ev("drift.remediate", "failure", `{"drift_id":"d1"}`), false, ""},
		{"oauth_app_change", ev("oauthapps.change_detected", "success", `{"change_id":"c1","summary":"New secret added to Klue"}`), true, "c1"},
		{"oauth_app_change", ev("oauthapps.change_detected", "failure", `{"change_id":"c1"}`), false, ""},
		{"oauth_app_change", ev("oauthapps.synced", "success", `{"change_id":"c1"}`), false, ""},
		{"access_drift", ev("drift.accept", "success", `{"drift_id":"d1"}`), false, ""},
	}
	for _, tc := range cases {
		r := alerts.RuleByID(tc.rule)
		h, ok := r.Match(tc.e)
		if ok != tc.match || (ok && h.Key != tc.key) {
			t.Errorf("%s on %s: match=%v key=%q, want %v %q", tc.rule, tc.e.Action, ok, h.Key, tc.match, tc.key)
		}
	}
	for _, r := range alerts.Rules {
		if (r.Kind == "event") != (r.Match != nil) || (r.Kind == "detection" || r.Kind == "scheduled") != (r.Detect != nil) || alerts.SeverityRank(r.Severity) < 0 {
			t.Errorf("rule %s is malformed", r.ID)
		}
	}
}

type world struct {
	st     *testkit.DB
	now    time.Time
	sealer *seal.Sealer
}

func newWorld(t *testing.T) *world {
	t.Helper()
	st, _ := testkit.Tiny(t)
	s, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	w := &world{st: st, now: testkit.Now, sealer: s}
	w.eval(t, false) // the first run only sets the cursor
	return w
}

func (w *world) write(t *testing.T, fn func(*store.TenantTx) error) {
	t.Helper()
	ctx := audit.WithSystemActor(context.Background(), "test")
	if err := w.st.InTenant(ctx, w.st.Tenant, fn); err != nil {
		t.Fatal(err)
	}
}

func (w *world) record(t *testing.T, action, outcome, detail string, at time.Time) {
	t.Helper()
	var d map[string]any
	_ = json.Unmarshal([]byte(detail), &d)
	w.write(t, func(tx *store.TenantTx) error {
		_, err := audit.Record(context.Background(), tx, action, d, audit.At(at), audit.Outcome(outcome))
		return err
	})
}

func (w *world) eval(t *testing.T, detect bool) alerts.Result {
	t.Helper()
	var res alerts.Result
	w.write(t, func(tx *store.TenantTx) error {
		var err error
		res, err = alerts.Evaluate(tx, w.now, detect)
		return err
	})
	return res
}

func (w *world) alerts(t *testing.T, status string) []*store.Alert {
	t.Helper()
	return testkit.Get(t, w.st, func(tx *store.TenantTx) ([]*store.Alert, error) { return tx.Alerts(store.AlertFilter{Status: status}) })
}

func (w *world) audited(t *testing.T, action string) int {
	t.Helper()
	evs := testkit.Get(t, w.st, func(tx *store.TenantTx) ([]*store.AuditEvent, error) {
		return tx.AuditEvents(store.AuditFilter{Action: action})
	})
	return len(evs)
}

func TestHistoryDoesNotAlert(t *testing.T) {
	st, _ := testkit.Tiny(t)
	w := &world{st: st, now: testkit.Now}
	w.record(t, "auth.break_glass.used", "success", `{}`, w.now) // before the engine ever ran
	if res := w.eval(t, false); res.Raised != 0 {
		t.Fatalf("history raised %d", res.Raised)
	}
	w.record(t, "auth.break_glass.used", "success", `{}`, w.now)
	if res := w.eval(t, false); res.Raised != 1 {
		t.Fatalf("new event raised %d", res.Raised)
	}
}

func TestDedupAndRaiseAgainAfterResolve(t *testing.T) {
	w := newWorld(t)
	w.write(t, func(tx *store.TenantTx) error {
		_, _, err := alerts.CreateChannel(tx, w.sealer, alerts.ChannelSpec{Name: "SecOps", Kind: "email", Target: "secops@example.com",
			MinSeverity: "high", Enabled: true}, true, alerts.Actor{Display: "test"}, w.now)
		if err != nil {
			return err
		}
		// min_severity critical: this channel takes critical alerts only
		_, _, err = alerts.CreateChannel(tx, w.sealer, alerts.ChannelSpec{Name: "Critical only", Kind: "email", Target: "c@example.com",
			MinSeverity: "critical", Enabled: true}, true, alerts.Actor{Display: "test"}, w.now)
		return err
	})
	w.record(t, "auth.break_glass.used", "success", `{}`, w.now)
	w.record(t, "auth.break_glass.used", "success", `{}`, w.now.Add(time.Minute))
	res := w.eval(t, false)
	if res.Raised != 1 || res.Bumped != 1 {
		t.Fatalf("result %+v, want 1 raised and 1 bumped", res)
	}
	as := w.alerts(t, "live")
	if len(as) != 1 || as[0].Count != 2 || as[0].Severity != "critical" || as[0].LastEventSeq == nil {
		t.Fatalf("alerts = %+v", as)
	}
	ds := testkit.Get(t, w.st, func(tx *store.TenantTx) ([]*store.AlertDelivery, error) { return tx.AlertDeliveries(as[0].ID) })
	if len(ds) != 2 {
		t.Fatalf("deliveries = %d, want 2 (both channels take critical)", len(ds))
	}
	if n := w.audited(t, "alert.raised"); n != 1 {
		t.Fatalf("alert.raised events = %d", n)
	}
	// the engine's own events never feed back
	if res := w.eval(t, false); res.Raised+res.Bumped != 0 {
		t.Fatalf("re-evaluation %+v", res)
	}
	w.write(t, func(tx *store.TenantTx) error {
		_, err := alerts.Resolve(tx, as[0].ID, "drill", alerts.Actor{Display: "test"}, w.now)
		return err
	})
	w.record(t, "auth.break_glass.used", "success", `{}`, w.now.Add(2*time.Minute))
	if res := w.eval(t, false); res.Raised != 1 {
		t.Fatalf("after resolve: %+v", res)
	}
	if n := len(w.alerts(t, "")); n != 2 {
		t.Fatalf("alerts total = %d", n)
	}
}

func TestThresholdAndWindow(t *testing.T) {
	w := newWorld(t)
	// four failures long ago, then four recent: never five in 15 minutes
	for i := range 4 {
		w.record(t, "auth.login.failure", "failure", `{"email":"bob@x"}`, w.now.Add(-2*time.Hour+time.Duration(i)*time.Minute))
	}
	for i := range 4 {
		w.record(t, "auth.login.failure", "failure", `{"email":"bob@x"}`, w.now.Add(time.Duration(i)*time.Minute))
	}
	w.record(t, "auth.login.failure", "failure", `{"email":"carol@x"}`, w.now.Add(4*time.Minute))
	if res := w.eval(t, false); res.Raised != 0 {
		t.Fatalf("raised %d below the threshold", res.Raised)
	}
	w.record(t, "auth.login.failure", "failure", `{"email":"bob@x"}`, w.now.Add(5*time.Minute))
	if res := w.eval(t, false); res.Raised != 1 {
		t.Fatalf("raised %d at the threshold", res.Raised)
	}
	as := w.alerts(t, "live")
	if len(as) != 1 || as[0].DedupKey != "bob@x" || as[0].Count != 5 {
		t.Fatalf("alerts %+v", as)
	}
	// a tenant can lower the threshold and switch rules off
	w.write(t, func(tx *store.TenantTx) error {
		if err := alerts.SetRule(tx, "signin_failures", alerts.RuleSpec{Enabled: true, Severity: "high", Threshold: 2, WindowMinutes: 15},
			alerts.Actor{Display: "test"}, w.now); err != nil {
			return err
		}
		return alerts.SetRule(tx, "break_glass_used", alerts.RuleSpec{Enabled: false, Severity: "critical", Threshold: 1, WindowMinutes: 60},
			alerts.Actor{Display: "test"}, w.now)
	})
	w.record(t, "auth.login.failure", "failure", `{"email":"carol@x"}`, w.now.Add(6*time.Minute))
	w.record(t, "auth.break_glass.used", "success", `{}`, w.now.Add(6*time.Minute))
	if res := w.eval(t, false); res.Raised != 1 {
		t.Fatalf("after settings: %+v", res)
	}
	for _, a := range w.alerts(t, "live") {
		if a.RuleID == "break_glass_used" {
			t.Error("a disabled rule raised")
		}
		if a.DedupKey == "carol@x" && a.Severity != "high" {
			t.Errorf("severity override not applied: %s", a.Severity)
		}
	}
	w.write(t, func(tx *store.TenantTx) error {
		var e *alerts.Error
		err := alerts.SetRule(tx, "signin_failures", alerts.RuleSpec{Enabled: true, Severity: "urgent", Threshold: 2, WindowMinutes: 15}, alerts.Actor{}, w.now)
		if !errors.As(err, &e) || e.Code != "invalid_severity" {
			t.Errorf("bad severity: %v", err)
		}
		if err := alerts.SetRule(tx, "nope", alerts.RuleSpec{}, alerts.Actor{}, w.now); !errors.As(err, &e) || e.Code != "rule_not_found" {
			t.Errorf("unknown rule: %v", err)
		}
		return nil
	})
}

func TestDetectionRaisesAndResolves(t *testing.T) {
	st := testkit.Demo(t)
	w := &world{st: st, now: testkit.Now}
	res := w.eval(t, true)
	if res.Raised == 0 {
		t.Fatal("no orphaned-privileged alert on the demo data (old-migration-token has no owner)")
	}
	var found bool
	for _, a := range w.alerts(t, "live") {
		if a.RuleID == "orphaned_privileged" && strings.Contains(a.Title, "old-migration-token") {
			found = true
		}
	}
	if !found {
		t.Fatalf("alerts: %+v", w.alerts(t, "live"))
	}
	if res := w.eval(t, true); res.Raised != 0 {
		t.Fatalf("second detection raised %d (dedup)", res.Raised)
	}
	// switching the rule off resolves its alerts
	w.write(t, func(tx *store.TenantTx) error {
		return alerts.SetRule(tx, "orphaned_privileged", alerts.RuleSpec{Enabled: false, Severity: "high", Threshold: 1, WindowMinutes: 60},
			alerts.Actor{Display: "test"}, w.now)
	})
	if res := w.eval(t, true); res.Resolved == 0 {
		t.Fatalf("nothing resolved: %+v", res)
	}
	for _, a := range w.alerts(t, "live") {
		if a.RuleID == "orphaned_privileged" {
			t.Errorf("still live: %s", a.Title)
		}
	}
}

// --------------------------------------------------------------- delivery

type recordingMailer struct {
	mu   sync.Mutex
	sent []alerts.Message
	fail error
}

func (m *recordingMailer) Send(_ context.Context, msg alerts.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	m.sent = append(m.sent, msg)
	return nil
}

func devClient(t *testing.T) *http.Client {
	t.Helper()
	c, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (w *world) service(t *testing.T, client *http.Client, mail alerts.Mailer) *alerts.Service {
	return &alerts.Service{DB: w.st.DB, Sealer: w.sealer, HTTP: client, Mail: mail, Clock: func() time.Time { return w.now },
		PublicURL: "https://tessera.example"}
}

func (w *world) deliveries(t *testing.T) []*store.AlertDelivery {
	t.Helper()
	var out []*store.AlertDelivery
	for _, a := range w.alerts(t, "") {
		out = append(out, testkit.Get(t, w.st, func(tx *store.TenantTx) ([]*store.AlertDelivery, error) { return tx.AlertDeliveries(a.ID) })...)
	}
	return out
}

func TestWebhookSignedAndRetried(t *testing.T) {
	w := newWorld(t)
	var mu sync.Mutex
	var bodies [][]byte
	var sigs []string
	fails := 1
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		bodies, sigs = append(bodies, b), append(sigs, r.Header.Get("X-Tessera-Signature"))
		if fails > 0 {
			fails--
			rw.WriteHeader(http.StatusBadGateway)
			return
		}
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	var secret string
	w.write(t, func(tx *store.TenantTx) error {
		var err error
		_, secret, err = alerts.CreateChannel(tx, w.sealer, alerts.ChannelSpec{Name: "Slack", Kind: "webhook", Target: srv.URL + "/hook",
			MinSeverity: "low", Enabled: true}, true, alerts.Actor{Display: "test"}, w.now)
		return err
	})
	if !strings.HasPrefix(secret, "whsec_") {
		t.Fatalf("secret %q", secret)
	}
	w.record(t, "auth.break_glass.used", "success", `{}`, w.now)
	w.eval(t, false)
	svc := w.service(t, devClient(t), nil)
	ctx := context.Background()
	if err := svc.DeliverTenant(ctx, w.st.Tenant, "tiny"); err != nil {
		t.Fatal(err)
	}
	d := w.deliveries(t)[0]
	if d.Status != "pending" || d.Attempts != 1 || d.LastError == nil || !strings.Contains(*d.LastError, "502") ||
		!d.NextAttemptAt.Equal(w.now.Add(alerts.Backoff[0])) {
		t.Fatalf("after a 502: %+v", d)
	}
	// not due yet: nothing is sent
	if err := svc.DeliverTenant(ctx, w.st.Tenant, "tiny"); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 1 {
		t.Fatalf("sent %d times before the retry was due", len(bodies))
	}
	w.now = w.now.Add(alerts.Backoff[0])
	if err := svc.DeliverTenant(ctx, w.st.Tenant, "tiny"); err != nil {
		t.Fatal(err)
	}
	d = w.deliveries(t)[0]
	if d.Status != "sent" || d.Attempts != 2 || d.SentAt == nil {
		t.Fatalf("after the retry: %+v", d)
	}
	if n := w.audited(t, "alert.delivered"); n != 1 {
		t.Errorf("alert.delivered events = %d", n)
	}
	// the signature verifies with the secret shown at creation
	var ts string
	for _, part := range strings.Split(sigs[1], ",") {
		if v, ok := strings.CutPrefix(part, "t="); ok {
			ts = v
		}
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(bodies[1])
	if want := "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil)); sigs[1] != want {
		t.Errorf("signature %q, want %q", sigs[1], want)
	}
	var p alerts.WebhookPayload
	if err := json.Unmarshal(bodies[1], &p); err != nil || p.Alert.Rule != "break_glass_used" || !strings.Contains(p.Text, "CRITICAL") ||
		!strings.HasPrefix(p.Alert.URL, "https://tessera.example/alerts?selected=") {
		t.Errorf("payload %s (%v)", bodies[1], err)
	}
}

func TestDeliveryGivesUp(t *testing.T) {
	w := newWorld(t)
	mail := &recordingMailer{fail: errors.New("relay down")}
	w.write(t, func(tx *store.TenantTx) error {
		_, _, err := alerts.CreateChannel(tx, w.sealer, alerts.ChannelSpec{Name: "Ops", Kind: "email", Target: "ops@example.com, sec@example.com",
			MinSeverity: "low", Enabled: true}, true, alerts.Actor{Display: "test"}, w.now)
		return err
	})
	w.record(t, "auth.break_glass.used", "success", `{}`, w.now)
	w.eval(t, false)
	svc := w.service(t, nil, mail)
	for i := 0; i < alerts.MaxAttempts; i++ {
		if err := svc.DeliverTenant(context.Background(), w.st.Tenant, "tiny"); err != nil {
			t.Fatal(err)
		}
		w.now = w.now.Add(5 * time.Hour)
	}
	d := w.deliveries(t)[0]
	if d.Status != "failed" || d.Attempts != alerts.MaxAttempts || d.LastError == nil || !strings.Contains(*d.LastError, "relay down") {
		t.Fatalf("delivery %+v", d)
	}
	if n := w.audited(t, "alert.delivery_failed"); n != 1 {
		t.Errorf("alert.delivery_failed events = %d", n)
	}
	// a working relay gets both recipients and a subject naming the tenant
	mail.fail = nil
	w.record(t, "auth.mfa.bypassed", "success", `{"email":"v@x"}`, w.now)
	w.eval(t, false)
	if err := svc.DeliverTenant(context.Background(), w.st.Tenant, "tiny"); err != nil {
		t.Fatal(err)
	}
	if len(mail.sent) != 1 || len(mail.sent[0].To) != 2 || !strings.Contains(mail.sent[0].Subject, "[Tessera tiny] HIGH") {
		t.Fatalf("sent %+v", mail.sent)
	}
}

// TestWebhookSSRFGuard: the delivery client refuses private and metadata
// addresses, and channel validation refuses plain http.
func TestWebhookSSRFGuard(t *testing.T) {
	w := newWorld(t)
	prod, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Prod})
	if err != nil {
		t.Fatal(err)
	}
	var ch *store.AlertChannel
	w.write(t, func(tx *store.TenantTx) error {
		var err error
		ch, _, err = alerts.CreateChannel(tx, w.sealer, alerts.ChannelSpec{Name: "Meta", Kind: "webhook", Target: "https://169.254.169.254/latest",
			MinSeverity: "low", Enabled: true}, false, alerts.Actor{Display: "test"}, w.now)
		return err
	})
	svc := w.service(t, prod, nil)
	if err := svc.TestChannel(context.Background(), w.st.Tenant, "tiny", ch); err == nil || !strings.Contains(err.Error(), "webhook") {
		t.Fatalf("metadata address: %v", err)
	}
	w.write(t, func(tx *store.TenantTx) error {
		for _, target := range []string{"http://hooks.example.com/x", "https://user:pw@hooks.example.com/x", "ftp://x", "not a url"} {
			var e *alerts.Error
			_, _, err := alerts.CreateChannel(tx, w.sealer, alerts.ChannelSpec{Name: "x", Kind: "webhook", Target: target,
				MinSeverity: "low", Enabled: true}, false, alerts.Actor{Display: "test"}, w.now)
			if !errors.As(err, &e) || e.Code != "invalid_target" {
				t.Errorf("%s: %v", target, err)
			}
		}
		var e *alerts.Error
		if _, _, err := alerts.CreateChannel(tx, w.sealer, alerts.ChannelSpec{Name: "x", Kind: "email", Target: "not-an-address",
			MinSeverity: "low", Enabled: true}, false, alerts.Actor{}, w.now); !errors.As(err, &e) || e.Code != "invalid_target" {
			t.Errorf("bad email: %v", err)
		}
		return nil
	})
}

func TestSecretSealedAndBound(t *testing.T) {
	w := newWorld(t)
	var ch *store.AlertChannel
	var secret string
	w.write(t, func(tx *store.TenantTx) error {
		var err error
		ch, secret, err = alerts.CreateChannel(tx, w.sealer, alerts.ChannelSpec{Name: "Teams", Kind: "webhook", Target: "https://hooks.example.com/x",
			MinSeverity: "low", Enabled: true}, false, alerts.Actor{Display: "test"}, w.now)
		return err
	})
	if strings.Contains(string(ch.SecretSealed), secret) {
		t.Fatal("secret stored in clear")
	}
	if _, err := w.sealer.Open(ch.SecretSealed, alerts.SecretAAD(w.st.Tenant, "another-channel")); err == nil {
		t.Fatal("sealed secret opens under another row's AAD")
	}
	got, err := w.sealer.Open(ch.SecretSealed, alerts.SecretAAD(w.st.Tenant, ch.ID))
	if err != nil || string(got) != secret {
		t.Fatalf("open: %q %v", got, err)
	}
	// rotation issues a new secret; an update without it keeps the old one
	w.write(t, func(tx *store.TenantTx) error {
		c2, s2, err := alerts.UpdateChannel(tx, w.sealer, ch.ID, alerts.ChannelSpec{Name: "Teams", Target: ch.Target, MinSeverity: "high",
			Enabled: true}, false, alerts.Actor{Display: "test"}, w.now)
		if err != nil || s2 != "" || string(c2.SecretSealed) != string(ch.SecretSealed) {
			t.Errorf("plain update: %q %v", s2, err)
		}
		_, s3, err := alerts.UpdateChannel(tx, w.sealer, ch.ID, alerts.ChannelSpec{Name: "Teams", Target: ch.Target, MinSeverity: "high",
			Enabled: true, RotateSecret: true}, false, alerts.Actor{Display: "test"}, w.now)
		if err != nil || s3 == "" || s3 == secret {
			t.Errorf("rotate: %q %v", s3, err)
		}
		return nil
	})
	// the audit trail names the host only
	evs := testkit.Get(t, w.st, func(tx *store.TenantTx) ([]*store.AuditEvent, error) {
		return tx.AuditEvents(store.AuditFilter{Action: "alert.channel.created"})
	})
	if len(evs) != 1 || strings.Contains(string(evs[0].Detail), "/x") || strings.Contains(string(evs[0].Detail), "whsec_") {
		t.Fatalf("audit detail %s", evs[0].Detail)
	}
}

func TestTriage(t *testing.T) {
	w := newWorld(t)
	var userID string
	w.write(t, func(tx *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "Olu", CreatedAt: w.now}
		if err := tx.InsertPlatformUser(u); err != nil {
			return err
		}
		userID = u.ID.String()
		return nil
	})
	w.record(t, "auth.break_glass.used", "success", `{}`, w.now)
	w.eval(t, false)
	id := w.alerts(t, "live")[0].ID
	by := alerts.Actor{UserID: userID, Display: "Olu"}
	w.write(t, func(tx *store.TenantTx) error {
		a, err := alerts.Acknowledge(tx, id, by, w.now)
		if err != nil || a.Status != "acknowledged" || a.AssigneeUserID == nil || *a.AssigneeUserID != userID {
			t.Errorf("ack: %+v %v", a, err)
		}
		var e *alerts.Error
		if _, err := alerts.Acknowledge(tx, id, by, w.now); !errors.As(err, &e) || e.Code != "not_open" {
			t.Errorf("second ack: %v", err)
		}
		bad := "00000000-0000-4000-8000-000000000999"
		if _, err := alerts.Assign(tx, id, &bad, by, w.now); !errors.As(err, &e) || e.Code != "user_not_found" {
			t.Errorf("assign unknown: %v", err)
		}
		if a, err := alerts.Assign(tx, id, nil, by, w.now); err != nil || a.AssigneeUserID != nil {
			t.Errorf("unassign: %+v %v", a, err)
		}
		if a, err := alerts.Resolve(tx, id, "false positive: drill", by, w.now); err != nil || a.Status != "resolved" || *a.Resolution != "false positive: drill" {
			t.Errorf("resolve: %+v %v", a, err)
		}
		if _, err := alerts.Resolve(tx, id, "", by, w.now); !errors.As(err, &e) || e.Code != "already_resolved" {
			t.Errorf("second resolve: %v", err)
		}
		if _, err := alerts.Acknowledge(tx, "nope", by, w.now); !errors.As(err, &e) || e.Code != "alert_not_found" {
			t.Errorf("unknown alert: %v", err)
		}
		return nil
	})
	for _, a := range []string{"alert.acknowledged", "alert.assigned", "alert.resolved"} {
		if w.audited(t, a) != 1 {
			t.Errorf("%s not audited once", a)
		}
	}
}

// ------------------------------------------------------------------- mail

func TestNewMailer(t *testing.T) {
	if m, err := alerts.NewMailer("log", nil); err != nil || m == nil {
		t.Fatalf("log: %v", err)
	}
	m, err := alerts.NewMailer("smtp://u:p@relay.example.com?from=alerts@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := m.(*alerts.SMTPMailer); s.Port != "587" || s.Username != "u" || s.ImplicitTLS {
		t.Errorf("smtp: %+v", s)
	}
	if s, _ := alerts.NewMailer("smtps://relay.example.com?from=a@example.com", nil); s.(*alerts.SMTPMailer).Port != "465" {
		t.Error("smtps default port")
	}
	for _, bad := range []string{"smtp://relay.example.com", "http://x?from=a@example.com", "smtp://u:secret@?from=a@example.com"} {
		_, err := alerts.NewMailer(bad, nil)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

// TestSMTPRequiresStartTLS: a relay that does not offer STARTTLS is refused
// before any credential or message is sent.
func TestSMTPRequiresStartTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, "220 fake ESMTP\r\n")
		buf := make([]byte, 4096)
		var seen strings.Builder
		for {
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			seen.Write(buf[:n])
			line := string(buf[:n])
			switch {
			case strings.HasPrefix(line, "EHLO"):
				_, _ = io.WriteString(c, "250-fake\r\n250 AUTH PLAIN\r\n")
			case strings.HasPrefix(line, "QUIT"):
				_, _ = io.WriteString(c, "221 bye\r\n")
			default:
				_, _ = io.WriteString(c, "250 ok\r\n")
			}
		}
		got <- seen.String()
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	m := &alerts.SMTPMailer{Host: host, Port: port, From: "a@example.com", Username: "u", Password: "p"}
	err = m.Send(context.Background(), alerts.Message{To: []string{"b@example.com"}, Subject: "s", Text: "t"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v", err)
	}
	ln.Close()
	select {
	case seen := <-got:
		if strings.Contains(seen, "AUTH") || strings.Contains(seen, "MAIL FROM") {
			t.Fatalf("sent before TLS: %q", seen)
		}
	case <-time.After(5 * time.Second):
	}
}
