package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// ---------------------------------------------------------------- templates

func TestCheckTemplate(t *testing.T) {
	cases := []struct {
		name          string
		kind, subj, b string
		want          string
	}{
		{"subject and body", notify.KindApprovalNeeded, "Please decide: {{subject}}", "Hello,\n{{body}}\n{{link}}", ""},
		{"spaces in the braces", notify.KindApprovalNeeded, "{{ subject }}", "", ""},
		{"only a body", notify.KindReviewReminder, "", "{{body}} {{product}} {{recipient}}", ""},
		{"escalation", notify.KindApprovalEscalated, "Escalated", "x", ""},
		{"unknown kind", "no.such.kind", "s", "b", "unknown_kind"},
		{"a one-time secret kind has no template", notify.KindClaimCode, "s", "b", "unknown_kind"},
		{"the digest has none", notify.KindDigest, "s", "b", "unknown_kind"},
		{"both empty", notify.KindApprovalNeeded, "  ", "", "template_empty"},
		{"unknown placeholder", notify.KindApprovalNeeded, "{{secret}}", "b", "unknown_placeholder"},
		{"a placeholder with a path", notify.KindApprovalNeeded, "s", "{{user.password}}", "invalid_placeholder"},
		{"unbalanced braces", notify.KindApprovalNeeded, "s", "{{body", "invalid_placeholder"},
		{"a closing brace alone", notify.KindApprovalNeeded, "s", "body}}", "invalid_placeholder"},
		{"subject on two lines", notify.KindApprovalNeeded, "a\nBcc: x@y.example", "b", "invalid_subject"},
		{"subject too long", notify.KindApprovalNeeded, strings.Repeat("a", notify.MaxTemplateSubject+1), "b", "template_too_long"},
		{"body too long", notify.KindApprovalNeeded, "s", strings.Repeat("a", notify.MaxTemplateBody+1), "template_too_long"},
		{"control character", notify.KindApprovalNeeded, "s", "a\x00b", "invalid_text"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := code(notify.CheckTemplate(tc.kind, tc.subj, tc.b)); got != tc.want {
				t.Errorf("code = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRender(t *testing.T) {
	vars := map[string]string{"subject": "S", "body": "B", "link": "https://x/inbox", "product": "P", "recipient": "a@b.example"}
	for in, want := range map[string]string{
		"{{subject}}: {{body}}":        "S: B",
		"{{ link }} for {{recipient}}": "https://x/inbox for a@b.example",
		"{{unknown}} stays out":        " stays out",
		"{{{subject}}}":                "{S}",
		"no placeholders":              "no placeholders",
		"{{body}}{{body}}":             "BB",
	} {
		if got := notify.Render(in, vars); got != want {
			t.Errorf("Render(%q) = %q, want %q", in, got, want)
		}
	}
}

// A tenant's template changes the email of its kind, and only that kind.
func TestDispatchTemplateTwoKinds(t *testing.T) {
	w := newWorld(t)
	w.tx(func(c *store.TenantTx) error {
		return notify.SaveTemplate(c, notify.KindApprovalNeeded, "Action: {{subject}} ({{product}})", "Dear colleague,\n{{body}}\nGo: {{link}}", "admin", w.now)
	})
	w.emit(notify.KindApprovalNeeded, "k1", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	w.emit(notify.KindApprovalEscalated, "k2", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	mail := &notify.MemorySender{}
	if st := w.run(w.dispatcher(mail, &clock{t: w.now})); st.Sent != 2 {
		t.Fatalf("stats = %+v", st)
	}
	var tpl, plain notify.Email
	for _, e := range mail.Sent {
		if strings.Contains(e.Subject, "Action:") {
			tpl = e
		} else {
			plain = e
		}
	}
	if tpl.Subject != "Action: subject k1 (Tessera)" || !strings.HasPrefix(tpl.Body, "Dear colleague,\nbody\nGo: https://tessera.example/inbox") ||
		strings.Count(tpl.Body, "https://tessera.example/inbox") != 1 || !strings.Contains(tpl.Body, "settings in Tessera.") {
		t.Errorf("templated email = %+v", tpl)
	}
	if plain.Subject != "[Tessera] subject k2" || !strings.Contains(plain.Body, "Open in Tessera: https://tessera.example/inbox") {
		t.Errorf("untemplated email = %+v", plain)
	}
}

func TestResetTemplateAndAudit(t *testing.T) {
	w := newWorld(t)
	w.tx(func(c *store.TenantTx) error {
		if err := notify.ResetTemplate(c, notify.KindApprovalNeeded, "admin", w.now); code(err) != "template_not_found" {
			t.Errorf("reset of none = %v", err)
		}
		if err := notify.ResetTemplate(c, "no.such", "admin", w.now); code(err) != "unknown_kind" {
			t.Errorf("reset of an unknown kind = %v", err)
		}
		if err := notify.SaveTemplate(c, notify.KindApprovalNeeded, "s", "b", "admin", w.now); err != nil {
			t.Fatal(err)
		}
		return notify.ResetTemplate(c, notify.KindApprovalNeeded, "admin", w.now)
	})
	if w.audited("notification.template.update") != 1 || w.audited("notification.template.reset") != 1 {
		t.Error("save and reset are not both audited")
	}
}

// ---------------------------------------------------------------- policy

func TestPolicyCheckAndSave(t *testing.T) {
	good := notify.DefaultPolicy()
	if good.ReviewRemindAfterDays != 7 || good.ReviewRemindEveryDays != 7 || good.RequestWarnHours != 24 || good.JITWarnMinutes != 60 || good.EscalateAfterHours != 48 {
		t.Fatalf("defaults = %+v", good)
	}
	for name, mod := range map[string]func(*notify.Policy){
		"after 0":          func(p *notify.Policy) { p.ReviewRemindAfterDays = 0 },
		"after 91":         func(p *notify.Policy) { p.ReviewRemindAfterDays = 91 },
		"every 0":          func(p *notify.Policy) { p.ReviewRemindEveryDays = 0 },
		"request warn 0":   func(p *notify.Policy) { p.RequestWarnHours = 0 },
		"request warn max": func(p *notify.Policy) { p.RequestWarnHours = 721 },
		"jit warn 4":       func(p *notify.Policy) { p.JITWarnMinutes = 4 },
		"jit warn 1441":    func(p *notify.Policy) { p.JITWarnMinutes = 1441 },
		"escalate 0":       func(p *notify.Policy) { p.EscalateAfterHours = 0 },
		"escalate 721":     func(p *notify.Policy) { p.EscalateAfterHours = 721 },
	} {
		p := good
		mod(&p)
		if p.Check() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	w := newWorld(t)
	w.tx(func(c *store.TenantTx) error {
		p := good
		p.EscalateAfterHours = 12
		if _, v, err := notify.SavePolicy(c, p, 0, "admin", w.now); err != nil || v != 1 {
			t.Fatalf("save = v%d %v", v, err)
		}
		if _, _, err := notify.SavePolicy(c, p, 0, "admin", w.now); code(err) != "version_conflict" {
			t.Errorf("stale save = %v", err)
		}
		got, v, err := notify.LoadPolicy(c)
		if err != nil || v != 1 || got.EscalateAfterHours != 12 {
			t.Errorf("load = %+v v%d %v", got, v, err)
		}
		return nil
	})
	if w.audited("notification.policy.update") != 1 {
		t.Error("the save is not audited")
	}
}

// The reminder cadence is the tenant's: first after 2 days, then every 3.
func TestScanFollowsTheReminderCadence(t *testing.T) {
	w := newWorld(t)
	camp := w.f.B.IDs["campaign"]
	mail := &notify.MemorySender{}
	clk := &clock{t: w.now}
	d := w.dispatcher(mail, clk)
	w.tx(func(c *store.TenantTx) error {
		p := notify.DefaultPolicy()
		p.ReviewRemindAfterDays, p.ReviewRemindEveryDays = 2, 3
		_, _, err := notify.SavePolicy(c, p, 0, "admin", w.now)
		return err
	})
	_ = camp
	for _, step := range []struct {
		add  time.Duration
		scan int
	}{{24 * time.Hour, 0}, {24 * time.Hour, 1}, {24 * time.Hour, 0}, {24 * time.Hour, 0}, {24 * time.Hour, 1}, {24 * time.Hour, 0}} {
		clk.add(step.add)
		if st := w.run(d); st.Scanned != step.scan {
			t.Errorf("at %v: scanned %d, want %d", clk.now().Sub(w.now), st.Scanned, step.scan)
		}
	}
}

// ---------------------------------------------------------------- suppression

func TestSuppressionSkipsEmailAndExplainsWhy(t *testing.T) {
	w := newWorld(t)
	w.tx(func(c *store.TenantTx) error {
		if _, err := notify.Suppress(c, "  ANN@B.example ", store.SuppressManual, "left the company", "", "admin", w.now); err != nil {
			t.Fatal(err)
		}
		if added, err := notify.Suppress(c, "ann@b.example", store.SuppressManual, "", "", "admin", w.now); err != nil || added {
			t.Errorf("a second suppression = %v, %v", added, err)
		}
		for _, bad := range []string{"", "not an address", "Ann <a@b.example>", "a@b.example\r\nBcc: x@y.example", "a@b.example, c@d.example"} {
			if _, err := notify.Suppress(c, bad, store.SuppressManual, "", "", "admin", w.now); code(err) != "invalid_address" {
				t.Errorf("%q = %v", bad, err)
			}
		}
		return nil
	})
	w.emit(notify.KindApprovalNeeded, "k1", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	mail := &notify.MemorySender{}
	st := w.run(w.dispatcher(mail, &clock{t: w.now}))
	if st.Sent != 0 || st.Skipped != 1 || mail.Count() != 0 {
		t.Fatalf("stats = %+v, sent %d", st, mail.Count())
	}
	if n := w.one(w.ann); !n.InApp || n.Delivery != store.DeliverySkipped {
		t.Errorf("the inbox entry = %+v", n)
	}
	w.read(func(c *store.TenantTx) {
		ms, _ := c.EmailMessages(store.EmailFilter{})
		if len(ms) != 1 || ms[0].Status != store.EmailRejected || !strings.Contains(string(ms[0].Attempts), "suppression list") {
			t.Errorf("messages = %+v", ms)
		}
	})
	// the other tenant's suppression list is its own
	if err := w.f.DB.ReadTenant(context.Background(), w.f.A.ID, func(c *store.TenantTx) error {
		if s, err := notify.Suppressed(c, w.annEmail); err != nil || s {
			t.Errorf("tenant A sees B's suppression: %v %v", s, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// lifting it sends again
	w.tx(func(c *store.TenantTx) error {
		if err := notify.Lift(c, "ann@b.example", "admin", w.now); err != nil {
			t.Fatal(err)
		}
		if err := notify.Lift(c, "ann@b.example", "admin", w.now); code(err) != "suppression_not_found" {
			t.Errorf("second lift = %v", err)
		}
		return nil
	})
	w.emit(notify.KindApprovalNeeded, "k2", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	if st := w.run(w.dispatcher(mail, &clock{t: w.now})); st.Sent != 1 {
		t.Errorf("after lifting: %+v", st)
	}
	// the message that was skipped can be sent again now that the suppression is gone
	var skipped *store.EmailMessage
	w.read(func(c *store.TenantTx) {
		ms, _ := c.EmailMessages(store.EmailFilter{Status: store.EmailRejected})
		if len(ms) == 1 {
			skipped = ms[0]
		}
	})
	if skipped == nil {
		t.Fatal("no skipped message")
	}
	w.tx(func(c *store.TenantTx) error {
		_, err := notify.Suppress(c, "ann@b.example", store.SuppressManual, "again", "", "admin", w.now)
		if err != nil {
			return err
		}
		if _, err := notify.RetryEmail(c, w.now, skipped.ID, "admin"); code(err) != "suppressed" {
			t.Errorf("resend while suppressed = %v", err)
		}
		if err := notify.Lift(c, "ann@b.example", "admin", w.now); err != nil {
			return err
		}
		m, err := notify.RetryEmail(c, w.now, skipped.ID, "admin")
		if err != nil || m.Status != store.EmailQueued {
			t.Errorf("resend = %+v, %v", m, err)
		}
		return nil
	})
	before := mail.Count()
	if st := w.run(w.dispatcher(mail, &clock{t: w.now})); st.Sent != 1 || mail.Count() != before+1 {
		t.Errorf("resend: %+v", st)
	}
	if w.audited("email.suppression.add") != 2 || w.audited("email.suppression.lift") != 2 {
		t.Errorf("add and lift are audited %d and %d times, want 2 and 2", w.audited("email.suppression.add"), w.audited("email.suppression.lift"))
	}
}

// ---------------------------------------------------------------- DSN

// dsnFor builds the multipart/report a relay sends back for a message with the given Message-ID.
func dsnFor(messageID, rcpt, action, status, diag string) []byte {
	return []byte(strings.Join([]string{
		"From: MAILER-DAEMON@relay.example", "To: noreply@larkspur.example", "Subject: Undelivered Mail Returned to Sender",
		"MIME-Version: 1.0", `Content-Type: multipart/report; report-type=delivery-status; boundary="BND"`, "",
		"--BND", "Content-Type: text/plain; charset=utf-8", "", "This is the mail system. Your message could not be delivered.", "",
		"--BND", "Content-Type: message/delivery-status", "",
		"Reporting-MTA: dns; relay.example", "X-Postfix-Queue-ID: QID9876", "",
		"Final-Recipient: rfc822; " + rcpt, "Original-Recipient: rfc822;" + rcpt, "Action: " + action, "Status: " + status,
		"Diagnostic-Code: smtp; " + diag, "",
		"--BND", "Content-Type: text/rfc822-headers", "",
		"Message-ID: <" + messageID + "@larkspur.example>", "Subject: [Tessera] subject", "", "--BND--", ""}, "\r\n"))
}

func TestParseDSN(t *testing.T) {
	id := "3f1d5a50-5f1c-4c3a-9a53-2d6f1e9a7b11"
	d, err := notify.ParseDSN(dsnFor(id, "ann@b.example", "failed", "5.1.1", "550 5.1.1 <ann@b.example>: user unknown"))
	if err != nil || d.NotificationID != id || d.QueueID != "QID9876" || len(d.Recipients) != 1 {
		t.Fatalf("dsn = %+v, %v", d, err)
	}
	if r := d.Recipients[0]; r.Address != "ann@b.example" || r.Action != "failed" || r.Status != "5.1.1" || !strings.Contains(r.Diagnostic, "user unknown") {
		t.Errorf("recipient = %+v", r)
	}
	// a bare message/delivery-status body
	bare := "Content-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; relay.example\r\n\r\nFinal-Recipient: rfc822; Pat@B.example\r\nAction: delayed\r\nStatus: 4.4.1\r\n"
	if d, err := notify.ParseDSN([]byte(bare)); err != nil || len(d.Recipients) != 1 || d.Recipients[0].Address != "pat@b.example" || d.NotificationID != "" {
		t.Errorf("bare = %+v, %v", d, err)
	}
	// a made-up status is dropped, not trusted
	if d, err := notify.ParseDSN(dsnFor(id, "ann@b.example", "failed", "9.9.9 oops", "x")); err != nil || d.Recipients[0].Status != "" {
		t.Errorf("odd status = %+v, %v", d, err)
	}
	for name, raw := range map[string]string{
		"not a message":      "hello",
		"plain text":         "Content-Type: text/plain\r\n\r\nhello",
		"no recipient":       "Content-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; relay.example\r\n",
		"no boundary":        "Content-Type: multipart/report\r\n\r\nx",
		"a bad recipient":    "Content-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; x\r\n\r\nFinal-Recipient: rfc822; not an address\r\nAction: failed\r\n",
		"no content type":    "Subject: x\r\n\r\nx",
		"a header injection": "Content-Type: message/delivery-status\r\n\r\nx\r\n\r\nFinal-Recipient: rfc822; a@b.example\r\nBcc: x",
	} {
		if _, err := notify.ParseDSN([]byte(raw)); err == nil && name != "a header injection" {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := notify.ParseDSN(make([]byte, notify.MaxDSNBytes+1)); code(err) != "dsn_too_large" {
		t.Errorf("a huge report = %v", err)
	}
}

// A hard bounce marks the message bounced, suppresses the address and shows in the delivery log; a soft one and a duplicate
// do not; a report for another address or message changes nothing.
func TestApplyDSN(t *testing.T) {
	w := newWorld(t)
	w.emit(notify.KindApprovalNeeded, "k1", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	w.emit(notify.KindApprovalNeeded, "k2", notify.Recipient{UserID: w.pat, Email: w.patMail})
	mail := &notify.MemorySender{}
	if st := w.run(w.dispatcher(mail, &clock{t: w.now})); st.Sent != 2 {
		t.Fatalf("stats = %+v", st)
	}
	var annMsg, patMsg *store.EmailMessage
	w.read(func(c *store.TenantTx) {
		ms, _ := c.EmailMessages(store.EmailFilter{})
		for _, m := range ms {
			if m.Recipient == w.annEmail {
				annMsg = m
			} else {
				patMsg = m
			}
		}
	})
	if annMsg == nil || patMsg == nil {
		t.Fatal("no messages")
	}
	apply := func(raw []byte) []notify.DSNResult {
		t.Helper()
		var out []notify.DSNResult
		w.tx(func(c *store.TenantTx) error {
			d, err := notify.ParseDSN(raw)
			if err != nil {
				t.Fatal(err)
			}
			out, err = notify.ApplyDSN(c, d, "admin", w.now.Add(time.Hour))
			return err
		})
		return out
	}
	// soft: recorded, status unchanged, not suppressed
	r := apply(dsnFor(patMsg.NotificationID, w.patMail, "delayed", "4.4.1", "connection timed out"))
	if len(r) != 1 || r[0].Outcome != "deferred" || r[0].Suppressed || r[0].MessageID != patMsg.ID {
		t.Errorf("delayed = %+v", r)
	}
	// a report for a message that is another recipient's
	r = apply(dsnFor(patMsg.NotificationID, w.annEmail, "failed", "5.1.1", "user unknown"))
	if len(r) != 1 || r[0].Outcome != "recipient_mismatch" || r[0].Suppressed {
		t.Errorf("mismatch = %+v", r)
	}
	// a report for nothing of ours
	r = apply(dsnFor("11111111-1111-1111-1111-111111111111", "ann@b.example", "failed", "5.1.1", "x"))
	if len(r) != 1 || r[0].Outcome != "not_matched" || r[0].Matched {
		t.Errorf("not matched = %+v", r)
	}
	// hard bounce
	r = apply(dsnFor(annMsg.NotificationID, "Ann@B.example", "failed", "5.1.1", "550 5.1.1 user unknown"))
	if len(r) != 1 || r[0].Outcome != "bounced" || !r[0].Suppressed {
		t.Fatalf("bounce = %+v", r)
	}
	w.read(func(c *store.TenantTx) {
		m, _ := c.EmailMessage(annMsg.ID)
		if m.Status != store.EmailBounced || !strings.Contains(string(m.Attempts), "5.1.1") || !strings.Contains(string(m.Attempts), "delivery status notification") {
			t.Errorf("message = %s %s", m.Status, m.Attempts)
		}
		if s, err := c.EmailSuppression("ann@b.example"); err != nil || s.Reason != store.SuppressHardBounce || s.MessageID != annMsg.ID {
			t.Errorf("suppression = %+v, %v", s, err)
		}
		if m, _ := c.EmailMessage(patMsg.ID); m.Status != store.EmailAccepted {
			t.Errorf("Pat's message is %s", m.Status)
		}
	})
	// the same report again
	if r := apply(dsnFor(annMsg.NotificationID, w.annEmail, "failed", "5.1.1", "550")); r[0].Outcome != "already_recorded" {
		t.Errorf("again = %+v", r)
	}
	// a bounced message can be sent again only after the suppression is lifted
	w.tx(func(c *store.TenantTx) error {
		if _, err := notify.RetryEmail(c, w.now, annMsg.ID, "admin"); code(err) != "suppressed" {
			t.Errorf("resend while suppressed = %v", err)
		}
		if err := notify.Lift(c, w.annEmail, "admin", w.now); err != nil {
			return err
		}
		m, err := notify.RetryEmail(c, w.now, annMsg.ID, "admin")
		if err != nil || m.Status != store.EmailQueued {
			t.Errorf("resend = %+v, %v", m, err)
		}
		return nil
	})
	if st := w.run(w.dispatcher(mail, &clock{t: w.now.Add(2 * time.Hour)})); st.Sent != 1 {
		t.Errorf("resend stats = %+v", st)
	}
	if w.audited("email.dsn") != 5 {
		t.Errorf("%d email.dsn events, want 5", w.audited("email.dsn"))
	}
}

// ---------------------------------------------------------------- chat

func TestCheckWebhookURL(t *testing.T) {
	prod := notify.ChatEnv{}
	dev := notify.ChatEnv{AnyHost: true}
	cases := []struct {
		name     string
		env      notify.ChatEnv
		provider string
		url      string
		want     string
	}{
		{"slack", prod, "slack", "https://hooks.slack.com/services/T000/B000/XXXX", ""},
		{"slack gov", prod, "slack", "https://hooks.slack-gov.com/services/T000/B000/XXXX", ""},
		{"teams connector", prod, "teams", "https://contoso.webhook.office.com/webhookb2/abc/IncomingWebhook/def/ghi", ""},
		{"teams workflow", prod, "teams", "https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sig=xyz", ""},
		{"slack url for teams", prod, "teams", "https://hooks.slack.com/services/T000/B000/XXXX", "invalid_webhook_host"},
		{"teams url for slack", prod, "slack", "https://contoso.webhook.office.com/x", "invalid_webhook_host"},
		{"any other host", prod, "slack", "https://evil.example.com/hooks.slack.com", "invalid_webhook_host"},
		{"a look-alike suffix", prod, "slack", "https://hooks.slack.com.evil.example/x", "invalid_webhook_host"},
		{"a look-alike prefix of a teams suffix", prod, "teams", "https://evilwebhook.office.com/x", "invalid_webhook_host"},
		{"http", prod, "slack", "http://hooks.slack.com/services/x", "invalid_webhook"},
		{"another port", prod, "slack", "https://hooks.slack.com:8443/services/x", "invalid_webhook"},
		{"user info", prod, "slack", "https://user:pw@hooks.slack.com/services/x", "invalid_webhook"},
		{"an internal address", prod, "slack", "https://169.254.169.254/latest/meta-data", "invalid_webhook_host"},
		{"loopback", prod, "slack", "https://127.0.0.1/x", "invalid_webhook_host"},
		{"not a URL", prod, "slack", "hooks.slack.com/services/x", "invalid_webhook"},
		{"empty", prod, "slack", "", "invalid_webhook"},
		{"dev: a local receiver", dev, "slack", "http://127.0.0.1:8123/hook", ""},
		{"dev: still needs http or https", dev, "slack", "ftp://127.0.0.1/hook", "invalid_webhook"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.env.CheckWebhookURL(tc.provider, tc.url)
			if got := code(err); got != tc.want {
				t.Errorf("code = %q, want %q", got, tc.want)
			}
		})
	}
}

// receiver is a webhook that records what it is sent and can fail on demand.
type receiver struct {
	mu    sync.Mutex
	posts []string
	fail  bool
	srv   *httptest.Server
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.fail {
			http.Error(w, "nope", http.StatusInternalServerError)
			return
		}
		r.posts = append(r.posts, string(b))
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.posts)
}

func chatWorld(t *testing.T, provider string, kinds ...string) (*world, *receiver, *notify.Dispatcher) {
	t.Helper()
	w := newWorld(t)
	rcv := newReceiver(t)
	env := relayEnv("dev", true)
	w.tx(func(c *store.TenantTx) error {
		return notify.SaveChat(c, notify.ChatEnv{Sealer: env.Sealer, AnyHost: true}, notify.ChatSpec{Provider: provider, Enabled: true,
			URL: rcv.srv.URL + "/hook/SECRET-TOKEN", Kinds: kinds}, 0, "admin", w.now.Add(-time.Hour))
	})
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: "dev", AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	d := w.dispatcher(&notify.MemorySender{}, &clock{t: w.now.Add(time.Minute)}) // the cursor stays 5 seconds behind the clock
	d.Relay, d.HTTP = env, hc
	return w, rcv, d
}

// One message per event, however many people it is for; kinds that are not chosen are not posted; Slack markup in the text is
// escaped; a second pass posts nothing; the webhook URL is sealed and never audited.
func TestChatPostsOncePerEvent(t *testing.T) {
	w, rcv, d := chatWorld(t, "slack", notify.KindApprovalNeeded)
	w.tx(func(c *store.TenantTx) error {
		to := []notify.Recipient{{UserID: w.ann, Email: w.annEmail}, {UserID: w.pat, Email: w.patMail}}
		if _, err := notify.Emit(c, w.now, notify.Message{Kind: notify.KindApprovalNeeded, Key: "req:1", Subject: "Approve <!channel> & co", Body: "body <@U1>", Link: "/inbox"}, to...); err != nil {
			return err
		}
		_, err := notify.Emit(c, w.now, notify.Message{Kind: notify.KindRequestApproved, Key: "req:1:ok", Subject: "not chosen", Body: "b"}, to...)
		return err
	})
	w.run(d)
	if rcv.count() != 1 {
		t.Fatalf("%d posts, want 1: %v", rcv.count(), rcv.posts)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(rcv.posts[0]), &m); err != nil {
		t.Fatal(err)
	}
	txt := m["text"]
	if !strings.Contains(txt, "*[Tessera] Approve &lt;!channel&gt; &amp; co*") || !strings.Contains(txt, "body &lt;@U1&gt;") ||
		!strings.Contains(txt, "https://tessera.example/inbox") || strings.Contains(txt, "<!channel>") || strings.Contains(txt, "not chosen") {
		t.Errorf("text = %q", txt)
	}
	w.run(d)
	if rcv.count() != 1 {
		t.Errorf("a second pass posted again: %d", rcv.count())
	}
	// a later event posts
	w.tx(func(c *store.TenantTx) error {
		_, err := notify.Emit(c, w.now.Add(30*time.Second), notify.Message{Kind: notify.KindApprovalNeeded, Key: "req:2", Subject: "second", Body: "b"}, notify.Recipient{UserID: w.ann, Email: w.annEmail})
		return err
	})
	w.run(d)
	if rcv.count() != 2 {
		t.Errorf("%d posts, want 2", rcv.count())
	}
	w.read(func(c *store.TenantTx) {
		row, _ := c.ChatWebhook()
		if strings.Contains(string(row.WebhookSealed), "SECRET-TOKEN") || row.WebhookHost == "" || row.LastPostAt == nil || row.FailCount != 0 {
			t.Errorf("row = %+v", row)
		}
		st, _ := notify.LoadChat(c)
		if b, _ := json.Marshal(st); strings.Contains(string(b), "SECRET-TOKEN") || !st.HasWebhook {
			t.Errorf("state = %s", b)
		}
		log, _ := c.AuditLog(-1)
		for _, e := range log {
			if strings.Contains(string(e.Detail), "SECRET-TOKEN") {
				t.Errorf("the webhook URL is in the audit log: %s", e.Detail)
			}
		}
	})
	if w.audited("notification.chat") != 2 || w.audited("chat.webhook.update") != 1 {
		t.Errorf("audit: %d posts, %d saves", w.audited("notification.chat"), w.audited("chat.webhook.update"))
	}
}

// History is not replayed when the webhook is turned on; a failing event is retried and then given up so the rest go through.
func TestChatRetriesThenGivesUp(t *testing.T) {
	w, rcv, d := chatWorld(t, "teams", notify.KindApprovalNeeded)
	// the saved cursor is an hour before now: an older notification is not posted
	w.tx(func(c *store.TenantTx) error {
		_, err := notify.Emit(c, w.now.Add(-2*time.Hour), notify.Message{Kind: notify.KindApprovalNeeded, Key: "old", Subject: "old", Body: "b"}, notify.Recipient{UserID: w.ann, Email: w.annEmail})
		return err
	})
	w.emit(notify.KindApprovalNeeded, "bad", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	w.emit(notify.KindApprovalNeeded, "good", notify.Recipient{UserID: w.pat, Email: w.patMail})
	rcv.mu.Lock()
	rcv.fail = true
	rcv.mu.Unlock()
	for i := 1; i < notify.ChatMaxFailures; i++ {
		w.run(d)
		w.read(func(c *store.TenantTx) {
			row, _ := c.ChatWebhook()
			if row.FailCount != i || !strings.Contains(row.LastError, "HTTP 500") || strings.Contains(row.LastError, "SECRET-TOKEN") {
				t.Errorf("after %d failures: %d %q", i, row.FailCount, row.LastError)
			}
		})
	}
	rcv.mu.Lock()
	rcv.fail = false
	rcv.mu.Unlock()
	w.run(d) // the fifth try works
	if rcv.count() < 1 {
		t.Fatalf("no post after the receiver recovered")
	}
	for _, p := range rcv.posts {
		if strings.Contains(p, `"text":"old"`) || strings.Contains(p, "old") && !strings.Contains(p, "bad") && !strings.Contains(p, "good") {
			t.Errorf("history was replayed: %s", p)
		}
		// the Teams payload is an adaptive card
		if !strings.Contains(p, "application/vnd.microsoft.card.adaptive") || !strings.Contains(p, `"type":"message"`) {
			t.Errorf("payload = %s", p)
		}
	}
	// now an event that always fails is given up after the limit, and the next one still goes out
	rcv.mu.Lock()
	rcv.fail = true
	n := len(rcv.posts)
	rcv.mu.Unlock()
	emitAt := func(at time.Duration, key string, r notify.Recipient) {
		w.tx(func(c *store.TenantTx) error {
			_, err := notify.Emit(c, w.now.Add(at), notify.Message{Kind: notify.KindApprovalNeeded, Key: key, Subject: "subject " + key, Body: "body", Link: "/inbox"}, r)
			return err
		})
	}
	emitAt(10*time.Second, "doomed", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	for i := 0; i < notify.ChatMaxFailures; i++ {
		w.run(d)
	}
	emitAt(20*time.Second, "after", notify.Recipient{UserID: w.pat, Email: w.patMail})
	rcv.mu.Lock()
	rcv.fail = false
	rcv.mu.Unlock()
	w.run(d)
	rcv.mu.Lock()
	defer rcv.mu.Unlock()
	if len(rcv.posts) != n+1 || !strings.Contains(rcv.posts[len(rcv.posts)-1], "subject after") {
		t.Errorf("posts after giving up: %d (was %d), last %q", len(rcv.posts), n, rcv.posts[len(rcv.posts)-1])
	}
	if w.audited("notification.chat") < 2 {
		t.Errorf("the dropped event is not audited")
	}
}

// Turning the webhook off posts nothing; the test message goes through; a missing webhook is a 404.
func TestChatTestAndSwitchOff(t *testing.T) {
	w, rcv, d := chatWorld(t, "slack", notify.KindApprovalNeeded)
	hc := d.HTTP
	env := notify.ChatEnv{Sealer: d.Relay.Sealer, AnyHost: true}
	w.tx(func(c *store.TenantTx) error {
		if err := notify.TestChat(context.Background(), c, env, hc, "Larkspur", "admin", w.now); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	if rcv.count() != 1 || !strings.Contains(rcv.posts[0], "Test message from Larkspur") {
		t.Errorf("test posts = %v", rcv.posts)
	}
	w.tx(func(c *store.TenantTx) error {
		return notify.SaveChat(c, env, notify.ChatSpec{Provider: "slack", Enabled: false, Kinds: []string{notify.KindApprovalNeeded}}, 1, "admin", w.now)
	})
	w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	w.run(d)
	if rcv.count() != 1 {
		t.Errorf("a switched-off webhook posted: %d", rcv.count())
	}
	// a Slack URL does not carry over to Teams
	w.tx(func(c *store.TenantTx) error {
		err := notify.SaveChat(c, env, notify.ChatSpec{Provider: "teams", Enabled: false, Kinds: []string{notify.KindApprovalNeeded}}, 2, "admin", w.now)
		if code(err) != "webhook_required" {
			t.Errorf("provider change without a URL = %v", err)
		}
		if err := notify.DeleteChat(c, 2, "admin", w.now); err != nil {
			t.Fatal(err)
		}
		if err := notify.TestChat(context.Background(), c, env, hc, "x", "admin", w.now); code(err) != "chat_not_found" {
			t.Errorf("test without a webhook = %v", err)
		}
		return nil
	})
}

func TestSaveChatValidation(t *testing.T) {
	w := newWorld(t)
	env := notify.ChatEnv{Sealer: relayEnv("prod", false).Sealer}
	good := notify.ChatSpec{Provider: "slack", Enabled: true, URL: "https://hooks.slack.com/services/T/B/X", Kinds: []string{notify.KindApprovalNeeded}}
	w.tx(func(c *store.TenantTx) error {
		for name, tc := range map[string]struct {
			mod  func(*notify.ChatSpec)
			want string
		}{
			"unknown provider": {func(s *notify.ChatSpec) { s.Provider = "discord" }, "invalid_provider"},
			"unknown kind":     {func(s *notify.ChatSpec) { s.Kinds = []string{"nope"} }, "unknown_kind"},
			"a secret kind":    {func(s *notify.ChatSpec) { s.Kinds = []string{notify.KindClaimCode} }, "unknown_kind"},
			"no kinds":         {func(s *notify.ChatSpec) { s.Kinds = nil }, "no_kinds"},
			"a wrong host":     {func(s *notify.ChatSpec) { s.URL = "https://example.com/x" }, "invalid_webhook_host"},
			"no URL at first":  {func(s *notify.ChatSpec) { s.URL = "" }, "webhook_required"},
		} {
			s := good
			tc.mod(&s)
			if got := code(notify.SaveChat(c, env, s, 0, "admin", w.now)); got != tc.want {
				t.Errorf("%s: %q, want %q", name, got, tc.want)
			}
		}
		if err := notify.SaveChat(c, env, good, 0, "admin", w.now); err != nil {
			t.Fatal(err)
		}
		if code(notify.SaveChat(c, env, good, 0, "admin", w.now)) != "version_conflict" {
			t.Error("stale save accepted")
		}
		return nil
	})
}
