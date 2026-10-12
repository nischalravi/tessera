package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func mail1() notify.Email {
	return notify.Email{ID: "n-1", To: "ann@b.example", Subject: "s", Body: "SECRET-BODY-TEXT do not log"}
}

func TestParseQueueID(t *testing.T) {
	for in, want := range map[string]string{
		"250 2.0.0 Ok: queued as ABC123":       "ABC123",
		"2.0.0 Ok: queued as 4F8a9.b-c.":       "4F8a9.b-c",
		"250 OK id=1rXyZ-0001Ab-Cd":            "1rXyZ-0001Ab-Cd",
		"2.0.0 Message accepted, Queue ID: Q9": "Q9",
		"250 2.0.0 OK":                         "",
		"":                                     "",
	} {
		if got := notify.ParseQueueID(in); got != want {
			t.Errorf("ParseQueueID(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestTranscript_CapturesTheSession: banner, capabilities, every command and
// reply with its codes, the queue id, and never the message body.
func TestTranscript_CapturesTheSession(t *testing.T) {
	f := newFakeSMTP(t)
	a, err := smtpFor(t, f, config.Dev, true).SendRecorded(context.Background(), mail1())
	if err != nil {
		t.Fatal(err)
	}
	if a.Outcome != notify.OutcomeAccepted || a.QueueID != "ABC123" || a.MailFrom != "tessera@example.com" || a.RcptTo != "ann@b.example" {
		t.Fatalf("attempt = %+v", a)
	}
	if !strings.Contains(a.Banner, "relay.example ESMTP") || len(a.Capabilities) != 2 || a.Capabilities[0] != "SIZE 1000" {
		t.Errorf("banner %q capabilities %v", a.Banner, a.Capabilities)
	}
	var cmds []string
	for _, s := range a.Steps {
		cmds = append(cmds, s.Command)
	}
	want := []string{"(connect)", "EHLO example.com", "MAIL FROM:<tessera@example.com>", "RCPT TO:<ann@b.example>", "DATA", "<message body not recorded>", "QUIT"}
	if strings.Join(cmds, "|") != strings.Join(want, "|") {
		t.Errorf("commands = %v", cmds)
	}
	last := a.Steps[5]
	if last.Code != 250 || last.Enhanced != "2.0.0" || !strings.Contains(last.Reply, "queued as ABC123") {
		t.Errorf("final step = %+v", last)
	}
	if a.Started.IsZero() || a.Finished.Before(a.Started) {
		t.Errorf("times %v %v", a.Started, a.Finished)
	}
	raw, _ := json.Marshal(a)
	if strings.Contains(string(raw), "SECRET-BODY-TEXT") {
		t.Error("the message body is in the transcript")
	}
}

// TestTranscript_RedactsAuthAndRecordsTLS: over STARTTLS and over implicit
// TLS the transcript shows the TLS version, cipher and certificate, and the
// AUTH credentials are redacted, while the relay did receive them.
func TestTranscript_RedactsAuthAndRecordsTLS(t *testing.T) {
	serverConf, clientConf := relayCert(t)
	s := testSealer(t)
	sealed, _ := notify.SealPassword(s, "hunter2-the-password")
	for _, mode := range []string{config.SMTPStartTLS, config.SMTPTLS} {
		t.Run(mode, func(t *testing.T) {
			f := newFakeSMTP(t)
			f.tlsConf, f.implicit = serverConf, mode == config.SMTPTLS
			c, err := notify.NewSMTP(config.Mail{Mode: config.MailSMTP, Host: "127.0.0.1", Port: f.port(), From: "tessera@example.com", Username: "relay-user",
				PasswordSealed: sealed, TLS: mode}, config.Dev, true, s)
			if err != nil {
				t.Fatal(err)
			}
			c.TLSConfig = clientConf
			a, err := c.SendRecorded(context.Background(), mail1())
			if err != nil {
				t.Fatal(err)
			}
			if a.TLS == nil || a.TLS.Version == "" || a.TLS.Cipher == "" || !strings.Contains(a.TLS.Subject, "relay.example") || !strings.Contains(a.TLS.Issuer, "relay.example") || a.TLS.Error != "" {
				t.Errorf("tls = %+v", a.TLS)
			}
			raw, _ := json.Marshal(a)
			for _, secret := range []string{"hunter2-the-password", "relay-user", "SECRET-BODY-TEXT", sealed} {
				if strings.Contains(string(raw), secret) {
					t.Errorf("the transcript contains %q:\n%s", secret, raw)
				}
			}
			found := false
			for _, st := range a.Steps {
				if st.Command == "AUTH PLAIN <redacted>" && st.Code == 235 && st.Enhanced == "2.7.0" {
					found = true
				}
			}
			if !found {
				t.Errorf("no redacted AUTH step in %+v", a.Steps)
			}
			if len(f.auth) != 1 || !strings.HasPrefix(f.auth[0], "AUTH PLAIN ") || strings.Contains(f.auth[0], "redacted") {
				t.Errorf("the relay did not get real credentials: %v", f.auth)
			}
			if mode == config.SMTPStartTLS && a.Steps[2].Command != "STARTTLS" {
				t.Errorf("steps = %+v", a.Steps)
			}
		})
	}
}

func TestTranscript_StartTLSFailureIsAFailure(t *testing.T) {
	serverConf, clientConf := relayCert(t)
	f := newFakeSMTP(t)
	f.tlsConf, f.starttls = serverConf, "454 4.7.0 TLS not available due to temporary reason"
	c := smtpFor(t, f, config.Dev, true)
	c.TLS, c.TLSConfig = config.SMTPStartTLS, clientConf
	a, err := c.SendRecorded(context.Background(), mail1())
	if err == nil || errors.Is(err, notify.ErrPermanent) {
		t.Fatalf("err = %v, want a retryable failure", err)
	}
	if a.Outcome != notify.OutcomeFailed || a.TLS == nil || !strings.Contains(a.TLS.Error, "454") {
		t.Errorf("attempt = %+v tls %+v", a, a.TLS)
	}
	// an untrusted certificate: the handshake fails, no mail is sent
	f2 := newFakeSMTP(t)
	f2.tlsConf = serverConf
	c2 := smtpFor(t, f2, config.Dev, true)
	c2.TLS = config.SMTPStartTLS // system roots do not trust the test certificate
	a, err = c2.SendRecorded(context.Background(), mail1())
	if err == nil || a.Outcome != notify.OutcomeFailed || a.TLS == nil || a.TLS.Error == "" || len(f2.to) != 0 {
		t.Errorf("untrusted certificate: %v %+v", err, a)
	}
	// a relay that offers no STARTTLS when it is required
	c3 := smtpFor(t, newFakeSMTP(t), config.Dev, true)
	c3.TLS = config.SMTPStartTLS
	if a, err = c3.SendRecorded(context.Background(), mail1()); err == nil || a.Outcome != notify.OutcomeFailed {
		t.Errorf("no STARTTLS offered: %v %+v", err, a)
	}
}

func TestTranscript_OutcomesByReplyClass(t *testing.T) {
	for name, tc := range map[string]struct {
		rcpt, outcome string
		permanent     bool
		code          int
		enhanced      string
	}{
		"4xx is deferred": {"451 4.3.0 Try again later", notify.OutcomeDeferred, false, 451, "4.3.0"},
		"5xx is rejected": {"550 5.1.1 No such user", notify.OutcomeRejected, true, 550, "5.1.1"},
		"552 is rejected": {"552 5.2.2 Mailbox full", notify.OutcomeRejected, true, 552, "5.2.2"},
		"421 is deferred": {"421 4.7.0 Too many connections", notify.OutcomeDeferred, false, 421, "4.7.0"},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := smtpFor(t, newFakeSMTP(t, tc.rcpt), config.Dev, true).SendRecorded(context.Background(), mail1())
			if err == nil || errors.Is(err, notify.ErrPermanent) != tc.permanent || a.Outcome != tc.outcome {
				t.Fatalf("err %v outcome %s", err, a.Outcome)
			}
			var rcpt notify.Step
			for _, s := range a.Steps {
				if strings.HasPrefix(s.Command, "RCPT") {
					rcpt = s
				}
			}
			if rcpt.Code != tc.code || rcpt.Enhanced != tc.enhanced {
				t.Errorf("rcpt step = %+v", rcpt)
			}
			if strings.Contains(a.Error, "ann@b.example") {
				t.Errorf("the recorded error holds the address: %s", a.Error)
			}
		})
	}
}

// TestTranscript_SlowRelayTimesOut: a relay that never answers fails the
// attempt at the timeout (a failure, so it is retried).
func TestTranscript_SlowRelayTimesOut(t *testing.T) {
	f := newFakeSMTP(t)
	f.delay = 3 * time.Second
	c := smtpFor(t, f, config.Dev, true)
	c.Timeout = 300 * time.Millisecond
	start := time.Now()
	a, err := c.SendRecorded(context.Background(), mail1())
	if err == nil || errors.Is(err, notify.ErrPermanent) || a.Outcome != notify.OutcomeFailed {
		t.Fatalf("err %v outcome %s", err, a.Outcome)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %s: the timeout did not apply", time.Since(start))
	}
}

func TestTranscript_IsCapped(t *testing.T) {
	a := &notify.Attempt{}
	for i := 0; i < 1000; i++ {
		notify.RecordStep(a, "CMD "+strings.Repeat("x", 1000), 250, strings.Repeat("y", 1000))
	}
	raw, _ := json.Marshal(a)
	if len(a.Steps) > notify.MaxSteps || !a.Truncated || len(raw) > notify.MaxTranscript+2*notify.MaxFieldLen+4096 {
		t.Errorf("%d steps, truncated=%v, %d bytes", len(a.Steps), a.Truncated, len(raw))
	}
	if len(a.Steps[0].Command) > notify.MaxFieldLen+4 {
		t.Errorf("a field was not clipped: %d", len(a.Steps[0].Command))
	}
}

// ---------------------------------------------------------------- the delivery log

func (w *world) message(notificationUser string) *store.EmailMessage {
	w.t.Helper()
	var m *store.EmailMessage
	w.read(func(c *store.TenantTx) {
		ns, _ := c.Notifications(notificationUser, false, -1)
		if len(ns) == 0 {
			w.t.Fatal("no notification")
		}
		var err error
		if m, err = c.EmailMessageForNotification(ns[0].ID); err != nil {
			w.t.Fatal(err)
		}
	})
	return m
}

func attemptsOf(t *testing.T, m *store.EmailMessage) []notify.Attempt {
	t.Helper()
	var as []notify.Attempt
	if err := json.Unmarshal(m.Attempts, &as); err != nil {
		t.Fatal(err)
	}
	return as
}

// TestDeliveryLog_DeferredThenAccepted: a 4xx is deferred and retried after
// the backoff; the second attempt is accepted and the queue id is kept. The
// log holds both transcripts, the audit events name the message, and the
// body is nowhere.
func TestDeliveryLog_DeferredThenAccepted(t *testing.T) {
	w := newWorld(t)
	w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	f := newFakeSMTP(t, "451 4.3.0 Try again later", "250 2.1.5 Ok")
	clk := &clock{t: w.now}
	d := w.dispatcher(smtpFor(t, f, config.Dev, true), clk)

	if st := w.run(d); st.Retried != 1 {
		t.Fatalf("first run = %+v", st)
	}
	m := w.message(w.ann)
	if m.Status != store.EmailDeferred || m.AttemptCount != 1 || m.QueueID != nil || m.Recipient != w.annEmail || !strings.HasPrefix(m.Subject, "subject") {
		t.Fatalf("after attempt 1: %+v", m)
	}
	if as := attemptsOf(t, m); len(as) != 1 || as[0].Outcome != notify.OutcomeDeferred || as[0].Steps[3].Code != 451 {
		t.Errorf("attempts = %+v", as)
	}
	if n := w.one(w.ann); n.NextAttemptAt == nil || !n.NextAttemptAt.Equal(w.now.Add(30*time.Second)) {
		t.Errorf("backoff: next = %v", n.NextAttemptAt)
	}
	if st := w.run(d); st.Retried+st.Sent != 0 {
		t.Errorf("tried before the backoff: %+v", st)
	}
	clk.add(31 * time.Second)
	if st := w.run(d); st.Sent != 1 {
		t.Fatalf("second run = %+v", st)
	}
	m = w.message(w.ann)
	if m.Status != store.EmailAccepted || m.AttemptCount != 2 || m.QueueID == nil || *m.QueueID != "ABC123" ||
		m.MailFrom == nil || *m.MailFrom != "tessera@example.com" || m.RcptTo == nil || *m.RcptTo != w.annEmail {
		t.Fatalf("after attempt 2: %+v", m)
	}
	if as := attemptsOf(t, m); len(as) != 2 || as[1].Outcome != notify.OutcomeAccepted || as[1].QueueID != "ABC123" {
		t.Errorf("attempts = %+v", as)
	}
	if strings.Contains(string(m.Attempts), "waiting for your approval") {
		t.Error("the body is in the log")
	}
	if !strings.Contains(f.data, "Subject:") {
		t.Error("the relay did not receive the message")
	}
}

// TestDeliveryLog_RejectedIsNotRetried: a 5xx is final: one attempt, a dead
// letter, status rejected, and a manual retry is refused.
func TestDeliveryLog_RejectedIsNotRetried(t *testing.T) {
	w := newWorld(t)
	w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	f := newFakeSMTP(t, "550 5.1.1 No such user")
	clk := &clock{t: w.now}
	d := w.dispatcher(smtpFor(t, f, config.Dev, true), clk)
	for i := 0; i < 3; i++ {
		w.run(d)
		clk.add(time.Hour)
	}
	m := w.message(w.ann)
	if m.Status != store.EmailRejected || m.AttemptCount != 1 || f.rcptN != 1 {
		t.Fatalf("message %+v, %d RCPT commands", m, f.rcptN)
	}
	if n := w.one(w.ann); n.Delivery != store.DeliveryDead {
		t.Errorf("delivery = %s", n.Delivery)
	}
	err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) error {
		_, err := notify.RetryEmail(c, clk.now(), m.ID, "x")
		return err
	})
	var ne *notify.Error
	if !errors.As(err, &ne) || ne.Code != "not_retryable" {
		t.Errorf("retry of a rejected message = %v", err)
	}
}

// TestDeliveryLog_ManualRetry: a failed message that ran out of attempts can
// be retried by an operator: it is queued, sent on the next pass and audited.
func TestDeliveryLog_ManualRetry(t *testing.T) {
	w := newWorld(t)
	w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	f := newFakeSMTP(t, "451 4.3.0 later", "451 4.3.0 later", "451 4.3.0 later", "250 2.1.5 Ok")
	clk := &clock{t: w.now}
	d := w.dispatcher(smtpFor(t, f, config.Dev, true), clk) // MaxAttempts is 3
	for i := 0; i < 5; i++ {
		w.run(d)
		clk.add(time.Hour)
	}
	m := w.message(w.ann)
	if m.Status != store.EmailDeferred || m.AttemptCount != 3 || w.one(w.ann).Delivery != store.DeliveryDead {
		t.Fatalf("before the retry: %+v", m)
	}
	var retried *store.EmailMessage
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) (err error) {
		retried, err = notify.RetryEmail(c, clk.now(), m.ID, "Admin")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if retried.Status != store.EmailQueued || w.audited("email.message.retry") != 1 {
		t.Errorf("after the retry call: %+v", retried)
	}
	if st := w.run(d); st.Sent != 1 {
		t.Fatalf("the retry was not sent: %+v", st)
	}
	if m = w.message(w.ann); m.Status != store.EmailAccepted || m.AttemptCount != 4 || *m.QueueID != "ABC123" {
		t.Errorf("after the retry: %+v", m)
	}
	// accepted is final
	err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) error {
		_, err := notify.RetryEmail(c, clk.now(), m.ID, "Admin")
		return err
	})
	if err == nil {
		t.Error("an accepted message was retried")
	}
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) error {
		_, err := notify.RetryEmail(c, clk.now(), "00000000-0000-4000-8000-00000000dead", "Admin")
		return err
	}); err == nil {
		t.Error("a missing message was retried")
	}
}

// TestDeliveryLog_NetworkFailureIsFailed: a relay that cannot be reached is
// "failed" and retried; skipped sends leave no record.
func TestDeliveryLog_NetworkFailureIsFailedAndSkipsLeaveNoRecord(t *testing.T) {
	w := newWorld(t)
	w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	f := newFakeSMTP(t)
	c := smtpFor(t, f, config.Dev, true)
	_ = f.ln.Close() // nothing listens any more
	if st := w.run(w.dispatcher(c, &clock{t: w.now})); st.Retried != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if m := w.message(w.ann); m.Status != store.EmailFailed || m.AttemptCount != 1 {
		t.Errorf("message = %+v", m)
	}
	w2 := newWorld(t)
	w2.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w2.ann, Email: w2.annEmail})
	w2.run(w2.dispatcher(nil, &clock{t: w2.now})) // email off: skipped
	w2.read(func(c *store.TenantTx) {
		if ms, _ := c.EmailMessages(store.EmailFilter{}); len(ms) != 0 {
			t.Errorf("a skipped send left %d delivery records", len(ms))
		}
	})
}

// TestDeliveryLog_DevSinkAndPlainSenders: senders without a transcript still
// get a record.
func TestDeliveryLog_DevSinkAndPlainSenders(t *testing.T) {
	w := newWorld(t)
	w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	w.run(w.dispatcher(&notify.DevSink{}, &clock{t: w.now}))
	m := w.message(w.ann)
	as := attemptsOf(t, m)
	if m.Status != store.EmailAccepted || len(as) != 1 || !strings.HasPrefix(*m.QueueID, "dev-") || !strings.Contains(as[0].Banner, "dev mail sink") {
		t.Errorf("dev sink record = %+v %+v", m, as)
	}
	w2 := newWorld(t)
	w2.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w2.ann, Email: w2.annEmail})
	w2.run(w2.dispatcher(&notify.MemorySender{Errs: []error{notify.ErrPermanent}}, &clock{t: w2.now}))
	if m := w2.message(w2.ann); m.Status != store.EmailRejected {
		t.Errorf("plain sender record = %+v", m)
	}
}
