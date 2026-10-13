package notify_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// world is tenant B of the isolation fixture with three signed-in users:
// ann (alice's account, has an email), nomail (no address) and pat (holds
// the operator role, so requests.decide).
type world struct {
	t                 *testing.T
	f                 *storetest.Fixture
	now               time.Time
	ann, nomail, pat  string
	annEmail, patMail string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, f: storetest.TwoTenants(t), now: storetest.Now, annEmail: "ann@b.example", patMail: "pat@b.example"}
	w.tx(func(c *store.TenantTx) error {
		alice := w.f.B.IDs["alice"]
		mk := func(name string, email *string, ident *int64) string {
			u := &store.PlatformUser{DisplayName: name, Email: email, IdentityID: ident, CreatedAt: w.now}
			if err := c.InsertPlatformUser(u); err != nil {
				t.Fatal(err)
			}
			return u.ID.String()
		}
		ae, pe := w.annEmail, w.patMail
		w.ann, w.nomail, w.pat = mk("Ann", &ae, &alice), mk("No Mail", nil, nil), mk("Pat", &pe, nil)
		pid, _ := uuid.Parse(w.pat)
		if err := c.InsertRoleAssignment(&store.RoleAssignment{UserID: pid, Role: "operator", Source: "manual", CreatedAt: w.now}); err != nil {
			return err
		}
		// the fixture's active JIT grant ends within the warning window: revoke it, so a scan finds nothing
		// until a test brings it back (setJIT)
		return w.setJITLocked(c, "revoked")
	})
	return w
}

func (w *world) setJITLocked(c *store.TenantTx, status string) error {
	r, err := c.Request(w.f.B.IDs["request:approved"])
	if err != nil {
		return err
	}
	r.Status = status
	return c.SaveRequest(r)
}

func (w *world) setJIT(status string) {
	w.t.Helper()
	w.tx(func(c *store.TenantTx) error { return w.setJITLocked(c, status) })
}

func (w *world) tx(fn func(c *store.TenantTx) error) {
	w.t.Helper()
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, fn); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) read(fn func(c *store.TenantTx)) {
	w.t.Helper()
	if err := w.f.DB.ReadTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) error { fn(c); return nil }); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) inbox(user string) []*store.Notification {
	var out []*store.Notification
	w.read(func(c *store.TenantTx) {
		var err error
		if out, err = c.Notifications(user, false, -1); err != nil {
			w.t.Fatal(err)
		}
	})
	return out
}

func (w *world) pref(user, kind, channel string) {
	w.t.Helper()
	w.tx(func(c *store.TenantTx) error { return c.PutNotificationPref(user, kind, channel, w.now) })
}

func (w *world) audited(action string) (n int) {
	w.read(func(c *store.TenantTx) {
		log, err := c.AuditLog(-1)
		if err != nil {
			w.t.Fatal(err)
		}
		for _, e := range log {
			if e.Action == action {
				n++
			}
		}
	})
	return n
}

func (w *world) emit(kind, key string, to ...notify.Recipient) int {
	w.t.Helper()
	var n int
	w.tx(func(c *store.TenantTx) (err error) {
		n, err = notify.Emit(c, w.now, notify.Message{Kind: kind, Key: key, Subject: "subject " + key, Body: "body", Link: "/inbox"}, to...)
		return err
	})
	return n
}

// ---------------------------------------------------------------- outbox

// TestEmit_RollsBackWithTheDomainEvent: a notification is written in the
// caller's transaction, so when the event's transaction fails there is none.
func TestEmit_RollsBackWithTheDomainEvent(t *testing.T) {
	w := newWorld(t)
	boom := errors.New("the domain event failed")
	err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) error {
		n, err := notify.Emit(c, w.now, notify.Message{Kind: notify.KindRequestApproved, Key: "k1", Subject: "s", Body: "b"},
			notify.Recipient{UserID: w.ann, Email: w.annEmail})
		if err != nil || n != 1 {
			t.Fatalf("Emit = %d, %v", n, err)
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if got := w.inbox(w.ann); len(got) != 0 {
		t.Errorf("a rolled-back event left %d notification(s)", len(got))
	}
	w.read(func(c *store.TenantTx) {
		if ok, err := c.HasNotification("k1|u:" + w.ann); err != nil || ok {
			t.Errorf("HasNotification after rollback = %v, %v", ok, err)
		}
	})
	if n := w.emit(notify.KindRequestApproved, "k1", notify.Recipient{UserID: w.ann}); n != 1 {
		t.Errorf("after the rollback the same event wrote %d, want 1", n)
	}
}

// TestEmit_Idempotent: the same event reported again writes nothing, per
// recipient, and a different event writes its own.
func TestEmit_Idempotent(t *testing.T) {
	w := newWorld(t)
	to := []notify.Recipient{{UserID: w.ann, Email: w.annEmail}, {UserID: w.nomail}, {UserID: w.ann}} // ann twice
	if n := w.emit(notify.KindRequestApproved, "e1", to...); n != 2 {
		t.Fatalf("first emit wrote %d, want 2", n)
	}
	if n := w.emit(notify.KindRequestApproved, "e1", to...); n != 0 {
		t.Errorf("repeat wrote %d, want 0", n)
	}
	if n := w.emit(notify.KindRequestApproved, "e1", notify.Recipient{UserID: w.pat}); n != 1 {
		t.Errorf("a new recipient of the same event wrote %d, want 1", n)
	}
	if n := w.emit(notify.KindRequestApproved, "e2", to...); n != 2 {
		t.Errorf("a new event wrote %d, want 2", n)
	}
	if got := w.inbox(w.ann); len(got) != 2 {
		t.Errorf("ann has %d, want 2", len(got))
	}
}

func TestEmit_Validation(t *testing.T) {
	w := newWorld(t)
	for name, m := range map[string]notify.Message{
		"unknown kind":      {Kind: "nope", Key: "k", Subject: "s"},
		"no key":            {Kind: notify.KindRequestApproved, Subject: "s"},
		"no subject":        {Kind: notify.KindRequestApproved, Key: "k", Subject: " "},
		"external link":     {Kind: notify.KindRequestApproved, Key: "k", Subject: "s", Link: "https://evil.example/"},
		"scheme-less link":  {Kind: notify.KindRequestApproved, Key: "k", Subject: "s", Link: "//evil.example"},
		"link with newline": {Kind: notify.KindRequestApproved, Key: "k", Subject: "s", Link: "/a\nb"},
	} {
		err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) error {
			_, err := notify.Emit(c, w.now, m, notify.Recipient{UserID: w.ann})
			return err
		})
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestEmit_Preferences: what a user's choice does, kind by kind.
func TestEmit_Preferences(t *testing.T) {
	type want struct {
		inbox    bool
		delivery string
	}
	cases := []struct {
		name    string
		kind    string
		channel string // "" = the default
		to      func(w *world) notify.Recipient
		want    want
	}{
		{"default of an informational kind", notify.KindRequestApproved, "", ann, want{true, store.DeliveryNone}},
		{"default of an action kind", notify.KindApprovalNeeded, "", ann, want{true, store.DeliveryPending}},
		{"in_app", notify.KindApprovalNeeded, notify.ChannelInApp, ann, want{true, store.DeliveryNone}},
		{"email only", notify.KindRequestApproved, notify.ChannelEmail, ann, want{false, store.DeliveryPending}},
		{"both", notify.KindRequestApproved, notify.ChannelBoth, ann, want{true, store.DeliveryPending}},
		{"digest", notify.KindRequestApproved, notify.ChannelDigest, ann, want{true, store.DeliveryDigest}},
		{"off", notify.KindRequestApproved, notify.ChannelOff, ann, want{false, ""}},
		{"email chosen but no address: kept in the inbox", notify.KindRequestApproved, notify.ChannelEmail, nomail, want{true, store.DeliveryNone}},
		{"security alerts cannot be turned off", notify.KindSecurityAlert, notify.ChannelOff, ann, want{true, store.DeliveryNone}},
		{"an identity without sign-in gets email only", notify.KindApprovalNeeded, "", identityOnly, want{false, store.DeliveryPending}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			r := tc.to(w)
			if tc.channel != "" && r.UserID != "" {
				w.pref(r.UserID, tc.kind, tc.channel)
			}
			wrote := w.emit(tc.kind, "k", r)
			if tc.want.delivery == "" {
				if wrote != 0 {
					t.Fatalf("wrote %d, want none", wrote)
				}
				return
			}
			var got []*store.Notification
			w.read(func(c *store.TenantTx) {
				if tc.want.inbox {
					got, _ = c.Notifications(r.UserID, false, -1)
					return
				}
				got, _ = c.DueNotifications(w.now, 10) // not in the bell: only the outbox holds it
			})
			if len(got) != 1 {
				t.Fatalf("got %d notifications, want 1 (wrote %d)", len(got), wrote)
			}
			if got[0].InApp != tc.want.inbox || got[0].Delivery != tc.want.delivery {
				t.Errorf("in_app=%v delivery=%s, want in_app=%v delivery=%s", got[0].InApp, got[0].Delivery, tc.want.inbox, tc.want.delivery)
			}
		})
	}
}

func ann(w *world) notify.Recipient    { return notify.Recipient{UserID: w.ann, Email: w.annEmail} }
func nomail(w *world) notify.Recipient { return notify.Recipient{UserID: w.nomail} }
func identityOnly(w *world) notify.Recipient {
	return notify.Recipient{IdentityID: w.f.B.IDs["bob"], Email: "bob@t.example"}
}

func TestEmit_SkipsListedUsers(t *testing.T) {
	w := newWorld(t)
	var n int
	w.tx(func(c *store.TenantTx) (err error) {
		n, err = notify.Emit(c, w.now, notify.Message{Kind: notify.KindApprovalNeeded, Key: "k", Subject: "s", Skip: []string{w.ann}},
			notify.Recipient{UserID: w.ann}, notify.Recipient{UserID: w.pat})
		return err
	})
	if n != 1 || len(w.inbox(w.ann)) != 0 || len(w.inbox(w.pat)) != 1 {
		t.Errorf("wrote %d, ann %d, pat %d", n, len(w.inbox(w.ann)), len(w.inbox(w.pat)))
	}
}

func TestRecipients(t *testing.T) {
	w := newWorld(t)
	w.read(func(c *store.TenantTx) {
		ds, err := notify.Deciders(c, w.now)
		if err != nil || len(ds) != 1 || ds[0].UserID != w.pat || ds[0].Email != w.patMail {
			t.Errorf("Deciders = %v, %v", ds, err)
		}
		// alice signs in as ann: the user, not the bare identity
		rs, err := notify.Identity(c, w.f.B.IDs["alice"])
		if err != nil || len(rs) != 1 || rs[0].UserID != w.ann {
			t.Errorf("Identity(alice) = %v, %v", rs, err)
		}
		// bob does not sign in: reached at his own address
		rs, err = notify.Identity(c, w.f.B.IDs["bob"])
		if err != nil || len(rs) != 1 || rs[0].UserID != "" || rs[0].IdentityID != w.f.B.IDs["bob"] {
			t.Errorf("Identity(bob) = %v, %v", rs, err)
		}
		// dave is terminated: nobody to tell
		if rs, err = notify.Identity(c, w.f.B.IDs["dave"]); err != nil || len(rs) != 0 {
			t.Errorf("Identity(dave) = %v, %v", rs, err)
		}
		if _, ok, err := notify.User(c, "not-a-uuid"); ok || err != nil {
			t.Errorf("User(bad id) = %v, %v", ok, err)
		}
	})
	// an expired operator role does not count
	w.tx(func(c *store.TenantTx) error {
		pid, _ := uuid.Parse(w.nomail)
		exp := w.now.Add(-time.Hour)
		return c.InsertRoleAssignment(&store.RoleAssignment{UserID: pid, Role: "operator", Source: "manual", CreatedAt: w.now.Add(-2 * time.Hour), ExpiresAt: &exp})
	})
	w.read(func(c *store.TenantTx) {
		if ds, _ := notify.Deciders(c, w.now); len(ds) != 1 {
			t.Errorf("an expired role made %d deciders", len(ds))
		}
	})
}

// ---------------------------------------------------------------- preferences and inbox

func TestPreferences(t *testing.T) {
	w := newWorld(t)
	set := func(m map[string]string) error {
		return w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) error {
			return notify.SetPreferences(c, w.now, w.ann, "Ann", m)
		})
	}
	code := func(err error) string {
		var ne *notify.Error
		if errors.As(err, &ne) {
			return ne.Code
		}
		return ""
	}
	for name, tc := range map[string]struct {
		in   map[string]string
		code string
	}{
		"empty":                    {map[string]string{}, "invalid_preferences"},
		"unknown kind":             {map[string]string{"nope": "off"}, "unknown_kind"},
		"digest is not a kind":     {map[string]string{"digest": "off"}, "unknown_kind"},
		"unknown channel":          {map[string]string{notify.KindRequestApproved: "sms"}, "invalid_channel"},
		"security cannot be off":   {map[string]string{notify.KindSecurityAlert: "off"}, "kind_mandatory"},
		"all or none: one bad one": {map[string]string{notify.KindRequestApproved: "off", notify.KindSecurityAlert: "off"}, "kind_mandatory"},
	} {
		if got := code(set(tc.in)); got != tc.code {
			t.Errorf("%s: code %q, want %q", name, got, tc.code)
		}
	}
	w.read(func(c *store.TenantTx) {
		if saved, _ := c.NotificationPrefs(w.ann); len(saved) != 0 {
			t.Errorf("a refused change saved %d", len(saved))
		}
	})
	if err := set(map[string]string{notify.KindRequestApproved: "digest", notify.KindSecurityAlert: "email"}); err != nil {
		t.Fatal(err)
	}
	w.read(func(c *store.TenantTx) {
		views, err := notify.Preferences(c, w.ann)
		if err != nil || len(views) != len(notify.Kinds) {
			t.Fatalf("Preferences = %v, %v", views, err)
		}
		for _, v := range views {
			switch v.Kind.ID {
			case notify.KindRequestApproved:
				if v.Channel != "digest" || v.IsDefault {
					t.Errorf("approved = %+v", v)
				}
			case notify.KindSecurityAlert:
				if v.Channel != "email" || !v.Kind.Mandatory {
					t.Errorf("security = %+v", v)
				}
			default:
				if !v.IsDefault || v.Channel != v.Kind.Default {
					t.Errorf("%s = %+v, want the default", v.Kind.ID, v)
				}
			}
		}
	})
	if n := w.audited("notification.prefs.put"); n != 1 {
		t.Errorf("%d prefs audit events, want 1", n)
	}
}

func TestMarkRead(t *testing.T) {
	w := newWorld(t)
	for _, k := range []string{"a", "b", "c"} {
		w.emit(notify.KindRequestApproved, k, notify.Recipient{UserID: w.ann})
	}
	w.emit(notify.KindRequestApproved, "p", notify.Recipient{UserID: w.pat})
	annIn, patIn := w.inbox(w.ann), w.inbox(w.pat)
	mark := func(user string, ids []string, all bool) (n int, err error) {
		err = w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) (err error) {
			n, err = notify.MarkRead(c, w.now, user, "x", ids, all)
			return err
		})
		return n, err
	}
	// pat names ann's id: ignored, nothing changes
	if n, err := mark(w.pat, []string{annIn[0].ID}, false); err != nil || n != 0 {
		t.Errorf("another user's id marked %d, %v", n, err)
	}
	if n, err := mark(w.ann, []string{annIn[0].ID, annIn[0].ID, patIn[0].ID}, false); err != nil || n != 1 {
		t.Errorf("mark one = %d, %v", n, err)
	}
	var unread int
	w.read(func(c *store.TenantTx) { unread, _ = c.CountUnreadNotifications(w.ann) })
	if unread != 2 {
		t.Errorf("unread = %d, want 2", unread)
	}
	if n, err := mark(w.ann, nil, true); err != nil || n != 2 {
		t.Errorf("mark all = %d, %v", n, err)
	}
	if n, err := mark(w.ann, nil, true); err != nil || n != 0 {
		t.Errorf("mark all again = %d, %v", n, err)
	}
	w.read(func(c *store.TenantTx) { unread, _ = c.CountUnreadNotifications(w.pat) })
	if unread != 1 {
		t.Errorf("pat's unread = %d, want 1: ann's marking touched it", unread)
	}
	if _, err := mark(w.ann, nil, false); err == nil {
		t.Error("an empty id list was accepted")
	}
	if n := w.audited("notification.read"); n != 2 {
		t.Errorf("%d read audit events, want 2 (the no-ops write none)", n)
	}
}

func TestInbox(t *testing.T) {
	w := newWorld(t)
	w.pref(w.ann, notify.KindRequestApproved, notify.ChannelEmail) // email only: not in the bell
	w.emit(notify.KindRequestApproved, "x", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	w.emit(notify.KindRequestDenied, "y", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	w.read(func(c *store.TenantTx) {
		items, unread, err := notify.Inbox(c, w.ann, true, 1000)
		if err != nil || unread != 1 || len(items) != 1 || items[0].Kind != notify.KindRequestDenied {
			t.Errorf("Inbox = %v, %d, %v", items, unread, err)
		}
	})
}

// ---------------------------------------------------------------- dispatch

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (w *world) dispatcher(s notify.Sender, c *clock) *notify.Dispatcher {
	return &notify.Dispatcher{DB: w.f.DB, Sender: s, Clock: c.now, MaxAttempts: 3, BaseURL: "https://tessera.example/", DigestHour: 8}
}

func (w *world) run(d *notify.Dispatcher) notify.Stats {
	w.t.Helper()
	st, err := d.Tenant(context.Background(), w.f.B.ID) // the fixture's tenant A has its own rows
	if err != nil {
		w.t.Fatal(err)
	}
	return st
}

func (w *world) one(user string) *store.Notification {
	w.t.Helper()
	got := w.inbox(user)
	if len(got) == 0 {
		w.t.Fatal("no notification")
	}
	return got[0]
}

func TestDispatch_SendsAndAudits(t *testing.T) {
	w := newWorld(t)
	w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	mail := &notify.MemorySender{}
	d := w.dispatcher(mail, &clock{t: w.now})
	if st := w.run(d); st.Sent != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if mail.Count() != 1 {
		t.Fatalf("%d emails", mail.Count())
	}
	e := mail.Sent[0]
	if e.To != w.annEmail || e.Subject != "[Tessera] subject k" || e.ID != w.one(w.ann).ID ||
		!strings.Contains(e.Body, "Open in Tessera: https://tessera.example/inbox") {
		t.Errorf("email = %+v", e)
	}
	n := w.one(w.ann)
	if n.Delivery != store.DeliverySent || n.Attempts != 1 || n.SentAt == nil || n.LastError != nil {
		t.Errorf("notification = %+v", n)
	}
	if got := w.audited("notification.send"); got != 1 {
		t.Errorf("%d send audit events, want 1", got)
	}
	// nothing more to do: a second run sends nothing (idempotent)
	if st := w.run(d); st.Sent != 0 || mail.Count() != 1 {
		t.Errorf("second run = %+v, %d emails", st, mail.Count())
	}
}

// TestDispatch_RetriesWithBackoffThenSucceeds: a failed send waits the
// backoff (30s, 60s, ...), is not tried early, and counts its attempts.
func TestDispatch_RetriesWithBackoffThenSucceeds(t *testing.T) {
	w := newWorld(t)
	w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	mail := &notify.MemorySender{Errs: []error{errors.New("421 try later " + w.annEmail), errors.New("451 busy")}}
	clk := &clock{t: w.now}
	d := w.dispatcher(mail, clk)

	if st := w.run(d); st.Retried != 1 || st.Sent != 0 {
		t.Fatalf("first run = %+v", st)
	}
	n := w.one(w.ann)
	if n.Delivery != store.DeliveryPending || n.Attempts != 1 || n.NextAttemptAt == nil || !n.NextAttemptAt.Equal(w.now.Add(30*time.Second)) {
		t.Fatalf("after attempt 1: %+v", n)
	}
	if n.LastError == nil || strings.Contains(*n.LastError, w.annEmail) {
		t.Errorf("last error %v must exist and not hold the address", n.LastError)
	}
	clk.add(29 * time.Second) // too early
	if st := w.run(d); st.Retried+st.Sent != 0 || w.one(w.ann).Attempts != 1 {
		t.Errorf("an early run tried again: %+v", st)
	}
	clk.add(time.Second)
	if st := w.run(d); st.Retried != 1 {
		t.Fatalf("second attempt = %+v", st)
	}
	n = w.one(w.ann)
	if n.Attempts != 2 || !n.NextAttemptAt.Equal(clk.now().Add(time.Minute)) {
		t.Fatalf("after attempt 2: %+v (backoff must double)", n)
	}
	clk.add(time.Minute)
	if st := w.run(d); st.Sent != 1 {
		t.Fatalf("third attempt = %+v", st)
	}
	if n = w.one(w.ann); n.Delivery != store.DeliverySent || n.Attempts != 3 {
		t.Errorf("final: %+v", n)
	}
	if got := w.audited("notification.send"); got != 3 {
		t.Errorf("%d send audit events, want 3 (every attempt)", got)
	}
}

func TestBackoff(t *testing.T) {
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute,
		32 * time.Minute, time.Hour, time.Hour}
	for i, w := range want {
		if got := notify.DefaultBackoff(i + 1); got != w {
			t.Errorf("DefaultBackoff(%d) = %s, want %s", i+1, got, w)
		}
	}
}

func TestDispatch_DeadLetters(t *testing.T) {
	cases := []struct {
		name     string
		errs     []error
		attempts int
	}{
		{"after MaxAttempts", []error{errors.New("a"), errors.New("b"), errors.New("c"), errors.New("d")}, 3},
		{"a permanent failure at once", []error{notify.ErrPermanent}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
			mail := &notify.MemorySender{Errs: tc.errs}
			clk := &clock{t: w.now}
			d := w.dispatcher(mail, clk)
			var total notify.Stats
			for i := 0; i < 6; i++ {
				st := w.run(d)
				total.Retried, total.Dead = total.Retried+st.Retried, total.Dead+st.Dead
				clk.add(time.Hour)
			}
			n := w.one(w.ann)
			if n.Delivery != store.DeliveryDead || n.Attempts != tc.attempts || n.LastError == nil || total.Dead != 1 {
				t.Errorf("notification = %+v, stats %+v", n, total)
			}
			if mail.Count() != 0 {
				t.Errorf("%d emails were sent", mail.Count())
			}
			if got := w.audited("notification.send"); got != tc.attempts {
				t.Errorf("%d audit events, want %d", got, tc.attempts)
			}
			// a dead letter is not picked up again, and still shows in the bell
			clk.add(24 * time.Hour)
			if st := w.run(d); st.Retried+st.Sent+st.Dead != 0 {
				t.Errorf("a dead letter was retried: %+v", st)
			}
			if !n.InApp {
				t.Error("the dead letter left the inbox")
			}
			w.read(func(c *store.TenantTx) {
				if n, _ := c.CountNotificationsDelivery(store.DeliveryDead); n != 1 {
					t.Errorf("%d dead letters", n)
				}
			})
		})
	}
}

// TestDispatch_ClaimIsALease: a claimed notification (a send in flight, or a
// crashed dispatcher) is not sent by a second run until its lease ends, and
// then it is retried as the next attempt.
func TestDispatch_ClaimIsALease(t *testing.T) {
	w := newWorld(t)
	w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	n := w.one(w.ann)
	w.tx(func(c *store.TenantTx) error { return c.ClaimNotification(n.ID, 0, w.now.Add(5*time.Minute)) })
	mail := &notify.MemorySender{}
	clk := &clock{t: w.now.Add(time.Minute)}
	d := w.dispatcher(mail, clk)
	if st := w.run(d); st.Sent != 0 || mail.Count() != 0 {
		t.Fatalf("a leased notification was sent: %+v", st)
	}
	// a second claimer with the same stale view loses
	w.tx(func(c *store.TenantTx) error {
		if err := c.ClaimNotification(n.ID, 0, w.now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("stale claim = %v, want ErrNotFound", err)
		}
		return nil
	})
	clk.add(10 * time.Minute)
	if st := w.run(d); st.Sent != 1 {
		t.Fatalf("after the lease: %+v", st)
	}
	if got := w.one(w.ann); got.Attempts != 2 || got.Delivery != store.DeliverySent {
		t.Errorf("notification = %+v", got)
	}
}

func TestDispatch_Concurrent(t *testing.T) {
	w := newWorld(t)
	for i := 0; i < 5; i++ {
		w.emit(notify.KindApprovalNeeded, "k"+string(rune('a'+i)), notify.Recipient{UserID: w.ann, Email: w.annEmail})
	}
	mail := &notify.MemorySender{}
	clk := &clock{t: w.now}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = w.dispatcher(mail, clk).Tenant(context.Background(), w.f.B.ID)
		}()
	}
	wg.Wait()
	ids := map[string]bool{}
	for _, e := range mail.Sent {
		if ids[e.ID] {
			t.Errorf("notification %s was sent twice", e.ID)
		}
		ids[e.ID] = true
	}
	if len(ids) != 5 {
		t.Errorf("%d distinct emails, want 5", len(ids))
	}
}

func TestDispatch_Skips(t *testing.T) {
	w := newWorld(t)
	w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	d := w.dispatcher(nil, &clock{t: w.now}) // email off
	if st := w.run(d); st.Skipped != 1 || st.Sent != 0 {
		t.Fatalf("stats = %+v", st)
	}
	n := w.one(w.ann)
	if n.Delivery != store.DeliverySkipped || n.LastError == nil || *n.LastError != "email is not configured" {
		t.Errorf("notification = %+v", n)
	}
	if !n.InApp {
		t.Error("the inbox entry went away")
	}
	if got := w.audited("notification.send"); got != 1 {
		t.Errorf("%d audit events, want 1", got)
	}
}

// ---------------------------------------------------------------- digest

func TestDispatch_DailyDigest(t *testing.T) {
	w := newWorld(t)
	w.pref(w.ann, notify.KindRequestApproved, notify.ChannelDigest)
	w.pref(w.ann, notify.KindRequestDenied, notify.ChannelDigest)
	early := time.Date(2026, 10, 8, 6, 0, 0, 0, time.UTC) // before the digest hour
	emit := func(at time.Time, kind, key string) {
		w.tx(func(c *store.TenantTx) error {
			_, err := notify.Emit(c, at, notify.Message{Kind: kind, Key: key, Subject: "subject " + key, Body: "b"},
				notify.Recipient{UserID: w.ann, Email: w.annEmail})
			return err
		})
	}
	emit(early, notify.KindRequestApproved, "one")
	emit(early, notify.KindRequestDenied, "two")
	mail := &notify.MemorySender{}
	clk := &clock{t: early}
	d := w.dispatcher(mail, clk)

	if st := w.run(d); st.Digests != 0 || mail.Count() != 0 {
		t.Fatalf("before the digest hour: %+v, %d emails", st, mail.Count())
	}
	for _, n := range w.inbox(w.ann) {
		if n.Delivery != store.DeliveryDigest || !n.InApp {
			t.Errorf("%s: delivery %s in_app %v: a digest item is in the bell and waits", n.Subject, n.Delivery, n.InApp)
		}
	}
	clk.add(3 * time.Hour) // 09:00
	if st := w.run(d); st.Digests != 1 || st.Sent != 1 {
		t.Fatalf("at the digest hour: %+v", st)
	}
	if mail.Count() != 1 {
		t.Fatalf("%d emails, want one digest", mail.Count())
	}
	e := mail.Sent[0]
	if !strings.Contains(e.Subject, "Daily digest: 2") || !strings.Contains(e.Body, "subject one") || !strings.Contains(e.Body, "subject two") {
		t.Errorf("digest = %+v", e)
	}
	for _, n := range w.inbox(w.ann) {
		if n.Kind != notify.KindDigest && n.Delivery != store.DeliveryDigested {
			t.Errorf("%s: delivery %s, want digested", n.Subject, n.Delivery)
		}
	}
	if len(w.inbox(w.ann)) != 2 {
		t.Error("the digest email itself must not appear in the bell")
	}
	if got := w.audited("notification.digest"); got != 1 {
		t.Errorf("%d digest audit events, want 1", got)
	}
	// an item after today's digest waits for tomorrow's; the same day builds no second one
	emit(clk.now(), notify.KindRequestApproved, "three")
	if st := w.run(d); st.Digests != 0 || mail.Count() != 1 {
		t.Errorf("same day again: %+v, %d emails", st, mail.Count())
	}
	clk.add(24 * time.Hour)
	if st := w.run(d); st.Digests != 1 || mail.Count() != 2 || !strings.Contains(mail.Sent[1].Body, "subject three") {
		t.Errorf("next day: %+v, emails %d", st, mail.Count())
	}
}

// ---------------------------------------------------------------- scan

// TestScan_ExpiringJITAndRequestLines: access ending within the window is
// announced once, however often the scan runs.
func TestScan_ExpiringJITAndRequestLines(t *testing.T) {
	w := newWorld(t)
	// the fixture's active JIT grant is bob's and ends at now+1h; alice's request line ends within the day
	w.tx(func(c *store.TenantTx) error {
		item, grp, acct := "item-x", w.f.B.IDs["group:okta:eng"], w.f.B.IDs["acct:okta:alice"]
		u, _ := uuid.Parse(w.ann)
		if err := c.PutCatalogItem(&store.CatalogItem{ID: item, GroupID: grp, Requestable: true, Risk: "low", UpdatedAt: w.now}); err != nil {
			return err
		}
		if err := c.InsertRequestLine(&store.RequestLine{ID: "line-x", BatchID: "b", CatalogItemID: item, GroupID: grp,
			BeneficiaryID: w.f.B.IDs["alice"], AccountID: acct, RequestedBy: u.String(), Justification: "j", RequestedAt: w.now}); err != nil {
			return err
		}
		exp := w.now.Add(10 * time.Hour)
		l, _ := c.RequestLine("line-x")
		l.Status, l.ExpiresAt = store.RequestApproved, &exp
		return c.SaveRequestLine(l, store.RequestPending)
	})
	w.setJIT("approved")
	mail := &notify.MemorySender{}
	d := w.dispatcher(mail, &clock{t: w.now})
	// bob's JIT grant: bob has no sign-in, so he is told by email; the request line: ann is both the
	// requester and (as alice) the beneficiary, one inbox entry
	st := w.run(d)
	if st.Scanned != 2 || st.Sent != 1 || mail.Count() != 1 || mail.Sent[0].To != "bob@t.example" {
		t.Fatalf("first scan: %+v, emails %v", st, mail.Sent)
	}
	if got := w.inbox(w.ann); len(got) != 1 || got[0].Kind != notify.KindRequestExpiring {
		t.Fatalf("ann's inbox = %+v", got)
	}
	for i := 0; i < 3; i++ {
		if st := w.run(d); st.Scanned != 0 || st.Sent != 0 {
			t.Errorf("repeat scan %d: %+v", i, st)
		}
	}
	if len(w.inbox(w.ann)) != 1 || mail.Count() != 1 {
		t.Error("a repeat scan notified again")
	}
}

// TestScan_OutsideTheWindow: access that ends later than the warning window is not announced yet.
func TestScan_OutsideTheWindow(t *testing.T) {
	w := newWorld(t)
	w.setJIT("approved") // ends at now+1h
	d := w.dispatcher(&notify.MemorySender{}, &clock{t: w.now.Add(-4 * time.Hour)})
	if st := w.run(d); st.Scanned != 0 {
		t.Errorf("scanned %d long before the one-hour window", st.Scanned)
	}
}

// TestExpiring_Producer: the producer #159 calls for identity and grant end
// dates: the person and the people in Also are told once per end date.
func TestExpiring_Producer(t *testing.T) {
	w := newWorld(t)
	end := w.now.Add(14 * 24 * time.Hour)
	emit := func(e notify.Ending) (n int) {
		w.tx(func(c *store.TenantTx) (err error) { n, err = notify.Expiring(c, w.now, e); return err })
		return n
	}
	e := notify.Ending{Key: "identity:alice", IdentityID: w.f.B.IDs["alice"], Also: []int64{w.f.B.IDs["bob"]}, What: "Alice's contract", EndsAt: end}
	if n := emit(e); n != 2 { // alice's user (bell) and bob (email only)
		t.Fatalf("wrote %d, want 2", n)
	}
	if n := emit(e); n != 0 {
		t.Errorf("repeat wrote %d", n)
	}
	e.EndsAt = end.Add(24 * time.Hour) // the end date moved: tell again
	if n := emit(e); n != 2 {
		t.Errorf("a moved end date wrote %d, want 2", n)
	}
	got := w.inbox(w.ann)
	if len(got) != 2 || got[0].Kind != notify.KindAccessEnding || got[0].Link != "/access/mine" || !strings.Contains(got[0].Subject, "Alice's contract") {
		t.Errorf("inbox = %+v", got)
	}
}

func TestSecurityAlert_CannotBeSilenced(t *testing.T) {
	w := newWorld(t)
	w.pref(w.ann, notify.KindSecurityAlert, notify.ChannelOff) // a stale or hand-edited row
	var n int
	w.tx(func(c *store.TenantTx) (err error) {
		n, err = notify.SecurityAlert(c, w.now, "k", "Admin role granted", "body", "/admin", notify.Recipient{UserID: w.ann, Email: w.annEmail})
		return err
	})
	if n != 1 || len(w.inbox(w.ann)) != 1 {
		t.Errorf("wrote %d, inbox %d", n, len(w.inbox(w.ann)))
	}
}

func TestKindsAreConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range Kinds() {
		if seen[k.ID] || k.Label == "" || k.Description == "" || !slices.Contains(notify.Channels, k.Default) {
			t.Errorf("kind %+v", k)
		}
		seen[k.ID] = true
		if k.Mandatory && k.Default == notify.ChannelOff {
			t.Errorf("%s: a mandatory kind defaults to off", k.ID)
		}
	}
	if !seen[notify.KindSecurityAlert] {
		t.Error("no security alert kind")
	}
}

func Kinds() []notify.Kind { return notify.Kinds }

// TestDispatch_RunOnceServesEveryTenantSeparately: one pass reaches each
// tenant's own outbox, and a tenant's notification is audited in its own chain.
func TestDispatch_RunOnceServesEveryTenantSeparately(t *testing.T) {
	w := newWorld(t)
	w.emit(notify.KindApprovalNeeded, "k", notify.Recipient{UserID: w.ann, Email: w.annEmail})
	mail := &notify.MemorySender{}
	st, err := w.dispatcher(mail, &clock{t: w.now}).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var to []string
	for _, e := range mail.Sent {
		to = append(to, e.To)
	}
	// B's own email, and A's JIT warning (A's rows carry the sentinel, B's do not)
	if !slices.Contains(to, w.annEmail) || st.Sent != len(to) {
		t.Errorf("emails to %v, stats %+v", to, st)
	}
	for _, e := range mail.Sent {
		if e.To != w.annEmail && !strings.Contains(e.To, "zz-larkspur-sentinel") {
			t.Errorf("an email went to %s, who is in neither tenant's rows", e.To)
		}
		if e.To == w.annEmail && strings.Contains(strings.ToLower(e.Subject+e.Body), "zz-larkspur-sentinel") {
			t.Errorf("tenant B's email carries tenant A's data: %+v", e)
		}
	}
	if n := w.audited("notification.send"); n != 1 {
		t.Errorf("tenant B has %d send audit events, want 1", n)
	}
}

// ---------------------------------------------------------------- reviews

// TestReviews_LaunchReminderAndClose: the fixture's campaign has one item for
// carol, who does not sign in, so she is reached at her address. Launch and
// close tell her once; a reminder follows each week the campaign stays open.
func TestReviews_LaunchReminderAndClose(t *testing.T) {
	w := newWorld(t)
	camp := w.f.B.IDs["campaign"]
	mail := &notify.MemorySender{}
	clk := &clock{t: w.now}
	d := w.dispatcher(mail, clk)
	launch := func() {
		w.tx(func(c *store.TenantTx) error { return notify.ReviewLaunched(c, w.now, camp) })
	}
	launch()
	launch() // the same event again
	w.run(d)
	if mail.Count() != 1 || mail.Sent[0].To != "carol@t.example" || !strings.Contains(mail.Sent[0].Subject, "Access review launched") ||
		!strings.Contains(mail.Sent[0].Body, "/governance/reviews") {
		t.Fatalf("launch emails = %+v", mail.Sent)
	}
	clk.add(6 * 24 * time.Hour)
	if st := w.run(d); st.Scanned != 0 {
		t.Errorf("a reminder came after 6 days: %+v", st)
	}
	clk.add(2 * 24 * time.Hour) // day 8
	if st := w.run(d); st.Scanned != 1 || st.Sent != 1 || !strings.Contains(mail.Sent[1].Subject, "Reminder") {
		t.Errorf("day 8: %+v, %+v", st, mail.Sent)
	}
	if st := w.run(d); st.Scanned != 0 {
		t.Errorf("the reminder repeated: %+v", st)
	}
	clk.add(7 * 24 * time.Hour) // day 15
	if st := w.run(d); st.Scanned != 1 {
		t.Errorf("no second weekly reminder: %+v", st)
	}
	// a decided campaign is not reminded about
	w.tx(func(c *store.TenantTx) error {
		if err := c.DecideItem(w.f.B.IDs["item"], "keep", nil, clk.now(), store.UserRef{}); err != nil {
			return err
		}
		return c.CompleteCampaign(camp)
	})
	clk.add(7 * 24 * time.Hour)
	if st := w.run(d); st.Scanned != 0 {
		t.Errorf("a completed campaign was reminded about: %+v", st)
	}
	w.tx(func(c *store.TenantTx) error { return notify.ReviewClosed(c, clk.now(), camp) })
	before := mail.Count()
	w.run(d)
	if mail.Count() != before+1 || !strings.Contains(mail.Sent[before].Subject, "Access review closed") {
		t.Errorf("close emails = %+v", mail.Sent[before:])
	}
}
