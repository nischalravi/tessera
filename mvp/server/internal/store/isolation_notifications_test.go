package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Notification isolation (issue #189): a tenant sees and changes only its
// own outbox, inbox and preferences; another tenant's ids look nonexistent
// and a row naming another tenant's user or identity is refused by the guard
// triggers.

type notifRows struct {
	reqRows
	due    string // a notification with email pending
	digest string // one waiting for the digest
	dedupe string
	msg    string // the email delivery record of due
}

func seedNotifRows(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) notifRows {
	t.Helper()
	r := notifRows{reqRows: seedReqRows(t, db, tn, tag), due: "n-due-" + tag, digest: "n-dig-" + tag, msg: "m-" + tag, dedupe: "k-due-" + tag}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		uid, email, now := r.user.ID.String(), "u-"+tag+"@t.example", storetest.Now
		if ok, err := c.InsertNotification(&store.Notification{ID: r.due, UserID: &uid, Email: &email, Kind: "request.approved",
			Subject: "s " + tag, Body: "b", DedupeKey: r.dedupe, InApp: true, CreatedAt: now, Delivery: store.DeliveryPending,
			NextAttemptAt: &now}); err != nil || !ok {
			t.Fatalf("InsertNotification = %v, %v", ok, err)
		}
		if _, err := c.InsertNotification(&store.Notification{ID: r.digest, UserID: &uid, Email: &email, Kind: "request.approved",
			Subject: "d " + tag, Body: "b", DedupeKey: "k-dig-" + tag, InApp: true, CreatedAt: now, Delivery: store.DeliveryDigest}); err != nil {
			return err
		}
		if err := c.PutNotificationPref(uid, "request.approved", "both", now); err != nil {
			return err
		}
		if err := c.EnsureEmailMessage(&store.EmailMessage{ID: r.msg, NotificationID: r.due, Kind: "request.approved",
			Recipient: email, Subject: "s " + tag, CreatedAt: now}); err != nil {
			return err
		}
		// an approved request line that ends within the hour
		exp := now.Add(time.Hour)
		l, err := c.RequestLine(r.line)
		if err != nil {
			return err
		}
		l.Status, l.ExpiresAt = store.RequestApproved, &exp
		return c.SaveRequestLine(l, store.RequestPending)
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func notifFixture(t *testing.T) (*storetest.Fixture, notifRows, notifRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedNotifRows(t, f.DB, f.A, "a"), seedNotifRows(t, f.DB, f.B, "b")
}

func TestIsolation_NotificationReads(t *testing.T) {
	f, a, b := notifFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		bu, au := b.user.ID.String(), a.user.ID.String()
		if ns, err := c.Notifications(bu, false, 50); err != nil || len(ns) != 2 || ns[0].Subject == "s a" {
			t.Errorf("Notifications(B's user) = %v, %v", ns, err)
		}
		if ns, err := c.Notifications(au, false, 50); err != nil || len(ns) != 0 {
			t.Errorf("Notifications(A's user) = %v, %v", ns, err)
		}
		if n, err := c.CountUnreadNotifications(au); err != nil || n != 0 {
			t.Errorf("CountUnreadNotifications(A's user) = %d, %v", n, err)
		}
		if ok, err := c.HasNotification(a.dedupe); err != nil || ok {
			t.Errorf("HasNotification(A's key) = %v, %v", ok, err)
		}
		if ok, err := c.HasNotification(b.dedupe); err != nil || !ok {
			t.Errorf("HasNotification(B's key) = %v, %v", ok, err)
		}
		if ns, err := c.DueNotifications(storetest.Now, 50); err != nil || len(ns) != 1 || ns[0].ID != b.due {
			t.Errorf("DueNotifications = %v, %v", ns, err)
		}
		if ns, err := c.DigestWaiting(); err != nil || len(ns) != 1 || ns[0].ID != b.digest {
			t.Errorf("DigestWaiting = %v, %v", ns, err)
		}
		if n, err := c.CountNotificationsDelivery(store.DeliveryPending); err != nil || n != 1 {
			t.Errorf("CountNotificationsDelivery = %d, %v", n, err)
		}
		if ps, err := c.NotificationPrefs(au); err != nil || len(ps) != 0 {
			t.Errorf("NotificationPrefs(A's user) = %v, %v", ps, err)
		}
		if ps, err := c.NotificationPrefs(bu); err != nil || len(ps) != 1 {
			t.Errorf("NotificationPrefs(B's user) = %v, %v", ps, err)
		}
		roles, err := c.ActiveUserRoles(storetest.Now)
		if err != nil {
			return err
		}
		for _, r := range roles {
			if r.UserID == au {
				t.Errorf("ActiveUserRoles lists A's user %s", au)
			}
		}
		if ls, err := c.ReviewerLoads(f.A.IDs["campaign"]); err != nil || len(ls) != 0 {
			t.Errorf("ReviewerLoads(A's campaign) = %v, %v", ls, err)
		}
		if ls, err := c.ReviewerLoads(f.B.IDs["campaign"]); err != nil || len(ls) != 1 || ls[0].ReviewerID != f.B.IDs["carol"] || ls[0].Open != 1 {
			t.Errorf("ReviewerLoads(B's campaign) = %v, %v", ls, err)
		}
		if ms, err := c.EmailMessages(store.EmailFilter{}); err != nil || len(ms) != 1 || ms[0].ID != b.msg {
			t.Errorf("EmailMessages = %v, %v", ms, err)
		}
		if _, err := c.EmailMessage(a.msg); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("EmailMessage(A's) = %v", err)
		}
		if _, err := c.EmailMessageForNotification(a.due); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("EmailMessageForNotification(A's) = %v", err)
		}
		from, to := storetest.Now, storetest.Now.Add(24*time.Hour)
		if rs, err := c.JITExpiringBetween(from, to); err != nil || len(rs) != 1 || rs[0].ID != f.B.IDs["request:approved"] {
			t.Errorf("JITExpiringBetween = %v, %v", rs, err)
		}
		if ls, err := c.RequestLinesExpiringBetween(from, to); err != nil || len(ls) != 1 || ls[0].ID != b.line {
			t.Errorf("RequestLinesExpiringBetween = %v, %v", ls, err)
		}
		return nil
	})
}

var notifMutations = map[string]func(c *store.TenantTx, a, b notifRows) error{
	"InsertNotification": func(c *store.TenantTx, a, _ notifRows) error {
		uid := a.user.ID.String() // A's user, named from B
		_, err := c.InsertNotification(&store.Notification{ID: "x", UserID: &uid, Kind: "k", Subject: "s", Body: "b",
			DedupeKey: "x", InApp: true, CreatedAt: storetest.Now, Delivery: store.DeliveryNone})
		return err
	},
	"InsertNotification.identity_id": func(c *store.TenantTx, a, _ notifRows) error {
		_, err := c.InsertNotification(&store.Notification{ID: "y", IdentityID: &a.alice, Kind: "k", Subject: "s", Body: "b",
			DedupeKey: "y", CreatedAt: storetest.Now, Delivery: store.DeliveryNone})
		return err
	},
	"MarkNotificationsRead": func(c *store.TenantTx, a, b notifRows) error {
		n, err := c.MarkNotificationsRead(b.user.ID.String(), []string{a.due}, storetest.Now)
		if err == nil && n == 0 {
			err = store.ErrNotFound
		}
		return err
	},
	"MarkAllNotificationsRead": func(c *store.TenantTx, a, _ notifRows) error {
		n, err := c.MarkAllNotificationsRead(a.user.ID.String(), storetest.Now)
		if err == nil && n == 0 {
			err = store.ErrNotFound
		}
		return err
	},
	"ClaimNotification": func(c *store.TenantTx, a, _ notifRows) error {
		return c.ClaimNotification(a.due, 0, storetest.Now.Add(time.Minute))
	},
	"FinishNotification": func(c *store.TenantTx, a, _ notifRows) error {
		return c.FinishNotification(a.due, 0, store.DeliverySent, nil, nil, nil)
	},
	"EnsureEmailMessage": func(c *store.TenantTx, a, _ notifRows) error {
		return c.EnsureEmailMessage(&store.EmailMessage{ID: "x", NotificationID: a.digest, Kind: "k", Recipient: "r", Subject: "s", CreatedAt: storetest.Now})
	},
	"SaveEmailMessage": func(c *store.TenantTx, a, _ notifRows) error {
		return c.SaveEmailMessage(&store.EmailMessage{ID: a.msg, Status: store.EmailAccepted, UpdatedAt: storetest.Now})
	},
	"RequeueNotification": func(c *store.TenantTx, a, _ notifRows) error {
		return c.RequeueNotification(a.due, storetest.Now)
	},
	"MarkDigested": func(c *store.TenantTx, a, _ notifRows) error { return c.MarkDigested(a.digest) },
	"PutNotificationPref": func(c *store.TenantTx, a, _ notifRows) error {
		return c.PutNotificationPref(a.user.ID.String(), "request.approved", "off", storetest.Now)
	},
}

func TestIsolation_NotificationMutationsScoped(t *testing.T) {
	for name, fn := range notifMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := notifFixture(t)
			before := notifDump(t, f.DB, f.A.ID, a)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v", name, err)
			}
			if notifDump(t, f.DB, f.A.ID, a) != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

// TestIsolation_NotificationDedupeIsPerTenant: the same dedupe key in two
// tenants is two notifications, and a repeat in one tenant writes nothing.
func TestIsolation_NotificationDedupeIsPerTenant(t *testing.T) {
	f, a, b := notifFixture(t)
	for _, tc := range []struct {
		tn   storetest.Tenant
		u    notifRows
		want bool
	}{{f.A, a, false}, {f.B, b, false}} {
		err := f.DB.InTenant(context.Background(), tc.tn.ID, func(c *store.TenantTx) error {
			uid := tc.u.user.ID.String()
			ok, err := c.InsertNotification(&store.Notification{ID: "again-" + uid, UserID: &uid, Kind: "k", Subject: "s", Body: "b",
				DedupeKey: tc.u.dedupe, InApp: true, CreatedAt: storetest.Now, Delivery: store.DeliveryNone})
			if ok != tc.want {
				t.Errorf("repeat of %s wrote = %v", tc.u.dedupe, ok)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		uid := b.user.ID.String()
		ok, err := c.InsertNotification(&store.Notification{ID: "same-key-as-a", UserID: &uid, Kind: "k", Subject: "s", Body: "b",
			DedupeKey: a.dedupe, InApp: true, CreatedAt: storetest.Now, Delivery: store.DeliveryNone})
		if !ok {
			t.Error("A's dedupe key blocked B from writing its own notification")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func notifDump(t *testing.T, db *store.DB, tid tenancy.ID, r notifRows) string {
	t.Helper()
	out := reqDump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		uid := r.user.ID.String()
		ns, err := c.Notifications(uid, false, -1)
		if err != nil {
			return err
		}
		ps, err := c.NotificationPrefs(uid)
		if err != nil {
			return err
		}
		due, err := c.DueNotifications(storetest.Now.Add(time.Hour), 100)
		if err != nil {
			return err
		}
		ms, err := c.EmailMessages(store.EmailFilter{})
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{ns, ps, due, ms})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func notificationsCovered() map[string]bool {
	out := map[string]bool{}
	for k := range notifMutations {
		out[k] = true
	}
	for _, k := range []string{"Notifications", "CountUnreadNotifications", "HasNotification", "DueNotifications", "DigestWaiting",
		"CountNotificationsDelivery", "NotificationPrefs", "ActiveUserRoles", "ReviewerLoads", "JITExpiringBetween",
		"RequestLinesExpiringBetween", "EmailMessages", "EmailMessage", "EmailMessageForNotification"} {
		out[k] = true // TestIsolation_NotificationReads
	}
	return out
}
