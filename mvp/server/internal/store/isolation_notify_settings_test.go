package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Tenant notification settings (schema 0760 to 0764): each tenant reads and writes only its own relay, chat webhook, wording,
// timings and suppression list, and the tables' own checks refuse what the API never sends.

func TestIsolation_MailRelay(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	put := func(tn storetest.Tenant, host string, sealed []byte) {
		t.Helper()
		if err := f.DB.InTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			return c.PutMailRelay(&store.MailRelayRow{Enabled: true, Host: host, Port: 587, TLS: "starttls", Username: "u", PasswordSealed: sealed,
				From: "t@" + host, UpdatedBy: "admin " + host}, storetest.Now)
		}); err != nil {
			t.Fatal(err)
		}
	}
	put(f.A, "smtp.a.example", []byte("sealed-a"))
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.MailRelay(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's relay: %v", err)
		}
		if err := c.SetMailRelayTest(storetest.Now, "accepted"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B records a test on A's relay: %v", err)
		}
		if err := c.DeleteMailRelay(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B deletes A's relay: %v", err)
		}
		return nil
	})
	put(f.B, "smtp.b.example", nil)
	put(f.B, "smtp.b2.example", nil)
	inA(t, f, func(c *store.TenantTx) error {
		r, err := c.MailRelay()
		if err != nil || r.Host != "smtp.a.example" || r.Version != 1 || string(r.PasswordSealed) != "sealed-a" || r.UpdatedBy != "admin smtp.a.example" {
			t.Errorf("A's relay changed by B's saves: %+v %v", r, err)
		}
		if err := c.SetMailRelayTest(storetest.Now, "accepted"); err != nil {
			t.Error(err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		r, err := c.MailRelay()
		if err != nil || r.Host != "smtp.b2.example" || r.Version != 2 || len(r.PasswordSealed) != 0 || r.LastTestAt != nil {
			t.Errorf("B's relay: %+v %v", r, err)
		}
		return nil
	})
	for name, row := range map[string]store.MailRelayRow{
		"port 0":      {Host: "h.example", Port: 0, TLS: "starttls", From: "a@b.example"},
		"port 70000":  {Host: "h.example", Port: 70000, TLS: "starttls", From: "a@b.example"},
		"unknown tls": {Host: "h.example", Port: 25, TLS: "ssl", From: "a@b.example"},
		"empty host":  {Host: "", Port: 25, TLS: "tls", From: "a@b.example"},
		"short from":  {Host: "h.example", Port: 25, TLS: "tls", From: "a"},
	} {
		row.UpdatedBy = "x"
		if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { return c.PutMailRelay(&row, storetest.Now) }); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIsolation_ChatWebhook(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	now := storetest.Now
	put := func(tn storetest.Tenant, enabled bool, at time.Time) {
		t.Helper()
		if err := f.DB.InTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			return c.PutChatWebhook(&store.ChatWebhookRow{Provider: "slack", Enabled: enabled, WebhookSealed: []byte("sealed"), WebhookHost: "hooks.slack.com",
				Kinds: `["request.approval_needed"]`, UpdatedBy: "admin"}, at)
		}); err != nil {
			t.Fatal(err)
		}
	}
	put(f.A, true, now)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.ChatWebhook(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's webhook: %v", err)
		}
		if err := c.SetChatProgress(&store.ChatWebhookRow{CursorAt: "x"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B moves A's cursor: %v", err)
		}
		if err := c.DeleteChatWebhook(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B deletes A's webhook: %v", err)
		}
		return nil
	})
	// turning it on starts the cursor at that moment; saving it again while on leaves the cursor alone
	inA(t, f, func(c *store.TenantTx) error {
		r, err := c.ChatWebhook()
		if err != nil || r.CursorAt != store.T(now) || !r.Enabled || r.Version != 1 {
			t.Fatalf("A's webhook: %+v %v", r, err)
		}
		r.CursorAt, r.CursorID, r.CursorKey, r.FailCount, r.LastError = store.T(now.Add(time.Hour)), "id1", "key1", 2, "HTTP 500"
		return c.SetChatProgress(r)
	})
	put(f.A, true, now.Add(2*time.Hour))
	inA(t, f, func(c *store.TenantTx) error {
		r, _ := c.ChatWebhook()
		if r.CursorAt != store.T(now.Add(time.Hour)) || r.CursorID != "id1" || r.CursorKey != "key1" || r.FailCount != 0 || r.LastError != "" || r.Version != 2 {
			t.Errorf("a save while on: %+v", r)
		}
		return nil
	})
	put(f.A, false, now.Add(3*time.Hour))
	put(f.A, true, now.Add(4*time.Hour)) // off, then on: starts again, no replay
	inA(t, f, func(c *store.TenantTx) error {
		r, _ := c.ChatWebhook()
		if r.CursorAt != store.T(now.Add(4*time.Hour)) || r.CursorID != "" || r.CursorKey != "" {
			t.Errorf("after off and on: %+v", r)
		}
		return nil
	})
	put(f.B, true, now)
	inB(t, f, func(c *store.TenantTx) error {
		if r, err := c.ChatWebhook(); err != nil || r.Version != 1 || r.CursorID != "" {
			t.Errorf("B's webhook: %+v %v", r, err)
		}
		return nil
	})
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.PutChatWebhook(&store.ChatWebhookRow{Provider: "discord", WebhookSealed: []byte("x"), WebhookHost: "h", Kinds: "[]", UpdatedBy: "x"}, now)
	}); err == nil {
		t.Error("an unknown provider was accepted")
	}
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		return c.PutChatWebhook(&store.ChatWebhookRow{Provider: "slack", WebhookSealed: []byte("x"), WebhookHost: "h", Kinds: "not json", UpdatedBy: "x"}, now)
	}); err == nil {
		t.Error("kinds that are not JSON were accepted")
	}
}

// NotificationsAfter and EmailMessageByQueueID read the calling tenant's rows only.
func TestIsolation_NotificationsAfterAndQueueID(t *testing.T) {
	f := storetest.TwoTenants(t)
	inB(t, f, func(c *store.TenantTx) error {
		rows, err := c.NotificationsAfter("", "", storetest.Now.Add(24*time.Hour), 100)
		if err != nil {
			t.Fatal(err)
		}
		if hasSentinel(rows) {
			t.Errorf("tenant B sees A's notifications: %v", rows)
		}
		if _, err := c.EmailMessageByQueueID("nope"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("queue id = %v", err)
		}
		if _, err := c.NotificationDeliveryOf("nope"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("delivery of = %v", err)
		}
		return nil
	})
}

func TestIsolation_NotificationTemplatesPolicyAndSuppressions(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	now := storetest.Now
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		tag := tn.Slug
		if err := f.DB.InTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			if err := c.PutNotificationTemplate(&store.NotificationTemplateRow{Kind: "request.approval_needed", Subject: "s " + tag, Body: "b " + tag, UpdatedBy: tag}, now); err != nil {
				return err
			}
			if err := c.PutNotificationPolicy(&store.NotificationPolicyRow{ReviewRemindAfterDays: 3, ReviewRemindEveryDays: 4, RequestWarnHours: 5,
				JITWarnMinutes: 30, EscalateAfterHours: 12 + len(tag), UpdatedBy: tag}, now); err != nil {
				return err
			}
			_, err := c.PutEmailSuppression(&store.EmailSuppressionRow{Address: "x@" + tag + ".example", Reason: store.SuppressManual, Note: tag, CreatedBy: tag}, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		other := f.A.Slug
		if tn.ID == f.A.ID {
			other = f.B.Slug
		}
		if err := f.DB.InTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			ts, err := c.NotificationTemplates()
			if err != nil || len(ts) != 1 || ts[0].Subject != "s "+tn.Slug {
				t.Errorf("%s templates = %+v %v", tn.Slug, ts, err)
			}
			p, err := c.NotificationPolicy()
			if err != nil || p.EscalateAfterHours != 12+len(tn.Slug) || p.Version != 1 || p.UpdatedBy != tn.Slug {
				t.Errorf("%s policy = %+v %v", tn.Slug, p, err)
			}
			ss, err := c.EmailSuppressions()
			if err != nil || len(ss) != 1 || ss[0].CreatedBy != tn.Slug {
				t.Errorf("%s suppressions = %+v %v", tn.Slug, ss, err)
			}
			if _, err := c.EmailSuppression("x@" + other + ".example"); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s reads %s's suppression: %v", tn.Slug, other, err)
			}
			if err := c.DeleteEmailSuppression("x@" + other + ".example"); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s lifts %s's suppression: %v", tn.Slug, other, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// a second save moves the version on; a suppression keeps its first reason
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if err := c.PutNotificationPolicy(&store.NotificationPolicyRow{ReviewRemindAfterDays: 2, ReviewRemindEveryDays: 2, RequestWarnHours: 2, JITWarnMinutes: 10, EscalateAfterHours: 2, UpdatedBy: "x"}, now); err != nil {
			return err
		}
		if p, _ := c.NotificationPolicy(); p.Version != 2 {
			t.Errorf("version = %d", p.Version)
		}
		added, err := c.PutEmailSuppression(&store.EmailSuppressionRow{Address: "x@" + f.A.Slug + ".example", Reason: store.SuppressHardBounce, CreatedBy: "x"}, now)
		if err != nil || added {
			t.Errorf("second suppression = %v, %v", added, err)
		}
		if s, _ := c.EmailSuppression("x@" + f.A.Slug + ".example"); s.Reason != store.SuppressManual {
			t.Errorf("reason = %s", s.Reason)
		}
		return c.DeleteNotificationTemplate("request.approval_needed")
	}); err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if ts, _ := c.NotificationTemplates(); len(ts) != 1 {
			t.Errorf("B's template went with A's: %+v", ts)
		}
		return nil
	})
	for name, row := range map[string]store.NotificationPolicyRow{
		"after 0":      {ReviewRemindAfterDays: 0, ReviewRemindEveryDays: 1, RequestWarnHours: 1, JITWarnMinutes: 5, EscalateAfterHours: 1},
		"every 91":     {ReviewRemindAfterDays: 1, ReviewRemindEveryDays: 91, RequestWarnHours: 1, JITWarnMinutes: 5, EscalateAfterHours: 1},
		"jit 4":        {ReviewRemindAfterDays: 1, ReviewRemindEveryDays: 1, RequestWarnHours: 1, JITWarnMinutes: 4, EscalateAfterHours: 1},
		"escalate 721": {ReviewRemindAfterDays: 1, ReviewRemindEveryDays: 1, RequestWarnHours: 1, JITWarnMinutes: 5, EscalateAfterHours: 721},
	} {
		row.UpdatedBy = "x"
		if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error { return c.PutNotificationPolicy(&row, now) }); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		_, err := c.PutEmailSuppression(&store.EmailSuppressionRow{Address: "y@a.example", Reason: "other", CreatedBy: "x"}, now)
		return err
	}); err == nil {
		t.Error("an unknown suppression reason was accepted")
	}
}

func notifySettingsCovered() map[string]bool {
	m := map[string]bool{}
	for _, n := range []string{"MailRelay", "PutMailRelay", "DeleteMailRelay", "SetMailRelayTest", "ChatWebhook", "PutChatWebhook", "DeleteChatWebhook",
		"SetChatProgress", "NotificationsAfter", "NotificationTemplates", "PutNotificationTemplate", "DeleteNotificationTemplate", "NotificationPolicy",
		"PutNotificationPolicy", "EmailSuppressions", "EmailSuppression", "PutEmailSuppression", "DeleteEmailSuppression", "EmailMessageByQueueID",
		"NotificationDeliveryOf"} {
		m[n] = true
	}
	return m
}
