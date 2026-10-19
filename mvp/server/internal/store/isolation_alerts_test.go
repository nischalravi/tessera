package store_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Alerting isolation (issue #168): a tenant sees and changes only its own
// rule settings, alerts, channels, deliveries and cursor, and no row may
// point at another tenant's user, alert or channel.

type alertRows struct {
	alert, channel, delivery, user string
}

func seedAlertRows(t *testing.T, f *storetest.Fixture, tn storetest.Tenant, tag string) alertRows {
	t.Helper()
	r := alertRows{alert: "alert-" + tag, channel: "chan-" + tag, delivery: "deliv-" + tag}
	now := storetest.Now
	fn := func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "alerts " + tag, CreatedAt: now}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		r.user = u.ID.String()
		if err := c.PutAlertRuleSetting(&store.AlertRuleSetting{RuleID: "signin_failures", Enabled: true, Severity: "high",
			Threshold: 3, WindowMinutes: 10, UpdatedBy: &r.user, UpdatedAt: now}); err != nil {
			return err
		}
		if err := c.InsertAlert(&store.Alert{ID: r.alert, RuleID: "signin_failures", DedupKey: "k", Severity: "high", Title: "t " + tag,
			Detail: json.RawMessage(`{}`), Count: 1, FirstSeenAt: now, LastSeenAt: now}); err != nil {
			return err
		}
		if err := c.InsertAlertChannel(&store.AlertChannel{ID: r.channel, Name: "ops " + tag, Kind: "email", Target: "ops@example.com",
			MinSeverity: "low", Enabled: true, CreatedBy: &r.user, CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		if err := c.InsertAlertDelivery(&store.AlertDelivery{ID: r.delivery, AlertID: r.alert, ChannelID: r.channel, Reason: "raised",
			NextAttemptAt: now.Add(-time.Minute), CreatedAt: now}); err != nil {
			return err
		}
		return c.SetAlertCursor(7, now)
	}
	if tn.ID == f.A.ID {
		inA(t, f, fn)
	} else {
		inB(t, f, fn)
	}
	return r
}

func alertFixture(t *testing.T) (*storetest.Fixture, alertRows, alertRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedAlertRows(t, f, f.A, "a"), seedAlertRows(t, f, f.B, "b")
}

func TestIsolation_AlertReads(t *testing.T) {
	f, a, b := alertFixture(t)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		if s, err := c.AlertRuleSettings(); err != nil || len(s) != 1 || s[0].UpdatedBy == nil || *s[0].UpdatedBy != b.user {
			t.Errorf("AlertRuleSettings = %v, %v", s, err)
		}
		if as, err := c.Alerts(store.AlertFilter{Status: "live"}); err != nil || len(as) != 1 || as[0].ID != b.alert {
			t.Errorf("Alerts = %v, %v", as, err)
		}
		if _, err := c.Alert(a.alert); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Alert(A's) = %v", err)
		}
		if al, err := c.LiveAlert("signin_failures", "k"); err != nil || al.ID != b.alert {
			t.Errorf("LiveAlert = %v, %v", al, err)
		}
		if as, err := c.LiveAlertsOfRule("signin_failures"); err != nil || len(as) != 1 || as[0].ID != b.alert {
			t.Errorf("LiveAlertsOfRule = %v, %v", as, err)
		}
		if n, err := c.AlertCounts(); err != nil || n["open"]["high"] != 1 {
			t.Errorf("AlertCounts = %v, %v", n, err)
		}
		if cs, err := c.AlertChannels(); err != nil || len(cs) != 1 || cs[0].ID != b.channel {
			t.Errorf("AlertChannels = %v, %v", cs, err)
		}
		if _, err := c.AlertChannel(a.channel); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AlertChannel(A's) = %v", err)
		}
		if ds, err := c.DueAlertDeliveries(now, 10); err != nil || len(ds) != 1 || ds[0].ID != b.delivery {
			t.Errorf("DueAlertDeliveries = %v, %v", ds, err)
		}
		if ds, err := c.AlertDeliveries(a.alert); err != nil || len(ds) != 0 {
			t.Errorf("AlertDeliveries(A's) = %v, %v", ds, err)
		}
		if _, err := c.AlertDelivery(a.delivery); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AlertDelivery(A's) = %v", err)
		}
		if seq, ok, err := c.AlertCursor(); err != nil || !ok || seq != 7 {
			t.Errorf("AlertCursor = %d, %v", seq, err)
		}
		if n, err := c.FailedAuditAnchors(); err != nil || n != 0 {
			t.Errorf("FailedAuditAnchors = %d, %v", n, err)
		}
		return nil
	})
}

// TestIsolation_AlertWrites: B's writes naming A's rows change nothing.
func TestIsolation_AlertWrites(t *testing.T) {
	f, a, _ := alertFixture(t)
	before := storetest.Dump(t, f.DB, f.A.ID)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.BumpAlert(a.alert, 1, now, nil, "critical", "x", nil); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BumpAlert(A's) = %v", err)
		}
		if err := c.SaveAlertState(&store.Alert{ID: a.alert, Status: "resolved"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SaveAlertState(A's) = %v", err)
		}
		if err := c.UpdateAlertChannel(&store.AlertChannel{ID: a.channel, Name: "x", Target: "x", MinSeverity: "low", UpdatedAt: now}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateAlertChannel(A's) = %v", err)
		}
		if err := c.SaveAlertDelivery(&store.AlertDelivery{ID: a.delivery, Status: "sent", NextAttemptAt: now}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SaveAlertDelivery(A's) = %v", err)
		}
		return nil
	})
	if after := storetest.Dump(t, f.DB, f.A.ID); after != before {
		t.Error("tenant A changed")
	}
	inA(t, f, func(c *store.TenantTx) error {
		al, err := c.Alert(a.alert)
		if err != nil || al.Status != "open" || al.Count != 1 {
			t.Errorf("A's alert = %+v, %v", al, err)
		}
		d, err := c.AlertDelivery(a.delivery)
		if err != nil || d.Status != "pending" {
			t.Errorf("A's delivery = %+v, %v", d, err)
		}
		return nil
	})
}

// TestIsolation_AlertCrossReferencesRefused: the triggers refuse rows that
// point at another tenant's user, alert or channel.
func TestIsolation_AlertCrossReferencesRefused(t *testing.T) {
	f, a, b := alertFixture(t)
	now := storetest.Now
	cases := map[string]func(c *store.TenantTx) error{
		"rule setting by A's user": func(c *store.TenantTx) error {
			return c.PutAlertRuleSetting(&store.AlertRuleSetting{RuleID: "break_glass", Enabled: true, Severity: "critical", Threshold: 1,
				WindowMinutes: 1, UpdatedBy: &a.user, UpdatedAt: now})
		},
		"alert assigned to A's user": func(c *store.TenantTx) error {
			return c.SaveAlertState(&store.Alert{ID: b.alert, Status: "acknowledged", AssigneeUserID: &a.user})
		},
		"alert acknowledged by A's user": func(c *store.TenantTx) error {
			return c.SaveAlertState(&store.Alert{ID: b.alert, Status: "acknowledged", AcknowledgedBy: &a.user, AcknowledgedAt: &now})
		},
		"alert resolved by A's user": func(c *store.TenantTx) error {
			return c.SaveAlertState(&store.Alert{ID: b.alert, Status: "resolved", ResolvedBy: &a.user, ResolvedAt: &now})
		},
		"channel created by A's user": func(c *store.TenantTx) error {
			return c.InsertAlertChannel(&store.AlertChannel{ID: "chan-x", Name: "x", Kind: "email", Target: "x@example.com",
				MinSeverity: "low", Enabled: true, CreatedBy: &a.user, CreatedAt: now, UpdatedAt: now})
		},
		"delivery of A's alert": func(c *store.TenantTx) error {
			return c.InsertAlertDelivery(&store.AlertDelivery{ID: "deliv-x", AlertID: a.alert, ChannelID: b.channel, Reason: "raised",
				NextAttemptAt: now, CreatedAt: now})
		},
		"delivery to A's channel": func(c *store.TenantTx) error {
			return c.InsertAlertDelivery(&store.AlertDelivery{ID: "deliv-y", AlertID: b.alert, ChannelID: a.channel, Reason: "raised",
				NextAttemptAt: now, CreatedAt: now})
		},
	}
	for name, fn := range cases {
		err := f.DB.InTenant(t.Context(), f.B.ID, fn)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestAlerts_OneLivePerKey: a second live alert of the same rule and key is
// refused; once resolved, a new one may be raised.
func TestAlerts_OneLivePerKey(t *testing.T) {
	f, _, b := alertFixture(t)
	now := storetest.Now
	dup := &store.Alert{ID: "alert-dup", RuleID: "signin_failures", DedupKey: "k", Severity: "high", Title: "t", Count: 1,
		FirstSeenAt: now, LastSeenAt: now}
	if err := f.DB.InTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error { return c.InsertAlert(dup) }); err == nil {
		t.Fatal("second live alert accepted")
	}
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.SaveAlertState(&store.Alert{ID: b.alert, Status: "resolved", ResolvedBy: &b.user, ResolvedAt: &now}); err != nil {
			return err
		}
		return c.InsertAlert(dup)
	})
}

func alertsCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"AlertRuleSettings", "PutAlertRuleSetting", "Alerts", "Alert", "LiveAlert", "LiveAlertsOfRule",
		"AlertCounts", "InsertAlert", "BumpAlert", "SaveAlertState", "AlertChannels", "AlertChannel", "InsertAlertChannel",
		"UpdateAlertChannel", "InsertAlertDelivery", "DueAlertDeliveries", "AlertDeliveries", "AlertDelivery",
		"SaveAlertDelivery", "AlertCursor", "SetAlertCursor", "FailedAuditAnchors"} {
		out[k] = true // TestIsolation_AlertReads, _AlertWrites, _AlertCrossReferencesRefused
	}
	return out
}
