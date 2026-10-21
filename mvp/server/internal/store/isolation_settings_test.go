package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The configurable-settings tables of issue #298 (schema/0490, 0491, 0493, 0494,
// 0495): each is read and written only through the tenant's own handle, and a row
// cannot point at another tenant's identity, template or user.

func TestIsolation_SodViewSettings(t *testing.T) {
	f := storetest.TwoTenants(t)
	inA(t, f, func(c *store.TenantTx) error {
		if _, err := c.SodViewSettings(); !store.ErrNoSettings(err) {
			t.Errorf("before a save = %v", err)
		}
		return c.PutSodViewSettings(&store.SodViewSettingsRow{Columns: []string{"risk"}, Filters: []string{}, UpdatedBy: "a"}, storetest.Now)
	})
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.SodViewSettings(); !store.ErrNoSettings(err) {
			t.Errorf("B reads A's configuration: %v", err)
		}
		if err := c.PutSodViewSettings(&store.SodViewSettingsRow{Columns: []string{"ruleset"}, UpdatedBy: "b"}, storetest.Now); err != nil {
			return err
		}
		return c.PutSodViewSettings(&store.SodViewSettingsRow{Columns: []string{"ruleset", "risk"}, UpdatedBy: "b"}, storetest.Now)
	})
	inA(t, f, func(c *store.TenantTx) error {
		r, err := c.SodViewSettings()
		if err != nil || r.Version != 1 || len(r.Columns) != 1 || r.Columns[0] != "risk" || r.Filters == nil {
			t.Errorf("A's configuration: %+v %v", r, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if r, err := c.SodViewSettings(); err != nil || r.Version != 2 || len(r.Columns) != 2 {
			t.Errorf("B's configuration: %+v %v", r, err)
		}
		return nil
	})
}

func TestIsolation_StepUpPolicy(t *testing.T) {
	f := storetest.TwoTenants(t)
	inA(t, f, func(c *store.TenantTx) error {
		return c.PutStepUpPolicy(&store.StepUpPolicyRow{Entries: map[string]store.StepUpEntry{"catalog.manage": {ACR: "phr", MaxAgeS: 300}}, UpdatedBy: "a"}, storetest.Now)
	})
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.StepUpPolicy(); !store.ErrNoSettings(err) {
			t.Errorf("B reads A's policy: %v", err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		r, err := c.StepUpPolicy()
		if err != nil || r.Entries["catalog.manage"].MaxAgeS != 300 || r.Version != 1 {
			t.Errorf("A's policy: %+v %v", r, err)
		}
		return nil
	})
}

func TestIsolation_UserPreferences(t *testing.T) {
	f := storetest.TwoTenants(t)
	var ua, ub uuid.UUID
	mk := func(tn storetest.Tenant, out *uuid.UUID) {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			u := &store.PlatformUser{DisplayName: "prefs", CreatedAt: storetest.Now}
			if err := c.InsertPlatformUser(u); err != nil {
				return err
			}
			*out = u.ID
			return c.PutUserPreferences(u.ID, &store.UserPreferencesRow{TimeZone: "Europe/Berlin", DateFormat: "dmy"}, storetest.Now)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	mk(f.A, &ua)
	mk(f.B, &ub)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.UserPreferences(ua); !store.ErrNoSettings(err) {
			t.Errorf("B reads A's user's preferences: %v", err)
		}
		if err := c.PutUserPreferences(ua, &store.UserPreferencesRow{}, storetest.Now); err == nil {
			t.Error("B wrote a row for A's user")
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		r, err := c.UserPreferences(ua)
		if err != nil || r.TimeZone != "Europe/Berlin" || r.DateFormat != "dmy" {
			t.Errorf("A's preferences: %+v %v", r, err)
		}
		return nil
	})
	_ = ub
}

func TestIsolation_ReviewTypes(t *testing.T) {
	f := storetest.TwoTenants(t)
	carolA, carolB := f.A.IDs["carol"], f.B.IDs["carol"]
	inA(t, f, func(c *store.TenantTx) error {
		return c.PutReviewTypeSettings(&store.ReviewTypeSettingsRow{ReviewType: "application_owner", Enabled: true, ReviewerSource: "owner",
			FallbackReviewerID: &carolA, OnIncomplete: "escalate", EscalationDays: 3, UpdatedBy: "a"}, storetest.Now)
	})
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.ReviewTypeSettings("application_owner"); !store.ErrNoSettings(err) {
			t.Errorf("B reads A's type: %v", err)
		}
		if l, err := c.ReviewTypeSettingsList(); err != nil || len(l) != 0 {
			t.Errorf("B lists A's types: %v %v", l, err)
		}
		// a fallback reviewer from another tenant is refused by the table
		err := c.PutReviewTypeSettings(&store.ReviewTypeSettingsRow{ReviewType: "role_owner", Enabled: true, ReviewerSource: "owner",
			FallbackReviewerID: &carolA, OnIncomplete: "revoke", EscalationDays: 7, UpdatedBy: "b"}, storetest.Now)
		if err == nil {
			t.Error("B named A's person as a fallback reviewer")
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		return c.PutReviewTypeSettings(&store.ReviewTypeSettingsRow{ReviewType: "role_owner", Enabled: true, ReviewerSource: "owner",
			FallbackReviewerID: &carolB, OnIncomplete: "revoke", EscalationDays: 7, UpdatedBy: "b"}, storetest.Now)
	})
	inA(t, f, func(c *store.TenantTx) error {
		r, err := c.ReviewTypeSettings("application_owner")
		if err != nil || r.OnIncomplete != "escalate" || r.FallbackReviewerID == nil || *r.FallbackReviewerID != carolA || r.Version != 1 {
			t.Errorf("A's type: %+v %v", r, err)
		}
		if _, err := c.ReviewTypeSettings("role_owner"); !store.ErrNoSettings(err) {
			t.Errorf("A reads B's type: %v", err)
		}
		return nil
	})
	// the table's own checks
	for name, row := range map[string]store.ReviewTypeSettingsRow{
		"unknown type":              {ReviewType: "friends", ReviewerSource: "owner", OnIncomplete: "revoke", EscalationDays: 7},
		"fixed without a reviewer":  {ReviewType: "role_owner", ReviewerSource: "fixed", OnIncomplete: "revoke", EscalationDays: 7},
		"escalate without fallback": {ReviewType: "role_owner", ReviewerSource: "owner", OnIncomplete: "escalate", EscalationDays: 7},
		"escalation days":           {ReviewType: "role_owner", ReviewerSource: "owner", OnIncomplete: "revoke", EscalationDays: 99},
	} {
		row.UpdatedBy = "x"
		err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error { return c.PutReviewTypeSettings(&row, storetest.Now) })
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIsolation_TemplateReviewTypes(t *testing.T) {
	f := storetest.TwoTenants(t)
	var tmpl string
	inA(t, f, func(c *store.TenantTx) error {
		tm := &store.ReviewTemplate{ID: "tmpl-a", Name: "q", UnusedDays: 60, DurationDays: 14, ReminderDays: 3, CloseOut: "revoke",
			EscalationDays: 7, Recurrence: "once", Enabled: false, CreatedAt: storetest.Now, UpdatedAt: storetest.Now}
		if err := c.InsertReviewTemplate(tm); err != nil {
			return err
		}
		tmpl = tm.ID
		return c.SetTemplateReviewType(tmpl, "service_account")
	})
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.TemplateReviewType(tmpl); !store.ErrNoSettings(err) {
			t.Errorf("B reads A's template type: %v", err)
		}
		if err := c.SetTemplateReviewType(tmpl, "role_owner"); err == nil {
			t.Error("B typed A's template")
		}
		if l, err := c.TemplateReviewTypes(); err != nil || len(l) != 0 {
			t.Errorf("B lists A's: %v %v", l, err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		if got, err := c.TemplateReviewType(tmpl); err != nil || got != "service_account" {
			t.Errorf("A's template type: %q %v", got, err)
		}
		if err := c.ClearTemplateReviewType(tmpl); err != nil {
			return err
		}
		if _, err := c.TemplateReviewType(tmpl); !store.ErrNoSettings(err) {
			t.Errorf("after clearing: %v", err)
		}
		return nil
	})
}

func TestIsolation_OrgSettings(t *testing.T) {
	f := storetest.TwoTenants(t)
	carolA, carolB := f.A.IDs["carol"], f.B.IDs["carol"]
	hours := 8.0
	req := true
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.ReplaceOrgOwners("dept-0123456789", []int64{carolA}); err != nil {
			return err
		}
		sys := "workday"
		if err := c.PutOrgHierarchySource(&store.OrgHierarchySourceRow{Source: "hr_department", System: &sys, UpdatedBy: "a"}, storetest.Now); err != nil {
			return err
		}
		return c.PutOrgSettings(&store.OrgSettingsRow{OrgID: "dept-0123456789", DefaultStages: []string{"manager", "decider"}, MaxHours: &hours,
			JustificationReq: &req, UpdatedBy: "a"}, storetest.Now)
	})
	inB(t, f, func(c *store.TenantTx) error {
		if o, err := c.OrgOwners(); err != nil || len(o) != 0 {
			t.Errorf("B lists A's owners: %v %v", o, err)
		}
		if _, err := c.OrgSettings("dept-0123456789"); !store.ErrNoSettings(err) {
			t.Errorf("B reads A's org settings: %v", err)
		}
		if l, err := c.OrgSettingsList(); err != nil || len(l) != 0 {
			t.Errorf("B lists A's org settings: %v %v", l, err)
		}
		if _, err := c.OrgHierarchySource(); !store.ErrNoSettings(err) {
			t.Errorf("B reads A's hierarchy source: %v", err)
		}
		if err := c.ReplaceOrgOwners("dept-0123456789", []int64{carolA}); err == nil {
			t.Error("B named A's person as an owner")
		}
		return c.ReplaceOrgOwners("dept-0123456789", []int64{carolB})
	})
	inA(t, f, func(c *store.TenantTx) error {
		o, err := c.OrgOwners()
		if err != nil || len(o) != 1 || o[0].IdentityID != carolA {
			t.Errorf("A's owners changed by B: %v %v", o, err)
		}
		r, err := c.OrgSettings("dept-0123456789")
		if err != nil || r.Version != 1 || len(r.DefaultStages) != 2 || r.MaxHours == nil || *r.MaxHours != 8 || r.JustificationReq == nil || !*r.JustificationReq || r.DefaultHours != nil {
			t.Errorf("A's org settings: %+v %v", r, err)
		}
		if s, err := c.OrgHierarchySource(); err != nil || s.System == nil || *s.System != "workday" {
			t.Errorf("A's source: %+v %v", s, err)
		}
		return nil
	})
	// the table's own checks
	zero := 0.0
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.PutOrgSettings(&store.OrgSettingsRow{OrgID: "root", MaxHours: &zero, UpdatedBy: "x"}, storetest.Now)
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Errorf("a zero max_hours: %v", err)
	}
}

// settingsCovered lists the methods the isolation tests above exercise.
func settingsCovered() map[string]bool {
	return map[string]bool{"SodViewSettings": true, "PutSodViewSettings": true, "StepUpPolicy": true, "PutStepUpPolicy": true,
		"UserPreferences": true, "PutUserPreferences": true, "ReviewTypeSettingsList": true, "ReviewTypeSettings": true,
		"PutReviewTypeSettings": true, "TemplateReviewTypes": true, "TemplateReviewType": true, "SetTemplateReviewType": true,
		"ClearTemplateReviewType": true, "OrgOwners": true, "ReplaceOrgOwners": true, "OrgSettingsList": true, "OrgSettings": true,
		"PutOrgSettings": true, "OrgHierarchySource": true, "PutOrgHierarchySource": true}
}
