package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Request settings (schema/0380_request_settings.sql, issue #298): one row per
// tenant, read and written only through the tenant's own handle.

func TestIsolation_RequestSettings(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	hours := 24.0
	put := func(tn storetest.Tenant, min int, by string) {
		t.Helper()
		err := f.DB.InTenant(ctx, tn.ID, func(c *store.TenantTx) error {
			return c.PutRequestSettings(&store.RequestSettingsRow{JustificationRequired: true, JustificationMin: min, MaxHours: &hours,
				HistoryVisibility: "involved", ForOthers: "managers", UpdatedBy: by}, storetest.Now)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// a tenant that never saved settings has none
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.RequestSettings(); !store.ErrNoRequestSettings(err) {
			t.Errorf("before any save = %v, want not found", err)
		}
		return nil
	})
	put(f.A, 10, "admin a")
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.RequestSettings(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's settings: %v", err)
		}
		return nil
	})
	put(f.B, 30, "admin b")
	put(f.B, 40, "admin b")
	inA(t, f, func(c *store.TenantTx) error {
		r, err := c.RequestSettings()
		if err != nil || r.JustificationMin != 10 || r.UpdatedBy != "admin a" || r.Version != 1 {
			t.Errorf("A's settings changed by B's saves: %+v %v", r, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		r, err := c.RequestSettings()
		if err != nil || r.JustificationMin != 40 || r.Version != 2 || r.MaxHours == nil || *r.MaxHours != 24 || r.DefaultHours != nil ||
			r.ForOthers != "managers" || r.HistoryVisibility != "involved" || !r.JustificationRequired || r.AttachmentsAllowed {
			t.Errorf("B's settings: %+v %v", r, err)
		}
		return nil
	})
}

// The table's own checks refuse values the API would never send.
func TestRequestSettings_ChecksRefuseBadValues(t *testing.T) {
	f := storetest.TwoTenants(t)
	zero := 0.0
	for name, row := range map[string]store.RequestSettingsRow{
		"min length 0":    {JustificationMin: 0, HistoryVisibility: "readers", ForOthers: "permission"},
		"min length huge": {JustificationMin: 5000, HistoryVisibility: "readers", ForOthers: "permission"},
		"zero max hours":  {JustificationMin: 1, MaxHours: &zero, HistoryVisibility: "readers", ForOthers: "permission"},
		"bad visibility":  {JustificationMin: 1, HistoryVisibility: "all", ForOthers: "permission"},
		"bad for others":  {JustificationMin: 1, HistoryVisibility: "readers", ForOthers: "everyone"},
	} {
		row.UpdatedBy = "x"
		err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error { return c.PutRequestSettings(&row, storetest.Now) })
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// requestSettingsCovered lists the methods TestIsolation_RequestSettings exercises.
func requestSettingsCovered() map[string]bool {
	return map[string]bool{"RequestSettings": true, "PutRequestSettings": true}
}
