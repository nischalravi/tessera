package retention_test

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/retention"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestCheckEnforcesTheFloors(t *testing.T) {
	for _, c := range []struct {
		class string
		days  int
		ok    bool
	}{
		{store.ClassAudit, 365, true},
		{store.ClassAudit, 364, false},
		{store.ClassAudit, 3650, true},
		{store.ClassAudit, 3651, false},
		{store.ClassAudit, 0, false},
		{store.ClassAudit, -1, false},
		{store.ClassCampaigns, 364, false},
		{store.ClassRequests, 364, false},
		{store.ClassRequests, 365, true},
		{store.ClassJobRuns, 30, true},
		{store.ClassJobRuns, 29, false},
		{store.ClassOutbox, 30, true},
		{store.ClassOutbox, 1, false},
		{"logs", 400, false},
		{"", 400, false},
	} {
		if err := retention.Check(c.class, c.days); (err == nil) != c.ok {
			t.Errorf("Check(%q, %d) = %v, want ok=%v", c.class, c.days, err, c.ok)
		}
	}
}

func TestDefaultsRespectTheirFloorsAndCoverEveryClass(t *testing.T) {
	if len(retention.Classes) != len(store.ArchiveClasses) {
		t.Fatalf("%d classes with a retention, %d with an archive", len(retention.Classes), len(store.ArchiveClasses))
	}
	for i, c := range retention.Classes {
		if c.Name != store.ArchiveClasses[i] {
			t.Errorf("class %d is %s, the archive runs %s", i, c.Name, store.ArchiveClasses[i])
		}
		if err := retention.Check(c.Name, c.Default); err != nil {
			t.Errorf("the default of %s is refused: %v", c.Name, err)
		}
	}
	if c, _ := retention.Lookup(store.ClassAudit); c.Min < 365 {
		t.Errorf("the audit floor is %d days, under a year", c.Min)
	}
}

func TestEffective(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	if err := f.DB.InTenant(t.Context(), f.A.ID, func(tx *store.TenantTx) error {
		if err := tx.SetRetentionPolicy(store.ClassAudit, 500, now, "chg"); err != nil {
			return err
		}
		return tx.SetRetentionPolicy(store.ClassJobRuns, 7, now, "") // below the floor: lifted
	}); err != nil {
		t.Fatal(err)
	}
	get := func(tn *storetest.Tenant) map[string]retention.Setting {
		out := map[string]retention.Setting{}
		if err := f.DB.ReadTenant(t.Context(), tn.ID, func(tx *store.TenantTx) error {
			ss, err := retention.Effective(tx)
			for _, s := range ss {
				out[s.Name] = s
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	a, b := get(&f.A), get(&f.B)
	if s := a[store.ClassAudit]; s.Days != 500 || !s.Custom || s.UpdatedBy == nil || *s.UpdatedBy != "chg" {
		t.Errorf("A audit = %+v", s)
	}
	if s := a[store.ClassJobRuns]; s.Days != 30 || !s.Custom {
		t.Errorf("A job runs = %+v, want the floor", s)
	}
	if s := a[store.ClassCampaigns]; s.Days != 730 || s.Custom {
		t.Errorf("A campaigns = %+v, want the default", s)
	}
	if s := b[store.ClassAudit]; s.Days != 730 || s.Custom {
		t.Errorf("B audit = %+v: another tenant's setting leaked", s)
	}
	cut := retention.Cutoff(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), 730)
	if !cut.Equal(time.Date(2024, 10, 20, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("cutoff = %v", cut)
	}
}
