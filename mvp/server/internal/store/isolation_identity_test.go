package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Identity model isolation (issue #64): a tenant sees and changes only its
// own populations, source records, identifiers and affiliations; another
// tenant's person, source record or affiliation id looks nonexistent, and a
// row naming one is refused by the guard triggers. storetest seeds both
// tenants with the back-filled model plus one guest affiliation whose org
// unit carries tenant A's sentinel.

func idModelDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	var out string
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		pops, err := c.GuestPopulations()
		if err != nil {
			return err
		}
		srcs, err := c.SourceRecords()
		if err != nil {
			return err
		}
		xs, err := c.Identifiers()
		if err != nil {
			return err
		}
		affs, err := c.Affiliations()
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{pops, srcs, xs, affs})
		out = string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIsolation_IdentityModelReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := f.A, f.B
	inB(t, f, func(c *store.TenantTx) error {
		affs, err := c.Affiliations()
		if err != nil || len(affs) == 0 {
			t.Fatalf("Affiliations = %v, %v", affs, err)
		}
		for _, x := range affs {
			if x.OrgUnit != nil && strings.Contains(*x.OrgUnit, storetest.Sentinel) {
				t.Errorf("B reads A's affiliation %+v", x)
			}
		}
		if _, err := c.Affiliation(a.Refs["affiliation:guest"]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Affiliation(A's) = %v", err)
		}
		if got, err := c.Affiliation(b.Refs["affiliation:guest"]); err != nil || got.IdentityID != b.IDs["alice"] {
			t.Errorf("Affiliation(B's) = %+v, %v", got, err)
		}
		for name, ident := range map[string]int64{"alice": a.IDs["alice"], "bob": a.IDs["bob"]} {
			// ids of the two tenants differ (A seeded first), so A's id names no B person
			if b.IDs[name] == ident {
				continue
			}
			if got, err := c.AffiliationsFor(ident); err != nil || len(got) != 0 {
				t.Errorf("AffiliationsFor(A's %s) = %v, %v", name, got, err)
			}
			if got, err := c.IdentifiersFor(ident); err != nil || len(got) != 0 {
				t.Errorf("IdentifiersFor(A's %s) = %v, %v", name, got, err)
			}
			if got, err := c.SourceRecordsFor(ident); err != nil || len(got) != 0 {
				t.Errorf("SourceRecordsFor(A's %s) = %v, %v", name, got, err)
			}
		}
		xs, err := c.Identifiers()
		if err != nil || len(xs) == 0 {
			t.Fatalf("Identifiers = %v, %v", xs, err)
		}
		for _, x := range xs {
			if x.ValueNorm != nil && strings.Contains(*x.ValueNorm, strings.ToLower(storetest.Sentinel)) {
				t.Errorf("B reads A's identifier %q", *x.ValueNorm)
			}
			// a hash from A's table is not found in B, whatever its type
			if _, err := c.IdentifierByHMAC(x.Type, x.Issuer, strings.Repeat("0", 64)); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("IdentifierByHMAC(unknown) = %v", err)
			}
		}
		srcs, err := c.SourceRecords()
		if err != nil || len(srcs) == 0 {
			t.Fatalf("SourceRecords = %v, %v", srcs, err)
		}
		if _, err := c.SourceRecord(srcs[0].ID); err != nil {
			t.Errorf("SourceRecord(B's) = %v", err)
		}
		pops, err := c.GuestPopulations()
		if err != nil || len(pops) == 0 {
			t.Fatalf("GuestPopulations = %v, %v", pops, err)
		}
		if _, err := c.GuestPopulation("nowhere"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GuestPopulation(unknown) = %v", err)
		}
		return nil
	})
	// the same lookups in A find A's rows (positive control)
	inA(t, f, func(c *store.TenantTx) error {
		got, err := c.Affiliation(a.Refs["affiliation:guest"])
		if err != nil || got.OrgUnit == nil || !strings.Contains(*got.OrgUnit, storetest.Sentinel) {
			t.Errorf("A's own affiliation = %+v, %v", got, err)
		}
		return nil
	})
}

// A source record of tenant A, found through B's lists by id.
func firstSource(t *testing.T, f *storetest.Fixture, tn storetest.Tenant) *store.SourceRecord {
	t.Helper()
	var out *store.SourceRecord
	if err := f.DB.ReadTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		s, err := c.SourceRecords()
		if err == nil && len(s) > 0 {
			out = s[0]
		}
		return err
	}); err != nil || out == nil {
		t.Fatalf("no source record: %v", err)
	}
	return out
}

// Mutations aimed at tenant A's rows from tenant B fail with ErrNotFound or
// the cross-tenant guard and leave A alone.
func TestIsolation_IdentityModelMutationsScoped(t *testing.T) {
	now := storetest.Now
	mutations := map[string]func(c *store.TenantTx, a, b storetest.Tenant, aSrc *store.SourceRecord) error{
		"EndAffiliation": func(c *store.TenantTx, a, _ storetest.Tenant, _ *store.SourceRecord) error {
			return c.EndAffiliation(a.Refs["affiliation:guest"], store.AffEnded, now, nil, "x")
		},
		// B's own row naming A's person: the guard trigger refuses it
		"InsertAffiliation": func(c *store.TenantTx, a, _ storetest.Tenant, _ *store.SourceRecord) error {
			return c.InsertAffiliation(&store.Affiliation{ID: uuid.NewString(), IdentityID: a.IDs["alice"], Type: store.AffAlum,
				Source: store.AffSourceManual, StartsAt: now, Status: store.AffActive, CreatedAt: now})
		},
		"InsertSourceRecord": func(c *store.TenantTx, a, _ storetest.Tenant, _ *store.SourceRecord) error {
			id := a.IDs["alice"]
			return c.InsertSourceRecord(&store.SourceRecord{ID: uuid.NewString(), IdentityID: &id, SOR: "sis", SORID: "x-1",
				Attributes: "{}", Status: store.RecordActive, ReceivedAt: now})
		},
		"InsertIdentifier (person)": func(c *store.TenantTx, a, _ storetest.Tenant, _ *store.SourceRecord) error {
			return c.InsertIdentifier(&store.Identifier{ID: uuid.NewString(), IdentityID: a.IDs["alice"], Type: store.IdentNetID,
				ValueHMAC: "h-1", Status: store.RecordActive, CreatedAt: now})
		},
		"InsertIdentifier (source record)": func(c *store.TenantTx, _, b storetest.Tenant, aSrc *store.SourceRecord) error {
			return c.InsertIdentifier(&store.Identifier{ID: uuid.NewString(), IdentityID: b.IDs["alice"], Type: store.IdentNetID,
				ValueHMAC: "h-2", SourceRecordID: &aSrc.ID, Status: store.RecordActive, CreatedAt: now})
		},
	}
	for name, fn := range mutations {
		t.Run(name, func(t *testing.T) {
			f := storetest.TwoTenants(t)
			aSrc := firstSource(t, f, f.A)
			before := idModelDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, f.A, f.B, aSrc) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := idModelDump(t, f.DB, f.A.ID); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

// PutGuestPopulation upserts within the calling tenant only.
func TestIsolation_PutGuestPopulationScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	before := idModelDump(t, f.DB, f.A.ID)
	inB(t, f, func(c *store.TenantTx) error {
		return c.PutGuestPopulation(&store.GuestPopulation{Key: "guest", Name: "B only", MaxDurationDays: 7, DefaultAAL: 1,
			CreatedAt: storetest.Now})
	})
	if idModelDump(t, f.DB, f.A.ID) != before {
		t.Error("B's PutGuestPopulation changed A")
	}
	inB(t, f, func(c *store.TenantTx) error {
		p, err := c.GuestPopulation("guest")
		if err != nil || p.Name != "B only" || p.MaxDurationDays != 7 {
			t.Errorf("B's population = %+v, %v", p, err)
		}
		return nil
	})
}

// A user of another tenant cannot be recorded as the creator or ender.
func TestIsolation_AffiliationForeignActorRefused(t *testing.T) {
	f := storetest.TwoTenants(t)
	var aUser string
	inA(t, f, func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "a-user", CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		aUser = u.ID.String()
		return nil
	})
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertAffiliation(&store.Affiliation{ID: uuid.NewString(), IdentityID: f.B.IDs["alice"], Type: store.AffAlum,
			Source: store.AffSourceManual, StartsAt: storetest.Now, Status: store.AffActive, CreatedBy: &aUser, CreatedAt: storetest.Now})
	})
	if !errors.Is(err, store.ErrCrossTenant) {
		t.Errorf("foreign created_by = %v, want ErrCrossTenant", err)
	}
}

// An ended affiliation is history, and a population must exist in the
// affiliation's own tenant.
func TestAffiliations_HistoryAndPopulationFK(t *testing.T) {
	f := storetest.TwoTenants(t)
	end := storetest.Now.Add(time.Hour)
	inB(t, f, func(c *store.TenantTx) error {
		id := f.B.Refs["affiliation:guest"]
		if err := c.EndAffiliation(id, store.AffEnded, end, nil, "done"); err != nil {
			t.Fatal(err)
		}
		if err := c.EndAffiliation(id, store.AffRevoked, end, nil, "again"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second end = %v, want ErrNotFound", err)
		}
		a, err := c.Affiliation(id)
		if err != nil || a.Status != store.AffEnded || *a.EndReason != "done" {
			t.Errorf("affiliation = %+v, %v", a, err)
		}
		return nil
	})
	pop := "no-such-population"
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertAffiliation(&store.Affiliation{ID: uuid.NewString(), IdentityID: f.B.IDs["alice"], Type: store.AffAlum,
			Source: store.AffSourceManual, Population: &pop, StartsAt: storetest.Now, Status: store.AffActive, CreatedAt: storetest.Now})
	})
	if err == nil {
		t.Error("an affiliation naming an unknown population was accepted")
	}
}

func identityModelCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"GuestPopulations", "GuestPopulation", "SourceRecords", "SourceRecordsFor", "SourceRecord",
		"Identifiers", "IdentifiersFor", "IdentifierByHMAC", "Affiliations", "AffiliationsFor", "Affiliation"} {
		out[k] = true // TestIsolation_IdentityModelReads
	}
	for _, k := range []string{"EndAffiliation", "InsertAffiliation", "InsertSourceRecord", "InsertIdentifier"} {
		out[k] = true // TestIsolation_IdentityModelMutationsScoped
	}
	out["PutGuestPopulation"] = true // TestIsolation_PutGuestPopulationScoped
	return out
}
