package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Intake isolation (issue #67): a tenant sees and changes only its own
// organizational sponsors, intake events and conversions; another tenant's
// ids look nonexistent, and a row naming one is refused by the guard
// triggers. storetest seeds both tenants with a sponsor, an intake event
// whose detail carries tenant A's sentinel, and one conversion.

func intakeDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	var out string
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		sp, err := c.OrgSponsors()
		if err != nil {
			return err
		}
		in, err := c.IntakeEvents()
		if err != nil {
			return err
		}
		cv, err := c.Conversions()
		if err != nil {
			return err
		}
		srcs, err := c.SourceRecords()
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{sp, in, cv, srcs})
		out = string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIsolation_IntakeReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := f.A, f.B
	inB(t, f, func(c *store.TenantTx) error {
		recs, err := c.IntakeEvents()
		if err != nil || len(recs) != 1 || recs[0].ID != b.Refs["intake"] {
			t.Fatalf("IntakeEvents = %v, %v", recs, err)
		}
		if strings.Contains(recs[0].Detail, storetest.Sentinel) {
			t.Errorf("B reads A's intake detail %q", recs[0].Detail)
		}
		if _, err := c.IntakeEvent(a.Refs["intake"]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("IntakeEvent(A's) = %v", err)
		}
		if got, err := c.IntakeEvent(b.Refs["intake"]); err != nil || got.IdentityID != nil {
			t.Errorf("IntakeEvent(B's) = %+v, %v", got, err)
		}
		// the event key "sis:evt-1" exists in both tenants and is found only in B's own
		if got, err := c.IntakeEventByEvent("sis:evt-1"); err != nil || got.ID != b.Refs["intake"] {
			t.Errorf("IntakeEventByEvent = %+v, %v", got, err)
		}
		sponsors, err := c.OrgSponsors()
		if err != nil || len(sponsors) != 1 || strings.Contains(sponsors[0].Name, storetest.Sentinel) {
			t.Errorf("OrgSponsors = %+v, %v", sponsors, err)
		}
		if _, err := c.OrgSponsor("hr"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OrgSponsor(unknown) = %v", err)
		}
		cvs, err := c.Conversions()
		if err != nil || len(cvs) != 1 || cvs[0].ID != b.Refs["conversion"] {
			t.Errorf("Conversions = %+v, %v", cvs, err)
		}
		if a.IDs["alice"] != b.IDs["alice"] {
			if got, err := c.ConversionsFor(a.IDs["alice"]); err != nil || len(got) != 0 {
				t.Errorf("ConversionsFor(A's alice) = %v, %v", got, err)
			}
		}
		if _, err := c.SourceRecordBySOR("sis", "no-such-applicant"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SourceRecordBySOR(unknown) = %v", err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		got, err := c.IntakeEvent(a.Refs["intake"])
		if err != nil || !strings.Contains(got.Detail, storetest.Sentinel) {
			t.Errorf("A's own intake event = %+v, %v", got, err)
		}
		return nil
	})
}

// Mutations aimed at tenant A's rows from tenant B fail and leave A alone.
func TestIsolation_IntakeMutationsScoped(t *testing.T) {
	now := storetest.Now
	sponsor := "admissions"
	mutations := map[string]func(c *store.TenantTx, a, b storetest.Tenant, aSrc *store.SourceRecord) error{
		"SetIntakeOutcome": func(c *store.TenantTx, a, _ storetest.Tenant, _ *store.SourceRecord) error {
			return c.SetIntakeOutcome(a.Refs["intake"], store.IntakeEventRejected, nil, nil, "{}")
		},
		"UpdateSourceRecord": func(c *store.TenantTx, _, _ storetest.Tenant, aSrc *store.SourceRecord) error {
			return c.UpdateSourceRecord(aSrc.ID, `{"x":"y"}`, now)
		},
		"InsertIntakeEvent (person)": func(c *store.TenantTx, a, _ storetest.Tenant, _ *store.SourceRecord) error {
			id := a.IDs["alice"]
			return c.InsertIntakeEvent(&store.IntakeEvent{ID: uuid.NewString(), Channel: store.ChannelSIS,
				MatchMode: store.MatchAuthoritative, IdentityID: &id, SponsorOrg: &sponsor, EventKey: "sis:x-1", EventType: "applied",
				Status: store.IntakeEventResolved, Detail: "{}", CreatedAt: now})
		},
		"InsertIntakeEvent (source record)": func(c *store.TenantTx, _, _ storetest.Tenant, aSrc *store.SourceRecord) error {
			return c.InsertIntakeEvent(&store.IntakeEvent{ID: uuid.NewString(), Channel: store.ChannelSIS,
				MatchMode: store.MatchAuthoritative, SourceRecordID: &aSrc.ID, SponsorOrg: &sponsor, EventKey: "sis:x-2",
				EventType: "applied", Status: store.IntakeEventResolved, Detail: "{}", CreatedAt: now})
		},
		"InsertConversion": func(c *store.TenantTx, a, _ storetest.Tenant, _ *store.SourceRecord) error {
			return c.InsertConversion(&store.Conversion{ID: uuid.NewString(), IdentityID: a.IDs["alice"],
				FromAffiliationID: a.Refs["affiliation:guest"], ToAffiliationID: a.Refs["affiliation:guest"],
				FromType: store.AffEmployee, ToType: store.AffGuestVisitor, Trigger: store.ConvSISStatus, EffectiveAt: now, CreatedAt: now})
		},
	}
	for name, fn := range mutations {
		t.Run(name, func(t *testing.T) {
			f := storetest.TwoTenants(t)
			aSrc := firstSource(t, f, f.A)
			before := intakeDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, f.A, f.B, aSrc) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := intakeDump(t, f.DB, f.A.ID); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

// PutOrgSponsor upserts within the calling tenant only.
func TestIsolation_PutOrgSponsorScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	before := intakeDump(t, f.DB, f.A.ID)
	inB(t, f, func(c *store.TenantTx) error {
		return c.PutOrgSponsor(&store.OrgSponsor{Key: "admissions", Name: "B only", Population: "applicant", CreatedAt: storetest.Now})
	})
	if intakeDump(t, f.DB, f.A.ID) != before {
		t.Error("B's PutOrgSponsor changed A")
	}
	inB(t, f, func(c *store.TenantTx) error {
		o, err := c.OrgSponsor("admissions")
		if err != nil || o.Name != "B only" {
			t.Errorf("B's sponsor = %+v, %v", o, err)
		}
		return nil
	})
}

// An event key is unique within a tenant, not across tenants, and an intake
// record cannot name a sponsor its tenant does not have.
func TestIntake_EventKeyAndSponsorRules(t *testing.T) {
	f := storetest.TwoTenants(t)
	dup := &store.IntakeEvent{ID: uuid.NewString(), Channel: store.ChannelSIS, MatchMode: store.MatchAuthoritative,
		EventKey: "sis:evt-1", EventType: "admitted", Status: store.IntakeEventReceived, Detail: "{}", CreatedAt: storetest.Now}
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return c.InsertIntakeEvent(dup) })
	if !errors.Is(err, store.ErrIntakeSeen) {
		t.Errorf("same event key twice = %v, want ErrIntakeSeen", err)
	}
	nowhere := "nowhere"
	err = f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		return c.InsertIntakeEvent(&store.IntakeEvent{ID: uuid.NewString(), Channel: store.ChannelHRIS,
			MatchMode: store.MatchAuthoritative, SponsorOrg: &nowhere, EventKey: "hris:evt-9", EventType: "joiner",
			Status: store.IntakeEventReceived, Detail: "{}", CreatedAt: storetest.Now})
	})
	if err == nil {
		t.Error("an intake event naming an unknown organizational sponsor was accepted")
	}
}

func intakeCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"OrgSponsors", "OrgSponsor", "IntakeEvents", "IntakeEvent", "IntakeEventByEvent",
		"Conversions", "ConversionsFor", "SourceRecordBySOR"} {
		out[k] = true // TestIsolation_IntakeReads
	}
	for _, k := range []string{"SetIntakeOutcome", "UpdateSourceRecord", "InsertIntakeEvent", "InsertConversion"} {
		out[k] = true // TestIsolation_IntakeMutationsScoped
	}
	out["PutOrgSponsor"] = true // TestIsolation_PutOrgSponsorScoped
	return out
}
