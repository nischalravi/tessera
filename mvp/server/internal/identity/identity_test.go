package identity_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/identity"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The fixture back-fills at build time: every human has one source record,
// one employee affiliation and identifiers; machines have none of them; no
// audit event is written; identity ids are untouched; a second run adds nothing.
func TestBackfill(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	k := storetest.IdentityKeyer(t)
	err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		people, err := c.Identities()
		if err != nil {
			return err
		}
		idsBefore, _ := json.Marshal(people)
		auditBefore, err := c.AuditLog(-1)
		if err != nil {
			return err
		}
		humans := 0
		for _, p := range people {
			affs, err := c.AffiliationsFor(p.ID)
			if err != nil {
				return err
			}
			srcs, err := c.SourceRecordsFor(p.ID)
			if err != nil {
				return err
			}
			if p.Type != "human" {
				if len(affs) != 0 || len(srcs) != 0 {
					t.Errorf("machine identity %s got affiliations or source records", p.ExternalID)
				}
				continue
			}
			humans++
			wantAffs := 1
			if p.ID == f.B.IDs["alice"] {
				wantAffs = 2 // plus the fixture's guest affiliation
			}
			if len(affs) != wantAffs || len(srcs) != 1 || srcs[0].SOR != identity.SorHRIS || srcs[0].SORID != p.ExternalID {
				t.Errorf("%s: %d affiliations, %d source records", p.ExternalID, len(affs), len(srcs))
			}
			// the HR affiliation is among them (a fixture's guest affiliation can share its start time, so no order is assumed)
			if len(affs) > 0 && !slices.ContainsFunc(affs, func(a *store.Affiliation) bool {
				return a.Type == store.AffEmployee && a.Source == store.AffSourceHRIS
			}) {
				t.Errorf("%s: no HR affiliation among %+v", p.ExternalID, affs)
			}
			xs, err := c.IdentifiersFor(p.ID)
			if err != nil {
				return err
			}
			for _, x := range xs {
				if x.VerifiedBy == nil || *x.VerifiedBy != store.VerifiedBySource || x.ValueHMAC == "" || x.SourceRecordID == nil {
					t.Errorf("%s: identifier %+v", p.ExternalID, x)
				}
			}
		}
		if humans == 0 {
			t.Fatal("fixture has no humans")
		}
		st, err := identity.Backfill(c, k, storetest.Now.Add(time.Hour))
		if err != nil {
			return err
		}
		if st != (identity.Stats{}) {
			t.Errorf("second Backfill changed things: %+v", st)
		}
		idsAfter, _ := json.Marshal(people)
		if string(idsBefore) != string(idsAfter) {
			t.Error("identities changed")
		}
		auditAfter, err := c.AuditLog(-1)
		if err != nil {
			return err
		}
		if len(auditAfter) != len(auditBefore) {
			t.Errorf("Backfill wrote %d audit events, want 0", len(auditAfter)-len(auditBefore))
		}
		pops, err := c.GuestPopulations()
		if err != nil || len(pops) != len(identity.DefaultPopulations) {
			t.Errorf("populations = %v, %v", pops, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A terminated person's HR affiliation is ended at the termination date, and
// a person whose email another person already holds keeps the first holder's
// identifier and loses nothing else.
func TestBackfill_TerminatedAndDuplicates(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	k := storetest.IdentityKeyer(t)
	err := f.DB.InTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		bob, err := c.Identity(f.A.IDs["bob"])
		if err != nil {
			return err
		}
		// a fresh tenant view: remove nothing, but add a new person with the same email as bob
		dup := &store.Identity{ExternalID: "dup-1", Name: "Bob Again", Email: bob.Email, Type: "human", Status: "terminated",
			CreatedAt: storetest.Now.AddDate(0, 0, -30)}
		term := storetest.Now.AddDate(0, 0, -3)
		dup.TerminatedAt = &term
		if _, err := c.InsertIdentity(dup); err != nil {
			return err
		}
		st, err := identity.Backfill(c, k, storetest.Now)
		if err != nil {
			return err
		}
		if st.SourceRecords != 1 || st.Affiliations != 1 || st.Identifiers != 1 || st.SkippedIdentifiers != 1 {
			t.Errorf("Backfill = %+v, want 1 record, 1 affiliation, 1 identifier (employee id), 1 skipped email", st)
		}
		var id int64
		ids, err := c.Identities()
		for _, i := range ids {
			if i.ExternalID == "dup-1" {
				id = i.ID
			}
		}
		affs, err := c.AffiliationsFor(id)
		if err != nil || len(affs) != 1 || affs[0].Status != store.AffEnded || affs[0].EndsAt == nil || !affs[0].EndsAt.Equal(term) {
			t.Errorf("terminated person's affiliation = %+v, %v", affs, err)
		}
		if got := affiliations.Derive("terminated", affs, storetest.Now, affiliations.DefaultNotice); got != affiliations.StateExpired {
			t.Errorf("derived state = %s", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
