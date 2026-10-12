// Package identity seeds and back-fills the identity data model of the guest
// design (issue #64): the four populations of §3, and for every person
// already in the directory one source record, one affiliation and the
// identifiers their HR record carries.
//
// It writes no audit events: it describes data that is already there, the
// way ingest.Sync does, and it never touches the integer ids of identities.
package identity

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// DefaultPopulations are the demo tenant's population settings (design §3).
// Durations are the maximum for a new affiliation; IAL and AAL are the
// defaults a later PR enforces.
var DefaultPopulations = []store.GuestPopulation{
	{Key: "guest", Name: "Sponsored guests", MaxDurationDays: 365, DefaultIAL: 0, DefaultAAL: 2},
	{Key: "applicant", Name: "Applicants and admits", MaxDurationDays: 365, DefaultIAL: 0, DefaultAAL: 2},
	{Key: "prehire", Name: "Pre-hires", MaxDurationDays: 90, DefaultIAL: 2, DefaultAAL: 2},
	{Key: "partner", Name: "External partners", MaxDurationDays: 365, DefaultIAL: 0, DefaultAAL: 2},
}

// SeedPopulations creates the default populations that are missing. It leaves
// an existing row's settings alone.
func SeedPopulations(c *store.TenantTx, now time.Time) error {
	have, err := c.GuestPopulations()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, p := range have {
		seen[p.Key] = true
	}
	for _, p := range DefaultPopulations {
		if seen[p.Key] {
			continue
		}
		p.CreatedAt = now
		if err := c.PutGuestPopulation(&p); err != nil {
			return err
		}
	}
	return nil
}

// Stats counts what Backfill created.
type Stats struct {
	SourceRecords, Affiliations, Identifiers int
	// SkippedIdentifiers are identifiers another person already holds (two
	// HR records with one email); they are left for the review queue (GU-5).
	SkippedIdentifiers int
}

// SorHRIS is the system of record of the directory's people.
const SorHRIS = "hris"

// Backfill gives each human identity that has none a source record and an
// affiliation, and records the identifiers their HR record carries (email and
// employee id), authoritative because the HR system asserts them. It is
// idempotent. k may be nil: identifiers are then skipped.
func Backfill(c *store.TenantTx, k *identifiers.Keyer, now time.Time) (Stats, error) {
	var st Stats
	people, err := c.Identities()
	if err != nil {
		return st, err
	}
	affs, err := c.Affiliations()
	if err != nil {
		return st, err
	}
	srcs, err := c.SourceRecords()
	if err != nil {
		return st, err
	}
	hasAff, hasSrc := map[int64]bool{}, map[string]*store.SourceRecord{}
	for _, a := range affs {
		hasAff[a.IdentityID] = true
	}
	for _, s := range srcs {
		hasSrc[s.SOR+"\x00"+s.SORID] = s
	}
	for _, p := range people {
		if p.Type != "human" || p.Status == store.IdentityStatusMerged {
			continue
		}
		src := hasSrc[SorHRIS+"\x00"+p.ExternalID]
		if src == nil {
			attrs := ojson.Object{}
			if p.Department != nil {
				attrs = append(attrs, ojson.KV{Key: "department", Value: *p.Department})
			}
			if p.Title != nil {
				attrs = append(attrs, ojson.KV{Key: "title", Value: *p.Title})
			}
			raw, err := store.JSON(attrs)
			if err != nil {
				return st, err
			}
			id := p.ID
			src = &store.SourceRecord{ID: uuid.NewString(), IdentityID: &id, SOR: SorHRIS, SORID: p.ExternalID,
				Attributes: raw, Status: store.RecordActive, ReceivedAt: p.CreatedAt}
			if err := c.InsertSourceRecord(src); err != nil {
				return st, fmt.Errorf("identity: source record for %s: %w", p.ExternalID, err)
			}
			st.SourceRecords++
		}
		if !hasAff[p.ID] {
			if err := c.InsertAffiliation(employeeAffiliation(p, src.ID, now)); err != nil {
				return st, fmt.Errorf("identity: affiliation for %s: %w", p.ExternalID, err)
			}
			st.Affiliations++
		}
		if k == nil {
			continue
		}
		have, err := c.IdentifiersFor(p.ID)
		if err != nil {
			return st, err
		}
		if len(have) > 0 {
			continue
		}
		wanted := []struct{ typ, val string }{{store.IdentEmployeeID, p.ExternalID}}
		if p.Email != nil && *p.Email != "" {
			wanted = append([]struct{ typ, val string }{{store.IdentEmail, *p.Email}}, wanted...)
		}
		for _, w := range wanted {
			added, err := addIdentifier(c, k, p, src.ID, w.typ, w.val)
			if err != nil {
				return st, err
			}
			if added {
				st.Identifiers++
			} else {
				st.SkippedIdentifiers++
			}
		}
	}
	return st, nil
}

// employeeAffiliation is the HR relationship of a directory person: from the
// hire date (or the day the record was created), ended at termination.
func employeeAffiliation(p *store.Identity, srcID string, now time.Time) *store.Affiliation {
	starts := p.CreatedAt
	if p.HiredAt != nil {
		starts = *p.HiredAt
	}
	ref := srcID
	a := &store.Affiliation{ID: uuid.NewString(), IdentityID: p.ID, Type: store.AffEmployee, Source: store.AffSourceHRIS,
		SourceRef: &ref, StartsAt: starts, Status: store.AffActive, CreatedAt: now}
	if p.Department != nil && *p.Department != "" {
		d := *p.Department
		a.OrgUnit = &d
	}
	switch {
	case p.Status == "terminated" || p.TerminatedAt != nil:
		end := p.CreatedAt
		if p.TerminatedAt != nil {
			end = *p.TerminatedAt
		}
		if end.Before(starts) {
			end = starts
		}
		a.Status, a.EndsAt = store.AffEnded, &end
	case starts.After(now):
		a.Status = store.AffPending
	}
	return a
}

// addIdentifier records one authoritative identifier; false when the value is
// unusable or another person already holds it.
func addIdentifier(c *store.TenantTx, k *identifiers.Keyer, p *store.Identity, srcID, typ, val string) (bool, error) {
	norm, mac, err := k.Prepare(c.Tenant(), typ, "", val)
	if err != nil {
		return false, nil // a malformed HR value is not an identifier; never fail the seed on it
	}
	if _, err := c.IdentifierByHMAC(typ, "", mac); err == nil {
		return false, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	by, at := store.VerifiedBySource, p.CreatedAt
	x := &store.Identifier{ID: uuid.NewString(), IdentityID: p.ID, Type: typ, ValueNorm: norm, ValueHMAC: mac,
		VerifiedAt: &at, VerifiedBy: &by, SourceRecordID: &srcID, Status: store.RecordActive, CreatedAt: p.CreatedAt}
	if err := c.InsertIdentifier(x); err != nil {
		return false, err
	}
	return true, nil
}
