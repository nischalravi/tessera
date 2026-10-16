// Package intake turns SIS status changes and future-dated HRIS hires into
// intake records and affiliations (guest accounts design §4.1, §8.4, issue
// #67 / GU-4).
//
// A feed record is authoritative: it may attach to an existing person, but
// only through an authoritative identifier (the system of record's own id, an
// employee id or a student id that the feed asserted). A personal email that
// belongs to someone else is not enough: the record is held in review for the
// matching of GU-5 and nothing is created for it. Self-asserted channels never
// reach this package.
//
// Conversion is one identity gaining and losing affiliations: applicant to
// admit to student, pre-hire to employee. The old affiliation ends and the new
// one starts on the same identity; the pair is written to identity_conversions
// and audited. Organizational sponsors (admissions, HR) stand behind these
// populations in place of an individual sponsor.
//
// Every function works inside the caller's tenant transaction, which carries
// the audit event, so a rollback leaves neither change nor event. A replayed
// feed is a no-op: each event has a key (system, event id and phase).
//
// The HRIS mapping reads the existing connectors.HrisEventRecord only, so a
// real connector that emits joiner and leaver events with the documented
// payload keys (see connectors.DemoPrehireHRIS) feeds it unchanged.
package intake

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Systems of record of the two feeds. The HRIS one is the directory's own
// (identity.SorHRIS), so a prehire and the employee they become share a source record.
const (
	SorSIS  = "sis"
	SorHRIS = "hris"
)

// Organizational sponsors (design §3).
const (
	SponsorAdmissions = "admissions"
	SponsorHR         = "hr"
)

// Outcomes of one applied record.
const (
	OutcomeCreated   = "created"   // a new person and affiliation
	OutcomeStarted   = "started"   // an affiliation began on a known person
	OutcomeConverted = "converted" // one affiliation ended, the next began
	OutcomeEnded     = "ended"     // an application withdrawn or an offer rescinded
	OutcomeUnchanged = "unchanged" // already in this state
	OutcomeReview    = "review"    // held for matching (GU-5)
	OutcomeRejected  = "rejected"  // the record is malformed
	OutcomeDuplicate = "duplicate" // this event was already applied
	OutcomeIgnored   = "ignored"   // not an intake event (no row is written)
)

// Limits on feed values.
const (
	maxID     = 64
	maxName   = 200
	maxField  = 100
	holdAfter = 30 * 24 * time.Hour // a pre-hire without a hire event ends this long after the start date (design §3)
	admitTail = 30 * 24 * time.Hour // an admit lasts until matriculation plus this
	appTail   = 183 * 24 * time.Hour
)

// DefaultSponsors are the organizational sponsors of the demo tenant.
var DefaultSponsors = []store.OrgSponsor{
	{Key: SponsorAdmissions, Name: "Office of Admissions", Population: "applicant"},
	{Key: SponsorHR, Name: "Human Resources", Population: "prehire"},
}

// SeedSponsors creates the default organizational sponsors that are missing.
// It leaves an existing row alone.
func SeedSponsors(c *store.TenantTx, now time.Time) error {
	have, err := c.OrgSponsors()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, o := range have {
		seen[o.Key] = true
	}
	for _, o := range DefaultSponsors {
		if seen[o.Key] {
			continue
		}
		o.CreatedAt = now
		if err := c.PutOrgSponsor(&o); err != nil {
			return err
		}
	}
	return nil
}

// Result is what one record did.
type Result struct {
	Outcome    string
	IntakeID   string
	IdentityID int64 // 0 when no person is involved (review, rejected, ignored)
	Reason     string
	Conversion *store.Conversion
}

// Stats counts a Run by outcome.
type Stats struct {
	Applied map[string]int
	Records int
}

func (s *Stats) add(r *Result) {
	if s.Applied == nil {
		s.Applied = map[string]int{}
	}
	s.Applied[r.Outcome]++
	s.Records++
}

// ctx is the actor-carrying context of the transaction.
func ctxOf(c *store.TenantTx) context.Context { return c.Context() }

// Run applies every SIS status change and HRIS event the connectors report
// after since, in feed order (SIS changes by effective date, so a status that
// arrives late does not undo a later one). Usage records are ignored.
func Run(c *store.TenantTx, k *identifiers.Keyer, now time.Time, conns []connectors.Connector, since *time.Time) (Stats, error) {
	var st Stats
	for _, cn := range conns {
		if sc, ok := cn.(connectors.SisConnector); ok {
			var recs []*connectors.SisRecord
			if err := sc.SisRecords(ctxOf(c), since, func(r *connectors.SisRecord) error {
				recs = append(recs, r)
				return nil
			}); err != nil {
				return st, fmt.Errorf("intake: %s: %w", cn.System(), err)
			}
			sort.SliceStable(recs, func(i, j int) bool { return recs[i].EffectiveAt.Before(recs[j].EffectiveAt) })
			for _, r := range recs {
				res, err := ApplySIS(c, k, r, now)
				if err != nil {
					return st, err
				}
				st.add(res)
			}
		}
		err := cn.StreamEvents(ctxOf(c), since, func(ev connectors.Event) error {
			h, ok := ev.(*connectors.HrisEventRecord)
			if !ok {
				return nil
			}
			res, err := ApplyHRIS(c, k, h, now)
			if err != nil {
				return err
			}
			if res.Outcome != OutcomeIgnored {
				st.add(res)
			}
			return nil
		})
		if err != nil {
			return st, fmt.Errorf("intake: %s: %w", cn.System(), err)
		}
	}
	return st, nil
}

// clean trims a feed value and reports whether it is usable text of at most max runes.
func clean(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > max || !utf8.ValidString(s) {
		return "", false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return s, true
}

// optional is clean for a value that may be empty (empty is fine, unusable text is dropped).
func optional(s string, max int) string {
	v, _ := clean(s, max)
	return v
}

// survivor follows merges: a feed that names a person merged into another
// reaches the survivor.
func survivor(c *store.TenantTx, id int64) (int64, error) {
	m, err := c.MergeSurvivors()
	if err != nil {
		return 0, err
	}
	if s, ok := m[id]; ok {
		return s, nil
	}
	return id, nil
}

// find is the lookup result of authoritative matching.
type find struct {
	identityID int64
	source     *store.SourceRecord
	review     string // non-empty: hold the record, with this reason
}

// holdReason values (no personal data).
const (
	reasonEmailTaken   = "email_matches_another_person"
	reasonAwaiting     = "awaiting_review"
	reasonBadRecord    = "invalid_record"
	reasonNoWorker     = "no_worker_id"
	reasonNoPrehire    = "no_active_prehire"
	reasonAlreadyHired = "already_employed"
)

// lookup finds the person an authoritative record belongs to: the system of
// record's own source record first, then the authoritative identifiers the
// feed asserted. A personal email that another person holds holds the record
// for review; a free email is not used to attach to anyone.
func lookup(c *store.TenantTx, k *identifiers.Keyer, sor, sorid string, ids []idAssertion, email string) (*find, error) {
	src, err := c.SourceRecordBySOR(sor, sorid)
	switch {
	case err == nil:
		if src.IdentityID == nil {
			return &find{source: src, review: reasonAwaiting}, nil
		}
		who, err := survivor(c, *src.IdentityID)
		if err != nil {
			return nil, err
		}
		return &find{identityID: who, source: src}, nil
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	for _, a := range ids {
		_, mac, err := k.Digest(c.Tenant(), a.typ, "", a.value)
		if err != nil {
			continue
		}
		x, err := c.IdentifierByHMAC(a.typ, "", mac)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		who, err := survivor(c, x.IdentityID)
		if err != nil {
			return nil, err
		}
		return &find{identityID: who}, nil
	}
	if email != "" {
		if _, mac, err := k.Digest(c.Tenant(), store.IdentEmail, "", email); err == nil {
			if _, err := c.IdentifierByHMAC(store.IdentEmail, "", mac); err == nil {
				return &find{review: reasonEmailTaken}, nil
			} else if !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
		}
	}
	return &find{}, nil
}

func newID() string { return uuid.NewString() }

func strPtr(s string) *string { return &s }

// ensureIdentity returns the person with i's external id, creating a human
// identity from i when there is none (created reports which).
func ensureIdentity(c *store.TenantTx, i *store.Identity) (id int64, created bool, err error) {
	if have, err := c.IdentityByExternalID(i.ExternalID); err == nil {
		who, err := survivor(c, have.ID)
		return who, false, err
	} else if !errors.Is(err, store.ErrNotFound) {
		return 0, false, err
	}
	i.Type, i.Status = "human", "active"
	id, err = c.InsertIdentity(i)
	return id, err == nil, err
}

// idAssertion is an authoritative identifier the feed asserts for a person.
type idAssertion struct{ typ, value string }

// addIdentifier records one authoritative identifier for a person; false when
// the value is unusable or another person holds it (left for the review queue).
func addIdentifier(c *store.TenantTx, k *identifiers.Keyer, identityID int64, srcID, typ, val string, now time.Time) (bool, error) {
	norm, mac, err := k.Digest(c.Tenant(), typ, "", val)
	if err != nil {
		return false, nil // a malformed feed value is not an identifier
	}
	if x, err := c.IdentifierByHMAC(typ, "", mac); err == nil {
		return x.IdentityID == identityID, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	by := store.VerifiedBySource
	x := &store.Identifier{ID: uuid.NewString(), IdentityID: identityID, Type: typ, ValueNorm: norm, ValueHMAC: mac,
		VerifiedAt: &now, VerifiedBy: &by, SourceRecordID: &srcID, Status: store.RecordActive, CreatedAt: now}
	if err := c.InsertIdentifier(x); err != nil {
		return false, err
	}
	return true, nil
}

// newIntake writes the intake record for an event, or returns the one already
// written (dup true).
func newIntake(c *store.TenantTx, channel, sponsor, key, typ string, effective, now time.Time) (rec *store.IntakeRecord, dup bool, err error) {
	if prev, err := c.IntakeRecordByEvent(key); err == nil {
		return prev, true, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, false, err
	}
	sp, eff := sponsor, effective
	rec = &store.IntakeRecord{ID: uuid.NewString(), Channel: channel, MatchMode: store.MatchAuthoritative, SponsorOrg: &sp,
		EventKey: key, EventType: typ, EffectiveAt: &eff, Status: store.IntakeReceived, Detail: "{}", CreatedAt: now}
	return rec, false, c.InsertIntakeRecord(rec)
}

// finish records the outcome on the intake record and appends the audit event.
// The audit detail carries ids and outcomes, never names, emails or identifiers.
func finish(c *store.TenantTx, rec *store.IntakeRecord, status string, identityID int64, srcID *string, outcome, reason string, now time.Time) (*Result, error) {
	var iid *int64
	if identityID != 0 {
		iid = &identityID
	}
	detail := ojson.Object{{Key: "outcome", Value: outcome}}
	if reason != "" {
		detail = append(detail, ojson.KV{Key: "reason", Value: reason})
	}
	raw, err := store.JSON(detail)
	if err != nil {
		return nil, err
	}
	if err := c.SetIntakeOutcome(rec.ID, status, iid, srcID, raw); err != nil {
		return nil, err
	}
	ad := ojson.Object{{Key: "intake_id", Value: rec.ID}, {Key: "channel", Value: rec.Channel},
		{Key: "event_type", Value: rec.EventType}, {Key: "outcome", Value: outcome}, {Key: "status", Value: status}}
	if iid != nil {
		ad = append(ad, ojson.KV{Key: "identity_id", Value: identityID})
	}
	if reason != "" {
		ad = append(ad, ojson.KV{Key: "reason", Value: reason})
	}
	if _, err := audit.Record(ctxOf(c), c, "intake."+rec.Channel+"."+outcome, ad, audit.At(now),
		audit.Target("intake", rec.ID)); err != nil {
		return nil, err
	}
	return &Result{Outcome: outcome, IntakeID: rec.ID, IdentityID: identityID, Reason: reason}, nil
}

// current returns a person's affiliations of the given types that have not ended.
func current(c *store.TenantTx, identityID int64, now time.Time, types ...string) ([]*store.Affiliation, error) {
	all, err := c.AffiliationsFor(identityID)
	if err != nil {
		return nil, err
	}
	var out []*store.Affiliation
	for _, a := range all {
		if a.Status != store.AffPending && a.Status != store.AffActive {
			continue
		}
		if a.EndsAt != nil && !a.EndsAt.After(now) {
			continue // ran out; nothing sweeps it until GU-11
		}
		for _, t := range types {
			if a.Type == t {
				out = append(out, a)
				break
			}
		}
	}
	return out, nil
}

// start inserts an affiliation of the feed's source on a person.
func start(c *store.TenantTx, identityID int64, typ, source, srcRef, unit, population string, at time.Time, ends *time.Time, now time.Time) (*store.Affiliation, error) {
	a := &store.Affiliation{ID: uuid.NewString(), IdentityID: identityID, Type: typ, Source: source, StartsAt: at,
		EndsAt: ends, Status: store.AffActive, CreatedAt: now}
	if at.After(now) {
		a.Status = store.AffPending
	}
	if srcRef != "" {
		a.SourceRef = &srcRef
	}
	if unit != "" {
		a.OrgUnit = &unit
	}
	if population != "" {
		a.Population = &population
	}
	return a, c.InsertAffiliation(a)
}

// stop ends an affiliation at at (not before it started).
func stop(c *store.TenantTx, a *store.Affiliation, status string, at time.Time, reason string) error {
	if at.Before(a.StartsAt) {
		at = a.StartsAt
	}
	return c.EndAffiliation(a.ID, status, at, nil, reason)
}

// convert ends from and records the pair with the audit event; to has already begun.
func convert(c *store.TenantTx, from, to *store.Affiliation, trigger string, rec *store.IntakeRecord, at, now time.Time) (*store.Conversion, error) {
	if err := stop(c, from, store.AffEnded, at, "converted to "+to.Type); err != nil {
		return nil, err
	}
	id := rec.ID
	v := &store.Conversion{ID: uuid.NewString(), IdentityID: to.IdentityID, FromAffiliationID: from.ID, ToAffiliationID: to.ID,
		FromType: from.Type, ToType: to.Type, Trigger: trigger, IntakeID: &id, EffectiveAt: at, CreatedAt: now}
	if err := c.InsertConversion(v); err != nil {
		return nil, err
	}
	_, err := audit.Record(ctxOf(c), c, "identity.conversion", ojson.Object{{Key: "identity_id", Value: to.IdentityID},
		{Key: "from", Value: from.Type}, {Key: "to", Value: to.Type}, {Key: "trigger", Value: trigger},
		{Key: "intake_id", Value: rec.ID}}, audit.At(now), audit.Target("identity", fmt.Sprint(to.IdentityID)))
	return v, err
}

// populationDays is a population's maximum duration, or an error naming the
// missing population (a tenant that was never seeded).
func populationDays(c *store.TenantTx, key string) (time.Duration, error) {
	p, err := c.GuestPopulation(key)
	if err != nil {
		return 0, fmt.Errorf("intake: population %q: %w", key, err)
	}
	return time.Duration(p.MaxDurationDays) * 24 * time.Hour, nil
}

// attrs is the non-sensitive attribute object of a source record.
func attrs(kv ...string) (string, error) {
	o := ojson.Object{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			o = append(o, ojson.KV{Key: kv[i], Value: kv[i+1]})
		}
	}
	return store.JSON(o)
}
