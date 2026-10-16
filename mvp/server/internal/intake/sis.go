package intake

import (
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// sisExternalID is the directory external id of an applicant. The prefix keeps
// it apart from HR worker ids, so a SIS id never names an employee.
func sisExternalID(applicantID string) string { return "sis-" + applicantID }

var sisStatuses = map[string]bool{connectors.SisApplied: true, connectors.SisAdmitted: true, connectors.SisDeposited: true,
	connectors.SisMatriculated: true, connectors.SisWithdrawn: true, connectors.SisDenied: true}

// ApplySIS applies one SIS status change (design §3, §8.4):
//
//	applied      applicant affiliation starts
//	admitted,    applicant converts to admit (admit starts, applicant ends)
//	deposited
//	matriculated admit (or applicant) converts to student
//	withdrawn,   the applicant or admit affiliation is revoked
//	denied
//
// All of it happens on one identity. A status that is older than the person's
// current one changes nothing, so a late or replayed feed is safe.
func ApplySIS(c *store.TenantTx, k *identifiers.Keyer, r *connectors.SisRecord, now time.Time) (*Result, error) {
	if k == nil {
		return nil, errors.New("intake: no identifier key")
	}
	eventID, ok1 := clean(r.EventID, maxID)
	appID, ok2 := clean(r.ApplicantID, maxID)
	name, ok3 := clean(r.Name, maxName)
	if !ok1 || !ok2 || !ok3 || !sisStatuses[r.Status] || r.EffectiveAt.IsZero() {
		return rejectSIS(c, eventID, r, now)
	}
	if err := SeedSponsors(c, now); err != nil {
		return nil, err
	}
	rec, dup, err := newIntake(c, store.ChannelSIS, SponsorAdmissions, SorSIS+":"+eventID, r.Status, r.EffectiveAt, now)
	if err != nil {
		return nil, err
	}
	if dup {
		res := &Result{Outcome: OutcomeDuplicate, IntakeID: rec.ID}
		if rec.IdentityID != nil {
			res.IdentityID = *rec.IdentityID
		}
		return res, nil
	}
	// the applicant's personal email is required (design §4.2); a malformed one is a bad record
	email := r.Email
	if _, _, err := k.Digest(c.Tenant(), store.IdentEmail, "", email); err != nil {
		return finish(c, rec, store.IntakeRejected, 0, nil, OutcomeRejected, reasonBadRecord, now)
	}
	asserted := []idAssertion{{store.IdentApplicantID, appID}}
	if sid := optional(r.StudentID, maxID); sid != "" {
		asserted = append(asserted, idAssertion{store.IdentStudentID, sid})
	}
	f, err := lookup(c, k, SorSIS, appID, asserted, email)
	if err != nil {
		return nil, err
	}
	if f.review != "" {
		var srcID *string
		if f.source != nil {
			srcID = &f.source.ID
		}
		return finish(c, rec, store.IntakeReview, 0, srcID, OutcomeReview, f.review, now)
	}
	created := false
	who := f.identityID
	if who == 0 {
		if r.Status == connectors.SisWithdrawn || r.Status == connectors.SisDenied {
			// an application we never saw ended: there is nobody to create
			return finish(c, rec, store.IntakeResolved, 0, nil, OutcomeUnchanged, "", now)
		}
		who, created, err = ensureIdentity(c, &store.Identity{ExternalID: sisExternalID(appID), Name: name,
			Source: strPtr("sis"), CreatedAt: now})
		if err != nil {
			return nil, err
		}
	}
	src := f.source
	raw, err := attrs("program", optional(r.Program, maxField), "term", optional(r.Term, maxField), "status", r.Status,
		"event", eventID)
	if err != nil {
		return nil, err
	}
	if src == nil {
		src = &store.SourceRecord{ID: newID(), IdentityID: &who, SOR: SorSIS, SORID: appID, Attributes: raw,
			Status: store.RecordActive, ReceivedAt: now}
		if err := c.InsertSourceRecord(src); err != nil {
			return nil, err
		}
	} else if err := c.UpdateSourceRecord(src.ID, raw, now); err != nil {
		return nil, err
	}
	for _, a := range asserted {
		if _, err := addIdentifier(c, k, who, src.ID, a.typ, a.value, now); err != nil {
			return nil, err
		}
	}
	if _, err := addIdentifier(c, k, who, src.ID, store.IdentEmail, email, now); err != nil {
		return nil, err
	}
	outcome, conv, err := sisTransition(c, who, rec, r, now)
	if err != nil {
		return nil, err
	}
	if created && outcome == OutcomeStarted {
		outcome = OutcomeCreated
	}
	res, err := finish(c, rec, store.IntakeResolved, who, &src.ID, outcome, "", now)
	if err != nil {
		return nil, err
	}
	res.Conversion = conv
	return res, nil
}

// rejectSIS records an unusable record without its content (an unusable event
// id gets a key from the clock, so the rejection is still visible).
func rejectSIS(c *store.TenantTx, eventID string, r *connectors.SisRecord, now time.Time) (*Result, error) {
	if err := SeedSponsors(c, now); err != nil {
		return nil, err
	}
	key := SorSIS + ":" + eventID
	if eventID == "" {
		key = SorSIS + ":invalid:" + newID()
	}
	rec, dup, err := newIntake(c, store.ChannelSIS, SponsorAdmissions, key, optional(r.Status, maxField), nonZero(r.EffectiveAt, now), now)
	if err != nil {
		return nil, err
	}
	if dup {
		return &Result{Outcome: OutcomeDuplicate, IntakeID: rec.ID}, nil
	}
	return finish(c, rec, store.IntakeRejected, 0, nil, OutcomeRejected, reasonBadRecord, now)
}

func nonZero(t, def time.Time) time.Time {
	if t.IsZero() {
		return def
	}
	return t
}

// rank orders the application funnel; withdrawn and denied are not on it.
func rank(typ string) int {
	switch typ {
	case store.AffApplicant:
		return 1
	case store.AffAdmit:
		return 2
	case store.AffStudent:
		return 3
	}
	return 0
}

// sisTransition moves the person's SIS affiliations to the state the status
// names. A change effective in the future takes effect now: the feed reports
// what has happened.
func sisTransition(c *store.TenantTx, who int64, rec *store.IntakeRecord, r *connectors.SisRecord, now time.Time) (string, *store.Conversion, error) {
	at := r.EffectiveAt.UTC()
	if at.After(now) {
		at = now
	}
	held, err := current(c, who, now, store.AffApplicant, store.AffAdmit, store.AffStudent)
	if err != nil {
		return "", nil, err
	}
	var top *store.Affiliation // the most advanced affiliation held
	for _, a := range held {
		if top == nil || rank(a.Type) > rank(top.Type) {
			top = a
		}
	}
	unit := optional(r.Program, maxField)
	srcRef := rec.ID
	switch r.Status {
	case connectors.SisWithdrawn, connectors.SisDenied:
		ended := false
		for _, a := range held {
			if a.Type == store.AffStudent {
				continue // leaving the university after matriculation is the registrar's, not an application ending
			}
			if err := stop(c, a, store.AffRevoked, at, "application "+r.Status); err != nil {
				return "", nil, err
			}
			ended = true
		}
		if ended {
			return OutcomeEnded, nil, nil
		}
		return OutcomeUnchanged, nil, nil
	}
	target := store.AffApplicant
	switch r.Status {
	case connectors.SisAdmitted, connectors.SisDeposited:
		target = store.AffAdmit
	case connectors.SisMatriculated:
		target = store.AffStudent
	}
	if top != nil && rank(top.Type) >= rank(target) {
		return OutcomeUnchanged, nil, nil
	}
	ends, pop, err := sisEnd(c, target, at, r.TermStart)
	if err != nil {
		return "", nil, err
	}
	to, err := start(c, who, target, store.AffSourceSIS, srcRef, unit, pop, at, ends, now)
	if err != nil {
		return "", nil, err
	}
	if top == nil {
		return OutcomeStarted, nil, nil
	}
	// the less advanced affiliations all end; the most advanced one is the "from" of the conversion
	for _, a := range held {
		if a.ID != top.ID {
			if err := stop(c, a, store.AffEnded, at, "converted to "+target); err != nil {
				return "", nil, err
			}
		}
	}
	conv, err := convert(c, top, to, store.ConvSISStatus, rec, at, now)
	if err != nil {
		return "", nil, err
	}
	return OutcomeConverted, conv, nil
}

// sisEnd is when a new SIS affiliation ends and which population bounds it:
// an applicant until the application term plus six months, an admit until
// matriculation plus 30 days, a student until the registrar ends it. Without a
// term start, or with one already past, the population's maximum applies.
func sisEnd(c *store.TenantTx, typ string, at time.Time, term *time.Time) (*time.Time, string, error) {
	if typ == store.AffStudent {
		return nil, "", nil
	}
	max, err := populationDays(c, "applicant")
	if err != nil {
		return nil, "", err
	}
	end := at.Add(max)
	if term != nil {
		tail := appTail
		if typ == store.AffAdmit {
			tail = admitTail
		}
		if t := term.UTC().Add(tail); t.After(at) && t.Before(end) {
			end = t
		}
	}
	return &end, "applicant", nil
}
