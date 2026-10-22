package intake

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Contractor (VMS) intake (issue #304). A record from Fieldglass, Beeline or a
// generic feed is authoritative like a SIS or HRIS one, and maps onto the
// lifecycle of issue #159: the person is a contractor with a sponsor and an end
// date, and the lifecycle sweep runs their leaver plan on that date.
//
//	active, pending  the contractor exists (created if new) with the sponsor and
//	                 end date the feed names; a later record moves either
//	ended            the term ends now: containment and the leaver plan run
//
// Rules:
//   - every contractor needs a sponsor, an active employee named by employee id
//     or e-mail. A record without one, with an unknown or ambiguous one, or
//     whose sponsor cannot sponsor, is held in review and changes nothing: no
//     contractor is ever created without a sponsor;
//   - a contractor needs an end date; a record without one is rejected;
//   - an end date further away than lifecycle.MaxTermDays is clamped to it (the
//     next sync moves it on), and the outcome says so;
//   - a record older than the one applied last changes nothing;
//   - a contractor whose e-mail belongs to someone else is held (matching).

// vmsSystems are the feed kinds a record may name.
var vmsSystems = map[string]bool{store.VmsFieldglass: true, store.VmsBeeline: true, store.VmsCSV: true}

var vmsStatuses = map[string]bool{connectors.VmsPending: true, connectors.VmsActive: true, connectors.VmsEnded: true}

// Hold and reject reasons of a contractor record (no personal data).
const (
	reasonSponsorRequired = "sponsor_required"
	reasonSponsorNotFound = "sponsor_not_found"
	reasonSponsorAmbig    = "sponsor_ambiguous"
	reasonSponsorIneligib = "sponsor_not_eligible"
	reasonSponsorSelf     = "sponsor_is_self"
	reasonEndRequired     = "end_required"
	reasonTermEnded       = "term_already_ended"
	reasonNotActive       = "identity_not_active"
	reasonNotContractor   = "not_a_contractor"
	reasonEndClamped      = "end_clamped"
)

// vmsExternalID is the directory external id of a contractor. The prefix keeps
// it apart from HR worker ids, so a VMS id never names an employee.
func vmsExternalID(system, workerID string) string { return "vms-" + system + "-" + workerID }

// vmsActor is who the lifecycle history and audit trail name.
func vmsActor(system string) requests.Actor { return requests.Actor{Display: "vms:" + system} }

// ApplyVMS applies one contractor record.
func ApplyVMS(c *store.TenantTx, k *identifiers.Keyer, r *connectors.VmsRecord, now time.Time) (*Result, error) {
	if k == nil {
		return nil, errors.New("intake: no identifier key")
	}
	system, ok0 := clean(r.System, 32)
	eventID, ok1 := clean(r.EventID, maxID)
	workerID, ok2 := clean(r.WorkerID, maxID)
	name, ok3 := clean(r.Name, maxName)
	if !ok0 || !vmsSystems[system] || !ok1 || !ok2 || !ok3 || !vmsStatuses[r.Status] {
		return rejectVMS(c, system, eventID, r, reasonBadRecord, now)
	}
	eff := nonZero(r.UpdatedAt.UTC(), now)
	rec, dup, err := newIntake(c, store.ChannelVMS, "", "vms:"+system+":"+eventID, r.Status, eff, now)
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
	email := r.Email
	if _, _, err := k.Digest(c.Tenant(), store.IdentEmail, "", email); err != nil {
		return finish(c, rec, store.IntakeEventRejected, 0, nil, OutcomeRejected, reasonBadRecord, now)
	}
	sorid := system + ":" + workerID
	f, err := lookup(c, k, SorVMS, sorid, nil, email)
	if err != nil {
		return nil, err
	}
	var srcID *string
	if f.source != nil {
		srcID = &f.source.ID
	}
	if f.review != "" {
		return finish(c, rec, store.IntakeEventReview, 0, srcID, OutcomeReview, f.review, now)
	}
	// an older record than the one applied last is stale, whatever its event id
	if f.source != nil && staleVMS(f.source, eff) {
		return finish(c, rec, store.IntakeEventResolved, f.identityID, srcID, OutcomeUnchanged, "stale_record", now)
	}
	if f.identityID != 0 {
		if res, err := vmsGuards(c, rec, f, srcID, now); res != nil || err != nil {
			return res, err
		}
	}
	ended := r.Status == connectors.VmsEnded || (r.EndsAt != nil && !r.EndsAt.After(now))
	if ended {
		return endVMS(c, rec, f, system, srcID, now)
	}
	if r.EndsAt == nil {
		return finish(c, rec, store.IntakeEventRejected, f.identityID, srcID, OutcomeRejected, reasonEndRequired, now)
	}
	sponsor, why, err := vmsSponsor(c, k, r, f.identityID)
	if err != nil {
		return nil, err
	}
	if why != "" {
		return finish(c, rec, store.IntakeEventReview, f.identityID, srcID, OutcomeReview, why, now)
	}
	endsAt, clamped := r.EndsAt.UTC(), false
	if limit := now.Add(time.Duration(lifecycle.MaxTermDays) * 24 * time.Hour); endsAt.After(limit) {
		endsAt, clamped = limit, true
	}
	var startsAt *time.Time
	if r.StartsAt != nil && r.StartsAt.After(now) && r.StartsAt.Before(endsAt) {
		s := r.StartsAt.UTC()
		startsAt = &s
	}
	who, created := f.identityID, false
	if who == 0 {
		who, created, err = ensureIdentity(c, &store.Identity{ExternalID: vmsExternalID(system, workerID), Name: name,
			Source: strPtr("vms"), CreatedAt: now})
		if err != nil {
			return nil, err
		}
	}
	src := f.source
	raw, err := attrs("supplier", optional(r.Supplier, maxField), "role", optional(r.Role, maxField), "status", r.Status,
		"system", system, "event", eventID, "updated_at", eff.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	if src == nil {
		src = &store.SourceRecord{ID: newID(), IdentityID: &who, SOR: SorVMS, SORID: sorid, Attributes: raw,
			Status: store.RecordActive, ReceivedAt: now}
		if err := c.InsertSourceRecord(src); err != nil {
			return nil, err
		}
	} else if err := c.UpdateSourceRecord(src.ID, raw, now); err != nil {
		return nil, err
	}
	if _, err := addIdentifier(c, k, who, src.ID, store.IdentEmail, email, now); err != nil {
		return nil, err
	}
	old, err := c.LifecycleFor(who)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	org := optional(r.Supplier, maxField)
	spec := lifecycle.Spec{WorkerType: store.WorkerContractor, SponsorID: &sponsor, StartsAt: startsAt, EndsAt: &endsAt,
		Reason: "contractor record from " + system}
	if org != "" {
		spec.Organization = &org
	}
	outcome := OutcomeUnchanged
	if old == nil || !sameVMSTerm(old, &spec) {
		if _, err := lifecycle.Set(c, who, spec, vmsActor(system), now); err != nil {
			return nil, fmt.Errorf("intake: contractor %s: %w", system, err)
		}
		outcome = OutcomeStarted
		if created {
			outcome = OutcomeCreated
		}
	}
	reason := ""
	if clamped {
		reason = reasonEndClamped
	}
	return finish(c, rec, store.IntakeEventResolved, who, &src.ID, outcome, reason, now)
}

// vmsGuards holds a record for a person the feed must not change: someone who
// is not a contractor (an employee that a feed id was matched to), a person who
// is no longer active, or one whose term already ended (a returning contractor
// is a human's decision).
func vmsGuards(c *store.TenantTx, rec *store.IntakeEvent, f *find, srcID *string, now time.Time) (*Result, error) {
	p, err := c.Identity(f.identityID)
	if err != nil {
		return nil, err
	}
	hold := func(why string) (*Result, error) {
		return finish(c, rec, store.IntakeEventReview, f.identityID, srcID, OutcomeReview, why, now)
	}
	if p.Status != "active" {
		return hold(reasonNotActive)
	}
	l, err := c.LifecycleFor(p.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return hold(reasonNotContractor)
	case err != nil:
		return nil, err
	case l.WorkerType != store.WorkerContractor:
		return hold(reasonNotContractor)
	case l.EndedAt != nil:
		return hold(reasonTermEnded)
	}
	return nil, nil
}

// endVMS ends the contractor's term now (the assignment ended in the VMS).
func endVMS(c *store.TenantTx, rec *store.IntakeEvent, f *find, system string, srcID *string, now time.Time) (*Result, error) {
	if f.identityID == 0 {
		return finish(c, rec, store.IntakeEventResolved, 0, srcID, OutcomeUnchanged, "", now) // nobody to end
	}
	_, ended, err := lifecycle.EndNow(c, f.identityID, "assignment ended in "+system, vmsActor(system), now)
	if err != nil {
		return nil, err
	}
	outcome := OutcomeUnchanged
	if ended {
		outcome = OutcomeEnded
	}
	return finish(c, rec, store.IntakeEventResolved, f.identityID, srcID, outcome, "", now)
}

// vmsSponsor resolves the sponsor a record names to an eligible employee. why
// is the review reason when there is none.
func vmsSponsor(c *store.TenantTx, k *identifiers.Keyer, r *connectors.VmsRecord, contractor int64) (id int64, why string, err error) {
	empID, mail := optional(r.SponsorEmployeeID, maxID), optional(r.SponsorEmail, maxName)
	if empID == "" && mail == "" {
		return 0, reasonSponsorRequired, nil
	}
	var sp *store.Identity
	if empID != "" {
		sp, err = c.IdentityByExternalID(empID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return 0, "", err
		}
		if err != nil {
			sp = nil
		}
	}
	if sp == nil && mail != "" {
		have, err := c.IdentitiesByEmail(mail)
		if err != nil {
			return 0, "", err
		}
		switch len(have) {
		case 0:
		case 1:
			sp = have[0]
		default:
			return 0, reasonSponsorAmbig, nil
		}
	}
	if sp == nil {
		return 0, reasonSponsorNotFound, nil
	}
	who, err := survivor(c, sp.ID)
	if err != nil {
		return 0, "", err
	}
	if sp, err = c.Identity(who); err != nil {
		return 0, "", err
	}
	switch {
	case contractor != 0 && sp.ID == contractor:
		return 0, reasonSponsorSelf, nil
	case sp.Type != "human" || sp.Status != "active":
		return 0, reasonSponsorIneligib, nil
	}
	if l, err := c.LifecycleFor(sp.ID); err == nil && l.WorkerType != store.WorkerEmployee {
		return 0, reasonSponsorIneligib, nil
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return 0, "", err
	}
	return sp.ID, "", nil
}

// sameVMSTerm reports whether the stored lifecycle already is the one a record asks for.
func sameVMSTerm(l *store.Lifecycle, s *lifecycle.Spec) bool {
	eq := func(a, b *time.Time) bool { return (a == nil && b == nil) || (a != nil && b != nil && a.Equal(*b)) }
	org := func(a, b *string) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }
	return l.WorkerType == s.WorkerType && l.SponsorID != nil && s.SponsorID != nil && *l.SponsorID == *s.SponsorID &&
		eq(l.EndsAt, s.EndsAt) && eq(l.StartsAt, s.StartsAt) && org(l.Organization, s.Organization)
}

// staleVMS reports whether the source record already holds a version newer than at.
func staleVMS(src *store.SourceRecord, at time.Time) bool {
	var a map[string]string
	if json.Unmarshal([]byte(src.Attributes), &a) != nil {
		return false
	}
	prev, err := time.Parse(time.RFC3339Nano, a["updated_at"])
	return err == nil && at.Before(prev)
}

// rejectVMS records an unusable record without its content (an unusable event
// id gets a key from the clock, so the rejection is still visible).
func rejectVMS(c *store.TenantTx, system, eventID string, r *connectors.VmsRecord, why string, now time.Time) (*Result, error) {
	key := "vms:" + system + ":" + eventID
	if system == "" || !vmsSystems[system] || eventID == "" {
		key = "vms:invalid:" + newID()
	}
	rec, dup, err := newIntake(c, store.ChannelVMS, "", key, optional(r.Status, maxField), nonZero(r.UpdatedAt.UTC(), now), now)
	if err != nil {
		return nil, err
	}
	if dup {
		return &Result{Outcome: OutcomeDuplicate, IntakeID: rec.ID}, nil
	}
	return finish(c, rec, store.IntakeEventRejected, 0, nil, OutcomeRejected, why, now)
}

// SortVMS orders records oldest first, so an assignment that changed twice in a
// window ends in its latest state.
func SortVMS(recs []*connectors.VmsRecord) {
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].UpdatedAt.Before(recs[j].UpdatedAt) })
}
