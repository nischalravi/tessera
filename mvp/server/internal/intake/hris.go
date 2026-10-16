package intake

import (
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Phases of an HRIS hire; part of the event key, so the announcement and the
// effective hire of one event are two intakes.
const (
	phaseAnnounce  = "announce"
	phaseEffective = "effective"
	phaseRescind   = "rescind"
)

func payloadStr(o ojson.Object, key string) string {
	if v, ok := o.Get(key); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func payloadTrue(o ojson.Object, key string) bool {
	v, ok := o.Get(key)
	b, isBool := v.(bool)
	return ok && isBool && b
}

// ApplyHRIS applies one HRIS event to the pre-hire lifecycle (design §3, §8.4).
// It reads only connectors.HrisEventRecord, so any HRIS connector that emits
// these events works:
//
//   - a joiner whose effective date is in the future announces an accepted
//     offer: the person gets a prehire affiliation (until the start date plus
//     30 days) and HR is the organizational sponsor;
//   - the same joiner once its date has arrived converts the prehire to an
//     employee: prehire ends, employee starts, same identity;
//   - a leaver (or a joiner marked rescinded) for a worker who has not started
//     rescinds the offer: the prehire affiliation is revoked.
//
// Any other event (a joiner with no prior announcement, a leaver of an
// employee, movers, usage) is not intake and is left to the JML process.
// Payload keys: worker_id (or the event's identity external id), name,
// personal_email (or email), department, title, manager_external_id.
func ApplyHRIS(c *store.TenantTx, k *identifiers.Keyer, ev *connectors.HrisEventRecord, now time.Time) (*Result, error) {
	if k == nil {
		return nil, errors.New("intake: no identifier key")
	}
	if ev.Type != "joiner" && ev.Type != "leaver" {
		return &Result{Outcome: OutcomeIgnored}, nil
	}
	worker := payloadStr(ev.Payload, "worker_id")
	if worker == "" && ev.Identity != nil {
		worker = ev.Identity.ExternalID
	}
	worker, okW := clean(worker, maxID)
	evID, okE := clean(ev.ExternalID, maxID)
	if !okW || !okE {
		return &Result{Outcome: OutcomeIgnored, Reason: reasonNoWorker}, nil
	}
	phase := phaseEffective
	switch {
	case ev.Type == "leaver" || payloadTrue(ev.Payload, "rescinded"):
		phase = phaseRescind
	case ev.EffectiveAt.After(now):
		phase = phaseAnnounce
	}
	key := SorHRIS + ":" + evID + ":" + phase
	if prev, err := c.IntakeRecordByEvent(key); err == nil {
		res := &Result{Outcome: OutcomeDuplicate, IntakeID: prev.ID}
		if prev.IdentityID != nil {
			res.IdentityID = *prev.IdentityID
		}
		return res, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	switch phase {
	case phaseAnnounce:
		return hrisAnnounce(c, k, ev, worker, key, now)
	case phaseRescind:
		return hrisRescind(c, ev, worker, key, now)
	}
	return hrisHire(c, ev, worker, key, now)
}

// workerPerson is the person a worker id's source record belongs to, or 0.
func workerPerson(c *store.TenantTx, worker string) (int64, *store.SourceRecord, error) {
	src, err := c.SourceRecordBySOR(SorHRIS, worker)
	if errors.Is(err, store.ErrNotFound) || (err == nil && src.IdentityID == nil) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	who, err := survivor(c, *src.IdentityID)
	return who, src, err
}

func hrisAnnounce(c *store.TenantTx, k *identifiers.Keyer, ev *connectors.HrisEventRecord, worker, key string, now time.Time) (*Result, error) {
	if err := SeedSponsors(c, now); err != nil {
		return nil, err
	}
	hire := ev.EffectiveAt.UTC()
	rec, _, err := newIntake(c, store.ChannelHRIS, SponsorHR, key, ev.Type, hire, now)
	if err != nil {
		return nil, err
	}
	name, okN := clean(payloadStr(ev.Payload, "name"), maxName)
	email := payloadStr(ev.Payload, "personal_email")
	if email == "" {
		email = payloadStr(ev.Payload, "email")
	}
	if _, _, err := k.Digest(c.Tenant(), store.IdentEmail, "", email); err != nil || !okN {
		return finish(c, rec, store.IntakeRejected, 0, nil, OutcomeRejected, reasonBadRecord, now)
	}
	if _, err := c.GuestPopulation("prehire"); err != nil {
		return nil, err
	}
	f, err := lookup(c, k, SorHRIS, worker, []idAssertion{{store.IdentEmployeeID, worker}}, email)
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
	dept, title := optional(payloadStr(ev.Payload, "department"), maxField), optional(payloadStr(ev.Payload, "title"), maxField)
	who, created := f.identityID, false
	if who == 0 {
		i := &store.Identity{ExternalID: worker, Name: name, Source: strPtr("hris"), HiredAt: &hire, CreatedAt: now}
		if dept != "" {
			i.Department = &dept
		}
		if title != "" {
			i.Title = &title
		}
		if m := optional(payloadStr(ev.Payload, "manager_external_id"), maxID); m != "" {
			if mgr, err := c.IdentityByExternalID(m); err == nil {
				i.ManagerID = &mgr.ID
			} else if !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
		}
		if who, created, err = ensureIdentity(c, i); err != nil {
			return nil, err
		}
	}
	held, err := current(c, who, now, store.AffEmployee, store.AffPrehire)
	if err != nil {
		return nil, err
	}
	if len(held) > 0 {
		return finish(c, rec, store.IntakeResolved, who, nil, OutcomeUnchanged, reasonAlreadyHired, now)
	}
	raw, err := attrs("department", dept, "title", title, "hire_date", hire.Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	src := f.source
	if src == nil {
		src = &store.SourceRecord{ID: newID(), IdentityID: &who, SOR: SorHRIS, SORID: worker, Attributes: raw,
			Status: store.RecordActive, ReceivedAt: now}
		if err := c.InsertSourceRecord(src); err != nil {
			return nil, err
		}
	} else if err := c.UpdateSourceRecord(src.ID, raw, now); err != nil {
		return nil, err
	}
	for _, a := range []idAssertion{{store.IdentEmployeeID, worker}, {store.IdentEmail, email}} {
		if _, err := addIdentifier(c, k, who, src.ID, a.typ, a.value, now); err != nil {
			return nil, err
		}
	}
	// the offer is accepted now; with no hire event the pre-hire ends 30 days after the start date
	ends := hire.Add(holdAfter)
	if _, err := start(c, who, store.AffPrehire, store.AffSourceHRIS, rec.ID, dept, "prehire", now, &ends, now); err != nil {
		return nil, err
	}
	outcome := OutcomeStarted
	if created {
		outcome = OutcomeCreated
	}
	return finish(c, rec, store.IntakeResolved, who, &src.ID, outcome, "", now)
}

// hrisHire converts a pre-hire whose start date has arrived. A hire with no
// announced pre-hire is the JML joiner flow's, not intake's.
func hrisHire(c *store.TenantTx, ev *connectors.HrisEventRecord, worker, key string, now time.Time) (*Result, error) {
	who, src, err := workerPerson(c, worker)
	if err != nil || who == 0 {
		return &Result{Outcome: OutcomeIgnored, Reason: reasonNoPrehire}, err
	}
	pre, err := current(c, who, now, store.AffPrehire)
	if err != nil {
		return nil, err
	}
	if len(pre) == 0 {
		return &Result{Outcome: OutcomeIgnored, Reason: reasonNoPrehire}, nil
	}
	if err := SeedSponsors(c, now); err != nil {
		return nil, err
	}
	at := ev.EffectiveAt.UTC()
	rec, _, err := newIntake(c, store.ChannelHRIS, SponsorHR, key, ev.Type, at, now)
	if err != nil {
		return nil, err
	}
	from := pre[0]
	if at.Before(from.StartsAt) {
		at = from.StartsAt // the feed reported the hire after the fact
	}
	unit := optional(payloadStr(ev.Payload, "department"), maxField)
	if unit == "" && from.OrgUnit != nil {
		unit = *from.OrgUnit
	}
	to, err := start(c, who, store.AffEmployee, store.AffSourceHRIS, rec.ID, unit, "", at, nil, now)
	if err != nil {
		return nil, err
	}
	conv, err := convert(c, from, to, store.ConvHRISHire, rec, at, now)
	if err != nil {
		return nil, err
	}
	res, err := finish(c, rec, store.IntakeResolved, who, &src.ID, OutcomeConverted, "", now)
	if err != nil {
		return nil, err
	}
	res.Conversion = conv
	return res, nil
}

// hrisRescind ends the pre-hire of a worker whose offer was withdrawn before
// the start date. The person stays: the history is theirs, and a re-offer
// attaches to the same identity.
func hrisRescind(c *store.TenantTx, ev *connectors.HrisEventRecord, worker, key string, now time.Time) (*Result, error) {
	who, src, err := workerPerson(c, worker)
	if err != nil || who == 0 {
		return &Result{Outcome: OutcomeIgnored, Reason: reasonNoPrehire}, err
	}
	pre, err := current(c, who, now, store.AffPrehire)
	if err != nil {
		return nil, err
	}
	if len(pre) == 0 {
		return &Result{Outcome: OutcomeIgnored, Reason: reasonNoPrehire}, nil
	}
	if err := SeedSponsors(c, now); err != nil {
		return nil, err
	}
	at := ev.EffectiveAt.UTC()
	if at.After(now) || at.IsZero() {
		at = now
	}
	rec, _, err := newIntake(c, store.ChannelHRIS, SponsorHR, key, ev.Type, at, now)
	if err != nil {
		return nil, err
	}
	for _, a := range pre {
		if err := stop(c, a, store.AffRevoked, at, "offer rescinded"); err != nil {
			return nil, err
		}
	}
	return finish(c, rec, store.IntakeResolved, who, &src.ID, OutcomeEnded, "", now)
}
