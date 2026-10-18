package sponsorship

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Result is a written invitation.
type Result struct {
	Sponsorship *store.Sponsorship
	Guest       *store.Identity
	Decision    Decision
}

// refusal turns a refused decision into the API's error.
func refusal(d Decision) error {
	return refuse(422, d.Code, "%s", d.Message)
}

// Invite checks an invitation and, if the policy permits it, writes it: a new
// identity (status invited, external id guest:<uuid>), the sponsor-asserted
// and unverified email identifier, the source and intake records, and the
// sponsorship, which is active or waits for a second approver. It never looks
// for the person among the people we know (K3), and a refusal writes nothing.
// channel is the intake channel (sponsor_invite or bulk_invite); batch ties
// the rows of a bulk invitation together.
func (s *Service) Invite(tx *store.TenantTx, by Actor, in Invite, channel, batch string, now time.Time) (*Result, error) {
	p, err := s.Check(tx, by, in, nil, nil, now)
	if err != nil {
		return nil, err
	}
	if !p.Decision.Allowed {
		return nil, refusal(p.Decision)
	}
	return s.writeInvite(tx, by, p, channel, batch, now)
}

func (s *Service) writeInvite(tx *store.TenantTx, by Actor, p *Plan, channel, batch string, now time.Time) (*Result, error) {
	if s.Keyer == nil {
		return nil, errors.New("sponsorship: no identifier key")
	}
	sp, err := sponsorOf(tx, by)
	if err != nil {
		return nil, err
	}
	intakeID := uuid.NewString()
	// the identifier's issuer is this one invitation: two invitations for one
	// email never collide, so nothing a sponsor sees depends on who else is known
	issuer := "sponsor-invite:" + intakeID
	norm, mac, err := s.Keyer.Digest(tx.Tenant(), store.IdentEmail, issuer, p.Email)
	if err != nil {
		return nil, refuse(422, "invalid_email", "%s", err.Error())
	}
	email, source := p.Email, SourceSor
	guestID, err := tx.InsertIdentity(&store.Identity{TenantID: tx.Tenant(), ExternalID: "guest:" + uuid.NewString(),
		Name: strings.TrimSpace(p.Given + " " + p.Family), Email: &email, Type: "human", Status: "invited", Source: &source, CreatedAt: now})
	if err != nil {
		return nil, err
	}
	attrs, err := json.Marshal(map[string]any{"asserted_by": "sponsor", "sponsor_identity_id": sp.ID, "channel": channel,
		"given_name": p.Given, "family_name": p.Family})
	if err != nil {
		return nil, err
	}
	srcID := uuid.NewString()
	if err := tx.InsertSourceRecord(&store.SourceRecord{ID: srcID, IdentityID: &guestID, SOR: SourceSor, SORID: intakeID,
		Attributes: string(attrs), Status: store.RecordActive, ReceivedAt: now}); err != nil {
		return nil, err
	}
	intake := &store.IntakeRecord{ID: intakeID, Channel: channel, MatchMode: store.MatchSelfAsserted, SourceRecordID: &srcID,
		SubmittedBy: by.uid(), SponsorIdentityID: &sp.ID, Status: store.IntakeReceived, InvitationStatus: store.InvitationReady, CreatedAt: now}
	if batch != "" {
		intake.BatchID = &batch
	}
	if err := tx.InsertIntake(intake); err != nil {
		return nil, err
	}
	// sponsor-asserted: never verified until the guest proves the address (GU-6)
	if err := tx.InsertIdentifier(&store.Identifier{ID: uuid.NewString(), IdentityID: guestID, Type: store.IdentEmail, Issuer: issuer,
		ValueNorm: norm, ValueHMAC: mac, SourceRecordID: &srcID, Status: store.RecordActive, CreatedAt: now}); err != nil {
		return nil, err
	}
	guest, err := tx.Identity(guestID)
	if err != nil {
		return nil, err
	}
	ss, err := s.create(tx, by, sp, guest, p, intakeID, now)
	if err != nil {
		return nil, err
	}
	return &Result{Sponsorship: ss, Guest: guest, Decision: p.Decision}, nil
}

// SponsorExisting makes the sponsor a further sponsor of a person who is
// already known (a second sponsorship, for example after a merge, GU-5). The
// API does not expose it: an invitation never names an existing person.
func (s *Service) SponsorExisting(tx *store.TenantTx, by Actor, guestID int64, in Invite, now time.Time) (*Result, error) {
	guest, err := tx.Identity(guestID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "identity_not_found", "person not found")
	} else if err != nil {
		return nil, err
	}
	p, err := s.Check(tx, by, in, guest, nil, now)
	if err != nil {
		return nil, err
	}
	if !p.Decision.Allowed {
		return nil, refusal(p.Decision)
	}
	sp, err := sponsorOf(tx, by)
	if err != nil {
		return nil, err
	}
	intakeID := uuid.NewString()
	if err := tx.InsertIntake(&store.IntakeRecord{ID: intakeID, Channel: store.ChannelSponsorInvite, MatchMode: store.MatchSelfAsserted,
		SubmittedBy: by.uid(), SponsorIdentityID: &sp.ID, Status: "resolved", InvitationStatus: store.InvitationReady, CreatedAt: now}); err != nil {
		return nil, err
	}
	ss, err := s.create(tx, by, sp, guest, p, intakeID, now)
	if err != nil {
		return nil, err
	}
	return &Result{Sponsorship: ss, Guest: guest, Decision: p.Decision}, nil
}

// create writes the sponsorship of an allowed plan and, when no second
// approver is needed, activates it.
func (s *Service) create(tx *store.TenantTx, by Actor, sp, guest *store.Identity, p *Plan, intakeID string, now time.Time) (*store.Sponsorship, error) {
	bundle, err := json.Marshal(p.Bundle)
	if err != nil {
		return nil, err
	}
	status := store.SponsorActive
	if p.Decision.NeedsApproval {
		status = store.SponsorPendingApproval
	}
	ss := &store.Sponsorship{ID: uuid.NewString(), GuestIdentityID: guest.ID, IntakeID: intakeID, SponsorIdentityID: sp.ID,
		Population: p.Population.Key, Purpose: p.Purpose, AccessBundle: string(bundle), RequiredIAL: p.RequiredIAL,
		RequiredAAL: p.RequiredAAL, StartsAt: p.Starts, EndsAt: p.Ends, Status: status, PolicyVersion: p.Decision.Version,
		CreatedBy: by.uid(), CreatedAt: now, UpdatedAt: now}
	if err := tx.InsertSponsorship(ss); err != nil {
		return nil, err
	}
	if err := s.event(tx, ss, "created", "", by, p.Purpose, now); err != nil {
		return nil, err
	}
	if status == store.SponsorPendingApproval {
		if err := s.event(tx, ss, "approval_requested", status, by, "", now); err != nil {
			return nil, err
		}
		if err := notify.SponsorshipApprovalNeeded(tx, now, ss, by.skip()...); err != nil {
			return nil, err
		}
	} else if err := s.activate(tx, ss, by, now); err != nil {
		return nil, err
	}
	return ss, tx.Audit(now, by.Display, "sponsorship.create", detail(ss, rulesKV(p.Decision),
		ojson.KV{Key: "intake_id", Value: intakeID}, ojson.KV{Key: "needs_approval", Value: p.Decision.NeedsApproval},
		ojson.KV{Key: "bundle_items", Value: len(p.Bundle)}, ojson.KV{Key: "required_ial", Value: p.RequiredIAL}))
}

func (a Actor) skip() []string {
	if u := a.uid(); u != nil {
		return []string{*u}
	}
	return nil
}

// event appends to the history. from is the previous status ("" for none).
func (s *Service) event(tx *store.TenantTx, ss *store.Sponsorship, ev, from string, by Actor, note string, now time.Time) error {
	e := &store.SponsorshipEvent{SponsorshipID: ss.ID, Event: ev, ToStatus: ss.Status, PolicyVersion: ss.PolicyVersion,
		ActorUserID: by.uid(), Actor: by.Display, At: now}
	if from != "" {
		e.FromStatus = &from
	}
	if note = strings.TrimSpace(note); note != "" {
		e.Note = &note
	}
	return tx.AddSponsorshipEvent(e)
}

// activate makes a sponsorship's standing real: the guest's affiliation and
// lifecycle. Its status is already active.
func (s *Service) activate(tx *store.TenantTx, ss *store.Sponsorship, by Actor, now time.Time) error {
	pop, _ := PopulationOf(ss.Population)
	if a, err := affiliations.ForSponsorship(tx, ss.GuestIdentityID, ss.ID); err != nil {
		return err
	} else if a == nil {
		sp, err := tx.Identity(ss.SponsorIdentityID)
		if err != nil {
			return err
		}
		unit := ""
		if sp.Department != nil {
			unit = *sp.Department
		}
		creator := ""
		if ss.CreatedBy != nil {
			creator = *ss.CreatedBy
		}
		if _, err := affiliations.AddSponsored(tx, affiliations.SponsoredInput{IdentityID: ss.GuestIdentityID, Type: pop.AffType,
			SponsorshipID: ss.ID, OrgUnit: unit, StartsAt: ss.StartsAt, EndsAt: ss.EndsAt, By: creator}, now); err != nil {
			return err
		}
	}
	return s.syncPerson(tx, ss.GuestIdentityID, by, now, "sponsorship "+ss.ID)
}

// syncPerson makes the guest's lifecycle follow their live sponsorships: the
// worker type and sponsor of the one that ends last, the latest end date,
// the earliest start. With none left it settles the person.
func (s *Service) syncPerson(tx *store.TenantTx, guestID int64, by Actor, now time.Time, note string) error {
	all, err := tx.Sponsorships(store.SponsorshipFilter{Guest: guestID})
	if err != nil {
		return err
	}
	var last *store.Sponsorship
	var starts time.Time
	for _, x := range all {
		if !x.Live() {
			continue
		}
		if last == nil || x.EndsAt.After(last.EndsAt) {
			last = x
		}
		if starts.IsZero() || x.StartsAt.Before(starts) {
			starts = x.StartsAt
		}
	}
	if last == nil {
		return s.settle(tx, guestID, by, now, note, all)
	}
	pop, _ := PopulationOf(last.Population)
	_, err = lifecycle.ApplySponsored(tx, guestID, lifecycle.Sponsored{WorkerType: pop.WorkerType, SponsorID: last.SponsorIdentityID,
		StartsAt: starts, EndsAt: last.EndsAt, Note: note}, by.lc(), now)
	return err
}

// settle is what happens to a person nobody vouches for any more: a running
// term ends now through the lifecycle's leaver path, and an invitation that
// never became a term retires its invited identity. A sponsorship still
// waiting for approval keeps the invitation open.
func (s *Service) settle(tx *store.TenantTx, guestID int64, by Actor, now time.Time, note string, all []*store.Sponsorship) error {
	for _, x := range all {
		if x.Status == store.SponsorPendingApproval || x.Status == store.SponsorRequested {
			return nil
		}
	}
	if _, ended, err := lifecycle.EndNow(tx, guestID, note, by.lc(), now); err != nil || ended {
		return err
	}
	g, err := tx.Identity(guestID)
	if err != nil {
		return err
	}
	if g.Status == "invited" {
		return tx.TerminateIdentity(guestID, now)
	}
	return nil
}
