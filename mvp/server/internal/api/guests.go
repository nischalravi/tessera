package api

import (
	"errors"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Guest sponsorships and invitations (guest accounts design §9.2, issue #65):
//
//	POST /api/guests/invitations                       {given_name, family_name, email, population, purpose, starts_at, ends_at, bundle, required_ial}
//	POST /api/guests/invitations/bulk                  {csv, dry_run}: per-row policy results; dry_run writes nothing
//	GET  /api/guests                                   ?sponsor=me|all&state=&population=: the guests I sponsor (all needs guests.read)
//	GET  /api/sponsorships/approvals                   sponsorships waiting for a second approver (sponsorships.approve)
//	GET  /api/sponsorships/{sponsorship_id}            one sponsorship with its history
//	POST /api/sponsorships/{sponsorship_id}/approve    {}                         (sponsorships.approve)
//	POST /api/sponsorships/{sponsorship_id}/reject     {reason}                   (sponsorships.approve)
//	POST /api/sponsorships/{sponsorship_id}/renew      {ends_at, justification}   the sponsor
//	POST /api/sponsorships/{sponsorship_id}/end        {reason}                   the sponsor, or sponsorships.approve
//	POST /api/sponsorships/{sponsorship_id}/transfer   {to_identity_id, reason}   the sponsor
//	POST /api/sponsorships/{sponsorship_id}/accept-transfer  {}                   the person asked
//	POST /api/guests/{identity_id}/resend-invitation   {}                         a new claim link by email (the sponsor, or sponsorships.approve)
//	POST /api/guests/{identity_id}/revoke-invitation   {}                         cancel the invitation (the sponsor, or sponsorships.approve)
//
// Anyone with guests.sponsor may try to sponsor: the sponsor policy (versioned
// in policy_version) decides who is eligible and answers 422 with a stable
// code. Every change needs a fresh phishing-resistant sign-in. A sponsor sees
// their own guests; guests.read and sponsorships.approve see every one. An
// invitation never says whether the email matches a person we know. The
// invitation's claim link and email are issued when the sponsorship becomes
// active (internal/guests/claim, GU-6); granting the access bundle is GU-12 and
// the sponsor leaving GU-11.

func (s *Server) registerGuestRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	sponsor := needStepUp(auth.PermGuestsSponsor, auth.StepUpPolicy)
	approver := needStepUp(auth.PermSponsorshipsApprove, auth.StepUpPolicy)
	s.handle(P, "/api/guests/invitations", write, sponsor, s.inviteGuest)
	s.handle(P, "/api/guests/invitations/bulk", write, sponsor, s.bulkInviteGuests)
	s.handle(G, "/api/guests", read, need(auth.PermGuestsSponsor), s.listGuests)
	// the literal route first: routes match in registration order
	s.handle(G, "/api/sponsorships/approvals", read, need(auth.PermSponsorshipsApprove), s.sponsorshipApprovals)
	s.handle(G, "/api/sponsorships/{sponsorship_id}", read, need(auth.PermGuestsSponsor), s.getSponsorship)
	s.handle(P, "/api/sponsorships/{sponsorship_id}/approve", write, approver, s.approveSponsorship)
	s.handle(P, "/api/sponsorships/{sponsorship_id}/reject", write, approver, s.rejectSponsorship)
	s.handle(P, "/api/sponsorships/{sponsorship_id}/renew", write, sponsor, s.renewSponsorship)
	s.handle(P, "/api/sponsorships/{sponsorship_id}/end", write, sponsor, s.endSponsorship)
	s.handle(P, "/api/sponsorships/{sponsorship_id}/transfer", write, sponsor, s.transferSponsorship)
	s.handle(P, "/api/sponsorships/{sponsorship_id}/accept-transfer", write, sponsor, s.acceptTransfer)
	s.handle(P, "/api/guests/{identity_id}/resend-invitation", write, sponsor, s.resendInvitation)
	s.handle(P, "/api/guests/{identity_id}/revoke-invitation", write, sponsor, s.revokeInvitation)
}

func (s *Server) sponsorActor(r *http.Request) (sponsorship.Actor, error) {
	a, err := s.requestActor(r)
	if err != nil {
		return sponsorship.Actor{}, err
	}
	return sponsorship.Actor{UserID: a.UserID, Display: a.Display, IdentityID: a.IdentityID,
		Approver: s.can(r, auth.PermSponsorshipsApprove)}, nil
}

func (s *Server) keyed() error {
	if s.guests == nil || s.guests.Keyer == nil {
		return &readiness.Error{Status: http.StatusServiceUnavailable, Code: "guests_unavailable", Msg: "invitations need the identifier key (the KEK)"}
	}
	return nil
}

// ---------------------------------------------------------------- views

type sponsorshipEventView struct {
	Event         string    `json:"event"`
	FromStatus    *string   `json:"from_status"`
	ToStatus      string    `json:"to_status"`
	Note          *string   `json:"note"`
	PolicyVersion string    `json:"policy_version"`
	Actor         string    `json:"actor"`
	At            time.Time `json:"at"`
}

type guestRef struct {
	personRef
	Email *string `json:"email"`
}

type sponsorshipView struct {
	ID                string                   `json:"id"`
	Status            string                   `json:"status"`
	State             string                   `json:"state"`
	Guest             guestRef                 `json:"guest"`
	Sponsor           personRef                `json:"sponsor"`
	Population        string                   `json:"population"`
	Purpose           string                   `json:"purpose"`
	Bundle            []sponsorship.BundleItem `json:"bundle"`
	RequiredIAL       int                      `json:"required_ial"`
	RequiredAAL       int                      `json:"required_aal"`
	StartsAt          time.Time                `json:"starts_at"`
	EndsAt            time.Time                `json:"ends_at"`
	DaysLeft          *int                     `json:"days_left"`
	PolicyVersion     string                   `json:"policy_version"`
	CreatedBy         *userRef                 `json:"created_by"`
	CreatedAt         time.Time                `json:"created_at"`
	ApprovedBy        *userRef                 `json:"approved_by"`
	ApprovedAt        *time.Time               `json:"approved_at"`
	TransferTo        *personRef               `json:"transfer_to"`
	TransferDeadline  *time.Time               `json:"transfer_deadline"`
	EndedAt           *time.Time               `json:"ended_at"`
	EndReason         *string                  `json:"end_reason"`
	Invitation        string                   `json:"invitation"` // ready, sent, claiming, expired, claimed or revoked
	InvitationExpires *time.Time               `json:"invitation_expires_at"`
	CanResend         bool                     `json:"can_resend_invitation"`
	CanRevoke         bool                     `json:"can_revoke_invitation"`
	CanRenew          bool                     `json:"can_renew"`
	CanEnd            bool                     `json:"can_end"`
	CanTransfer       bool                     `json:"can_transfer"`
	CanAcceptTransfer bool                     `json:"can_accept_transfer"`
	CanApprove        bool                     `json:"can_approve"`
	Events            []sponsorshipEventView   `json:"events,omitempty"`
}

// sponsorshipState is what a reader sees: the status, with a running
// sponsorship told apart as upcoming, active or ending (within the first
// lifecycle warning window).
func sponsorshipState(ss *store.Sponsorship, now time.Time) string {
	if ss.Status != store.SponsorActive {
		return ss.Status
	}
	switch {
	case ss.StartsAt.After(now):
		return "upcoming"
	case !ss.EndsAt.After(now.AddDate(0, 0, lifecycle.WarnDays[0])):
		return "ending"
	}
	return "active"
}

func (s *Server) sponsorshipView(v *viewer, ss *store.Sponsorship, act sponsorship.Actor, withEvents bool) (sponsorshipView, error) {
	tx, now := v.tx, s.clock().UTC()
	out := sponsorshipView{ID: ss.ID, Status: ss.Status, State: sponsorshipState(ss, now), Population: ss.Population, Purpose: ss.Purpose,
		Bundle: sponsorship.ParseBundle(ss.AccessBundle), RequiredIAL: ss.RequiredIAL, RequiredAAL: ss.RequiredAAL, StartsAt: ss.StartsAt,
		EndsAt: ss.EndsAt, PolicyVersion: ss.PolicyVersion, CreatedAt: ss.CreatedAt, ApprovedAt: ss.ApprovedAt,
		TransferDeadline: ss.TransferDeadline, EndedAt: ss.EndedAt, EndReason: ss.EndReason}
	var err error
	if out.Guest.personRef, err = v.person(ss.GuestIdentityID); err != nil {
		return out, err
	}
	if g, err := tx.Identity(ss.GuestIdentityID); err != nil {
		return out, err
	} else {
		out.Guest.Email = g.Email
	}
	if out.Sponsor, err = v.person(ss.SponsorIdentityID); err != nil {
		return out, err
	}
	if ss.TransferToIdentityID != nil {
		t, err := v.person(*ss.TransferToIdentityID)
		if err != nil {
			return out, err
		}
		out.TransferTo = &t
	}
	if ss.CreatedBy != nil {
		u := v.user(*ss.CreatedBy)
		out.CreatedBy = &u
	}
	if ss.ApprovedBy != nil {
		u := v.user(*ss.ApprovedBy)
		out.ApprovedBy = &u
	}
	in, err := tx.Intake(ss.IntakeID)
	if err != nil {
		return out, err
	}
	ts, err := tx.ClaimTokensForIntake(ss.IntakeID)
	if err != nil {
		return out, err
	}
	out.Invitation, out.InvitationExpires = invitationState(in, ts, now)
	if ss.Live() {
		d := max(0, int(math.Ceil(ss.EndsAt.Sub(now).Hours()/24)))
		out.DaysLeft = &d
	}
	owner := act.Is(ss.SponsorIdentityID)
	mayInvite := owner || act.Approver
	out.CanResend = mayInvite && ss.Live() && s.claimReady() && slices.Contains([]string{"ready", "sent", "claiming", "expired"}, out.Invitation)
	out.CanRevoke = mayInvite && (ss.Live() || ss.Status == store.SponsorPendingApproval) &&
		slices.Contains([]string{"ready", "sent", "claiming", "expired"}, out.Invitation)
	out.CanRenew = ss.Status == store.SponsorActive && (owner || act.Approver)
	out.CanEnd = (ss.Live() || ss.Status == store.SponsorPendingApproval) && (owner || act.Approver)
	out.CanTransfer = (ss.Status == store.SponsorActive || ss.Status == store.SponsorTransferPending) && (owner || act.Approver)
	out.CanAcceptTransfer = ss.Status == store.SponsorTransferPending && ss.TransferToIdentityID != nil &&
		act.Is(*ss.TransferToIdentityID) && ss.TransferDeadline != nil && ss.TransferDeadline.After(now)
	out.CanApprove = ss.Status == store.SponsorPendingApproval && act.Approver && !owner && !act.Is(ss.GuestIdentityID) &&
		!(ss.CreatedBy != nil && *ss.CreatedBy == act.UserID.String())
	if withEvents {
		evs, err := tx.SponsorshipEvents(ss.ID)
		if err != nil {
			return out, err
		}
		out.Events = make([]sponsorshipEventView, len(evs))
		for i, e := range evs {
			out.Events[i] = sponsorshipEventView{e.Event, e.FromStatus, e.ToStatus, e.Note, e.PolicyVersion, e.Actor, e.At}
		}
	}
	return out, nil
}

// sponsorshipVisible reports whether the signed-in user may see a sponsorship: readers of
// every guest and approvers, the sponsor, and the person asked to take it over.
func (s *Server) sponsorshipVisible(r *http.Request, ss *store.Sponsorship, act sponsorship.Actor) bool {
	if s.can(r, auth.PermGuestsRead) || act.Approver {
		return true
	}
	return act.Is(ss.SponsorIdentityID) || ss.TransferToIdentityID != nil && act.Is(*ss.TransferToIdentityID)
}

// sponsorshipOf loads the sponsorship named by the path for the signed-in
// user; one they may not see looks missing, like another tenant's.
func (s *Server) sponsorshipOf(r *http.Request, p *params) (*store.Sponsorship, sponsorship.Actor, error) {
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, act, err
	}
	ss, err := sponsorship.Load(store.TxFrom(r.Context()), p.path["sponsorship_id"])
	if err != nil {
		return nil, act, reqErr(err)
	}
	if !s.sponsorshipVisible(r, ss, act) {
		return nil, act, &readiness.Error{Status: http.StatusNotFound, Code: "sponsorship_not_found", Msg: "sponsorship not found"}
	}
	return ss, act, nil
}

func (s *Server) getSponsorship(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ss, act, err := s.sponsorshipOf(r, p)
	if err != nil {
		return nil, err
	}
	return s.sponsorshipView(newViewer(store.TxFrom(r.Context())), ss, act, true)
}

type populationView struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	MaxDays     int    `json:"max_days"`
	MaxActive   int    `json:"max_active"`
	DefaultIAL  int    `json:"default_ial"`
	DefaultAAL  int    `json:"default_aal"`
	NeedsReview bool   `json:"approval_with_sensitive_bundle"`
}

var populationNames = map[string]string{store.PopVisitor: "Visitor", store.PopContractor: "Contractor",
	store.PopVolunteer: "Volunteer", store.PopPartner: "Partner"}

func (s *Server) listGuests(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	which, state, pop := qs(p, "sponsor"), qs(p, "state"), qs(p, "population")
	bad := func(code, msg string) error {
		return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: code, Msg: msg}
	}
	switch {
	case which != "" && which != "me" && which != "all":
		return nil, bad("invalid_sponsor", "sponsor is me or all")
	case state != "" && !slices.Contains([]string{store.SponsorRequested, store.SponsorPendingApproval, store.SponsorActive,
		store.SponsorTransferPending, store.SponsorEnded, store.SponsorRevoked, store.SponsorRejected}, state):
		return nil, bad("invalid_state", "state is a sponsorship status")
	case pop != "" && !slices.ContainsFunc(sponsorship.Populations, func(x sponsorship.Population) bool { return x.Key == pop }):
		return nil, bad("invalid_population", "population is visitor, contractor, volunteer or partner")
	}
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, err
	}
	readAll := s.can(r, auth.PermGuestsRead)
	if which == "all" && !readAll {
		return nil, &readiness.Error{Status: http.StatusForbidden, Code: "forbidden", Msg: "seeing every guest needs guests.read"}
	}
	tx := store.TxFrom(r.Context())
	f := store.SponsorshipFilter{Status: state, Population: pop}
	empty := false
	if which != "all" {
		if act.IdentityID == nil {
			empty = true
		} else {
			f.Involving = *act.IdentityID
		}
	}
	rows := []sponsorshipView{}
	if !empty {
		ss, err := tx.Sponsorships(f)
		if err != nil {
			return nil, err
		}
		v := newViewer(tx)
		for _, x := range ss {
			sv, err := s.sponsorshipView(v, x, act, false)
			if err != nil {
				return nil, err
			}
			rows = append(rows, sv)
		}
	}
	pol := s.guests.Policy
	pops := []populationView{}
	for _, sp := range sponsorship.Populations {
		gp, err := tx.GuestPopulation(sp.Group)
		if errors.Is(err, store.ErrNotFound) {
			continue
		} else if err != nil {
			return nil, err
		}
		pops = append(pops, populationView{Key: sp.Key, Name: populationNames[sp.Key], MaxDays: sponsorship.MaxDays(sp, gp), MaxActive: pol.MaxActive[sp.Key],
			DefaultIAL: max(gp.DefaultIAL, pol.DefaultIAL[sp.Key]), DefaultAAL: gp.DefaultAAL,
			NeedsReview: slices.Contains(pol.Approval.Populations, sp.Key)})
	}
	can := false
	if act.IdentityID != nil {
		if can, err = s.guests.CanSponsor(tx, *act.IdentityID); err != nil {
			return nil, err
		}
	}
	return map[string]any{"rows": rows, "populations": pops, "policy_version": pol.Version, "max_invites_per_day": pol.MaxInvitesPerDay,
		"transfer_deadline_days": pol.TransferDeadlineDays, "can_sponsor": can, "can_read_all": readAll, "can_approve": act.Approver}, nil
}

func (s *Server) sponsorshipApprovals(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	ss, err := tx.Sponsorships(store.SponsorshipFilter{Status: store.SponsorPendingApproval})
	if err != nil {
		return nil, err
	}
	v, out := newViewer(tx), []sponsorshipView{}
	for _, x := range ss {
		sv, err := s.sponsorshipView(v, x, act, false)
		if err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, nil
}

// ---------------------------------------------------------------- invitations

type inviteBody struct {
	GivenName   string     `json:"given_name"`
	FamilyName  string     `json:"family_name"`
	Email       string     `json:"email"`
	Population  string     `json:"population"`
	Purpose     string     `json:"purpose"`
	StartsAt    *time.Time `json:"starts_at"`
	EndsAt      time.Time  `json:"ends_at"`
	Bundle      []int64    `json:"bundle"`
	RequiredIAL *int       `json:"required_ial"`
}

func (b inviteBody) invite() sponsorship.Invite {
	in := sponsorship.Invite{GivenName: b.GivenName, FamilyName: b.FamilyName, Email: b.Email, Population: strings.ToLower(strings.TrimSpace(b.Population)),
		Purpose: b.Purpose, EndsAt: b.EndsAt.UTC(), Bundle: b.Bundle, RequiredIAL: b.RequiredIAL}
	if b.StartsAt != nil {
		in.StartsAt = b.StartsAt.UTC()
	}
	return in
}

func (s *Server) inviteGuest(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	if err := s.keyed(); err != nil {
		return nil, err
	}
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, err
	}
	var b inviteBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	res, err := s.guests.Invite(tx, act, b.invite(), store.ChannelSponsorInvite, "", s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	v, err := s.sponsorshipView(newViewer(tx), res.Sponsorship, act, true)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, v}, nil
}

type bulkBody struct {
	CSV    string `json:"csv"`
	DryRun bool   `json:"dry_run"`
}

func (s *Server) bulkInviteGuests(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	if err := s.keyed(); err != nil {
		return nil, err
	}
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, err
	}
	var b bulkBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	rows, err := sponsorship.ParseCSV(b.CSV)
	if err != nil {
		return nil, reqErr(err)
	}
	res, err := s.guests.BulkInvite(store.TxFrom(r.Context()), act, rows, b.DryRun, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	if b.DryRun {
		return res, nil
	}
	return statusBody{http.StatusCreated, res}, nil
}

// ---------------------------------------------------------------- changes

type renewBody struct {
	EndsAt        time.Time `json:"ends_at"`
	Justification string    `json:"justification"`
}

type transferBody struct {
	ToIdentityID int64  `json:"to_identity_id"`
	Reason       string `json:"reason"`
}

// change runs one change to the sponsorship named by the path and answers
// with its new state.
func (s *Server) change(r *http.Request, p *params, body any, allowEmpty bool,
	fn func(tx *store.TenantTx, act sponsorship.Actor, id string, now time.Time) (*store.Sponsorship, error)) (any, error) {
	ss, act, err := s.sponsorshipOf(r, p)
	if err != nil {
		return nil, err
	}
	if err := decodeBody(r, body, allowEmpty); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	out, err := fn(tx, act, ss.ID, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return s.sponsorshipView(newViewer(tx), out, act, true)
}

func (s *Server) approveSponsorship(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.change(r, p, &struct{}{}, true, func(tx *store.TenantTx, act sponsorship.Actor, id string, now time.Time) (*store.Sponsorship, error) {
		return s.guests.Approve(tx, act, id, now)
	})
}

func (s *Server) rejectSponsorship(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b reasonBody
	return s.change(r, p, &b, false, func(tx *store.TenantTx, act sponsorship.Actor, id string, now time.Time) (*store.Sponsorship, error) {
		return s.guests.Reject(tx, act, id, b.Reason, now)
	})
}

func (s *Server) renewSponsorship(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b renewBody
	return s.change(r, p, &b, false, func(tx *store.TenantTx, act sponsorship.Actor, id string, now time.Time) (*store.Sponsorship, error) {
		return s.guests.Renew(tx, act, id, b.EndsAt.UTC(), b.Justification, now)
	})
}

func (s *Server) endSponsorship(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b reasonBody
	return s.change(r, p, &b, false, func(tx *store.TenantTx, act sponsorship.Actor, id string, now time.Time) (*store.Sponsorship, error) {
		return s.guests.End(tx, act, id, b.Reason, now)
	})
}

func (s *Server) transferSponsorship(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b transferBody
	return s.change(r, p, &b, false, func(tx *store.TenantTx, act sponsorship.Actor, id string, now time.Time) (*store.Sponsorship, error) {
		return s.guests.Transfer(tx, act, id, b.ToIdentityID, b.Reason, now)
	})
}

func (s *Server) acceptTransfer(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.change(r, p, &struct{}{}, true, func(tx *store.TenantTx, act sponsorship.Actor, id string, now time.Time) (*store.Sponsorship, error) {
		return s.guests.AcceptTransfer(tx, act, id, now)
	})
}

// ---------------------------------------------------------------- invitations: resend and revoke

// invitationState is what a reader sees of an invitation: the intake's status,
// with a link that outlived its lifetime read as expired and a link the guest
// opened (the claim is under way) as claiming. expires is when the newest link stops working.
func invitationState(in *store.IntakeRecord, ts []*store.ClaimToken, now time.Time) (string, *time.Time) {
	if in.InvitationStatus != store.InvitationSent || len(ts) == 0 {
		return in.InvitationStatus, nil
	}
	t := ts[0] // newest first
	switch {
	case t.Status == store.ClaimConsumed:
		return "claiming", nil
	case t.Status == store.ClaimExpired || !now.Before(t.ExpiresAt):
		return store.InvitationExpired, nil
	}
	exp := t.ExpiresAt
	return in.InvitationStatus, &exp
}

// invitationOf finds the sponsorship the signed-in user may manage the
// invitation of: the guest's, where they are the sponsor or an approver. One
// they may not manage looks missing.
func (s *Server) invitationOf(r *http.Request, p *params) (*store.Sponsorship, sponsorship.Actor, error) {
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, act, err
	}
	missing := &readiness.Error{Status: http.StatusNotFound, Code: "sponsorship_not_found", Msg: "no invitation to manage for this person"}
	id, err := strconv.ParseInt(p.path["identity_id"], 10, 64)
	if err != nil {
		return nil, act, missing
	}
	all, err := store.TxFrom(r.Context()).Sponsorships(store.SponsorshipFilter{Guest: id})
	if err != nil {
		return nil, act, err
	}
	var pick *store.Sponsorship
	for _, x := range all { // newest first; a running one wins
		if !(act.Is(x.SponsorIdentityID) || act.Approver) {
			continue
		}
		if pick == nil || x.Live() && !pick.Live() {
			pick = x
		}
	}
	if pick == nil {
		return nil, act, missing
	}
	return pick, act, nil
}

func (s *Server) resendInvitation(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ss, act, err := s.invitationOf(r, p)
	if err != nil {
		return nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	if !s.claimReady() {
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "claim_unavailable", Msg: "claim links need TESSERA_PUBLIC_URL and the identifier key"}
	}
	tx := store.TxFrom(r.Context())
	in, err := tx.Intake(ss.IntakeID)
	if err != nil {
		return nil, err
	}
	if in.InvitationStatus == store.InvitationRevoked {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "invitation_revoked", Msg: "this invitation was revoked; invite the person again"}
	}
	if _, err := s.claimSvc.Issue(tx, ss, "resend", s.clock().UTC()); err != nil {
		return nil, reqErr(err)
	}
	return s.sponsorshipView(newViewer(tx), ss, act, true)
}

func (s *Server) revokeInvitation(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ss, act, err := s.invitationOf(r, p)
	if err != nil {
		return nil, err
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return nil, err
	}
	if s.claimSvc == nil {
		return nil, &readiness.Error{Status: http.StatusServiceUnavailable, Code: "claim_unavailable", Msg: "claim links need TESSERA_PUBLIC_URL and the identifier key"}
	}
	tx := store.TxFrom(r.Context())
	in, err := tx.Intake(ss.IntakeID)
	if err != nil {
		return nil, err
	}
	if in.InvitationStatus == store.InvitationClaimed {
		return nil, &readiness.Error{Status: http.StatusConflict, Code: "already_claimed", Msg: "the guest has already claimed their invitation"}
	}
	if err := s.claimSvc.Revoke(tx, ss, "revoked by "+act.Display, s.clock().UTC()); err != nil {
		return nil, reqErr(err)
	}
	return s.sponsorshipView(newViewer(tx), ss, act, true)
}
