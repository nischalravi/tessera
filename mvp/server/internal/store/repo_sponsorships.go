package store

import (
	"database/sql"
	"time"
)

// Sponsorships, invitations' intake records and sponsorship history
// (schema/0227_sponsorships.sql, issue #65). Every statement binds @tenant.

// Sponsorship statuses. Active and transfer-pending sponsorships are live: the
// guest has access under them. The last three are final.
const (
	SponsorRequested       = "requested"
	SponsorPendingApproval = "pending_approval"
	SponsorActive          = "active"
	SponsorTransferPending = "transfer_pending"
	SponsorEnded           = "ended"
	SponsorRevoked         = "revoked"
	SponsorRejected        = "rejected"
)

// Sponsorship populations (the sponsor-side label of a guest, design §3).
const (
	PopVisitor    = "visitor"
	PopContractor = "contractor"
	PopVolunteer  = "volunteer"
	PopPartner    = "partner"
)

// Intake channels and match modes of sponsor invitations, and the states of
// the invitation a later PR (GU-6) sends.
const (
	ChannelSponsorInvite = "sponsor_invite"
	ChannelBulkInvite    = "bulk_invite"
	MatchSelfAsserted    = "self_asserted"
	IntakeReceived       = "received"
	InvitationReady      = "ready"
)

// IntakeRecord is how a person came to the organization.
type IntakeRecord struct {
	ID                string
	Channel           string
	MatchMode         string
	SourceRecordID    *string
	SubmittedBy       *string // platform user id
	SponsorIdentityID *int64  // the person who invited, for invitations
	BatchID           *string
	Status            string
	InvitationStatus  string
	CreatedAt         time.Time
}

// Sponsorship is one sponsor's decision to vouch for one guest.
type Sponsorship struct {
	ID                   string
	GuestIdentityID      int64
	IntakeID             string
	SponsorIdentityID    int64
	Population           string
	Purpose              string
	AccessBundle         string // JSON list of catalog items
	RequiredIAL          int
	RequiredAAL          int
	StartsAt             time.Time
	EndsAt               time.Time
	Status               string
	PolicyVersion        string
	ApprovedBy           *string
	ApprovedAt           *time.Time
	TransferToIdentityID *int64
	TransferDeadline     *time.Time
	CreatedBy            *string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	EndedAt              *time.Time
	EndReason            *string
}

// Live reports whether the sponsorship gives the guest standing now.
func (s *Sponsorship) Live() bool {
	return s.Status == SponsorActive || s.Status == SponsorTransferPending
}

// SponsorshipEvent is one entry of a sponsorship's history.
type SponsorshipEvent struct {
	ID            int64
	SponsorshipID string
	Event         string
	FromStatus    *string
	ToStatus      string
	Note          *string
	PolicyVersion string
	ActorUserID   *string
	Actor         string
	At            time.Time
}

// SponsorshipFilter selects sponsorships; zero fields match everything.
type SponsorshipFilter struct {
	Sponsor    int64 // sponsor identity
	Guest      int64 // guest identity
	Involving  int64 // sponsor, or transfer target of a pending transfer
	Status     string
	Population string
}

const intakeCols = `r.id, r.channel, r.match_mode, r.source_record_id, r.submitted_by, r.sponsor_identity_id, r.batch_id,
	r.status, r.invitation_status, r.created_at`

const sponsorCols = `s.id, s.guest_identity_id, s.intake_id, s.sponsor_identity_id, s.population, s.purpose, s.access_bundle,
	s.required_ial, s.required_aal, s.starts_at, s.ends_at, s.status, s.policy_version, s.approved_by, s.approved_at,
	s.transfer_to_identity_id, s.transfer_deadline, s.created_by, s.created_at, s.updated_at, s.ended_at, s.end_reason`

var (
	intakeInsert = tq("intake_records.insert", `
		INSERT INTO intake_records (id, tenant_id, channel, match_mode, source_record_id, submitted_by,
			sponsor_identity_id, batch_id, status, invitation_status, created_at)
		VALUES (@id, @tenant, @channel, @match_mode, @source_record_id, @submitted_by, @sponsor_identity_id,
			@batch_id, @status, @invitation_status, @created_at)`)
	intakeGet = tq("intake_records.get", `
		SELECT `+intakeCols+` FROM intake_records r WHERE r.tenant_id = @tenant AND r.id = @id`)
	intakeCountSince = tq("intake_records.count_since", `
		SELECT count(r.id) FROM intake_records r WHERE r.tenant_id = @tenant AND r.sponsor_identity_id = @sponsor
			AND r.channel IN ('sponsor_invite','bulk_invite') AND r.created_at >= @since`)

	sponsorInsert = tq("sponsorships.insert", `
		INSERT INTO sponsorships (id, tenant_id, guest_identity_id, intake_id, sponsor_identity_id, population, purpose,
			access_bundle, required_ial, required_aal, starts_at, ends_at, status, policy_version, approved_by,
			approved_at, transfer_to_identity_id, transfer_deadline, created_by, created_at, updated_at, ended_at, end_reason)
		VALUES (@id, @tenant, @guest_identity_id, @intake_id, @sponsor_identity_id, @population, @purpose,
			@access_bundle, @required_ial, @required_aal, @starts_at, @ends_at, @status, @policy_version, @approved_by,
			@approved_at, @transfer_to_identity_id, @transfer_deadline, @created_by, @created_at, @updated_at,
			@ended_at, @end_reason)`)
	sponsorGet = tq("sponsorships.get", `
		SELECT `+sponsorCols+` FROM sponsorships s WHERE s.tenant_id = @tenant AND s.id = @id`)
	sponsorFiltered = tq("sponsorships.filtered", `
		SELECT `+sponsorCols+` FROM sponsorships s WHERE s.tenant_id = @tenant
			AND (@sponsor = 0 OR s.sponsor_identity_id = @sponsor)
			AND (@guest = 0 OR s.guest_identity_id = @guest)
			AND (@involving = 0 OR s.sponsor_identity_id = @involving
				OR (s.status = 'transfer_pending' AND s.transfer_to_identity_id = @involving))
			AND (@status = '' OR s.status = @status)
			AND (@population = '' OR s.population = @population)
		ORDER BY s.created_at DESC, s.id`)
	sponsorSave = tq("sponsorships.save", `
		UPDATE sponsorships SET sponsor_identity_id = @sponsor_identity_id, access_bundle = @access_bundle,
			required_ial = @required_ial, required_aal = @required_aal, ends_at = @ends_at, status = @status,
			policy_version = @policy_version, approved_by = @approved_by, approved_at = @approved_at,
			transfer_to_identity_id = @transfer_to_identity_id, transfer_deadline = @transfer_deadline,
			updated_at = @updated_at, ended_at = @ended_at, end_reason = @end_reason
		WHERE tenant_id = @tenant AND id = @id AND status = @from`)
	sponsorCountLive = tq("sponsorships.count_live", `
		SELECT count(s.id) FROM sponsorships s WHERE s.tenant_id = @tenant AND s.sponsor_identity_id = @sponsor
			AND s.population = @population AND s.id <> @exclude
			AND s.status IN ('pending_approval','active','transfer_pending')`)
	sponsorDue = tq("sponsorships.due", `
		SELECT `+sponsorCols+` FROM sponsorships s WHERE s.tenant_id = @tenant
			AND ((s.status = 'transfer_pending' AND s.transfer_deadline <= @now)
				OR (s.status IN ('pending_approval','active','transfer_pending') AND s.ends_at <= @now))
		ORDER BY s.ends_at, s.id`)

	sponsorEventInsert = tq("sponsorship_events.insert", `
		INSERT INTO sponsorship_events (tenant_id, sponsorship_id, event, from_status, to_status, note, policy_version,
			actor_user_id, actor, at)
		VALUES (@tenant, @sponsorship_id, @event, @from_status, @to_status, @note, @policy_version, @actor_user_id,
			@actor, @at)`)
	sponsorEventsFor = tq("sponsorship_events.for_sponsorship", `
		SELECT e.id, e.sponsorship_id, e.event, e.from_status, e.to_status, e.note, e.policy_version, e.actor_user_id,
			e.actor, e.at FROM sponsorship_events e
		WHERE e.tenant_id = @tenant AND e.sponsorship_id = @sponsorship_id ORDER BY e.id`)

	affiliationsSetEnd = tq("affiliations.set_end", `
		UPDATE affiliations SET ends_at = @ends_at
		WHERE tenant_id = @tenant AND id = @id AND status IN ('pending','active')`)
)

func scanIntake(s scanner) (*IntakeRecord, error) {
	var r IntakeRecord
	var src, by, batch sql.NullString
	var sponsor sql.NullInt64
	var at nullTime
	if err := s.Scan(&r.ID, &r.Channel, &r.MatchMode, &src, &by, &sponsor, &batch, &r.Status, &r.InvitationStatus, &at); err != nil {
		return nil, err
	}
	r.SourceRecordID, r.SubmittedBy, r.SponsorIdentityID, r.BatchID = strp(src), strp(by), intp(sponsor), strp(batch)
	var err error
	r.CreatedAt, err = at.val()
	return &r, err
}

func scanSponsorship(s scanner) (*Sponsorship, error) {
	var x Sponsorship
	var approvedBy, createdBy, reason sql.NullString
	var transferTo sql.NullInt64
	var starts, ends, approvedAt, deadline, created, updated, ended nullTime
	if err := s.Scan(&x.ID, &x.GuestIdentityID, &x.IntakeID, &x.SponsorIdentityID, &x.Population, &x.Purpose,
		&x.AccessBundle, &x.RequiredIAL, &x.RequiredAAL, &starts, &ends, &x.Status, &x.PolicyVersion, &approvedBy,
		&approvedAt, &transferTo, &deadline, &createdBy, &created, &updated, &ended, &reason); err != nil {
		return nil, err
	}
	x.ApprovedBy, x.CreatedBy, x.EndReason, x.TransferToIdentityID = strp(approvedBy), strp(createdBy), strp(reason), intp(transferTo)
	var err error
	if x.StartsAt, err = starts.val(); err != nil {
		return nil, err
	}
	if x.EndsAt, err = ends.val(); err != nil {
		return nil, err
	}
	if x.ApprovedAt, err = approvedAt.ptr(); err != nil {
		return nil, err
	}
	if x.TransferDeadline, err = deadline.ptr(); err != nil {
		return nil, err
	}
	if x.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	if x.UpdatedAt, err = updated.val(); err != nil {
		return nil, err
	}
	x.EndedAt, err = ended.ptr()
	return &x, err
}

func scanSponsorshipEvent(s scanner) (*SponsorshipEvent, error) {
	var e SponsorshipEvent
	var from, note, uid sql.NullString
	var at nullTime
	if err := s.Scan(&e.ID, &e.SponsorshipID, &e.Event, &from, &e.ToStatus, &note, &e.PolicyVersion, &uid, &e.Actor, &at); err != nil {
		return nil, err
	}
	e.FromStatus, e.Note, e.ActorUserID = strp(from), strp(note), strp(uid)
	var err error
	e.At, err = at.val()
	return &e, err
}

// InsertIntake records how a person came to us.
func (tx *TenantTx) InsertIntake(r *IntakeRecord) error {
	_, err := tx.exec(intakeInsert, sql.Named("id", r.ID), sql.Named("channel", r.Channel),
		sql.Named("match_mode", r.MatchMode), sql.Named("source_record_id", optStr(r.SourceRecordID)),
		sql.Named("submitted_by", optStr(r.SubmittedBy)), sql.Named("sponsor_identity_id", IP(r.SponsorIdentityID)),
		sql.Named("batch_id", optStr(r.BatchID)), sql.Named("status", r.Status),
		sql.Named("invitation_status", r.InvitationStatus), sql.Named("created_at", T(r.CreatedAt)))
	return err
}

// Intake returns one intake record, or ErrNotFound.
func (tx *TenantTx) Intake(id string) (*IntakeRecord, error) {
	return one(tx, scanIntake, intakeGet, sql.Named("id", id))
}

// CountInvitesSince counts the invitations a person made at or after since.
func (tx *TenantTx) CountInvitesSince(sponsor int64, since time.Time) (int, error) {
	return tx.count(intakeCountSince, sql.Named("sponsor", sponsor), sql.Named("since", T(since)))
}

// InsertSponsorship records a sponsorship.
func (tx *TenantTx) InsertSponsorship(s *Sponsorship) error {
	_, err := tx.exec(sponsorInsert, sql.Named("id", s.ID), sql.Named("guest_identity_id", s.GuestIdentityID),
		sql.Named("intake_id", s.IntakeID), sql.Named("sponsor_identity_id", s.SponsorIdentityID),
		sql.Named("population", s.Population), sql.Named("purpose", s.Purpose), sql.Named("access_bundle", s.AccessBundle),
		sql.Named("required_ial", s.RequiredIAL), sql.Named("required_aal", s.RequiredAAL),
		sql.Named("starts_at", T(s.StartsAt)), sql.Named("ends_at", T(s.EndsAt)), sql.Named("status", s.Status),
		sql.Named("policy_version", s.PolicyVersion), sql.Named("approved_by", optStr(s.ApprovedBy)),
		sql.Named("approved_at", TP(s.ApprovedAt)), sql.Named("transfer_to_identity_id", IP(s.TransferToIdentityID)),
		sql.Named("transfer_deadline", TP(s.TransferDeadline)), sql.Named("created_by", optStr(s.CreatedBy)),
		sql.Named("created_at", T(s.CreatedAt)), sql.Named("updated_at", T(s.UpdatedAt)),
		sql.Named("ended_at", TP(s.EndedAt)), sql.Named("end_reason", optStr(s.EndReason)))
	return err
}

// Sponsorship returns one sponsorship, or ErrNotFound.
func (tx *TenantTx) Sponsorship(id string) (*Sponsorship, error) {
	return one(tx, scanSponsorship, sponsorGet, sql.Named("id", id))
}

// Sponsorships returns the sponsorships matching f, newest first.
func (tx *TenantTx) Sponsorships(f SponsorshipFilter) ([]*Sponsorship, error) {
	return collect(tx, scanSponsorship, sponsorFiltered, sql.Named("sponsor", f.Sponsor), sql.Named("guest", f.Guest),
		sql.Named("involving", f.Involving), sql.Named("status", f.Status), sql.Named("population", f.Population))
}

// SaveSponsorship writes s's changeable fields; ErrNotFound if it is no
// longer in status from (a concurrent change).
func (tx *TenantTx) SaveSponsorship(s *Sponsorship, from string) error {
	res, err := tx.exec(sponsorSave, sql.Named("id", s.ID), sql.Named("from", from),
		sql.Named("sponsor_identity_id", s.SponsorIdentityID), sql.Named("access_bundle", s.AccessBundle),
		sql.Named("required_ial", s.RequiredIAL), sql.Named("required_aal", s.RequiredAAL),
		sql.Named("ends_at", T(s.EndsAt)), sql.Named("status", s.Status), sql.Named("policy_version", s.PolicyVersion),
		sql.Named("approved_by", optStr(s.ApprovedBy)), sql.Named("approved_at", TP(s.ApprovedAt)),
		sql.Named("transfer_to_identity_id", IP(s.TransferToIdentityID)),
		sql.Named("transfer_deadline", TP(s.TransferDeadline)), sql.Named("updated_at", T(s.UpdatedAt)),
		sql.Named("ended_at", TP(s.EndedAt)), sql.Named("end_reason", optStr(s.EndReason)))
	return affectedOne(res, err)
}

// CountLiveSponsorships counts a sponsor's sponsorships of a population that
// hold a place against their limit (waiting for approval, active or being
// transferred), not counting the one named exclude ("" for none).
func (tx *TenantTx) CountLiveSponsorships(sponsor int64, population, exclude string) (int, error) {
	return tx.count(sponsorCountLive, sql.Named("sponsor", sponsor), sql.Named("population", population),
		sql.Named("exclude", exclude))
}

// DueSponsorships returns the sponsorships whose end date has passed or
// whose transfer was not accepted by its deadline, soonest first.
func (tx *TenantTx) DueSponsorships(now time.Time) ([]*Sponsorship, error) {
	return collect(tx, scanSponsorship, sponsorDue, sql.Named("now", T(now)))
}

// AddSponsorshipEvent appends to a sponsorship's history.
func (tx *TenantTx) AddSponsorshipEvent(e *SponsorshipEvent) error {
	_, err := tx.exec(sponsorEventInsert, sql.Named("sponsorship_id", e.SponsorshipID), sql.Named("event", e.Event),
		sql.Named("from_status", optStr(e.FromStatus)), sql.Named("to_status", e.ToStatus), sql.Named("note", optStr(e.Note)),
		sql.Named("policy_version", e.PolicyVersion), sql.Named("actor_user_id", optStr(e.ActorUserID)),
		sql.Named("actor", e.Actor), sql.Named("at", T(e.At)))
	return err
}

// SponsorshipEvents returns a sponsorship's history, oldest first.
func (tx *TenantTx) SponsorshipEvents(id string) ([]*SponsorshipEvent, error) {
	return collect(tx, scanSponsorshipEvent, sponsorEventsFor, sql.Named("sponsorship_id", id))
}

// SetAffiliationEnd moves the planned end of a pending or active affiliation
// (a renewal); ErrNotFound if it is unknown or already final.
func (tx *TenantTx) SetAffiliationEnd(id string, endsAt time.Time) error {
	res, err := tx.exec(affiliationsSetEnd, sql.Named("id", id), sql.Named("ends_at", T(endsAt)))
	return affectedOne(res, err)
}
