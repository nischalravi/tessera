package store

import (
	"database/sql"
	"encoding/json"
	"strconv"
	"time"
)

// Guest lifecycle: settings, reminders, renewal tokens, lifecycle tasks,
// step-up renewals and deprovisioning stages (schema/0364_guest_lifecycle.sql,
// issue #74). Every statement binds @tenant.

// Task kinds, triggers, statuses and outcomes.
const (
	TaskSponsorTransfer = "sponsor_transfer"
	TaskRenewalRequest  = "renewal_request"
	TaskDualStatus      = "dual_status"

	TaskTriggerLeaver     = "leaver"
	TaskTriggerMover      = "mover"
	TaskTriggerIneligible = "ineligible"
	TaskTriggerGuest      = "guest_request"
	TaskTriggerConversion = "conversion"

	TaskOpen      = "open"
	TaskDone      = "done"
	TaskDeclined  = "declined"
	TaskExpired   = "expired"
	TaskCancelled = "cancelled"

	OutcomeTransferred = "transferred"
	OutcomeEnded       = "ended"
	OutcomeSuspended   = "suspended"
	OutcomeRenewed     = "renewed"
	OutcomeDismissed   = "dismissed"
	OutcomeConfirmed   = "confirmed"
)

// Deprovisioning stages.
const (
	StageGrace         = "grace"
	StageDeprovisioned = "deprovisioned"
	StagePurged        = "purged"
	StageReturned      = "returned"
)

// Reminder audiences, renewal-token and step-up statuses.
const (
	AudienceSponsor = "sponsor"
	AudienceGuest   = "guest"

	TokenIssued  = "issued"
	TokenUsed    = "used"
	TokenRevoked = "revoked"
	TokenExpired = "expired"

	StepupPending   = "pending"
	StepupApplied   = "applied"
	StepupCancelled = "cancelled"
)

// GuestLifecycleSettings are a tenant's lifecycle settings (design §8).
type GuestLifecycleSettings struct {
	SponsorReminderDays  []int
	GuestReminderDays    int // 0: no reminder to the guest
	TransferDeadlineDays int
	OnSponsorDeparture   string // "end" or "suspend"
	ConversionDualStatus string // "end" or "sponsor_confirms"
	GraceDays            map[string]int
	RetentionDays        int
	RetentionDaysVisitor int
	KeepRematchHashes    bool
	UpdatedBy            *string
	UpdatedAt            *time.Time
}

// DefaultGuestLifecycleSettings are the design's defaults.
func DefaultGuestLifecycleSettings() GuestLifecycleSettings {
	return GuestLifecycleSettings{SponsorReminderDays: []int{30, 14, 3}, GuestReminderDays: 14, TransferDeadlineDays: 14,
		OnSponsorDeparture: "end", ConversionDualStatus: "end",
		GraceDays:     map[string]int{PopVisitor: 0, PopContractor: 30, PopVolunteer: 30, PopPartner: 30},
		RetentionDays: 2555, RetentionDaysVisitor: 365}
}

// RenewalToken is a guest's "request renewal" link, by its hash.
type RenewalToken struct {
	ID              string
	SponsorshipID   string
	GuestIdentityID int64
	TokenHash       string
	Status          string
	ExpiresAt       time.Time
	CreatedAt       time.Time
	UsedAt          *time.Time
}

// LifecycleTask is an Inbox task of the guest lifecycle.
type LifecycleTask struct {
	ID                string
	Kind              string
	SponsorshipID     string
	SubjectIdentityID int64
	Trigger           string
	Status            string
	Deadline          *time.Time
	Outcome           *string
	Note              *string
	ResolvedBy        *string
	ResolvedAt        *time.Time
	CreatedAt         time.Time
}

// LifecycleTaskFilter selects tasks; empty fields match all.
type LifecycleTaskFilter struct {
	Kind, Status, Sponsorship string
	Subject                   int64
}

// Stepup is a renewal waiting for the guest's identity assurance.
type Stepup struct {
	ID              string
	SponsorshipID   string
	RequestedEndsAt time.Time
	Justification   string
	RequiredIAL     int
	Status          string
	RequestedBy     *string
	CreatedAt       time.Time
	ResolvedAt      *time.Time
}

// Deprovisioning is where a person stands after their last affiliation ended.
type Deprovisioning struct {
	IdentityID      int64
	Population      string
	Stage           string
	HeldAccess      bool
	EndedAt         time.Time
	GraceUntil      time.Time
	RetentionUntil  time.Time
	DeprovisionedAt *time.Time
	PurgedAt        *time.Time
	ReturnedAt      *time.Time
	UpdatedAt       time.Time
}

const (
	taskCols = `t.id, t.kind, t.sponsorship_id, t.subject_identity_id, t.trigger, t.status, t.deadline, t.outcome, t.note,
		t.resolved_by, t.resolved_at, t.created_at`
	stepupCols = `u.id, u.sponsorship_id, u.requested_ends_at, u.justification, u.required_ial, u.status, u.requested_by,
		u.created_at, u.resolved_at`
	deprovCols = `d.identity_id, d.population, d.stage, d.held_access, d.ended_at, d.grace_until, d.retention_until,
		d.deprovisioned_at, d.purged_at, d.returned_at, d.updated_at`
	renewalCols = `r.id, r.sponsorship_id, r.guest_identity_id, r.token_hash, r.status, r.expires_at, r.created_at, r.used_at`
)

var (
	glSettingsGet = tq("guest_lifecycle_settings.get", `
		SELECT s.sponsor_reminder_days, s.guest_reminder_days, s.transfer_deadline_days, s.on_sponsor_departure,
			s.conversion_dual_status, s.grace_days_visitor, s.grace_days_contractor, s.grace_days_volunteer,
			s.grace_days_partner, s.retention_days, s.retention_days_visitor, s.keep_rematch_hashes, s.updated_by, s.updated_at
		FROM guest_lifecycle_settings s WHERE s.tenant_id = @tenant`)
	glSettingsPut = tq("guest_lifecycle_settings.put", `
		INSERT INTO guest_lifecycle_settings (tenant_id, sponsor_reminder_days, guest_reminder_days, transfer_deadline_days,
			on_sponsor_departure, conversion_dual_status, grace_days_visitor, grace_days_contractor, grace_days_volunteer,
			grace_days_partner, retention_days, retention_days_visitor, keep_rematch_hashes, updated_by, updated_at)
		VALUES (@tenant, @sponsor_reminder_days, @guest_reminder_days, @transfer_deadline_days, @on_sponsor_departure,
			@conversion_dual_status, @grace_visitor, @grace_contractor, @grace_volunteer, @grace_partner, @retention_days,
			@retention_days_visitor, @keep_rematch_hashes, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET sponsor_reminder_days = excluded.sponsor_reminder_days,
			guest_reminder_days = excluded.guest_reminder_days, transfer_deadline_days = excluded.transfer_deadline_days,
			on_sponsor_departure = excluded.on_sponsor_departure, conversion_dual_status = excluded.conversion_dual_status,
			grace_days_visitor = excluded.grace_days_visitor, grace_days_contractor = excluded.grace_days_contractor,
			grace_days_volunteer = excluded.grace_days_volunteer, grace_days_partner = excluded.grace_days_partner,
			retention_days = excluded.retention_days, retention_days_visitor = excluded.retention_days_visitor,
			keep_rematch_hashes = excluded.keep_rematch_hashes, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`)

	glReminderMark = tq("guest_reminders.mark", `
		INSERT INTO guest_reminders (tenant_id, sponsorship_id, ends_at, audience, threshold_days, sent_at)
		VALUES (@tenant, @sponsorship_id, @ends_at, @audience, @threshold_days, @sent_at)
		ON CONFLICT (tenant_id, sponsorship_id, ends_at, audience, threshold_days) DO NOTHING`)
	glReminderCount = tq("guest_reminders.count", `
		SELECT count(r.sponsorship_id) FROM guest_reminders r WHERE r.tenant_id = @tenant
			AND (@sponsorship = '' OR r.sponsorship_id = @sponsorship) AND (@audience = '' OR r.audience = @audience)`)

	glTokenInsert = tq("guest_renewal_tokens.insert", `
		INSERT INTO guest_renewal_tokens (id, tenant_id, sponsorship_id, guest_identity_id, token_hash, status, expires_at, created_at)
		VALUES (@id, @tenant, @sponsorship_id, @guest_identity_id, @token_hash, 'issued', @expires_at, @created_at)`)
	glTokenConsume = tq("guest_renewal_tokens.consume", `
		UPDATE guest_renewal_tokens SET status = 'used', used_at = @now
		WHERE tenant_id = @tenant AND token_hash = @token_hash AND status = 'issued' AND expires_at > @now`)
	glTokenByHash = tq("guest_renewal_tokens.by_hash", `
		SELECT `+renewalCols+` FROM guest_renewal_tokens r WHERE r.tenant_id = @tenant AND r.token_hash = @token_hash`)
	glTokenRevoke = tq("guest_renewal_tokens.revoke", `
		UPDATE guest_renewal_tokens SET status = 'revoked'
		WHERE tenant_id = @tenant AND sponsorship_id = @sponsorship_id AND status = 'issued'`)
	glTokenExpire = tq("guest_renewal_tokens.expire", `
		UPDATE guest_renewal_tokens SET status = 'expired' WHERE tenant_id = @tenant AND status = 'issued' AND expires_at <= @now`)
	glTokenFor = tq("guest_renewal_tokens.for_sponsorship", `
		SELECT `+renewalCols+` FROM guest_renewal_tokens r WHERE r.tenant_id = @tenant AND r.sponsorship_id = @sponsorship_id
		ORDER BY r.created_at, r.id`)

	glTaskInsert = tq("guest_lifecycle_tasks.insert", `
		INSERT INTO guest_lifecycle_tasks (id, tenant_id, kind, sponsorship_id, subject_identity_id, trigger, status, deadline, created_at)
		VALUES (@id, @tenant, @kind, @sponsorship_id, @subject_identity_id, @trigger, 'open', @deadline, @created_at)`)
	glTaskGet = tq("guest_lifecycle_tasks.get", `
		SELECT `+taskCols+` FROM guest_lifecycle_tasks t WHERE t.tenant_id = @tenant AND t.id = @id`)
	glTaskList = tq("guest_lifecycle_tasks.list", `
		SELECT `+taskCols+` FROM guest_lifecycle_tasks t WHERE t.tenant_id = @tenant
			AND (@kind = '' OR t.kind = @kind) AND (@status = '' OR t.status = @status)
			AND (@sponsorship = '' OR t.sponsorship_id = @sponsorship) AND (@subject = 0 OR t.subject_identity_id = @subject)
		ORDER BY t.created_at DESC, t.id`)
	glTaskResolve = tq("guest_lifecycle_tasks.resolve", `
		UPDATE guest_lifecycle_tasks SET status = @status, outcome = @outcome, note = @note, resolved_by = @resolved_by,
			resolved_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'open'`)

	glStepupInsert = tq("sponsorship_stepups.insert", `
		INSERT INTO sponsorship_stepups (id, tenant_id, sponsorship_id, requested_ends_at, justification, required_ial, status,
			requested_by, created_at)
		VALUES (@id, @tenant, @sponsorship_id, @requested_ends_at, @justification, @required_ial, 'pending', @requested_by, @created_at)`)
	glStepupList = tq("sponsorship_stepups.list", `
		SELECT `+stepupCols+` FROM sponsorship_stepups u WHERE u.tenant_id = @tenant
			AND (@status = '' OR u.status = @status) AND (@sponsorship = '' OR u.sponsorship_id = @sponsorship)
		ORDER BY u.created_at, u.id`)
	glStepupResolve = tq("sponsorship_stepups.resolve", `
		UPDATE sponsorship_stepups SET status = @status, resolved_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)

	glDeprovInsert = tq("guest_deprovisioning.insert", `
		INSERT INTO guest_deprovisioning (tenant_id, identity_id, population, stage, held_access, ended_at, grace_until,
			retention_until, updated_at)
		VALUES (@tenant, @identity_id, @population, 'grace', @held_access, @ended_at, @grace_until, @retention_until, @updated_at)`)
	glDeprovGet = tq("guest_deprovisioning.get", `
		SELECT `+deprovCols+` FROM guest_deprovisioning d WHERE d.tenant_id = @tenant AND d.identity_id = @identity_id`)
	glDeprovList = tq("guest_deprovisioning.list", `
		SELECT `+deprovCols+` FROM guest_deprovisioning d WHERE d.tenant_id = @tenant AND (@stage = '' OR d.stage = @stage)
		ORDER BY d.ended_at, d.identity_id`)
	glDeprovAdvance = tq("guest_deprovisioning.advance", `
		UPDATE guest_deprovisioning SET stage = @stage, updated_at = @now,
			deprovisioned_at = CASE WHEN @stage = 'deprovisioned' THEN @now ELSE deprovisioned_at END,
			purged_at = CASE WHEN @stage = 'purged' THEN @now ELSE purged_at END,
			returned_at = CASE WHEN @stage = 'returned' THEN @now ELSE returned_at END
		WHERE tenant_id = @tenant AND identity_id = @identity_id AND stage = @from`)
	glDeprovRestart = tq("guest_deprovisioning.restart", `
		UPDATE guest_deprovisioning SET stage = 'grace', population = @population, held_access = @held_access,
			ended_at = @ended_at, grace_until = @grace_until, retention_until = @retention_until, deprovisioned_at = NULL,
			returned_at = NULL, updated_at = @updated_at
		WHERE tenant_id = @tenant AND identity_id = @identity_id AND stage = 'returned'`)
	// people whose last sponsorship ended and who have no running stage row (none, or one that returned)
	glAwaiting = tq("guest_deprovisioning.awaiting", `
		SELECT i.id FROM identities i WHERE i.tenant_id = @tenant AND i.status = 'terminated' AND i.type = 'human'
			AND EXISTS (SELECT 1 FROM sponsorships s WHERE s.tenant_id = @tenant AND s.guest_identity_id = i.id)
			AND NOT EXISTS (SELECT 1 FROM guest_deprovisioning d WHERE d.tenant_id = @tenant AND d.identity_id = i.id
				AND d.stage <> 'returned')
		ORDER BY i.id`)

	glReviveIdentity = tq("identities.revive", `
		UPDATE identities SET status = 'active', terminated_at = NULL
		WHERE tenant_id = @tenant AND id = @id AND status IN ('terminated','deprovisioned')`)
	glPurgeIdentity = tq("identities.purge", `
		UPDATE identities SET name = @name, email = NULL, department = NULL, title = NULL, description = NULL,
			external_id = @external_id, status = 'purged'
		WHERE tenant_id = @tenant AND id = @id AND status IN ('terminated','deprovisioned')`)
	glPurgeIdentifiers = tq("identity_identifiers.purge", `
		UPDATE identity_identifiers SET value_norm = NULL,
			value_hmac = CASE WHEN @keep = 1 THEN value_hmac ELSE 'purged:' || id END,
			status = CASE WHEN @keep = 1 THEN status ELSE 'retired' END
		WHERE tenant_id = @tenant AND identity_id = @identity_id`)
	glPurgeSources = tq("identity_source_records.purge", `
		UPDATE identity_source_records SET attributes = '{}', status = 'retired'
		WHERE tenant_id = @tenant AND identity_id = @identity_id`)
	glPurgeUsers = tq("platform_users.purge", `
		UPDATE platform_users SET email = NULL, display_name = 'Purged person'
		WHERE tenant_id = @tenant AND identity_id = @identity_id`)
	glPurgeLogins = tq("external_logins.purge", `
		UPDATE external_logins SET email_at_last_login = NULL,
			subject = CASE WHEN @keep = 1 THEN subject ELSE 'purged:' || id END
		WHERE external_logins.tenant_id = @tenant AND user_id IN (SELECT u.id FROM platform_users u WHERE u.tenant_id = @tenant AND u.identity_id = @identity_id)`)
	glPurgeNotes = tq("notifications.purge_for_identity", `
		UPDATE notifications SET recipient_email = NULL, subject = '[purged]', body = '[purged]'
		WHERE tenant_id = @tenant AND identity_id = @identity_id`)
	glPurgeMail = tq("email_messages.purge_for_identity", `
		UPDATE email_messages SET recipient = 'purged', rcpt_to = NULL, mail_from = NULL, subject = '[purged]', attempts = '[]'
		WHERE email_messages.tenant_id = @tenant AND notification_id IN (SELECT n.id FROM notifications n
			WHERE n.tenant_id = @tenant AND n.identity_id = @identity_id)`)
	glHeldAccess = tq("grant_edges.guest_held_access", `
		SELECT count(b.id) FROM guest_bundle_items b WHERE b.tenant_id = @tenant AND b.guest_identity_id = @identity_id
			AND b.status <> 'pending'`)
	glAccountSet = tq("accounts.set_status", `
		UPDATE accounts SET status = @status WHERE tenant_id = @tenant AND id = @id`)
)

func scanTask(s scanner) (*LifecycleTask, error) {
	var t LifecycleTask
	var outcome, note, by sql.NullString
	var deadline, resolved, created nullTime
	if err := s.Scan(&t.ID, &t.Kind, &t.SponsorshipID, &t.SubjectIdentityID, &t.Trigger, &t.Status, &deadline, &outcome, &note,
		&by, &resolved, &created); err != nil {
		return nil, err
	}
	t.Outcome, t.Note, t.ResolvedBy = strp(outcome), strp(note), strp(by)
	var err error
	if t.Deadline, err = deadline.ptr(); err != nil {
		return nil, err
	}
	if t.ResolvedAt, err = resolved.ptr(); err != nil {
		return nil, err
	}
	t.CreatedAt, err = created.val()
	return &t, err
}

func scanStepup(s scanner) (*Stepup, error) {
	var u Stepup
	var by sql.NullString
	var ends, created, resolved nullTime
	if err := s.Scan(&u.ID, &u.SponsorshipID, &ends, &u.Justification, &u.RequiredIAL, &u.Status, &by, &created, &resolved); err != nil {
		return nil, err
	}
	u.RequestedBy = strp(by)
	var err error
	if u.RequestedEndsAt, err = ends.val(); err != nil {
		return nil, err
	}
	if u.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	u.ResolvedAt, err = resolved.ptr()
	return &u, err
}

func scanDeprov(s scanner) (*Deprovisioning, error) {
	var d Deprovisioning
	var held int
	var ended, grace, retention, deprov, purged, returned, updated nullTime
	if err := s.Scan(&d.IdentityID, &d.Population, &d.Stage, &held, &ended, &grace, &retention, &deprov, &purged, &returned, &updated); err != nil {
		return nil, err
	}
	d.HeldAccess = held == 1
	var err error
	if d.EndedAt, err = ended.val(); err != nil {
		return nil, err
	}
	if d.GraceUntil, err = grace.val(); err != nil {
		return nil, err
	}
	if d.RetentionUntil, err = retention.val(); err != nil {
		return nil, err
	}
	if d.DeprovisionedAt, err = deprov.ptr(); err != nil {
		return nil, err
	}
	if d.PurgedAt, err = purged.ptr(); err != nil {
		return nil, err
	}
	if d.ReturnedAt, err = returned.ptr(); err != nil {
		return nil, err
	}
	d.UpdatedAt, err = updated.val()
	return &d, err
}

func scanRenewal(s scanner) (*RenewalToken, error) {
	var r RenewalToken
	var expires, created, used nullTime
	if err := s.Scan(&r.ID, &r.SponsorshipID, &r.GuestIdentityID, &r.TokenHash, &r.Status, &expires, &created, &used); err != nil {
		return nil, err
	}
	var err error
	if r.ExpiresAt, err = expires.val(); err != nil {
		return nil, err
	}
	if r.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	r.UsedAt, err = used.ptr()
	return &r, err
}

// GuestLifecycleSettings returns the tenant's settings (the design's defaults
// when none were saved).
func (tx *TenantTx) GuestLifecycleSettings() (GuestLifecycleSettings, error) {
	out := DefaultGuestLifecycleSettings()
	var days, onDep, conv string
	var guest, deadline, gv, gc, gvol, gp, ret, retV, keep int
	var by sql.NullString
	var at nullTime
	err := tx.queryRow(glSettingsGet).Scan(&days, &guest, &deadline, &onDep, &conv, &gv, &gc, &gvol, &gp, &ret, &retV, &keep, &by, &at)
	if err == sql.ErrNoRows {
		return out, nil
	} else if err != nil {
		return out, err
	}
	var list []int
	if err := json.Unmarshal([]byte(days), &list); err != nil {
		return out, err
	}
	out.SponsorReminderDays, out.GuestReminderDays, out.TransferDeadlineDays = list, guest, deadline
	out.OnSponsorDeparture, out.ConversionDualStatus = onDep, conv
	out.GraceDays = map[string]int{PopVisitor: gv, PopContractor: gc, PopVolunteer: gvol, PopPartner: gp}
	out.RetentionDays, out.RetentionDaysVisitor, out.KeepRematchHashes = ret, retV, keep == 1
	out.UpdatedBy = strp(by)
	out.UpdatedAt, err = at.ptr()
	return out, err
}

// PutGuestLifecycleSettings saves the tenant's settings; the schema bounds every value.
func (tx *TenantTx) PutGuestLifecycleSettings(s GuestLifecycleSettings, by string, at time.Time) error {
	days, err := json.Marshal(s.SponsorReminderDays)
	if err != nil {
		return err
	}
	_, err = tx.exec(glSettingsPut, sql.Named("sponsor_reminder_days", string(days)), sql.Named("guest_reminder_days", s.GuestReminderDays),
		sql.Named("transfer_deadline_days", s.TransferDeadlineDays), sql.Named("on_sponsor_departure", s.OnSponsorDeparture),
		sql.Named("conversion_dual_status", s.ConversionDualStatus), sql.Named("grace_visitor", s.GraceDays[PopVisitor]),
		sql.Named("grace_contractor", s.GraceDays[PopContractor]), sql.Named("grace_volunteer", s.GraceDays[PopVolunteer]),
		sql.Named("grace_partner", s.GraceDays[PopPartner]), sql.Named("retention_days", s.RetentionDays),
		sql.Named("retention_days_visitor", s.RetentionDaysVisitor), sql.Named("keep_rematch_hashes", B(s.KeepRematchHashes)),
		sql.Named("updated_by", emptyNil(by)), sql.Named("updated_at", T(at)))
	return err
}

// MarkReminder records that the reminder (sponsorship, end date, audience,
// threshold) was sent; false when it had been recorded before.
func (tx *TenantTx) MarkReminder(sponsorshipID string, endsAt time.Time, audience string, threshold int, at time.Time) (bool, error) {
	res, err := tx.exec(glReminderMark, sql.Named("sponsorship_id", sponsorshipID), sql.Named("ends_at", T(endsAt)),
		sql.Named("audience", audience), sql.Named("threshold_days", threshold), sql.Named("sent_at", T(at)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// CountReminders counts the reminders sent (sponsorship and audience "" for all).
func (tx *TenantTx) CountReminders(sponsorshipID, audience string) (int, error) {
	return tx.count(glReminderCount, sql.Named("sponsorship", sponsorshipID), sql.Named("audience", audience))
}

// InsertRenewalToken records a guest's renewal-request link (by its hash).
func (tx *TenantTx) InsertRenewalToken(r *RenewalToken) error {
	_, err := tx.exec(glTokenInsert, sql.Named("id", r.ID), sql.Named("sponsorship_id", r.SponsorshipID),
		sql.Named("guest_identity_id", r.GuestIdentityID), sql.Named("token_hash", r.TokenHash),
		sql.Named("expires_at", T(r.ExpiresAt)), sql.Named("created_at", T(r.CreatedAt)))
	return err
}

// ConsumeRenewalToken marks the token with this hash used, once, if it is issued
// and unexpired; ErrNotFound otherwise (the caller never says which).
func (tx *TenantTx) ConsumeRenewalToken(hash string, now time.Time) (*RenewalToken, error) {
	res, err := tx.exec(glTokenConsume, sql.Named("token_hash", hash), sql.Named("now", T(now)))
	if err := affectedOne(res, err); err != nil {
		return nil, err
	}
	return one(tx, scanRenewal, glTokenByHash, sql.Named("token_hash", hash))
}

// RevokeRenewalTokens revokes a sponsorship's issued tokens and returns how many.
func (tx *TenantTx) RevokeRenewalTokens(sponsorshipID string) (int, error) {
	res, err := tx.exec(glTokenRevoke, sql.Named("sponsorship_id", sponsorshipID))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// ExpireRenewalTokens marks issued tokens past their lifetime expired.
func (tx *TenantTx) ExpireRenewalTokens(now time.Time) (int, error) {
	res, err := tx.exec(glTokenExpire, sql.Named("now", T(now)))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// RenewalTokensFor lists a sponsorship's renewal tokens, oldest first.
func (tx *TenantTx) RenewalTokensFor(sponsorshipID string) ([]*RenewalToken, error) {
	return collect(tx, scanRenewal, glTokenFor, sql.Named("sponsorship_id", sponsorshipID))
}

// InsertLifecycleTask opens a task; the schema allows one open task per sponsorship and kind.
func (tx *TenantTx) InsertLifecycleTask(t *LifecycleTask) error {
	_, err := tx.exec(glTaskInsert, sql.Named("id", t.ID), sql.Named("kind", t.Kind), sql.Named("sponsorship_id", t.SponsorshipID),
		sql.Named("subject_identity_id", t.SubjectIdentityID), sql.Named("trigger", t.Trigger), sql.Named("deadline", TP(t.Deadline)),
		sql.Named("created_at", T(t.CreatedAt)))
	return err
}

// LifecycleTask returns one task, or ErrNotFound.
func (tx *TenantTx) LifecycleTask(id string) (*LifecycleTask, error) {
	return one(tx, scanTask, glTaskGet, sql.Named("id", id))
}

// LifecycleTasks returns the tasks matching f, newest first.
func (tx *TenantTx) LifecycleTasks(f LifecycleTaskFilter) ([]*LifecycleTask, error) {
	return collect(tx, scanTask, glTaskList, sql.Named("kind", f.Kind), sql.Named("status", f.Status),
		sql.Named("sponsorship", f.Sponsorship), sql.Named("subject", f.Subject))
}

// ResolveLifecycleTask closes an open task; ErrNotFound if it is unknown or already closed.
func (tx *TenantTx) ResolveLifecycleTask(id, status, outcome, note string, by *string, now time.Time) error {
	res, err := tx.exec(glTaskResolve, sql.Named("id", id), sql.Named("status", status), sql.Named("outcome", outcome),
		sql.Named("note", emptyNil(note)), sql.Named("resolved_by", optStr(by)), sql.Named("now", T(now)))
	return affectedOne(res, err)
}

// InsertStepup records a renewal waiting for the guest's identity assurance.
func (tx *TenantTx) InsertStepup(u *Stepup) error {
	_, err := tx.exec(glStepupInsert, sql.Named("id", u.ID), sql.Named("sponsorship_id", u.SponsorshipID),
		sql.Named("requested_ends_at", T(u.RequestedEndsAt)), sql.Named("justification", u.Justification),
		sql.Named("required_ial", u.RequiredIAL), sql.Named("requested_by", optStr(u.RequestedBy)), sql.Named("created_at", T(u.CreatedAt)))
	return err
}

// Stepups lists step-up renewals (status and sponsorship "" for all), oldest first.
func (tx *TenantTx) Stepups(status, sponsorshipID string) ([]*Stepup, error) {
	return collect(tx, scanStepup, glStepupList, sql.Named("status", status), sql.Named("sponsorship", sponsorshipID))
}

// ResolveStepup closes a pending step-up; ErrNotFound if it is unknown or closed.
func (tx *TenantTx) ResolveStepup(id, status string, now time.Time) error {
	res, err := tx.exec(glStepupResolve, sql.Named("id", id), sql.Named("status", status), sql.Named("now", T(now)))
	return affectedOne(res, err)
}

// InsertDeprovisioning starts a person's grace period.
func (tx *TenantTx) InsertDeprovisioning(d *Deprovisioning) error {
	_, err := tx.exec(glDeprovInsert, sql.Named("identity_id", d.IdentityID), sql.Named("population", d.Population),
		sql.Named("held_access", B(d.HeldAccess)), sql.Named("ended_at", T(d.EndedAt)), sql.Named("grace_until", T(d.GraceUntil)),
		sql.Named("retention_until", T(d.RetentionUntil)), sql.Named("updated_at", T(d.UpdatedAt)))
	return err
}

// RestartDeprovisioning begins a new cycle for a person who had returned.
func (tx *TenantTx) RestartDeprovisioning(d *Deprovisioning) error {
	res, err := tx.exec(glDeprovRestart, sql.Named("identity_id", d.IdentityID), sql.Named("population", d.Population),
		sql.Named("held_access", B(d.HeldAccess)), sql.Named("ended_at", T(d.EndedAt)), sql.Named("grace_until", T(d.GraceUntil)),
		sql.Named("retention_until", T(d.RetentionUntil)), sql.Named("updated_at", T(d.UpdatedAt)))
	return affectedOne(res, err)
}

// Deprovisioning returns a person's stage, or ErrNotFound.
func (tx *TenantTx) Deprovisioning(identityID int64) (*Deprovisioning, error) {
	return one(tx, scanDeprov, glDeprovGet, sql.Named("identity_id", identityID))
}

// DeprovisioningList lists people by stage ("" for all), oldest first.
func (tx *TenantTx) DeprovisioningList(stage string) ([]*Deprovisioning, error) {
	return collect(tx, scanDeprov, glDeprovList, sql.Named("stage", stage))
}

// AdvanceDeprovisioning moves a person from one stage to the next; ErrNotFound
// if they are not in stage from (a concurrent change, or a replay).
func (tx *TenantTx) AdvanceDeprovisioning(identityID int64, from, stage string, now time.Time) error {
	res, err := tx.exec(glDeprovAdvance, sql.Named("identity_id", identityID), sql.Named("from", from),
		sql.Named("stage", stage), sql.Named("now", T(now)))
	return affectedOne(res, err)
}

// AwaitingDeprovisioning lists terminated people with a sponsorship history
// and no deprovisioning row yet.
func (tx *TenantTx) AwaitingDeprovisioning() ([]int64, error) {
	rows, err := tx.query(glAwaiting)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// HeldBundleAccess counts the bundle items a guest ever held access through.
func (tx *TenantTx) HeldBundleAccess(identityID int64) (int, error) {
	return tx.count(glHeldAccess, sql.Named("identity_id", identityID))
}

// ReviveIdentity makes a terminated or deprovisioned person active again (a
// guest who returns within retention); ErrNotFound for anyone else.
func (tx *TenantTx) ReviveIdentity(id int64) error {
	res, err := tx.exec(glReviveIdentity, sql.Named("id", id))
	return affectedOne(res, err)
}

// SetAccountStatus sets an account's status ("deleted" after a delete in the target).
func (tx *TenantTx) SetAccountStatus(id int64, status string) error {
	_, err := tx.exec(glAccountSet, sql.Named("id", id), sql.Named("status", status))
	return err
}

// PurgeReport counts what a purge reduced, without any of the values.
type PurgeReport struct {
	Identity, Identifiers, SourceRecords, Users, Logins, Notifications, Messages int
}

// PurgeIdentityPII reduces a person's operational records to a tombstone: the
// id, affiliation history and dates stay; names, emails, phone numbers,
// identifiers (their hashes only when keepHashes) and intake attributes are
// nulled or redacted. It never touches the audit ledger. A person who is not
// terminated or deprovisioned is not purged (ErrNotFound); a second purge
// changes nothing.
func (tx *TenantTx) PurgeIdentityPII(id int64, keepHashes bool) (PurgeReport, error) {
	var r PurgeReport
	count := func(res sql.Result, err error) (int, error) {
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		return int(n), err
	}
	var err error
	if r.Identity, err = count(tx.exec(glPurgeIdentity, sql.Named("id", id), sql.Named("name", "Purged person"),
		sql.Named("external_id", "purged-"+strconv.FormatInt(id, 10)))); err != nil {
		return r, err
	}
	if r.Identity == 0 {
		return r, ErrNotFound
	}
	keep := B(keepHashes)
	if r.Identifiers, err = count(tx.exec(glPurgeIdentifiers, sql.Named("identity_id", id), sql.Named("keep", keep))); err != nil {
		return r, err
	}
	if r.SourceRecords, err = count(tx.exec(glPurgeSources, sql.Named("identity_id", id))); err != nil {
		return r, err
	}
	if r.Users, err = count(tx.exec(glPurgeUsers, sql.Named("identity_id", id))); err != nil {
		return r, err
	}
	if r.Logins, err = count(tx.exec(glPurgeLogins, sql.Named("identity_id", id), sql.Named("keep", keep))); err != nil {
		return r, err
	}
	if r.Messages, err = count(tx.exec(glPurgeMail, sql.Named("identity_id", id))); err != nil {
		return r, err
	}
	r.Notifications, err = count(tx.exec(glPurgeNotes, sql.Named("identity_id", id)))
	return r, err
}

// emptyNil stores an empty string as NULL.
func emptyNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}
