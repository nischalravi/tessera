package store

import (
	"database/sql"
	"errors"
	"time"
)

// The least-privilege loop's tables (schema/0921_lp_revocations.sql, issue #661, LP-5). Every statement binds the
// tenant. The state machine itself is internal/lp; this file only keeps the rows.

// Loop modes (design least-privilege-loop section 3).
const (
	LPModeOff     = "off"
	LPModeSuggest = "suggest"
	LPModeStaged  = "staged"
	LPModeAuto    = "auto"
)

// Revocation states (design section 5).
const (
	LPCandidate  = "candidate"
	LPAnnounced  = "announced"
	LPRevoking   = "revoking"
	LPRevoked    = "revoked"
	LPFinalized  = "finalized"
	LPRestoring  = "restoring"
	LPRestored   = "restored"
	LPExempted   = "exempted"
	LPFailed     = "failed"
	LPSuperseded = "superseded"
)

// Eligibility of a candidate: auto (high confidence, unused long enough, covered by a batch approval) or item
// (medium confidence or fewer unused days: approved on its own).
const (
	LPEligAuto = "auto"
	LPEligItem = "item"
)

// Sources of an exemption.
const (
	LPExemptObjection = "objection"
	LPExemptRestore   = "restore"
	LPExemptReview    = "review_keep"
)

// LPSettings is a tenant's loop configuration. A tenant with no row is off, not paused, with the design's
// defaults (25 per run, 100 per day, 10 per AWS account per day, 1 per principal per day; announce 7 days,
// finalize 30, auto needs 90 unused days).
type LPSettings struct {
	Mode            string
	Paused          bool
	PausedReason    string
	PausedBy        string
	PausedAt        *time.Time
	CapPerRun       int
	CapPerDay       int
	CapPerAccount   int
	CapPerPrincipal int
	AnnounceDays    int
	FinalizeDays    int
	AutoMinDays     int
	UpdatedBy       string
	UpdatedAt       time.Time
}

// DefaultLPSettings are the settings of a tenant that never set any.
func DefaultLPSettings() *LPSettings {
	return &LPSettings{Mode: LPModeOff, CapPerRun: 25, CapPerDay: 100, CapPerAccount: 10, CapPerPrincipal: 1,
		AnnounceDays: 7, FinalizeDays: 30, AutoMinDays: 90}
}

// LPRevocation is one proposed or executed removal of unused access.
type LPRevocation struct {
	ID          string
	State       string
	Kind        string
	Eligibility string
	ConnectorID string
	SnapshotID  string
	AccountID   string
	Principal   string
	PolicyARN   string
	UnusedDays  int
	Confidence  string
	Evidence    string // JSON
	// CandidateSHA256 is the digest of the document the right-size would leave in place.
	CandidateSHA256 string
	// RestorePayload is the exact prior state (JSON), kept verbatim; RestoreSHA256 is its digest recorded at the revoke.
	RestorePayload     string
	RestoreSHA256      string
	CreatedBy          string
	CreatedAt          time.Time
	ApprovedBy         string
	ApprovedAt         *time.Time
	AnnounceUntil      *time.Time
	ExecutedAt         *time.Time
	OpID               string
	RevokedAt          *time.Time
	RestoreUntil       *time.Time
	FinalizedAt        *time.Time
	RestoreOpID        string
	RestoreTrigger     string
	RestoreRequestedAt *time.Time
	RestoredAt         *time.Time
	Reason             string
	UpdatedAt          time.Time
}

// LPEvent is one transition of a revocation.
type LPEvent struct {
	ID           string
	RevocationID string
	From, To     string
	Actor        string
	Detail       string
	CreatedAt    time.Time
}

// LPProtectedRef is a principal or policy the loop never touches.
type LPProtectedRef struct {
	ID        string
	Kind      string // principal or policy
	Ref       string
	Reason    string
	CreatedBy string
	CreatedAt time.Time
}

// LPExemption keeps one grant from being proposed again until Until.
type LPExemption struct {
	ID           string
	Principal    string
	PolicyARN    string
	Source       string
	Reason       string
	RevocationID string
	Until        time.Time
	CreatedBy    string
	CreatedAt    time.Time
}

const lpRevCols = `r.id, r.state, r.kind, r.eligibility, r.connector_id, r.snapshot_id, r.account_id, r.principal_arn, r.policy_arn,
	r.unused_days, r.confidence, r.evidence, r.candidate_sha256, r.restore_payload, r.restore_sha256, r.created_by, r.created_at,
	r.approved_by, r.approved_at, r.announce_until, r.executed_at, r.op_id, r.revoked_at, r.restore_until, r.finalized_at,
	r.restore_op_id, r.restore_trigger, r.restore_requested_at, r.restored_at, r.reason, r.updated_at`

var (
	lpSettingsGet = tq("lp_settings.get", `
		SELECT s.mode, s.paused, s.paused_reason, s.paused_by, s.paused_at, s.cap_per_run, s.cap_per_day, s.cap_per_account,
			s.cap_per_principal, s.announce_days, s.finalize_days, s.auto_min_days, s.updated_by, s.updated_at
		FROM lp_settings s WHERE s.tenant_id = @tenant`)
	lpSettingsPut = tq("lp_settings.put", `
		INSERT INTO lp_settings (tenant_id, mode, paused, paused_reason, paused_by, paused_at, cap_per_run, cap_per_day,
			cap_per_account, cap_per_principal, announce_days, finalize_days, auto_min_days, updated_by, updated_at)
		VALUES (@tenant, @mode, @paused, @paused_reason, @paused_by, @paused_at, @cap_per_run, @cap_per_day,
			@cap_per_account, @cap_per_principal, @announce_days, @finalize_days, @auto_min_days, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET mode = excluded.mode, paused = excluded.paused,
			paused_reason = excluded.paused_reason, paused_by = excluded.paused_by, paused_at = excluded.paused_at,
			cap_per_run = excluded.cap_per_run, cap_per_day = excluded.cap_per_day, cap_per_account = excluded.cap_per_account,
			cap_per_principal = excluded.cap_per_principal, announce_days = excluded.announce_days,
			finalize_days = excluded.finalize_days, auto_min_days = excluded.auto_min_days,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)

	lpRevInsert = tq("lp_revocations.insert", `
		INSERT INTO lp_revocations (tenant_id, id, state, kind, eligibility, connector_id, snapshot_id, account_id, principal_arn,
			policy_arn, unused_days, confidence, evidence, candidate_sha256, restore_payload, restore_sha256, created_by,
			created_at, updated_at)
		VALUES (@tenant, @id, @state, @kind, @eligibility, @connector_id, @snapshot_id, @account_id, @principal_arn,
			@policy_arn, @unused_days, @confidence, @evidence, @candidate_sha256, @restore_payload, @restore_sha256,
			@created_by, @created_at, @created_at)`)
	lpRevGet = tq("lp_revocations.get", `
		SELECT `+lpRevCols+` FROM lp_revocations r WHERE r.tenant_id = @tenant AND r.id = @id`)
	lpRevList = tq("lp_revocations.list", `
		SELECT `+lpRevCols+` FROM lp_revocations r
		WHERE r.tenant_id = @tenant AND (@state = '' OR r.state = @state)
		ORDER BY r.created_at DESC, r.id DESC LIMIT @limit`)
	lpRevOldestInState = tq("lp_revocations.oldest_in_state", `
		SELECT `+lpRevCols+` FROM lp_revocations r
		WHERE r.tenant_id = @tenant AND r.state = @state
		ORDER BY r.created_at, r.id LIMIT @limit`)
	// The compare-and-set of a transition: the row changes only if it is still in the state the caller read.
	lpRevUpdate = tq("lp_revocations.update", `
		UPDATE lp_revocations SET state = @state, eligibility = @eligibility, approved_by = @approved_by,
			approved_at = @approved_at, announce_until = @announce_until, executed_at = @executed_at, op_id = @op_id,
			revoked_at = @revoked_at, restore_until = @restore_until, finalized_at = @finalized_at,
			restore_op_id = @restore_op_id, restore_trigger = @restore_trigger, restore_requested_at = @restore_requested_at,
			restored_at = @restored_at, reason = @reason, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id AND state = @from`)
	lpRevExecuted = tq("lp_revocations.executed", `
		SELECT COUNT(*) FROM lp_revocations r
		WHERE r.tenant_id = @tenant AND r.executed_at IS NOT NULL AND r.executed_at >= @since
			AND (@account = '' OR r.account_id = @account) AND (@principal = '' OR r.principal_arn = @principal)`)
	lpRevRestoredSince = tq("lp_revocations.restored_since", `
		SELECT COUNT(*) FROM lp_revocations r
		WHERE r.tenant_id = @tenant AND r.restore_requested_at IS NOT NULL AND r.restore_requested_at >= @since`)
	lpRevOpen = tq("lp_revocations.open_for_grant", `
		SELECT COUNT(*) FROM lp_revocations r
		WHERE r.tenant_id = @tenant AND r.principal_arn = @principal AND r.policy_arn = @policy
			AND r.state IN ('candidate', 'announced', 'revoking', 'revoked', 'restoring')`)

	lpEventInsert = tq("lp_revocation_events.insert", `
		INSERT INTO lp_revocation_events (tenant_id, id, revocation_id, from_state, to_state, actor, detail, created_at)
		VALUES (@tenant, @id, @revocation_id, @from_state, @to_state, @actor, @detail, @created_at)`)
	lpEventList = tq("lp_revocation_events.list", `
		SELECT e.id, e.revocation_id, e.from_state, e.to_state, e.actor, e.detail, e.created_at FROM lp_revocation_events e
		WHERE e.tenant_id = @tenant AND e.revocation_id = @revocation_id ORDER BY e.created_at, e.id`)

	lpProtectedInsert = tq("lp_protected.insert", `
		INSERT INTO lp_protected (tenant_id, id, kind, ref, reason, created_by, created_at)
		VALUES (@tenant, @id, @kind, @ref, @reason, @created_by, @created_at)`)
	lpProtectedList = tq("lp_protected.list", `
		SELECT p.id, p.kind, p.ref, p.reason, p.created_by, p.created_at FROM lp_protected p
		WHERE p.tenant_id = @tenant ORDER BY p.kind, p.ref`)
	lpProtectedDelete = tq("lp_protected.delete", `DELETE FROM lp_protected WHERE tenant_id = @tenant AND id = @id`)

	lpExemptInsert = tq("lp_exemptions.insert", `
		INSERT INTO lp_exemptions (tenant_id, id, principal_arn, policy_arn, source, reason, revocation_id, ends_at, created_by, created_at)
		VALUES (@tenant, @id, @principal_arn, @policy_arn, @source, @reason, @revocation_id, @ends_at, @created_by, @created_at)`)
	lpExemptActive = tq("lp_exemptions.active", `
		SELECT COUNT(*) FROM lp_exemptions x
		WHERE x.tenant_id = @tenant AND x.principal_arn = @principal AND x.policy_arn = @policy AND x.ends_at > @now`)
	lpExemptList = tq("lp_exemptions.list", `
		SELECT x.id, x.principal_arn, x.policy_arn, x.source, x.reason, x.revocation_id, x.ends_at, x.created_by, x.created_at
		FROM lp_exemptions x WHERE x.tenant_id = @tenant AND x.ends_at > @now ORDER BY x.ends_at DESC, x.id LIMIT @limit`)
)

// LPSettings returns the tenant's settings; a tenant that never set any gets the defaults and no error.
func (tx *TenantTx) LPSettings() (*LPSettings, error) {
	s, err := one(tx, func(r scanner) (*LPSettings, error) {
		var s LPSettings
		var paused int
		var pausedAt sql.NullString
		var at string
		if err := r.Scan(&s.Mode, &paused, &s.PausedReason, &s.PausedBy, &pausedAt, &s.CapPerRun, &s.CapPerDay, &s.CapPerAccount,
			&s.CapPerPrincipal, &s.AnnounceDays, &s.FinalizeDays, &s.AutoMinDays, &s.UpdatedBy, &at); err != nil {
			return nil, err
		}
		s.Paused = paused == 1
		var err error
		if s.PausedAt, err = rtp(pausedAt); err != nil {
			return nil, err
		}
		s.UpdatedAt, err = ParseRT(at)
		return &s, err
	}, lpSettingsGet)
	if errors.Is(err, ErrNotFound) {
		return DefaultLPSettings(), nil
	}
	return s, err
}

// PutLPSettings replaces the tenant's settings.
func (tx *TenantTx) PutLPSettings(s *LPSettings, now time.Time) error {
	paused := 0
	if s.Paused {
		paused = 1
	}
	_, err := tx.exec(lpSettingsPut, sql.Named("mode", s.Mode), sql.Named("paused", paused), sql.Named("paused_reason", s.PausedReason),
		sql.Named("paused_by", s.PausedBy), sql.Named("paused_at", RTP(s.PausedAt)), sql.Named("cap_per_run", s.CapPerRun),
		sql.Named("cap_per_day", s.CapPerDay), sql.Named("cap_per_account", s.CapPerAccount),
		sql.Named("cap_per_principal", s.CapPerPrincipal), sql.Named("announce_days", s.AnnounceDays),
		sql.Named("finalize_days", s.FinalizeDays), sql.Named("auto_min_days", s.AutoMinDays),
		sql.Named("updated_by", s.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}

// InsertLPRevocation records a new revocation in the state the caller set (a candidate).
func (tx *TenantTx) InsertLPRevocation(r *LPRevocation) error {
	_, err := tx.exec(lpRevInsert, sql.Named("id", r.ID), sql.Named("state", r.State), sql.Named("kind", r.Kind),
		sql.Named("eligibility", r.Eligibility), sql.Named("connector_id", r.ConnectorID), sql.Named("snapshot_id", r.SnapshotID),
		sql.Named("account_id", r.AccountID), sql.Named("principal_arn", r.Principal), sql.Named("policy_arn", r.PolicyARN),
		sql.Named("unused_days", r.UnusedDays), sql.Named("confidence", r.Confidence), sql.Named("evidence", r.Evidence),
		sql.Named("candidate_sha256", r.CandidateSHA256), sql.Named("restore_payload", r.RestorePayload),
		sql.Named("restore_sha256", r.RestoreSHA256), sql.Named("created_by", r.CreatedBy), sql.Named("created_at", RT(r.CreatedAt)))
	return err
}

func scanLPRevocation(s scanner) (*LPRevocation, error) {
	var r LPRevocation
	var created, updated string
	var approved, announce, executed, revoked, until, finalized, restoreReq, restored sql.NullString
	if err := s.Scan(&r.ID, &r.State, &r.Kind, &r.Eligibility, &r.ConnectorID, &r.SnapshotID, &r.AccountID, &r.Principal, &r.PolicyARN,
		&r.UnusedDays, &r.Confidence, &r.Evidence, &r.CandidateSHA256, &r.RestorePayload, &r.RestoreSHA256, &r.CreatedBy, &created,
		&r.ApprovedBy, &approved, &announce, &executed, &r.OpID, &revoked, &until, &finalized,
		&r.RestoreOpID, &r.RestoreTrigger, &restoreReq, &restored, &r.Reason, &updated); err != nil {
		return nil, err
	}
	var err error
	if r.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if r.UpdatedAt, err = ParseRT(updated); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		in  sql.NullString
		out **time.Time
	}{{approved, &r.ApprovedAt}, {announce, &r.AnnounceUntil}, {executed, &r.ExecutedAt}, {revoked, &r.RevokedAt},
		{until, &r.RestoreUntil}, {finalized, &r.FinalizedAt}, {restoreReq, &r.RestoreRequestedAt}, {restored, &r.RestoredAt}} {
		if *f.out, err = rtp(f.in); err != nil {
			return nil, err
		}
	}
	return &r, nil
}

// LPRevocation returns one revocation, or ErrNotFound.
func (tx *TenantTx) LPRevocation(id string) (*LPRevocation, error) {
	return one(tx, scanLPRevocation, lpRevGet, sql.Named("id", id))
}

// LPRevocations lists revocations newest first. state "" matches every state; limit <= 0 or above 500 is 100.
func (tx *TenantTx) LPRevocations(state string, limit int) ([]*LPRevocation, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return collect(tx, scanLPRevocation, lpRevList, sql.Named("state", state), sql.Named("limit", limit))
}

// LPRevocationsToAdvance lists the oldest revocations in one state, for the tick that moves them on.
func (tx *TenantTx) LPRevocationsToAdvance(state string, limit int) ([]*LPRevocation, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return collect(tx, scanLPRevocation, lpRevOldestInState, sql.Named("state", state), sql.Named("limit", limit))
}

// UpdateLPRevocation writes the mutable fields of r (its state included) if the row is still in state from.
// ErrNotFound: no such revocation, or another request moved it first.
func (tx *TenantTx) UpdateLPRevocation(r *LPRevocation, from string, now time.Time) error {
	return tx.affectOne(lpRevUpdate, sql.Named("id", r.ID), sql.Named("from", from), sql.Named("state", r.State),
		sql.Named("eligibility", r.Eligibility), sql.Named("approved_by", r.ApprovedBy), sql.Named("approved_at", RTP(r.ApprovedAt)),
		sql.Named("announce_until", RTP(r.AnnounceUntil)), sql.Named("executed_at", RTP(r.ExecutedAt)), sql.Named("op_id", r.OpID),
		sql.Named("revoked_at", RTP(r.RevokedAt)), sql.Named("restore_until", RTP(r.RestoreUntil)),
		sql.Named("finalized_at", RTP(r.FinalizedAt)), sql.Named("restore_op_id", r.RestoreOpID),
		sql.Named("restore_trigger", r.RestoreTrigger), sql.Named("restore_requested_at", RTP(r.RestoreRequestedAt)),
		sql.Named("restored_at", RTP(r.RestoredAt)), sql.Named("reason", r.Reason), sql.Named("updated_at", RT(now)))
}

// LPExecutedSince counts the revocations queued for execution at or after since; account and principal ""
// match every account and principal. These are the counts the caps bound.
func (tx *TenantTx) LPExecutedSince(since time.Time, account, principal string) (int, error) {
	return tx.count(lpRevExecuted, sql.Named("since", RT(since)), sql.Named("account", account), sql.Named("principal", principal))
}

// LPRestoredSince counts the revocations whose restore was requested at or after since.
func (tx *TenantTx) LPRestoredSince(since time.Time) (int, error) {
	return tx.count(lpRevRestoredSince, sql.Named("since", RT(since)))
}

// LPOpenForGrant counts the revocations of one grant that are not over (a second would be a duplicate).
func (tx *TenantTx) LPOpenForGrant(principal, policy string) (int, error) {
	return tx.count(lpRevOpen, sql.Named("principal", principal), sql.Named("policy", policy))
}

// InsertLPEvent records one transition of a revocation.
func (tx *TenantTx) InsertLPEvent(e *LPEvent) error {
	if e.ID == "" {
		e.ID = NewID()
	}
	_, err := tx.exec(lpEventInsert, sql.Named("id", e.ID), sql.Named("revocation_id", e.RevocationID), sql.Named("from_state", e.From),
		sql.Named("to_state", e.To), sql.Named("actor", e.Actor), sql.Named("detail", e.Detail), sql.Named("created_at", RT(e.CreatedAt)))
	return err
}

// LPEvents lists the transitions of a revocation, oldest first.
func (tx *TenantTx) LPEvents(revocationID string) ([]*LPEvent, error) {
	return collect(tx, func(s scanner) (*LPEvent, error) {
		var e LPEvent
		var at string
		if err := s.Scan(&e.ID, &e.RevocationID, &e.From, &e.To, &e.Actor, &e.Detail, &at); err != nil {
			return nil, err
		}
		var err error
		e.CreatedAt, err = ParseRT(at)
		return &e, err
	}, lpEventList, sql.Named("revocation_id", revocationID))
}

// InsertLPProtected adds a principal or policy the loop never touches. ErrDuplicate: it is listed already.
func (tx *TenantTx) InsertLPProtected(p *LPProtectedRef) error {
	if p.ID == "" {
		p.ID = NewID()
	}
	_, err := tx.exec(lpProtectedInsert, sql.Named("id", p.ID), sql.Named("kind", p.Kind), sql.Named("ref", p.Ref),
		sql.Named("reason", p.Reason), sql.Named("created_by", p.CreatedBy), sql.Named("created_at", RT(p.CreatedAt)))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// LPProtected lists what the loop never touches.
func (tx *TenantTx) LPProtected() ([]*LPProtectedRef, error) {
	return collect(tx, func(s scanner) (*LPProtectedRef, error) {
		var p LPProtectedRef
		var at string
		if err := s.Scan(&p.ID, &p.Kind, &p.Ref, &p.Reason, &p.CreatedBy, &at); err != nil {
			return nil, err
		}
		var err error
		p.CreatedAt, err = ParseRT(at)
		return &p, err
	}, lpProtectedList)
}

// DeleteLPProtected removes an entry; ErrNotFound when there is none.
func (tx *TenantTx) DeleteLPProtected(id string) error {
	return tx.affectOne(lpProtectedDelete, sql.Named("id", id))
}

// InsertLPExemption keeps a grant from being proposed until e.Until.
func (tx *TenantTx) InsertLPExemption(e *LPExemption) error {
	if e.ID == "" {
		e.ID = NewID()
	}
	_, err := tx.exec(lpExemptInsert, sql.Named("id", e.ID), sql.Named("principal_arn", e.Principal), sql.Named("policy_arn", e.PolicyARN),
		sql.Named("source", e.Source), sql.Named("reason", e.Reason), sql.Named("revocation_id", e.RevocationID),
		sql.Named("ends_at", RT(e.Until)), sql.Named("created_by", e.CreatedBy), sql.Named("created_at", RT(e.CreatedAt)))
	return err
}

// LPExempted reports whether the grant is exempted at now.
func (tx *TenantTx) LPExempted(principal, policy string, now time.Time) (bool, error) {
	n, err := tx.count(lpExemptActive, sql.Named("principal", principal), sql.Named("policy", policy), sql.Named("now", RT(now)))
	return n > 0, err
}

// LPExemptions lists the exemptions in force at now, latest end first.
func (tx *TenantTx) LPExemptions(now time.Time, limit int) ([]*LPExemption, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return collect(tx, func(s scanner) (*LPExemption, error) {
		var e LPExemption
		var until, at string
		if err := s.Scan(&e.ID, &e.Principal, &e.PolicyARN, &e.Source, &e.Reason, &e.RevocationID, &until, &e.CreatedBy, &at); err != nil {
			return nil, err
		}
		var err error
		if e.Until, err = ParseRT(until); err != nil {
			return nil, err
		}
		e.CreatedAt, err = ParseRT(at)
		return &e, err
	}, lpExemptList, sql.Named("now", RT(now)), sql.Named("limit", limit))
}
