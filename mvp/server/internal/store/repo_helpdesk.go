package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Verified help-desk resets (schema/0254_helpdesk.sql). The store only keeps
// the rows; the policy lives in internal/helpdesk.

// Help-desk case statuses.
const (
	HelpdeskOpen      = "open"
	HelpdeskExecuting = "executing"
	HelpdeskExecuted  = "executed"
	HelpdeskFailed    = "failed"
	HelpdeskCancelled = "cancelled"
)

// HelpdeskCase is one reset case.
type HelpdeskCase struct {
	ID                   string
	IdentityID           int64
	Kind                 string // password | mfa
	System               string // the executor: okta, entra or simulated
	Reason               string
	Status               string
	Privileged           bool // snapshot at start; the policy re-reads it
	RequestedBy          string
	RequestedByUserID    *uuid.UUID
	SecondApprover       *string
	SecondApproverUserID *uuid.UUID
	SecondApprovedAt     *time.Time
	ExecutedBy           *string
	ExecutedAt           *time.Time
	Result               string
	Error                string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// HelpdeskVerification is one verification attempt on a case.
type HelpdeskVerification struct {
	ID                string
	CaseID            string
	Method            string // push | callback | manager_approval | idv
	Outcome           string // passed | failed
	PhishingResistant bool
	VerifiedBy        string
	VerifiedByUserID  *uuid.UUID
	Evidence          string
	Provider          string
	CreatedAt         time.Time
}

// HelpdeskSignal is post-reset telemetry for an identity.
type HelpdeskSignal struct {
	ID         string
	IdentityID int64
	Kind       string // mfa_device_added | sign_in
	Location   string
	Device     string
	Source     string
	OccurredAt time.Time
	CreatedAt  time.Time
}

// HelpdeskFinding is a detection result for a case.
type HelpdeskFinding struct {
	ID         string
	CaseID     string
	IdentityID int64
	Rule       string
	Detail     string // JSON
	CreatedAt  time.Time
}

const helpdeskCaseCols = `c.id, c.identity_id, c.kind, c.system, c.reason, c.status, c.privileged, c.requested_by,
	c.requested_by_user_id, c.second_approver, c.second_approver_user_id, c.second_approved_at, c.executed_by,
	c.executed_at, c.result, c.error, c.created_at, c.updated_at`

const helpdeskVerificationCols = `v.id, v.case_id, v.method, v.outcome, v.phishing_resistant, v.verified_by,
	v.verified_by_user_id, v.evidence, v.provider, v.created_at`

const helpdeskSignalCols = `s.id, s.identity_id, s.kind, s.location, s.device, s.source, s.occurred_at, s.created_at`

const helpdeskFindingCols = `f.id, f.case_id, f.identity_id, f.rule, f.detail, f.created_at`

var (
	helpdeskCaseInsert = tq("helpdesk_cases.insert", `
		INSERT INTO helpdesk_cases (id, tenant_id, identity_id, kind, system, reason, status, privileged, requested_by,
			requested_by_user_id, created_at, updated_at)
		VALUES (@id, @tenant, @identity_id, @kind, @system, @reason, 'open', @privileged, @requested_by,
			@requested_by_user_id, @now, @now)`)
	helpdeskCaseGet = tq("helpdesk_cases.get", `
		SELECT `+helpdeskCaseCols+` FROM helpdesk_cases c WHERE c.tenant_id = @tenant AND c.id = @id`)
	helpdeskCaseList = tq("helpdesk_cases.list", `
		SELECT `+helpdeskCaseCols+` FROM helpdesk_cases c WHERE c.tenant_id = @tenant
		ORDER BY c.created_at DESC, c.id LIMIT 200`)
	helpdeskCaseExecutedSince = tq("helpdesk_cases.executed_since", `
		SELECT `+helpdeskCaseCols+` FROM helpdesk_cases c
		WHERE c.tenant_id = @tenant AND c.identity_id = @identity_id AND c.status = 'executed' AND c.executed_at >= @since
		ORDER BY c.executed_at, c.id`)
	helpdeskCaseSecondApprove = tq("helpdesk_cases.second_approve", `
		UPDATE helpdesk_cases SET second_approver = @by, second_approver_user_id = @by_user_id,
			second_approved_at = @now, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status IN ('open','failed') AND second_approved_at IS NULL`)
	helpdeskCaseClaim = tq("helpdesk_cases.claim", `
		UPDATE helpdesk_cases SET status = 'executing', executed_by = @by, error = '', updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status IN ('open','failed')`)
	helpdeskCaseFinish = tq("helpdesk_cases.finish", `
		UPDATE helpdesk_cases SET status = @status, executed_at = @executed_at, result = @result, error = @error,
			updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status = 'executing'`)
	helpdeskCaseCancel = tq("helpdesk_cases.cancel", `
		UPDATE helpdesk_cases SET status = 'cancelled', updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND status IN ('open','failed')`)

	helpdeskVerificationInsert = tq("helpdesk_verifications.insert", `
		INSERT INTO helpdesk_verifications (id, tenant_id, case_id, method, outcome, phishing_resistant, verified_by,
			verified_by_user_id, evidence, provider, created_at)
		VALUES (@id, @tenant, @case_id, @method, @outcome, @phishing_resistant, @verified_by, @verified_by_user_id,
			@evidence, @provider, @now)`)
	helpdeskVerificationsByCase = tq("helpdesk_verifications.by_case", `
		SELECT `+helpdeskVerificationCols+` FROM helpdesk_verifications v
		WHERE v.tenant_id = @tenant AND v.case_id = @case_id ORDER BY v.created_at, v.id`)

	helpdeskSignalInsert = tq("helpdesk_signals.insert", `
		INSERT INTO helpdesk_signals (id, tenant_id, identity_id, kind, location, device, source, occurred_at, created_at)
		VALUES (@id, @tenant, @identity_id, @kind, @location, @device, @source, @occurred_at, @now)`)
	helpdeskSignalsFor = tq("helpdesk_signals.for_identity", `
		SELECT `+helpdeskSignalCols+` FROM helpdesk_signals s
		WHERE s.tenant_id = @tenant AND s.identity_id = @identity_id ORDER BY s.occurred_at, s.id`)

	helpdeskFindingInsert = tq("helpdesk_findings.insert", `
		INSERT INTO helpdesk_findings (id, tenant_id, case_id, identity_id, rule, detail, created_at)
		VALUES (@id, @tenant, @case_id, @identity_id, @rule, @detail, @now)
		ON CONFLICT (tenant_id, case_id, rule) DO NOTHING`)
	helpdeskFindingList = tq("helpdesk_findings.list", `
		SELECT `+helpdeskFindingCols+` FROM helpdesk_findings f WHERE f.tenant_id = @tenant
		ORDER BY f.created_at DESC, f.id LIMIT 200`)
	helpdeskFindingsByCase = tq("helpdesk_findings.by_case", `
		SELECT `+helpdeskFindingCols+` FROM helpdesk_findings f
		WHERE f.tenant_id = @tenant AND f.case_id = @case_id ORDER BY f.created_at, f.id`)

	// Whether the identity's platform user holds a Tessera admin role (the
	// other half of "privileged"; privileged grants come from the graph).
	helpdeskAdminRole = tq("helpdesk.identity_admin_role", `
		SELECT EXISTS (SELECT 1 FROM platform_users u
		    JOIN role_assignments r ON r.tenant_id = u.tenant_id AND r.user_id = u.id
		    WHERE u.tenant_id = @tenant AND r.tenant_id = @tenant AND u.identity_id = @identity_id
		      AND r.role IN ('policy_admin','tenant_admin','break_glass')
		      AND (r.expires_at IS NULL OR r.expires_at > @now))`)
	// The platform user linked to an identity (a manager approving, a subject
	// approving themselves).
	helpdeskUserForIdentity = tq("helpdesk.users_for_identity", `
		SELECT u.id FROM platform_users u WHERE u.tenant_id = @tenant AND u.identity_id = @identity_id ORDER BY u.id`)
)

func uuidArg(u *uuid.UUID) any {
	if u == nil || *u == uuid.Nil {
		return nil
	}
	return u.String()
}

func scanHelpdeskCase(s scanner) (*HelpdeskCase, error) {
	var c HelpdeskCase
	var reqUser, secUser, secBy, execBy, secAt, execAt sql.NullString
	var created, updated string
	if err := s.Scan(&c.ID, &c.IdentityID, &c.Kind, &c.System, &c.Reason, &c.Status, &c.Privileged, &c.RequestedBy,
		&reqUser, &secBy, &secUser, &secAt, &execBy, &execAt, &c.Result, &c.Error, &created, &updated); err != nil {
		return nil, err
	}
	var err error
	if c.RequestedByUserID, err = uuidp(reqUser); err != nil {
		return nil, err
	}
	if c.SecondApproverUserID, err = uuidp(secUser); err != nil {
		return nil, err
	}
	c.SecondApprover, c.ExecutedBy = strp(secBy), strp(execBy)
	if c.SecondApprovedAt, err = rtp(secAt); err != nil {
		return nil, err
	}
	if c.ExecutedAt, err = rtp(execAt); err != nil {
		return nil, err
	}
	if c.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	c.UpdatedAt, err = ParseRT(updated)
	return &c, err
}

func scanHelpdeskVerification(s scanner) (*HelpdeskVerification, error) {
	var v HelpdeskVerification
	var by sql.NullString
	var at string
	if err := s.Scan(&v.ID, &v.CaseID, &v.Method, &v.Outcome, &v.PhishingResistant, &v.VerifiedBy, &by, &v.Evidence,
		&v.Provider, &at); err != nil {
		return nil, err
	}
	var err error
	if v.VerifiedByUserID, err = uuidp(by); err != nil {
		return nil, err
	}
	v.CreatedAt, err = ParseRT(at)
	return &v, err
}

func scanHelpdeskSignal(s scanner) (*HelpdeskSignal, error) {
	var g HelpdeskSignal
	var occ, created string
	if err := s.Scan(&g.ID, &g.IdentityID, &g.Kind, &g.Location, &g.Device, &g.Source, &occ, &created); err != nil {
		return nil, err
	}
	var err error
	if g.OccurredAt, err = ParseRT(occ); err != nil {
		return nil, err
	}
	g.CreatedAt, err = ParseRT(created)
	return &g, err
}

func scanHelpdeskFinding(s scanner) (*HelpdeskFinding, error) {
	var f HelpdeskFinding
	var at string
	if err := s.Scan(&f.ID, &f.CaseID, &f.IdentityID, &f.Rule, &f.Detail, &at); err != nil {
		return nil, err
	}
	var err error
	f.CreatedAt, err = ParseRT(at)
	return &f, err
}

// InsertHelpdeskCase opens a case (c.ID is set when empty; status is open).
func (tx *TenantTx) InsertHelpdeskCase(c *HelpdeskCase, now time.Time) error {
	if c.ID == "" {
		c.ID = NewID()
	}
	_, err := tx.exec(helpdeskCaseInsert, sql.Named("id", c.ID), sql.Named("identity_id", c.IdentityID),
		sql.Named("kind", c.Kind), sql.Named("system", c.System), sql.Named("reason", c.Reason),
		sql.Named("privileged", B(c.Privileged)), sql.Named("requested_by", c.RequestedBy),
		sql.Named("requested_by_user_id", uuidArg(c.RequestedByUserID)), sql.Named("now", RT(now)))
	return err
}

// HelpdeskCase returns one case or ErrNotFound.
func (tx *TenantTx) HelpdeskCase(id string) (*HelpdeskCase, error) {
	return one(tx, scanHelpdeskCase, helpdeskCaseGet, sql.Named("id", id))
}

// HelpdeskCases lists the newest cases first (at most 200).
func (tx *TenantTx) HelpdeskCases() ([]*HelpdeskCase, error) {
	return collect(tx, scanHelpdeskCase, helpdeskCaseList)
}

// HelpdeskCasesExecutedSince lists an identity's executed cases whose reset ran at or after since.
func (tx *TenantTx) HelpdeskCasesExecutedSince(identityID int64, since time.Time) ([]*HelpdeskCase, error) {
	return collect(tx, scanHelpdeskCase, helpdeskCaseExecutedSince, sql.Named("identity_id", identityID),
		sql.Named("since", RT(since)))
}

// SetHelpdeskSecondApproval records the second approver (ErrNotFound when the
// case is closed or already has one).
func (tx *TenantTx) SetHelpdeskSecondApproval(id string, by UserRef, now time.Time) error {
	return tx.execOne(helpdeskCaseSecondApprove, sql.Named("id", id), sql.Named("by", by.Display),
		sql.Named("by_user_id", by.idOrNil()), sql.Named("now", RT(now)))
}

// ClaimHelpdeskCase moves an open or failed case to executing. It is the
// single-flight guard: ErrNotFound when another request already claimed it.
func (tx *TenantTx) ClaimHelpdeskCase(id, by string, now time.Time) error {
	return tx.execOne(helpdeskCaseClaim, sql.Named("id", id), sql.Named("by", by), sql.Named("now", RT(now)))
}

// FinishHelpdeskCase records the outcome of an executing case (status executed or failed).
func (tx *TenantTx) FinishHelpdeskCase(id, status string, at time.Time, result, errText string) error {
	return tx.execOne(helpdeskCaseFinish, sql.Named("id", id), sql.Named("status", status),
		sql.Named("executed_at", RTP(&at)), sql.Named("result", result), sql.Named("error", errText),
		sql.Named("now", RT(at)))
}

// CancelHelpdeskCase closes an open or failed case without running it.
func (tx *TenantTx) CancelHelpdeskCase(id string, now time.Time) error {
	return tx.execOne(helpdeskCaseCancel, sql.Named("id", id), sql.Named("now", RT(now)))
}

// InsertHelpdeskVerification appends a verification attempt (v.ID set when empty).
func (tx *TenantTx) InsertHelpdeskVerification(v *HelpdeskVerification, now time.Time) error {
	if v.ID == "" {
		v.ID = NewID()
	}
	_, err := tx.exec(helpdeskVerificationInsert, sql.Named("id", v.ID), sql.Named("case_id", v.CaseID),
		sql.Named("method", v.Method), sql.Named("outcome", v.Outcome),
		sql.Named("phishing_resistant", B(v.PhishingResistant)), sql.Named("verified_by", v.VerifiedBy),
		sql.Named("verified_by_user_id", uuidArg(v.VerifiedByUserID)), sql.Named("evidence", v.Evidence),
		sql.Named("provider", v.Provider), sql.Named("now", RT(now)))
	return err
}

// HelpdeskVerifications lists a case's attempts, oldest first.
func (tx *TenantTx) HelpdeskVerifications(caseID string) ([]*HelpdeskVerification, error) {
	return collect(tx, scanHelpdeskVerification, helpdeskVerificationsByCase, sql.Named("case_id", caseID))
}

// InsertHelpdeskSignal records post-reset telemetry (g.ID set when empty).
func (tx *TenantTx) InsertHelpdeskSignal(g *HelpdeskSignal, now time.Time) error {
	if g.ID == "" {
		g.ID = NewID()
	}
	_, err := tx.exec(helpdeskSignalInsert, sql.Named("id", g.ID), sql.Named("identity_id", g.IdentityID),
		sql.Named("kind", g.Kind), sql.Named("location", g.Location), sql.Named("device", g.Device),
		sql.Named("source", g.Source), sql.Named("occurred_at", RT(g.OccurredAt)), sql.Named("now", RT(now)))
	return err
}

// HelpdeskSignals lists an identity's signals, oldest first.
func (tx *TenantTx) HelpdeskSignals(identityID int64) ([]*HelpdeskSignal, error) {
	return collect(tx, scanHelpdeskSignal, helpdeskSignalsFor, sql.Named("identity_id", identityID))
}

// InsertHelpdeskFinding records a finding; it reports false when the case
// already has one for the rule.
func (tx *TenantTx) InsertHelpdeskFinding(f *HelpdeskFinding, now time.Time) (bool, error) {
	if f.ID == "" {
		f.ID = NewID()
	}
	res, err := tx.exec(helpdeskFindingInsert, sql.Named("id", f.ID), sql.Named("case_id", f.CaseID),
		sql.Named("identity_id", f.IdentityID), sql.Named("rule", f.Rule), sql.Named("detail", f.Detail),
		sql.Named("now", RT(now)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// HelpdeskFindings lists the newest findings first (at most 200).
func (tx *TenantTx) HelpdeskFindings() ([]*HelpdeskFinding, error) {
	return collect(tx, scanHelpdeskFinding, helpdeskFindingList)
}

// HelpdeskFindingsForCase lists a case's findings.
func (tx *TenantTx) HelpdeskFindingsForCase(caseID string) ([]*HelpdeskFinding, error) {
	return collect(tx, scanHelpdeskFinding, helpdeskFindingsByCase, sql.Named("case_id", caseID))
}

// IdentityHoldsAdminRole reports whether a platform user linked to the
// identity holds a live Tessera admin role at now.
func (tx *TenantTx) IdentityHoldsAdminRole(identityID int64, now time.Time) (bool, error) {
	var admin bool
	err := tx.queryRow(helpdeskAdminRole, sql.Named("identity_id", identityID), sql.Named("now", RT(now))).Scan(&admin)
	return admin, err
}

// PlatformUserIDsForIdentity lists the platform users linked to an identity.
func (tx *TenantTx) PlatformUserIDsForIdentity(identityID int64) ([]uuid.UUID, error) {
	rows, err := tx.query(helpdeskUserForIdentity, sql.Named("identity_id", identityID))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []uuid.UUID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
