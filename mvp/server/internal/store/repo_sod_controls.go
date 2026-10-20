package store

import (
	"database/sql"
	"time"
)

// Mitigating controls, mitigations, remediation options and escalations for SoD
// violations (schema/0301_sod_controls.sql, issue #298).

// Control types, frequencies and mitigation kinds and statuses.
const (
	MitigationControl = "control"
	MitigationAccept  = "accept"

	MitigationPending   = "pending"
	MitigationActive    = "active"
	MitigationRejected  = "rejected"
	MitigationCancelled = "cancelled"
	MitigationExpired   = "expired"
	MitigationRevoked   = "revoked"
)

// SodControl is one control of the library.
type SodControl struct {
	ID                  string
	Name                string
	Description         string
	OwnerID             *int64
	Type                string
	Frequency           string
	EvidenceRequirement string
	Status              string
	Version             int
	CreatedAt           time.Time
	UpdatedBy           *string
	UpdatedAt           time.Time
}

// SodMitigation covers one identity's violation of one risk for a while.
type SodMitigation struct {
	ID            string
	RiskID        string
	IdentityID    int64
	Kind          string
	ControlID     *string
	Justification string
	Evidence      string // JSON list of references
	Status        string
	StartsAt      *time.Time
	EndsAt        time.Time
	RequestedBy   string
	RequestedAt   time.Time
	DecidedBy     *string
	DecidedAt     *time.Time
	DecisionNote  *string
	RevokedBy     *string
	RevokeReason  *string
	WarnedAt      *time.Time
	ClosedAt      *time.Time
}

// SodRiskOption is one remediation option a risk offers.
type SodRiskOption struct {
	RiskID string
	Option string
}

// SodEscalation is a violation sent to the risk owner.
type SodEscalation struct {
	ID          string
	RiskID      string
	IdentityID  int64
	EscalatedBy string
	Note        string
	CreatedAt   time.Time
}

const (
	scCols = `c.id, c.name, c.description, c.owner_identity_id, c.type, c.frequency, c.evidence_requirement, c.status,
		c.version, c.created_at, c.updated_by, c.updated_at`
	smCols = `m.id, m.risk_id, m.identity_id, m.kind, m.control_id, m.justification, m.evidence, m.status, m.starts_at,
		m.ends_at, m.requested_by, m.requested_at, m.decided_by, m.decided_at, m.decision_note, m.revoked_by,
		m.revoke_reason, m.warned_at, m.closed_at`
)

var (
	scList   = tq("sod_controls.list", `SELECT `+scCols+` FROM sod_controls c WHERE c.tenant_id = @tenant ORDER BY c.name, c.id`)
	scGet    = tq("sod_controls.get", `SELECT `+scCols+` FROM sod_controls c WHERE c.tenant_id = @tenant AND c.id = @id`)
	scByName = tq("sod_controls.by_name", `SELECT `+scCols+` FROM sod_controls c WHERE c.tenant_id = @tenant AND c.name = @name`)
	scInsert = tq("sod_controls.insert", `
		INSERT INTO sod_controls (id, tenant_id, name, description, owner_identity_id, type, frequency, evidence_requirement,
			status, version, created_at, updated_by, updated_at)
		VALUES (@id, @tenant, @name, @description, @owner, @type, @frequency, @evidence_requirement, @status, @version,
			@created_at, @updated_by, @updated_at)`)
	scSave = tq("sod_controls.save", `
		UPDATE sod_controls SET name = @name, description = @description, owner_identity_id = @owner, type = @type,
			frequency = @frequency, evidence_requirement = @evidence_requirement, status = @status, version = @version,
			updated_by = @updated_by, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id AND version = @from_version`)

	smList = tq("sod_mitigations.list", `
		SELECT `+smCols+` FROM sod_mitigations m WHERE m.tenant_id = @tenant ORDER BY m.requested_at DESC, m.id`)
	smGet  = tq("sod_mitigations.get", `SELECT `+smCols+` FROM sod_mitigations m WHERE m.tenant_id = @tenant AND m.id = @id`)
	smLive = tq("sod_mitigations.live_for", `
		SELECT `+smCols+` FROM sod_mitigations m
		WHERE m.tenant_id = @tenant AND m.risk_id = @risk_id AND m.identity_id = @identity_id AND m.status IN ('pending','active')`)
	smInsert = tq("sod_mitigations.insert", `
		INSERT INTO sod_mitigations (id, tenant_id, risk_id, identity_id, kind, control_id, justification, evidence, status,
			starts_at, ends_at, requested_by, requested_at, decided_by, decided_at, decision_note, revoked_by, revoke_reason,
			warned_at, closed_at)
		VALUES (@id, @tenant, @risk_id, @identity_id, @kind, @control_id, @justification, @evidence, @status, @starts_at,
			@ends_at, @requested_by, @requested_at, @decided_by, @decided_at, @decision_note, @revoked_by, @revoke_reason,
			@warned_at, @closed_at)`)
	smSave = tq("sod_mitigations.save", `
		UPDATE sod_mitigations SET status = @status, starts_at = @starts_at, decided_by = @decided_by, decided_at = @decided_at,
			decision_note = @decision_note, revoked_by = @revoked_by, revoke_reason = @revoke_reason, warned_at = @warned_at,
			closed_at = @closed_at
		WHERE tenant_id = @tenant AND id = @id AND status = @from_status`)

	sroList = tq("sod_risk_options.list", `
		SELECT o.risk_id, o.remediation FROM sod_risk_options o WHERE o.tenant_id = @tenant ORDER BY o.risk_id, o.remediation`)
	sroDelete = tq("sod_risk_options.delete_for_risk", `
		DELETE FROM sod_risk_options WHERE tenant_id = @tenant AND risk_id = @risk_id`)
	sroInsert = tq("sod_risk_options.insert", `
		INSERT INTO sod_risk_options (tenant_id, risk_id, remediation) VALUES (@tenant, @risk_id, @remediation)`)

	seList = tq("sod_escalations.list", `
		SELECT e.id, e.risk_id, e.identity_id, e.escalated_by, e.note, e.created_at FROM sod_escalations e
		WHERE e.tenant_id = @tenant ORDER BY e.created_at DESC, e.id`)
	seInsert = tq("sod_escalations.insert", `
		INSERT INTO sod_escalations (id, tenant_id, risk_id, identity_id, escalated_by, note, created_at)
		VALUES (@id, @tenant, @risk_id, @identity_id, @escalated_by, @note, @created_at)`)
)

func scanSodControl(s scanner) (*SodControl, error) {
	var c SodControl
	var owner sql.NullInt64
	var by sql.NullString
	var created, updated nullTime
	if err := s.Scan(&c.ID, &c.Name, &c.Description, &owner, &c.Type, &c.Frequency, &c.EvidenceRequirement, &c.Status,
		&c.Version, &created, &by, &updated); err != nil {
		return nil, err
	}
	c.OwnerID, c.UpdatedBy = intp(owner), strp(by)
	var err error
	if c.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	c.UpdatedAt, err = updated.val()
	return &c, err
}

func scanSodMitigation(s scanner) (*SodMitigation, error) {
	var m SodMitigation
	var ctrl, decBy, note, revBy, revWhy sql.NullString
	var starts, requested, ends, decAt, warned, closed nullTime
	if err := s.Scan(&m.ID, &m.RiskID, &m.IdentityID, &m.Kind, &ctrl, &m.Justification, &m.Evidence, &m.Status, &starts, &ends,
		&m.RequestedBy, &requested, &decBy, &decAt, &note, &revBy, &revWhy, &warned, &closed); err != nil {
		return nil, err
	}
	m.ControlID, m.DecidedBy, m.DecisionNote, m.RevokedBy, m.RevokeReason = strp(ctrl), strp(decBy), strp(note), strp(revBy), strp(revWhy)
	var err error
	if m.StartsAt, err = starts.ptr(); err != nil {
		return nil, err
	}
	if m.EndsAt, err = ends.val(); err != nil {
		return nil, err
	}
	if m.RequestedAt, err = requested.val(); err != nil {
		return nil, err
	}
	if m.DecidedAt, err = decAt.ptr(); err != nil {
		return nil, err
	}
	if m.WarnedAt, err = warned.ptr(); err != nil {
		return nil, err
	}
	m.ClosedAt, err = closed.ptr()
	return &m, err
}

// SodControls returns the control library, by name.
func (tx *TenantTx) SodControls() ([]*SodControl, error) { return collect(tx, scanSodControl, scList) }

// SodControl returns one control, or ErrNotFound.
func (tx *TenantTx) SodControl(id string) (*SodControl, error) {
	return one(tx, scanSodControl, scGet, sql.Named("id", id))
}

// SodControlByName returns the control with the name, or ErrNotFound.
func (tx *TenantTx) SodControlByName(name string) (*SodControl, error) {
	return one(tx, scanSodControl, scByName, sql.Named("name", name))
}

func sodControlArgs(c *SodControl) []sql.NamedArg {
	return []sql.NamedArg{sql.Named("id", c.ID), sql.Named("name", c.Name), sql.Named("description", c.Description),
		sql.Named("owner", IP(c.OwnerID)), sql.Named("type", c.Type), sql.Named("frequency", c.Frequency),
		sql.Named("evidence_requirement", c.EvidenceRequirement), sql.Named("status", c.Status), sql.Named("version", c.Version),
		sql.Named("updated_by", SP(c.UpdatedBy)), sql.Named("updated_at", T(c.UpdatedAt))}
}

// InsertSodControl creates a control.
func (tx *TenantTx) InsertSodControl(c *SodControl) error {
	_, err := tx.exec(scInsert, append(sodControlArgs(c), sql.Named("created_at", T(c.CreatedAt)))...)
	return err
}

// SaveSodControl updates a control still at version from; ErrNotFound if it moved on.
func (tx *TenantTx) SaveSodControl(c *SodControl, from int) error {
	return saved(tx.exec(scSave, append(sodControlArgs(c), sql.Named("from_version", from))...))
}

// SodMitigations returns every mitigation, newest request first.
func (tx *TenantTx) SodMitigations() ([]*SodMitigation, error) {
	return collect(tx, scanSodMitigation, smList)
}

// SodMitigation returns one mitigation, or ErrNotFound.
func (tx *TenantTx) SodMitigation(id string) (*SodMitigation, error) {
	return one(tx, scanSodMitigation, smGet, sql.Named("id", id))
}

// LiveSodMitigation returns the pending or active mitigation of an identity's
// violation of a risk, or ErrNotFound.
func (tx *TenantTx) LiveSodMitigation(riskID string, identityID int64) (*SodMitigation, error) {
	return one(tx, scanSodMitigation, smLive, sql.Named("risk_id", riskID), sql.Named("identity_id", identityID))
}

// InsertSodMitigation records a new mitigation.
func (tx *TenantTx) InsertSodMitigation(m *SodMitigation) error {
	_, err := tx.exec(smInsert, sql.Named("id", m.ID), sql.Named("risk_id", m.RiskID), sql.Named("identity_id", m.IdentityID),
		sql.Named("kind", m.Kind), sql.Named("control_id", SP(m.ControlID)), sql.Named("justification", m.Justification),
		sql.Named("evidence", m.Evidence), sql.Named("status", m.Status), sql.Named("starts_at", TP(m.StartsAt)),
		sql.Named("ends_at", T(m.EndsAt)), sql.Named("requested_by", m.RequestedBy), sql.Named("requested_at", T(m.RequestedAt)),
		sql.Named("decided_by", SP(m.DecidedBy)), sql.Named("decided_at", TP(m.DecidedAt)), sql.Named("decision_note", SP(m.DecisionNote)),
		sql.Named("revoked_by", SP(m.RevokedBy)), sql.Named("revoke_reason", SP(m.RevokeReason)), sql.Named("warned_at", TP(m.WarnedAt)),
		sql.Named("closed_at", TP(m.ClosedAt)))
	return err
}

// SaveSodMitigation writes a mitigation's decision, revocation and warning
// fields if it is still in status from; ErrNotFound if it moved on.
func (tx *TenantTx) SaveSodMitigation(m *SodMitigation, from string) error {
	return saved(tx.exec(smSave, sql.Named("id", m.ID), sql.Named("status", m.Status), sql.Named("starts_at", TP(m.StartsAt)),
		sql.Named("decided_by", SP(m.DecidedBy)), sql.Named("decided_at", TP(m.DecidedAt)), sql.Named("decision_note", SP(m.DecisionNote)),
		sql.Named("revoked_by", SP(m.RevokedBy)), sql.Named("revoke_reason", SP(m.RevokeReason)), sql.Named("warned_at", TP(m.WarnedAt)),
		sql.Named("closed_at", TP(m.ClosedAt)), sql.Named("from_status", from)))
}

// SodRiskOptions returns every explicit remediation option, by risk.
func (tx *TenantTx) SodRiskOptions() ([]*SodRiskOption, error) {
	return collect(tx, func(s scanner) (*SodRiskOption, error) {
		var o SodRiskOption
		err := s.Scan(&o.RiskID, &o.Option)
		return &o, err
	}, sroList)
}

// SetSodRiskOptions replaces a risk's remediation options (none: all four).
func (tx *TenantTx) SetSodRiskOptions(riskID string, options []string) error {
	if _, err := tx.exec(sroDelete, sql.Named("risk_id", riskID)); err != nil {
		return err
	}
	for _, o := range options {
		if _, err := tx.exec(sroInsert, sql.Named("risk_id", riskID), sql.Named("remediation", o)); err != nil {
			return err
		}
	}
	return nil
}

// SodEscalations returns every escalation, newest first.
func (tx *TenantTx) SodEscalations() ([]*SodEscalation, error) {
	return collect(tx, func(s scanner) (*SodEscalation, error) {
		var e SodEscalation
		var at nullTime
		if err := s.Scan(&e.ID, &e.RiskID, &e.IdentityID, &e.EscalatedBy, &e.Note, &at); err != nil {
			return nil, err
		}
		var err error
		e.CreatedAt, err = at.val()
		return &e, err
	}, seList)
}

// InsertSodEscalation records an escalation.
func (tx *TenantTx) InsertSodEscalation(e *SodEscalation) error {
	_, err := tx.exec(seInsert, sql.Named("id", e.ID), sql.Named("risk_id", e.RiskID), sql.Named("identity_id", e.IdentityID),
		sql.Named("escalated_by", e.EscalatedBy), sql.Named("note", e.Note), sql.Named("created_at", T(e.CreatedAt)))
	return err
}
