package store

import (
	"database/sql"
	"errors"
	"time"
)

// AWS production shadow agreement (schema/0916_aws_shadow.sql, issue #641).
// Every statement binds the tenant.

// Shadow check verdicts and triage states.
const (
	AWSShadowAgree        = "agree"
	AWSShadowDisagree     = "disagree"
	AWSShadowInconclusive = "inconclusive"
	AWSShadowError        = "error"

	AWSTriageNone          = "none"
	AWSTriageOpen          = "open"
	AWSTriageInvestigating = "investigating"
	AWSTriageEngineBug     = "engine_bug"
	AWSTriageExpected      = "expected"
	AWSTriageResolved      = "resolved"

	// AWSShadowDefaultK is the daily sample size of a tenant that has not set one.
	AWSShadowDefaultK = 20
	AWSShadowMaxK     = 200
)

// AWSShadowSettings is a tenant's opt-in. A tenant with no row is off with the default K.
type AWSShadowSettings struct {
	Enabled   bool
	DailyK    int
	UpdatedBy string
	UpdatedAt time.Time
}

// AWSShadowCheck is one sampled decision compared with the simulator. A
// disagreement (Verdict "disagree") is a finding and carries a triage state.
type AWSShadowCheck struct {
	ID              string
	ConnectorID     string
	SnapshotID      string
	SampleDay       string
	PrincipalARN    string
	Action          string
	ResourceARN     string
	TesseraOutcome  string // allow or deny
	TesseraFidelity string
	ExplanationID   string
	AWSDecision     string
	Verdict         string
	Detail          string
	CheckedAt       time.Time
	TriageStatus    string
}

// AWSShadowTriageRecord is one triage step of a disagreement.
type AWSShadowTriageRecord struct {
	ID        string
	CheckID   string
	Status    string
	Note      string
	Actor     string
	CreatedAt time.Time
}

// AWSShadowCounts are the checks of a period by verdict, and the disagreements still to triage.
type AWSShadowCounts struct {
	Agree, Disagree, Inconclusive, Error int
	OpenDisagreements                    int
	LastCheckedAt                        *time.Time
}

const awsShadowCols = `c.id, c.connector_id, c.snapshot_id, c.sample_day, c.principal_arn, c.action, c.resource_arn, c.tessera_outcome,
	c.tessera_fidelity, c.explanation_id, c.aws_decision, c.verdict, c.detail, c.checked_at, c.triage_status`

var (
	awsShadowSettingsGet = tq("aws_shadow_settings.get", `
		SELECT s.enabled, s.daily_k, s.updated_by, s.updated_at FROM aws_shadow_settings s WHERE s.tenant_id = @tenant`)
	awsShadowSettingsPut = tq("aws_shadow_settings.put", `
		INSERT INTO aws_shadow_settings (tenant_id, enabled, daily_k, updated_by, updated_at)
		VALUES (@tenant, @enabled, @daily_k, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET enabled = excluded.enabled, daily_k = excluded.daily_k,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
	awsShadowEnabled = tq("aws_shadow_settings.enabled", `
		SELECT COUNT(*) FROM aws_shadow_settings s WHERE s.tenant_id = @tenant AND s.enabled = 1`)
	awsShadowInsert = tq("aws_shadow_checks.insert", `
		INSERT INTO aws_shadow_checks (tenant_id, id, connector_id, snapshot_id, sample_day, principal_arn, action, resource_arn,
			tessera_outcome, tessera_fidelity, explanation_id, aws_decision, verdict, detail, checked_at, triage_status)
		VALUES (@tenant, @id, @connector_id, @snapshot_id, @sample_day, @principal_arn, @action, @resource_arn,
			@tessera_outcome, @tessera_fidelity, @explanation_id, @aws_decision, @verdict, @detail, @checked_at, @triage_status)`)
	awsShadowGet = tq("aws_shadow_checks.get", `
		SELECT `+awsShadowCols+` FROM aws_shadow_checks c WHERE c.tenant_id = @tenant AND c.id = @id`)
	awsShadowList = tq("aws_shadow_checks.list", `
		SELECT `+awsShadowCols+` FROM aws_shadow_checks c
		WHERE c.tenant_id = @tenant AND (@verdict = '' OR c.verdict = @verdict) AND (@triage = '' OR c.triage_status = @triage)
		ORDER BY c.checked_at DESC, c.id DESC LIMIT @limit`)
	awsShadowOnDay = tq("aws_shadow_checks.on_day", `
		SELECT COUNT(*) FROM aws_shadow_checks c WHERE c.tenant_id = @tenant AND c.sample_day = @day`)
	awsShadowTriageSet = tq("aws_shadow_checks.triage", `
		UPDATE aws_shadow_checks SET triage_status = @status
		WHERE tenant_id = @tenant AND id = @id AND verdict = 'disagree'`)
	awsShadowByVerdict = tq("aws_shadow_checks.by_verdict", `
		SELECT c.verdict, COUNT(*) FROM aws_shadow_checks c
		WHERE c.tenant_id = @tenant AND c.checked_at >= @since GROUP BY c.verdict`)
	awsShadowOpen = tq("aws_shadow_checks.open", `
		SELECT COUNT(*) FROM aws_shadow_checks c
		WHERE c.tenant_id = @tenant AND c.verdict = 'disagree' AND c.triage_status IN ('open', 'investigating')`)
	awsShadowLast = tq("aws_shadow_checks.last", `
		SELECT MAX(c.checked_at) FROM aws_shadow_checks c WHERE c.tenant_id = @tenant`)
	awsShadowTriageInsert = tq("aws_shadow_triage.insert", `
		INSERT INTO aws_shadow_triage (tenant_id, id, check_id, status, note, actor, created_at)
		VALUES (@tenant, @id, @check_id, @status, @note, @actor, @created_at)`)
	awsShadowTriageList = tq("aws_shadow_triage.list", `
		SELECT t.id, t.check_id, t.status, t.note, t.actor, t.created_at FROM aws_shadow_triage t
		WHERE t.tenant_id = @tenant AND t.check_id = @check_id ORDER BY t.created_at, t.id`)
)

// AWSShadowSettings returns the tenant's opt-in. A tenant that never set it gets
// the off default and no error.
func (tx *TenantTx) AWSShadowSettings() (*AWSShadowSettings, error) {
	s, err := one(tx, func(r scanner) (*AWSShadowSettings, error) {
		var s AWSShadowSettings
		var enabled int
		var at string
		if err := r.Scan(&enabled, &s.DailyK, &s.UpdatedBy, &at); err != nil {
			return nil, err
		}
		s.Enabled = enabled == 1
		var err error
		s.UpdatedAt, err = ParseRT(at)
		return &s, err
	}, awsShadowSettingsGet)
	if errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		return &AWSShadowSettings{DailyK: AWSShadowDefaultK}, nil
	}
	return s, err
}

// PutAWSShadowSettings replaces the tenant's opt-in.
func (tx *TenantTx) PutAWSShadowSettings(s *AWSShadowSettings, now time.Time) error {
	enabled := 0
	if s.Enabled {
		enabled = 1
	}
	_, err := tx.exec(awsShadowSettingsPut, sql.Named("enabled", enabled), sql.Named("daily_k", s.DailyK),
		sql.Named("updated_by", s.UpdatedBy), sql.Named("updated_at", RT(now)))
	return err
}

// AWSShadowEnabled reports whether the tenant has opted in.
func (tx *TenantTx) AWSShadowEnabled() (bool, error) {
	n, err := tx.count(awsShadowEnabled)
	return n > 0, err
}

// InsertAWSShadowCheck records one comparison. A disagreement starts open.
func (tx *TenantTx) InsertAWSShadowCheck(c *AWSShadowCheck) error {
	triage := AWSTriageNone
	if c.Verdict == AWSShadowDisagree {
		triage = AWSTriageOpen
	}
	c.TriageStatus = triage
	_, err := tx.exec(awsShadowInsert, sql.Named("id", c.ID), sql.Named("connector_id", c.ConnectorID),
		sql.Named("snapshot_id", c.SnapshotID), sql.Named("sample_day", c.SampleDay), sql.Named("principal_arn", c.PrincipalARN),
		sql.Named("action", c.Action), sql.Named("resource_arn", c.ResourceARN), sql.Named("tessera_outcome", c.TesseraOutcome),
		sql.Named("tessera_fidelity", c.TesseraFidelity), sql.Named("explanation_id", c.ExplanationID),
		sql.Named("aws_decision", c.AWSDecision), sql.Named("verdict", c.Verdict), sql.Named("detail", c.Detail),
		sql.Named("checked_at", RT(c.CheckedAt)), sql.Named("triage_status", triage))
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

func scanAWSShadowCheck(s scanner) (*AWSShadowCheck, error) {
	var c AWSShadowCheck
	var at string
	if err := s.Scan(&c.ID, &c.ConnectorID, &c.SnapshotID, &c.SampleDay, &c.PrincipalARN, &c.Action, &c.ResourceARN,
		&c.TesseraOutcome, &c.TesseraFidelity, &c.ExplanationID, &c.AWSDecision, &c.Verdict, &c.Detail, &at, &c.TriageStatus); err != nil {
		return nil, err
	}
	var err error
	c.CheckedAt, err = ParseRT(at)
	return &c, err
}

// AWSShadowCheck returns one check, or ErrNotFound.
func (tx *TenantTx) AWSShadowCheck(id string) (*AWSShadowCheck, error) {
	return one(tx, scanAWSShadowCheck, awsShadowGet, sql.Named("id", id))
}

// AWSShadowChecks lists checks newest first. verdict and triage "" match every
// value; limit <= 0 or above 500 is 100.
func (tx *TenantTx) AWSShadowChecks(verdict, triage string, limit int) ([]*AWSShadowCheck, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return collect(tx, scanAWSShadowCheck, awsShadowList, sql.Named("verdict", verdict), sql.Named("triage", triage),
		sql.Named("limit", limit))
}

// AWSShadowSampledOn is how many checks count against the UTC day (YYYY-MM-DD).
func (tx *TenantTx) AWSShadowSampledOn(day string) (int, error) {
	return tx.count(awsShadowOnDay, sql.Named("day", day))
}

// TriageAWSShadowCheck moves a disagreement to a triage state and records the
// step. ErrNotFound: no such check, or it is not a disagreement.
func (tx *TenantTx) TriageAWSShadowCheck(id, status, note, actor string, now time.Time) error {
	if err := tx.affectOne(awsShadowTriageSet, sql.Named("id", id), sql.Named("status", status)); err != nil {
		return err
	}
	_, err := tx.exec(awsShadowTriageInsert, sql.Named("id", NewID()), sql.Named("check_id", id), sql.Named("status", status),
		sql.Named("note", note), sql.Named("actor", actor), sql.Named("created_at", RT(now)))
	return err
}

// AWSShadowTriage lists the triage steps of a check, oldest first.
func (tx *TenantTx) AWSShadowTriage(checkID string) ([]*AWSShadowTriageRecord, error) {
	return collect(tx, func(s scanner) (*AWSShadowTriageRecord, error) {
		var r AWSShadowTriageRecord
		var at string
		if err := s.Scan(&r.ID, &r.CheckID, &r.Status, &r.Note, &r.Actor, &at); err != nil {
			return nil, err
		}
		var err error
		r.CreatedAt, err = ParseRT(at)
		return &r, err
	}, awsShadowTriageList, sql.Named("check_id", checkID))
}

// AWSShadowCounts counts the checks made at or after since by verdict, plus the
// disagreements still open or under investigation (of any age) and the time of the latest check.
func (tx *TenantTx) AWSShadowCounts(since time.Time) (*AWSShadowCounts, error) {
	out := &AWSShadowCounts{}
	rows, err := tx.query(awsShadowByVerdict, sql.Named("since", RT(since)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}
		switch v {
		case AWSShadowAgree:
			out.Agree = n
		case AWSShadowDisagree:
			out.Disagree = n
		case AWSShadowInconclusive:
			out.Inconclusive = n
		case AWSShadowError:
			out.Error = n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out.OpenDisagreements, err = tx.count(awsShadowOpen); err != nil {
		return nil, err
	}
	var last sql.NullString
	if err := tx.queryRow(awsShadowLast).Scan(&last); err != nil {
		return nil, err
	}
	if out.LastCheckedAt, err = rtp(last); err != nil {
		return nil, err
	}
	return out, nil
}
