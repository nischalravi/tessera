package store

import (
	"database/sql"
	"time"
)

// Vendor breach response plans (schema/0800_breach_response.sql, issue #475).
// A plan and its items only reference credentials by id and label; no secret
// material is held. Doing the work is internal/rotation and internal/oauthapps.

// Breach plan statuses.
const (
	BreachPlanned   = "planned"
	BreachRunning   = "running"
	BreachCompleted = "completed"
)

// Breach item kinds, actions and states.
const (
	BreachKindSecret         = "secret"
	BreachKindOAuthGrant     = "oauth_grant"
	BreachKindGitHubToken    = "github_token" // #nosec G101 -- the name of a credential kind, not a credential
	BreachKindServiceAccount = "service_account"

	BreachActionRotate = "rotate"
	BreachActionRevoke = "revoke"
	BreachActionManual = "manual"

	BreachPending    = "pending"
	BreachInProgress = "in_progress"
	BreachVerified   = "verified"
	BreachAttested   = "attested"
	BreachFailed     = "failed"
)

// BreachPlan is the tracked response to one vendor breach.
type BreachPlan struct {
	ID          string
	Vendor      string
	Reason      string
	Status      string
	BulkID      *string
	CreatedBy   string
	CreatedAt   time.Time
	StartedBy   *string
	StartedAt   *time.Time
	CompletedAt *time.Time
	Report      *string // JSON, set on completion
}

// BreachItem is one credential of a plan.
type BreachItem struct {
	ID           string
	PlanID       string
	Kind         string
	Ref          string
	Label        string
	Action       string
	State        string
	Detail       string
	Verification *string // JSON of the re-read
	VerifiedAt   *time.Time
	AttestedBy   *string
	AttestedNote *string
	UpdatedAt    time.Time
}

const breachPlanCols = `p.id, p.vendor, p.reason, p.status, p.bulk_id, p.created_by, p.created_at, p.started_by, p.started_at,
	p.completed_at, p.report`

const breachItemCols = `i.id, i.plan_id, i.kind, i.ref, i.label, i.action, i.state, i.detail, i.verification, i.verified_at,
	i.attested_by, i.attested_note, i.updated_at`

var (
	breachPlansInsert = tq("breach_plans.insert", `
		INSERT INTO breach_plans (id, tenant_id, vendor, reason, status, created_by, created_at)
		VALUES (@id, @tenant, @vendor, @reason, 'planned', @created_by, @created_at)`)
	breachPlansList = tq("breach_plans.list", `
		SELECT `+breachPlanCols+` FROM breach_plans p WHERE p.tenant_id = @tenant ORDER BY p.created_at DESC, p.id`)
	breachPlansGet = tq("breach_plans.get", `
		SELECT `+breachPlanCols+` FROM breach_plans p WHERE p.tenant_id = @tenant AND p.id = @id`)
	breachPlansStart = tq("breach_plans.start", `
		UPDATE breach_plans SET status = 'running', bulk_id = COALESCE(bulk_id, @bulk_id),
			started_by = COALESCE(started_by, @started_by), started_at = COALESCE(started_at, @started_at)
		WHERE tenant_id = @tenant AND id = @id AND status <> 'completed'`)
	breachPlansComplete = tq("breach_plans.complete", `
		UPDATE breach_plans SET status = 'completed', completed_at = @completed_at, report = @report
		WHERE tenant_id = @tenant AND id = @id AND status <> 'completed'`)
	breachItemsInsert = tq("breach_items.insert", `
		INSERT INTO breach_items (id, tenant_id, plan_id, kind, ref, label, action, state, detail, updated_at)
		VALUES (@id, @tenant, @plan_id, @kind, @ref, @label, @action, 'pending', @detail, @updated_at)
		ON CONFLICT (tenant_id, plan_id, kind, ref) DO NOTHING`)
	breachItemsList = tq("breach_items.list", `
		SELECT `+breachItemCols+` FROM breach_items i WHERE i.tenant_id = @tenant AND i.plan_id = @plan_id
		ORDER BY i.kind, i.label, i.id`)
	breachItemsGet = tq("breach_items.get", `
		SELECT `+breachItemCols+` FROM breach_items i WHERE i.tenant_id = @tenant AND i.plan_id = @plan_id AND i.id = @id`)
	breachItemsSet = tq("breach_items.set_state", `
		UPDATE breach_items SET state = @state, detail = @detail, verification = @verification, verified_at = @verified_at,
			updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id AND state <> 'attested'`)
	breachItemsAttest = tq("breach_items.attest", `
		UPDATE breach_items SET state = 'attested', attested_by = @attested_by, attested_note = @attested_note,
			detail = @detail, updated_at = @updated_at
		WHERE tenant_id = @tenant AND id = @id AND state <> 'verified'`)
)

func scanBreachPlan(s scanner) (*BreachPlan, error) {
	var p BreachPlan
	var created string
	var bulk, startedBy, started, completed, report sql.NullString
	if err := s.Scan(&p.ID, &p.Vendor, &p.Reason, &p.Status, &bulk, &p.CreatedBy, &created, &startedBy, &started, &completed, &report); err != nil {
		return nil, err
	}
	var err error
	if p.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	if p.StartedAt, err = rtp(started); err != nil {
		return nil, err
	}
	if p.CompletedAt, err = rtp(completed); err != nil {
		return nil, err
	}
	p.BulkID, p.StartedBy, p.Report = strp(bulk), strp(startedBy), strp(report)
	return &p, nil
}

func scanBreachItem(s scanner) (*BreachItem, error) {
	var i BreachItem
	var updated string
	var verification, verified, by, note sql.NullString
	if err := s.Scan(&i.ID, &i.PlanID, &i.Kind, &i.Ref, &i.Label, &i.Action, &i.State, &i.Detail, &verification, &verified,
		&by, &note, &updated); err != nil {
		return nil, err
	}
	var err error
	if i.VerifiedAt, err = rtp(verified); err != nil {
		return nil, err
	}
	if i.UpdatedAt, err = ParseRT(updated); err != nil {
		return nil, err
	}
	i.Verification, i.AttestedBy, i.AttestedNote = strp(verification), strp(by), strp(note)
	return &i, nil
}

// InsertBreachPlan records a new plan (status planned) and sets p.ID.
func (tx *TenantTx) InsertBreachPlan(p *BreachPlan) error {
	p.ID, p.Status = NewID(), BreachPlanned
	_, err := tx.exec(breachPlansInsert, sql.Named("id", p.ID), sql.Named("vendor", p.Vendor), sql.Named("reason", p.Reason),
		sql.Named("created_by", p.CreatedBy), sql.Named("created_at", RT(p.CreatedAt)))
	return err
}

// BreachPlans lists the tenant's plans, newest first.
func (tx *TenantTx) BreachPlans() ([]*BreachPlan, error) {
	return collect(tx, scanBreachPlan, breachPlansList)
}

// BreachPlan returns one plan or ErrNotFound.
func (tx *TenantTx) BreachPlan(id string) (*BreachPlan, error) {
	return one(tx, scanBreachPlan, breachPlansGet, sql.Named("id", id))
}

// StartBreachPlan marks the plan running and links its rotation bulk run (the
// first call that carries one wins). A completed plan is left alone.
func (tx *TenantTx) StartBreachPlan(id string, bulkID *string, by string, now time.Time) error {
	_, err := tx.exec(breachPlansStart, sql.Named("id", id), sql.Named("bulk_id", bulkID), sql.Named("started_by", by),
		sql.Named("started_at", RT(now)))
	return err
}

// CompleteBreachPlan marks the plan completed with its report (JSON).
func (tx *TenantTx) CompleteBreachPlan(id string, report string, now time.Time) error {
	_, err := tx.exec(breachPlansComplete, sql.Named("id", id), sql.Named("report", report), sql.Named("completed_at", RT(now)))
	return err
}

// AddBreachItem adds a credential to the plan unless it is already there.
func (tx *TenantTx) AddBreachItem(planID string, it *BreachItem, now time.Time) error {
	_, err := tx.exec(breachItemsInsert, sql.Named("id", NewID()), sql.Named("plan_id", planID), sql.Named("kind", it.Kind),
		sql.Named("ref", it.Ref), sql.Named("label", it.Label), sql.Named("action", it.Action), sql.Named("detail", it.Detail),
		sql.Named("updated_at", RT(now)))
	return err
}

// BreachItems lists the credentials of a plan.
func (tx *TenantTx) BreachItems(planID string) ([]*BreachItem, error) {
	return collect(tx, scanBreachItem, breachItemsList, sql.Named("plan_id", planID))
}

// BreachItem returns one credential of a plan or ErrNotFound.
func (tx *TenantTx) BreachItem(planID, id string) (*BreachItem, error) {
	return one(tx, scanBreachItem, breachItemsGet, sql.Named("plan_id", planID), sql.Named("id", id))
}

// SetBreachItemState records what a re-read found. An attested item is final.
func (tx *TenantTx) SetBreachItemState(id, state, detail string, verification *string, verifiedAt *time.Time, now time.Time) error {
	_, err := tx.exec(breachItemsSet, sql.Named("id", id), sql.Named("state", state), sql.Named("detail", detail),
		sql.Named("verification", verification), sql.Named("verified_at", RTP(verifiedAt)), sql.Named("updated_at", RT(now)))
	return err
}

// AttestBreachItem records that a person did the manual step. A verified item is final.
func (tx *TenantTx) AttestBreachItem(id, by, note, detail string, now time.Time) error {
	_, err := tx.exec(breachItemsAttest, sql.Named("id", id), sql.Named("attested_by", by), sql.Named("attested_note", note), sql.Named("detail", detail),
		sql.Named("updated_at", RT(now)))
	return err
}
