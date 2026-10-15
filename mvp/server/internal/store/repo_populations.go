package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// ---------------------------------------------------------------- frozen review populations (issue #110)

// ReviewPopulation is the immutable header of a campaign's frozen population.
// The JSON columns are stored as written by the freezer.
type ReviewPopulation struct {
	TenantID       tenancy.ID
	CampaignID     int64
	CreatedAt      time.Time
	PopulationHash string
	ItemCount      int
	SystemCounts   json.RawMessage // {"<system>": n}
	SourceSyncs    json.RawMessage // {"<system>": "<ISO time>" | null}
	Scope          json.RawMessage
	RulesVersion   string
	QASamplePct    int
}

// PopulationRow is one in-scope grant of a frozen population. Ordinal is its
// 1-based position in the canonical order (ascending EdgeID).
type PopulationRow struct {
	TenantID      tenancy.ID
	CampaignID    int64
	Ordinal       int
	EdgeID        int64
	IdentityID    int64
	IdentityRef   string
	AccountRef    string
	System        string
	Entitlement   string
	EdgeSrc       string
	EdgeDst       string
	InScopeReason string
	Disposition   string // review | auto_certified
}

// AutoDecision is a grant the exception-only rules certified without a human,
// with the rule that decided it. QA fields are set when a sampled decision is
// reviewed by a human.
type AutoDecision struct {
	ID              int64
	TenantID        tenancy.ID
	CampaignID      int64
	Ordinal         int
	EdgeID          int64
	IdentityID      int64
	Rule            json.RawMessage // {"id", "version", "inputs"}
	QASample        bool
	QAReviewerID    *int64
	QADecision      *string // keep | revoke
	QAComment       *string
	QADecidedAt     *time.Time
	QADecidedByUser *uuid.UUID
	Overturned      bool
}

const (
	populationCols = `p.tenant_id, p.campaign_id, p.created_at, p.population_hash, p.item_count, p.system_counts,
		p.source_syncs, p.scope, p.rules_version, p.qa_sample_pct`
	populationRowCols = `r.tenant_id, r.campaign_id, r.ordinal, r.edge_id, r.identity_id, r.identity_ref, r.account_ref, r.system,
		r.entitlement, r.edge_src, r.edge_dst, r.in_scope_reason, r.disposition`
	autoDecisionCols = `a.id, a.tenant_id, a.campaign_id, a.ordinal, a.edge_id, a.identity_id, a.decided_by_rule, a.qa_sample,
		a.qa_reviewer_id, a.qa_decision, a.qa_comment, a.qa_decided_at, a.qa_decided_by_user_id, a.overturned`
)

var (
	populationInsert = tq("review_populations.insert", `
		INSERT INTO review_populations (tenant_id, campaign_id, created_at, population_hash, item_count, system_counts,
			source_syncs, scope, rules_version, qa_sample_pct)
		VALUES (@tenant, @campaign_id, @created_at, @population_hash, @item_count, @system_counts,
			@source_syncs, @scope, @rules_version, @qa_sample_pct)`)
	populationGet = tq("review_populations.get", `
		SELECT `+populationCols+` FROM review_populations p WHERE p.tenant_id = @tenant AND p.campaign_id = @campaign_id`)
	populationRowInsert = tq("review_population_rows.insert", `
		INSERT INTO review_population_rows (tenant_id, campaign_id, ordinal, edge_id, identity_id, identity_ref, account_ref,
			system, entitlement, edge_src, edge_dst, in_scope_reason, disposition)
		VALUES (@tenant, @campaign_id, @ordinal, @edge_id, @identity_id, @identity_ref, @account_ref,
			@system, @entitlement, @edge_src, @edge_dst, @in_scope_reason, @disposition)`)
	populationRows = tq("review_population_rows.by_campaign", `
		SELECT `+populationRowCols+` FROM review_population_rows r
		WHERE r.tenant_id = @tenant AND r.campaign_id = @campaign_id ORDER BY r.ordinal`)
	autoDecisionInsert = tq("review_auto_decisions.insert", `
		INSERT INTO review_auto_decisions (tenant_id, campaign_id, ordinal, edge_id, identity_id, decided_by_rule, qa_sample,
			qa_reviewer_id)
		VALUES (@tenant, @campaign_id, @ordinal, @edge_id, @identity_id, @decided_by_rule, @qa_sample, @qa_reviewer_id)`)
	autoDecisionsByCampaign = tq("review_auto_decisions.by_campaign", `
		SELECT `+autoDecisionCols+` FROM review_auto_decisions a
		WHERE a.tenant_id = @tenant AND a.campaign_id = @campaign_id ORDER BY a.ordinal`)
	autoDecisionGet = tq("review_auto_decisions.get", `
		SELECT `+autoDecisionCols+` FROM review_auto_decisions a WHERE a.tenant_id = @tenant AND a.id = @id`)
	autoDecisionQA = tq("review_auto_decisions.qa_decide", `
		UPDATE review_auto_decisions SET qa_decision = @qa_decision, qa_comment = @qa_comment, qa_decided_at = @qa_decided_at,
			qa_decided_by_user_id = @qa_decided_by_user_id, overturned = @overturned
		WHERE tenant_id = @tenant AND id = @id AND qa_sample = 1 AND qa_decision IS NULL`)
	settingGet = tq("tenant_settings.get", `
		SELECT s.value FROM tenant_settings s WHERE s.tenant_id = @tenant AND s.key = @key`)
	settingPut = tq("tenant_settings.put", `
		INSERT INTO tenant_settings (tenant_id, key, value, updated_at) VALUES (@tenant, @key, @value, @updated_at)
		ON CONFLICT (tenant_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
)

func scanPopulation(s scanner) (*ReviewPopulation, error) {
	var x ReviewPopulation
	var tid, counts, syncs, scope string
	var created nullTime
	if err := s.Scan(&tid, &x.CampaignID, &created, &x.PopulationHash, &x.ItemCount, &counts, &syncs, &scope,
		&x.RulesVersion, &x.QASamplePct); err != nil {
		return nil, err
	}
	var err error
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	x.CreatedAt, err = created.val()
	x.SystemCounts, x.SourceSyncs, x.Scope = json.RawMessage(counts), json.RawMessage(syncs), json.RawMessage(scope)
	return &x, err
}

func scanPopulationRow(s scanner) (*PopulationRow, error) {
	var x PopulationRow
	var tid string
	if err := s.Scan(&tid, &x.CampaignID, &x.Ordinal, &x.EdgeID, &x.IdentityID, &x.IdentityRef, &x.AccountRef, &x.System,
		&x.Entitlement, &x.EdgeSrc, &x.EdgeDst, &x.InScopeReason, &x.Disposition); err != nil {
		return nil, err
	}
	var err error
	x.TenantID, err = tenantOf(tid)
	return &x, err
}

func scanAutoDecision(s scanner) (*AutoDecision, error) {
	var x AutoDecision
	var tid, rule string
	var qa, over int
	var rev sql.NullInt64
	var dec, com, by sql.NullString
	var at nullTime
	if err := s.Scan(&x.ID, &tid, &x.CampaignID, &x.Ordinal, &x.EdgeID, &x.IdentityID, &rule, &qa, &rev, &dec, &com, &at, &by,
		&over); err != nil {
		return nil, err
	}
	var err error
	if x.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	if x.QADecidedByUser, err = uuidp(by); err != nil {
		return nil, err
	}
	x.Rule, x.QASample, x.Overturned = json.RawMessage(rule), qa == 1, over == 1
	x.QAReviewerID, x.QADecision, x.QAComment = intp(rev), strp(dec), strp(com)
	x.QADecidedAt, err = at.ptr()
	return &x, err
}

// InsertReviewPopulation writes a campaign's frozen population: the header and
// every row. Both are immutable once written (schema triggers).
func (tx *TenantTx) InsertReviewPopulation(p *ReviewPopulation, rows []*PopulationRow) error {
	if err := tx.own(p.TenantID); err != nil {
		return err
	}
	if _, err := tx.exec(populationInsert, sql.Named("campaign_id", p.CampaignID), sql.Named("created_at", T(p.CreatedAt)),
		sql.Named("population_hash", p.PopulationHash), sql.Named("item_count", p.ItemCount),
		sql.Named("system_counts", string(p.SystemCounts)), sql.Named("source_syncs", string(p.SourceSyncs)),
		sql.Named("scope", string(p.Scope)), sql.Named("rules_version", p.RulesVersion),
		sql.Named("qa_sample_pct", p.QASamplePct)); err != nil {
		return err
	}
	for _, r := range rows {
		if err := tx.own(r.TenantID); err != nil {
			return err
		}
		if _, err := tx.exec(populationRowInsert, sql.Named("campaign_id", r.CampaignID), sql.Named("ordinal", r.Ordinal),
			sql.Named("edge_id", r.EdgeID), sql.Named("identity_id", r.IdentityID), sql.Named("identity_ref", r.IdentityRef),
			sql.Named("account_ref", r.AccountRef), sql.Named("system", r.System), sql.Named("entitlement", r.Entitlement),
			sql.Named("edge_src", r.EdgeSrc), sql.Named("edge_dst", r.EdgeDst),
			sql.Named("in_scope_reason", r.InScopeReason), sql.Named("disposition", r.Disposition)); err != nil {
			return err
		}
	}
	return nil
}

// ReviewPopulation returns a campaign's frozen population header
// (ErrNotFound for a campaign launched before populations were frozen).
func (tx *TenantTx) ReviewPopulation(campaignID int64) (*ReviewPopulation, error) {
	return one(tx, scanPopulation, populationGet, sql.Named("campaign_id", campaignID))
}

// PopulationRows returns a frozen population's rows in canonical order.
func (tx *TenantTx) PopulationRows(campaignID int64) ([]*PopulationRow, error) {
	return collect(tx, scanPopulationRow, populationRows, sql.Named("campaign_id", campaignID))
}

// InsertAutoDecision records an auto-certified grant and the rule that decided it.
func (tx *TenantTx) InsertAutoDecision(x *AutoDecision) error {
	if err := tx.own(x.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(autoDecisionInsert, sql.Named("campaign_id", x.CampaignID), sql.Named("ordinal", x.Ordinal),
		sql.Named("edge_id", x.EdgeID), sql.Named("identity_id", x.IdentityID), sql.Named("decided_by_rule", string(x.Rule)),
		sql.Named("qa_sample", B(x.QASample)), sql.Named("qa_reviewer_id", IP(x.QAReviewerID)))
	return err
}

// AutoDecisions returns a campaign's auto-certified grants in population order.
func (tx *TenantTx) AutoDecisions(campaignID int64) ([]*AutoDecision, error) {
	return collect(tx, scanAutoDecision, autoDecisionsByCampaign, sql.Named("campaign_id", campaignID))
}

// AutoDecision returns one auto-decision by id.
func (tx *TenantTx) AutoDecision(id int64) (*AutoDecision, error) {
	return one(tx, scanAutoDecision, autoDecisionGet, sql.Named("id", id))
}

// QADecideAutoDecision records a human QA decision on a sampled auto-decision,
// once; overturned is true when the reviewer revoked an auto-keep. It reports
// ErrNotFound when the row is missing, not sampled or already decided.
func (tx *TenantTx) QADecideAutoDecision(id int64, decision string, comment *string, at time.Time, by UserRef) error {
	res, err := tx.exec(autoDecisionQA, sql.Named("qa_decision", decision), sql.Named("qa_comment", SP(comment)),
		sql.Named("qa_decided_at", T(at)), sql.Named("qa_decided_by_user_id", by.idOrNil()),
		sql.Named("overturned", B(decision == "revoke")), sql.Named("id", id))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// TenantSetting returns a tenant setting; ok is false when it is unset.
func (tx *TenantTx) TenantSetting(key string) (value string, ok bool, err error) {
	err = tx.queryRow(settingGet, sql.Named("key", key)).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: setting %s: %w", key, err)
	}
	return value, true, nil
}

// SetTenantSetting creates or replaces a tenant setting.
func (tx *TenantTx) SetTenantSetting(key, value string, at time.Time) error {
	_, err := tx.exec(settingPut, sql.Named("key", key), sql.Named("value", value), sql.Named("updated_at", T(at)))
	return err
}
