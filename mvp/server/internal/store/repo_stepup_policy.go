package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// Tenant step-up policy per action (schema/0493_stepup_policy.sql, issue #298).
// One row per tenant; internal/auth treats ErrNotFound as "the code's own
// requirements only".

// StepUpEntry is one action's requirement as stored.
type StepUpEntry struct {
	ACR     string `json:"acr"`
	MaxAgeS int    `json:"max_age_s"`
}

// StepUpPolicyRow is the stored policy: permission -> requirement.
type StepUpPolicyRow struct {
	Entries   map[string]StepUpEntry
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

var (
	stepUpGet = tq("stepup_policy.get", `
		SELECT s.entries, s.version, s.updated_by, s.updated_at FROM stepup_policy s WHERE s.tenant_id = @tenant`)
	stepUpPut = tq("stepup_policy.put", `
		INSERT INTO stepup_policy (tenant_id, entries, version, updated_by, updated_at)
		VALUES (@tenant, @entries, 1, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET entries = excluded.entries, version = stepup_policy.version + 1,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
)

// StepUpPolicy returns the tenant's saved policy; ErrNotFound if it never saved one.
func (tx *TenantTx) StepUpPolicy() (*StepUpPolicyRow, error) {
	return one(tx, func(s scanner) (*StepUpPolicyRow, error) {
		var r StepUpPolicyRow
		var entries, at string
		if err := s.Scan(&entries, &r.Version, &r.UpdatedBy, &at); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(entries), &r.Entries); err != nil {
			return nil, err
		}
		var err error
		r.UpdatedAt, err = ParseRT(at)
		return &r, err
	}, stepUpGet)
}

// PutStepUpPolicy replaces the tenant's policy and moves the version on.
func (tx *TenantTx) PutStepUpPolicy(r *StepUpPolicyRow, now time.Time) error {
	entries := r.Entries
	if entries == nil {
		entries = map[string]StepUpEntry{}
	}
	b, err := json.Marshal(entries) // map keys are sorted: the stored text is stable
	if err != nil {
		return err
	}
	_, err = tx.exec(stepUpPut, sql.Named("entries", string(b)), sql.Named("updated_by", r.UpdatedBy),
		sql.Named("updated_at", RT(now)))
	return err
}
