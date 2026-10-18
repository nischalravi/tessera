package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// Request access drafts (schema/0312_request_drafts.sql), private to the
// platform user who saved them: every read and write names the user.

// RequestDraft is a saved, unsubmitted request. Items is the JSON array the
// API validated; the store keeps it as it is.
type RequestDraft struct {
	ID             string
	UserID         string
	BeneficiaryIDs []int64
	Items          json.RawMessage
	DurationHours  *float64
	Justification  string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const draftCols = `d.id, d.user_id, d.beneficiary_ids, d.items, d.duration_hours, d.justification, d.created_at, d.updated_at`

var (
	draftsInsert = tq("request_drafts.insert", `
		INSERT INTO request_drafts (id, tenant_id, user_id, beneficiary_ids, items, duration_hours, justification,
			created_at, updated_at)
		VALUES (@id, @tenant, @user_id, @beneficiary_ids, @items, @duration_hours, @justification, @now, @now)`)
	draftsUpdate = tq("request_drafts.update", `
		UPDATE request_drafts SET beneficiary_ids = @beneficiary_ids, items = @items, duration_hours = @duration_hours,
			justification = @justification, updated_at = @now
		WHERE tenant_id = @tenant AND id = @id AND user_id = @user_id`)
	draftsGet = tq("request_drafts.get", `
		SELECT `+draftCols+` FROM request_drafts d WHERE d.tenant_id = @tenant AND d.id = @id AND d.user_id = @user_id`)
	draftsByUser = tq("request_drafts.by_user", `
		SELECT `+draftCols+` FROM request_drafts d WHERE d.tenant_id = @tenant AND d.user_id = @user_id
		ORDER BY d.updated_at DESC, d.id`)
	draftsCount = tq("request_drafts.count_by_user", `
		SELECT count(*) FROM request_drafts d WHERE d.tenant_id = @tenant AND d.user_id = @user_id`)
	draftsDelete = tq("request_drafts.delete", `
		DELETE FROM request_drafts WHERE tenant_id = @tenant AND id = @id AND user_id = @user_id`)
)

func scanDraft(s scanner) (*RequestDraft, error) {
	var d RequestDraft
	var bens, items, created, updated string
	var hours sql.NullFloat64
	if err := s.Scan(&d.ID, &d.UserID, &bens, &items, &hours, &d.Justification, &created, &updated); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(bens), &d.BeneficiaryIDs); err != nil {
		return nil, err
	}
	if d.BeneficiaryIDs == nil {
		d.BeneficiaryIDs = []int64{}
	}
	d.Items = json.RawMessage(items)
	if hours.Valid {
		h := hours.Float64
		d.DurationHours = &h
	}
	var err error
	if d.CreatedAt, err = ParseRT(created); err != nil {
		return nil, err
	}
	d.UpdatedAt, err = ParseRT(updated)
	return &d, err
}

func draftArgs(d *RequestDraft) ([]sql.NamedArg, error) {
	bens, err := json.Marshal(d.BeneficiaryIDs)
	if err != nil {
		return nil, err
	}
	var hours any
	if d.DurationHours != nil {
		hours = *d.DurationHours
	}
	items := string(d.Items)
	if items == "" {
		items = "[]"
	}
	return []sql.NamedArg{sql.Named("id", d.ID), sql.Named("user_id", d.UserID), sql.Named("beneficiary_ids", string(bens)),
		sql.Named("items", items), sql.Named("duration_hours", hours), sql.Named("justification", d.Justification)}, nil
}

// InsertRequestDraft saves a new draft for d.UserID (d.ID is set when empty).
func (tx *TenantTx) InsertRequestDraft(d *RequestDraft, now time.Time) error {
	if d.ID == "" {
		d.ID = NewID()
	}
	args, err := draftArgs(d)
	if err != nil {
		return err
	}
	_, err = tx.exec(draftsInsert, append(args, sql.Named("now", RT(now)))...)
	if err == nil {
		d.CreatedAt, d.UpdatedAt = now, now
	}
	return err
}

// UpdateRequestDraft replaces a draft of d.UserID; ErrNotFound when the user has no such draft.
func (tx *TenantTx) UpdateRequestDraft(d *RequestDraft, now time.Time) error {
	args, err := draftArgs(d)
	if err != nil {
		return err
	}
	if err := tx.execOne(draftsUpdate, append(args, sql.Named("now", RT(now)))...); err != nil {
		return err
	}
	d.UpdatedAt = now
	return nil
}

// RequestDraft returns one of the user's drafts, or ErrNotFound.
func (tx *TenantTx) RequestDraft(id, userID string) (*RequestDraft, error) {
	return one(tx, scanDraft, draftsGet, sql.Named("id", id), sql.Named("user_id", userID))
}

// RequestDrafts lists the user's drafts, most recently saved first.
func (tx *TenantTx) RequestDrafts(userID string) ([]*RequestDraft, error) {
	return collect(tx, scanDraft, draftsByUser, sql.Named("user_id", userID))
}

// CountRequestDrafts counts the user's drafts.
func (tx *TenantTx) CountRequestDrafts(userID string) (int, error) {
	return tx.count(draftsCount, sql.Named("user_id", userID))
}

// DeleteRequestDraft deletes one of the user's drafts; ErrNotFound when there is none.
func (tx *TenantTx) DeleteRequestDraft(id, userID string) error {
	return tx.execOne(draftsDelete, sql.Named("id", id), sql.Named("user_id", userID))
}
