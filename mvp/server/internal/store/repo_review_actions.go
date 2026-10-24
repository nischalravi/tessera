package store

import (
	"database/sql"
	"time"
)

// Certification actions (schema/0912_review_item_events.sql, issue #588): consult, answer and
// reassign events on a review item, and the lock and close states of a campaign.

// Review item event kinds.
const (
	ReviewEventConsult  = "consult"
	ReviewEventAnswer   = "answer"
	ReviewEventReassign = "reassign"
)

// Campaign states beyond open and completed.
const (
	CampaignOpen   = "open"
	CampaignLocked = "locked" // decisions paused; unlock reopens it
	CampaignClosed = "closed" // final; undecided items stay undecided
)

// ReviewItemEvent is one consult, answer or reassignment.
type ReviewItemEvent struct {
	ID               int64
	ItemID           int64
	Kind             string
	RefID            *int64
	ActorUserID      string
	Actor            string
	TargetIdentityID *int64
	Note             string
	At               time.Time
}

const reviewEventCols = `e.id, e.item_id, e.kind, e.ref_id, e.actor_user_id, e.actor, e.target_identity_id, e.note, e.at`

var (
	reviewEventIns = tq("review_item_events.insert", `
		INSERT INTO review_item_events (tenant_id, item_id, kind, ref_id, actor_user_id, actor, target_identity_id, note, at)
		VALUES (@tenant, @item_id, @kind, @ref_id, @actor_user_id, @actor, @target_identity_id, @note, @at)`)
	reviewEventsForItem = tq("review_item_events.for_item", `
		SELECT `+reviewEventCols+` FROM review_item_events e WHERE e.tenant_id = @tenant AND e.item_id = @item_id ORDER BY e.id`)
	reviewEventGet = tq("review_item_events.get", `
		SELECT `+reviewEventCols+` FROM review_item_events e WHERE e.tenant_id = @tenant AND e.id = @id`)
	// consultations asked of a person and not yet answered
	reviewOpenConsults = tq("review_item_events.open_consults", `
		SELECT `+reviewEventCols+` FROM review_item_events e
		WHERE e.tenant_id = @tenant AND e.kind = 'consult' AND e.target_identity_id = @identity_id
			AND NOT EXISTS (SELECT 1 FROM review_item_events a
				WHERE a.tenant_id = @tenant AND a.kind = 'answer' AND a.ref_id = e.id)
		ORDER BY e.id`)
	campaignTransition = tq("review_campaigns.transition", `
		UPDATE review_campaigns SET status = @to WHERE tenant_id = @tenant AND id = @id AND status IN (@from1, @from2)`)
)

func scanReviewEvent(s scanner) (*ReviewItemEvent, error) {
	var e ReviewItemEvent
	var ref, target sql.NullInt64
	var at string
	if err := s.Scan(&e.ID, &e.ItemID, &e.Kind, &ref, &e.ActorUserID, &e.Actor, &target, &e.Note, &at); err != nil {
		return nil, err
	}
	if ref.Valid {
		e.RefID = &ref.Int64
	}
	if target.Valid {
		e.TargetIdentityID = &target.Int64
	}
	var err error
	e.At, err = ParseRT(at)
	return &e, err
}

// InsertReviewItemEvent records an event and returns its id.
func (tx *TenantTx) InsertReviewItemEvent(e *ReviewItemEvent) (int64, error) {
	var ref, target any
	if e.RefID != nil {
		ref = *e.RefID
	}
	if e.TargetIdentityID != nil {
		target = *e.TargetIdentityID
	}
	return tx.insert(reviewEventIns, sql.Named("item_id", e.ItemID), sql.Named("kind", e.Kind), sql.Named("ref_id", ref),
		sql.Named("actor_user_id", e.ActorUserID), sql.Named("actor", e.Actor), sql.Named("target_identity_id", target),
		sql.Named("note", e.Note), sql.Named("at", RT(e.At)))
}

// ReviewItemEvents lists an item's events, oldest first.
func (tx *TenantTx) ReviewItemEvents(itemID int64) ([]*ReviewItemEvent, error) {
	return collect(tx, scanReviewEvent, reviewEventsForItem, sql.Named("item_id", itemID))
}

// ReviewItemEvent returns one event; ErrNotFound if it is not the tenant's.
func (tx *TenantTx) ReviewItemEvent(id int64) (*ReviewItemEvent, error) {
	return one(tx, scanReviewEvent, reviewEventGet, sql.Named("id", id))
}

// OpenReviewConsultations lists the consultations asked of an identity that no answer closes.
func (tx *TenantTx) OpenReviewConsultations(identityID int64) ([]*ReviewItemEvent, error) {
	return collect(tx, scanReviewEvent, reviewOpenConsults, sql.Named("identity_id", identityID))
}

// TransitionCampaign moves a campaign from one of two states to another; false if it was in neither.
func (tx *TenantTx) TransitionCampaign(id int64, from1, from2, to string) (bool, error) {
	res, err := tx.exec(campaignTransition, sql.Named("id", id), sql.Named("from1", from1), sql.Named("from2", from2), sql.Named("to", to))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// CampaignLock says when a campaign was locked and when the lock ends.
type CampaignLock struct {
	CampaignID int64
	LockedBy   string
	Reason     string
	LockedAt   time.Time
	ExpiresAt  time.Time
}

var (
	campaignLockPut = tq("review_campaign_locks.put", `
		INSERT INTO review_campaign_locks (tenant_id, campaign_id, locked_by, reason, locked_at, expires_at)
		VALUES (@tenant, @campaign_id, @locked_by, @reason, @locked_at, @expires_at)
		ON CONFLICT (tenant_id, campaign_id) DO UPDATE SET locked_by = excluded.locked_by, reason = excluded.reason,
			locked_at = excluded.locked_at, expires_at = excluded.expires_at`)
	campaignLockGet = tq("review_campaign_locks.get", `
		SELECT l.campaign_id, l.locked_by, l.reason, l.locked_at, l.expires_at FROM review_campaign_locks l
		WHERE l.tenant_id = @tenant AND l.campaign_id = @campaign_id`)
	campaignLockDelete = tq("review_campaign_locks.delete", `
		DELETE FROM review_campaign_locks WHERE tenant_id = @tenant AND campaign_id = @campaign_id`)
)

// PutCampaignLock records a lock (replacing an earlier one).
func (tx *TenantTx) PutCampaignLock(l *CampaignLock) error {
	_, err := tx.exec(campaignLockPut, sql.Named("campaign_id", l.CampaignID), sql.Named("locked_by", l.LockedBy), sql.Named("reason", l.Reason),
		sql.Named("locked_at", RT(l.LockedAt)), sql.Named("expires_at", RT(l.ExpiresAt)))
	return err
}

// CampaignLock returns a campaign's lock; ErrNotFound if it has none.
func (tx *TenantTx) CampaignLock(campaignID int64) (*CampaignLock, error) {
	return one(tx, func(s scanner) (*CampaignLock, error) {
		var l CampaignLock
		var at, exp string
		if err := s.Scan(&l.CampaignID, &l.LockedBy, &l.Reason, &at, &exp); err != nil {
			return nil, err
		}
		var err error
		if l.LockedAt, err = ParseRT(at); err != nil {
			return nil, err
		}
		l.ExpiresAt, err = ParseRT(exp)
		return &l, err
	}, campaignLockGet, sql.Named("campaign_id", campaignID))
}

// DeleteCampaignLock removes a campaign's lock record (none is not an error).
func (tx *TenantTx) DeleteCampaignLock(campaignID int64) error {
	_, err := tx.exec(campaignLockDelete, sql.Named("campaign_id", campaignID))
	return err
}
