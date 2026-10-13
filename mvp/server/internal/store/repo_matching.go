package store

import (
	"database/sql"
	"time"
)

// Identity matching, the review queue, four-eyes merge requests, matching
// settings and claim links (schema/0230_matching.sql, issue #68). Every
// statement binds @tenant.

// Match outcomes (what the matcher did) and statuses (where a result stands).
const (
	MatchOutcomeAutoLink  = "auto_link"
	MatchOutcomeReview    = "review"
	MatchOutcomeSuspected = "suspected"
	MatchOutcomeNew       = "new"

	MatchReview         = "review"
	MatchReverification = "reverification"
	MatchLinked         = "linked"
	MatchNewPerson      = "new_person"
	MatchRejected       = "rejected"
	MatchSuperseded     = "superseded"

	// intake statuses the matcher sets
	IntakeMatching = "matching"
	IntakeReview   = "review"
	IntakeResolved = "resolved"
	IntakeRejected = "rejected"
)

// Merge request kinds and statuses.
const (
	MergeKindMerge     = "merge"
	MergeKindMatchLink = "match_link"

	MergeReqPending   = "pending"
	MergeReqApproved  = "approved"
	MergeReqRejected  = "rejected"
	MergeReqCancelled = "cancelled"
)

// Claim link statuses.
const (
	ClaimLinkStarted   = "started"
	ClaimLinkLinked    = "linked"
	ClaimLinkContinued = "continued"
	ClaimLinkFailed    = "failed"
)

// DefaultUnmergeDays is how long a merge can be undone unless the tenant says otherwise.
const DefaultUnmergeDays = 180

// MatchResult is what the matcher said about one intake and one candidate.
type MatchResult struct {
	ID             string
	IntakeID       string
	SubjectID      *int64 // the provisional person the intake created
	CandidateID    *int64 // nil for tier D
	Tier           string
	Score          float64
	Rules          string // JSON: the rules fired with the masked attributes compared
	Outcome        string
	Status         string
	Decision       *string
	DecidedBy      *string
	SecondReviewer *string
	Reason         *string
	DecidedAt      *time.Time
	MergeID        *string
	CreatedAt      time.Time
}

// MatchFilter selects results; zero fields match everything.
type MatchFilter struct {
	Status    string
	Intake    string
	Candidate int64
	Subject   int64
}

// MergeRequest is a merge or reviewer link waiting for a second reviewer.
type MergeRequest struct {
	ID             string
	Kind           string
	SurvivorID     int64
	MergedID       int64
	MatchID        *string
	Reason         string
	Risk           string // JSON list of why a second reviewer is needed
	RequestedBy    string
	RequestedAt    time.Time
	Status         string
	DecidedBy      *string
	DecidedAt      *time.Time
	DecisionReason *string
	MergeID        *string
}

// MatchingSettings are a tenant's matching settings.
type MatchingSettings struct {
	AutoLinkTierB      bool
	RequireReviewTierA bool
	UnmergeWindowDays  int
	UpdatedBy          *string
	UpdatedAt          *time.Time
}

// ClaimLink is a claim's "I already have an account" sign-in.
type ClaimLink struct {
	ID            string
	SessionIDHash string
	IntakeID      string
	LoginTxnID    string
	Status        string
	CreatedAt     time.Time
	CompletedAt   *time.Time
}

const matchCols = `r.id, r.intake_id, r.subject_id, r.candidate_id, r.tier, r.score, r.rules, r.outcome, r.status, r.decision,
	r.decided_by, r.second_reviewer, r.reason, r.decided_at, r.merge_id, r.created_at`

const mergeReqCols = `q.id, q.kind, q.survivor_id, q.merged_id, q.match_id, q.reason, q.risk, q.requested_by, q.requested_at, q.status,
	q.decided_by, q.decided_at, q.decision_reason, q.merge_id`

const claimLinkCols = `l.id, l.session_id_hash, l.intake_id, l.login_txn_id, l.status, l.created_at, l.completed_at`

var (
	matchInsert = tq("match_results.insert", `
		INSERT INTO match_results (id, tenant_id, intake_id, subject_id, candidate_id, tier, score, rules, outcome, status,
			decision, decided_by, second_reviewer, reason, decided_at, merge_id, created_at)
		VALUES (@id, @tenant, @intake_id, @subject_id, @candidate_id, @tier, @score, @rules, @outcome, @status,
			@decision, @decided_by, @second_reviewer, @reason, @decided_at, @merge_id, @created_at)`)
	matchGet = tq("match_results.get", `
		SELECT `+matchCols+` FROM match_results r WHERE r.tenant_id = @tenant AND r.id = @id`)
	matchFiltered = tq("match_results.filtered", `
		SELECT `+matchCols+` FROM match_results r WHERE r.tenant_id = @tenant
			AND (@status = '' OR r.status = @status)
			AND (@intake = '' OR r.intake_id = @intake)
			AND (@candidate = 0 OR r.candidate_id = @candidate)
			AND (@subject = 0 OR r.subject_id = @subject)
		ORDER BY r.created_at, r.id`)
	matchDecide = tq("match_results.decide", `
		UPDATE match_results SET status = @status, decision = @decision, decided_by = @decided_by,
			second_reviewer = @second_reviewer, reason = @reason, decided_at = @decided_at, merge_id = @merge_id
		WHERE tenant_id = @tenant AND id = @id AND status IN ('review','reverification')`)

	mergeReqInsert = tq("identity_merge_requests.insert", `
		INSERT INTO identity_merge_requests (id, tenant_id, kind, survivor_id, merged_id, match_id, reason, risk,
			requested_by, requested_at, status)
		VALUES (@id, @tenant, @kind, @survivor_id, @merged_id, @match_id, @reason, @risk, @requested_by, @requested_at, 'pending')`)
	mergeReqGet = tq("identity_merge_requests.get", `
		SELECT `+mergeReqCols+` FROM identity_merge_requests q WHERE q.tenant_id = @tenant AND q.id = @id`)
	mergeReqList = tq("identity_merge_requests.list", `
		SELECT `+mergeReqCols+` FROM identity_merge_requests q WHERE q.tenant_id = @tenant
			AND (@status = '' OR q.status = @status) ORDER BY q.requested_at DESC, q.id`)
	mergeReqPendingFor = tq("identity_merge_requests.pending_for", `
		SELECT `+mergeReqCols+` FROM identity_merge_requests q WHERE q.tenant_id = @tenant
			AND q.merged_id = @merged_id AND q.status = 'pending'`)
	mergeReqDecide = tq("identity_merge_requests.decide", `
		UPDATE identity_merge_requests SET status = @status, decided_by = @decided_by, decided_at = @decided_at,
			decision_reason = @decision_reason, merge_id = @merge_id
		WHERE tenant_id = @tenant AND id = @id AND status = 'pending'`)

	settingsGet = tq("matching_settings.get", `
		SELECT s.auto_link_tier_b, s.require_review_tier_a, s.unmerge_window_days, s.updated_by, s.updated_at
		FROM matching_settings s WHERE s.tenant_id = @tenant`)
	settingsPut = tq("matching_settings.put", `
		INSERT INTO matching_settings (tenant_id, auto_link_tier_b, require_review_tier_a, unmerge_window_days,
			updated_by, updated_at)
		VALUES (@tenant, @auto_link_tier_b, @require_review_tier_a, @unmerge_window_days, @updated_by, @updated_at)
		ON CONFLICT (tenant_id) DO UPDATE SET auto_link_tier_b = excluded.auto_link_tier_b,
			require_review_tier_a = excluded.require_review_tier_a, unmerge_window_days = excluded.unmerge_window_days,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)

	claimLinkInsert = tq("claim_links.insert", `
		INSERT INTO claim_links (id, tenant_id, session_id_hash, intake_id, login_txn_id, status, created_at)
		VALUES (@id, @tenant, @session_id_hash, @intake_id, @login_txn_id, 'started', @created_at)`)
	claimLinkByTxn = tq("claim_links.by_txn", `
		SELECT `+claimLinkCols+` FROM claim_links l WHERE l.tenant_id = @tenant AND l.login_txn_id = @login_txn_id`)
	claimLinkFinish = tq("claim_links.finish", `
		UPDATE claim_links SET status = @status, completed_at = @completed_at
		WHERE tenant_id = @tenant AND id = @id AND status = 'started'`)

	intakeSetStatus = tq("intake_records.set_status", `
		UPDATE intake_records SET status = @status WHERE tenant_id = @tenant AND id = @id`)
)

func scanMatch(s scanner) (*MatchResult, error) {
	var r MatchResult
	var subject, cand sql.NullInt64
	var decision, by, second, reason, mergeID sql.NullString
	var decidedAt, createdAt nullTime
	if err := s.Scan(&r.ID, &r.IntakeID, &subject, &cand, &r.Tier, &r.Score, &r.Rules, &r.Outcome, &r.Status, &decision,
		&by, &second, &reason, &decidedAt, &mergeID, &createdAt); err != nil {
		return nil, err
	}
	r.SubjectID, r.CandidateID = intp(subject), intp(cand)
	r.Decision, r.DecidedBy, r.SecondReviewer, r.Reason, r.MergeID = strp(decision), strp(by), strp(second), strp(reason), strp(mergeID)
	var err error
	if r.DecidedAt, err = decidedAt.ptr(); err != nil {
		return nil, err
	}
	r.CreatedAt, err = createdAt.val()
	return &r, err
}

func scanMergeReq(s scanner) (*MergeRequest, error) {
	var q MergeRequest
	var match, by, reason, mergeID sql.NullString
	var at, decidedAt nullTime
	if err := s.Scan(&q.ID, &q.Kind, &q.SurvivorID, &q.MergedID, &match, &q.Reason, &q.Risk, &q.RequestedBy, &at, &q.Status,
		&by, &decidedAt, &reason, &mergeID); err != nil {
		return nil, err
	}
	q.MatchID, q.DecidedBy, q.DecisionReason, q.MergeID = strp(match), strp(by), strp(reason), strp(mergeID)
	var err error
	if q.RequestedAt, err = at.val(); err != nil {
		return nil, err
	}
	q.DecidedAt, err = decidedAt.ptr()
	return &q, err
}

func scanClaimLink(s scanner) (*ClaimLink, error) {
	var l ClaimLink
	var at, done nullTime
	if err := s.Scan(&l.ID, &l.SessionIDHash, &l.IntakeID, &l.LoginTxnID, &l.Status, &at, &done); err != nil {
		return nil, err
	}
	var err error
	if l.CreatedAt, err = at.val(); err != nil {
		return nil, err
	}
	l.CompletedAt, err = done.ptr()
	return &l, err
}

// InsertMatchResult records a result.
func (tx *TenantTx) InsertMatchResult(r *MatchResult) error {
	_, err := tx.exec(matchInsert, sql.Named("id", r.ID), sql.Named("intake_id", r.IntakeID), sql.Named("subject_id", IP(r.SubjectID)),
		sql.Named("candidate_id", IP(r.CandidateID)), sql.Named("tier", r.Tier), sql.Named("score", r.Score), sql.Named("rules", r.Rules),
		sql.Named("outcome", r.Outcome), sql.Named("status", r.Status), sql.Named("decision", optStr(r.Decision)),
		sql.Named("decided_by", optStr(r.DecidedBy)), sql.Named("second_reviewer", optStr(r.SecondReviewer)),
		sql.Named("reason", optStr(r.Reason)), sql.Named("decided_at", TP(r.DecidedAt)), sql.Named("merge_id", optStr(r.MergeID)),
		sql.Named("created_at", T(r.CreatedAt)))
	return err
}

// MatchResult returns one result, or ErrNotFound.
func (tx *TenantTx) MatchResult(id string) (*MatchResult, error) {
	return one(tx, scanMatch, matchGet, sql.Named("id", id))
}

// MatchResults returns the results matching f, oldest first.
func (tx *TenantTx) MatchResults(f MatchFilter) ([]*MatchResult, error) {
	return collect(tx, scanMatch, matchFiltered, sql.Named("status", f.Status), sql.Named("intake", f.Intake),
		sql.Named("candidate", f.Candidate), sql.Named("subject", f.Subject))
}

// DecideMatchResult records a decision on a result that is in the queue or
// waiting for re-verification; ErrNotFound if it is unknown or already final.
func (tx *TenantTx) DecideMatchResult(r *MatchResult) error {
	res, err := tx.exec(matchDecide, sql.Named("id", r.ID), sql.Named("status", r.Status), sql.Named("decision", optStr(r.Decision)),
		sql.Named("decided_by", optStr(r.DecidedBy)), sql.Named("second_reviewer", optStr(r.SecondReviewer)),
		sql.Named("reason", optStr(r.Reason)), sql.Named("decided_at", TP(r.DecidedAt)), sql.Named("merge_id", optStr(r.MergeID)))
	return affectedOne(res, err)
}

// SetIntakeStatus sets an intake record's matching status.
func (tx *TenantTx) SetIntakeStatus(id, status string) error {
	res, err := tx.exec(intakeSetStatus, sql.Named("id", id), sql.Named("status", status))
	return affectedOne(res, err)
}

// InsertMergeRequest records a merge or reviewer link waiting for a second reviewer.
func (tx *TenantTx) InsertMergeRequest(q *MergeRequest) error {
	_, err := tx.exec(mergeReqInsert, sql.Named("id", q.ID), sql.Named("kind", q.Kind), sql.Named("survivor_id", q.SurvivorID),
		sql.Named("merged_id", q.MergedID), sql.Named("match_id", optStr(q.MatchID)), sql.Named("reason", q.Reason),
		sql.Named("risk", q.Risk), sql.Named("requested_by", q.RequestedBy), sql.Named("requested_at", T(q.RequestedAt)))
	return err
}

// MergeRequest returns one request, or ErrNotFound.
func (tx *TenantTx) MergeRequest(id string) (*MergeRequest, error) {
	return one(tx, scanMergeReq, mergeReqGet, sql.Named("id", id))
}

// MergeRequests lists requests, newest first; status "" lists all.
func (tx *TenantTx) MergeRequests(status string) ([]*MergeRequest, error) {
	return collect(tx, scanMergeReq, mergeReqList, sql.Named("status", status))
}

// PendingMergeRequestFor returns the pending request to merge an identity, or ErrNotFound.
func (tx *TenantTx) PendingMergeRequestFor(mergedID int64) (*MergeRequest, error) {
	return one(tx, scanMergeReq, mergeReqPendingFor, sql.Named("merged_id", mergedID))
}

// DecideMergeRequest records the second reviewer's decision on a pending
// request; ErrNotFound if it is unknown or already decided. The schema itself
// refuses an approval by the requester.
func (tx *TenantTx) DecideMergeRequest(id, status, by string, reason *string, mergeID *string, at time.Time) error {
	res, err := tx.exec(mergeReqDecide, sql.Named("id", id), sql.Named("status", status), sql.Named("decided_by", by),
		sql.Named("decided_at", T(at)), sql.Named("decision_reason", optStr(reason)), sql.Named("merge_id", optStr(mergeID)))
	return affectedOne(res, err)
}

// MatchingSettings returns the tenant's settings (the defaults when none were saved).
func (tx *TenantTx) MatchingSettings() (MatchingSettings, error) {
	out := MatchingSettings{UnmergeWindowDays: DefaultUnmergeDays}
	var a, b, c int
	var by sql.NullString
	var at nullTime
	err := tx.queryRow(settingsGet).Scan(&a, &b, &c, &by, &at)
	if err == sql.ErrNoRows {
		return out, nil
	} else if err != nil {
		return out, err
	}
	out.AutoLinkTierB, out.RequireReviewTierA, out.UnmergeWindowDays = a == 1, b == 1, c
	out.UpdatedBy = strp(by)
	out.UpdatedAt, err = at.ptr()
	return out, err
}

// PutMatchingSettings saves the tenant's settings.
func (tx *TenantTx) PutMatchingSettings(s MatchingSettings, by string, at time.Time) error {
	_, err := tx.exec(settingsPut, sql.Named("auto_link_tier_b", B(s.AutoLinkTierB)),
		sql.Named("require_review_tier_a", B(s.RequireReviewTierA)), sql.Named("unmerge_window_days", s.UnmergeWindowDays),
		sql.Named("updated_by", by), sql.Named("updated_at", T(at)))
	return err
}

// InsertClaimLink records the start of a claim's sign-in as an existing account.
func (tx *TenantTx) InsertClaimLink(l *ClaimLink) error {
	_, err := tx.exec(claimLinkInsert, sql.Named("id", l.ID), sql.Named("session_id_hash", l.SessionIDHash),
		sql.Named("intake_id", l.IntakeID), sql.Named("login_txn_id", l.LoginTxnID), sql.Named("created_at", T(l.CreatedAt)))
	return err
}

// ClaimLinkByTxn returns the claim link carried by a login transaction, or ErrNotFound.
func (tx *TenantTx) ClaimLinkByTxn(loginTxn string) (*ClaimLink, error) {
	return one(tx, scanClaimLink, claimLinkByTxn, sql.Named("login_txn_id", loginTxn))
}

// FinishClaimLink records what came of a claim link; ErrNotFound if it is unknown or already finished.
func (tx *TenantTx) FinishClaimLink(id, status string, at time.Time) error {
	res, err := tx.exec(claimLinkFinish, sql.Named("id", id), sql.Named("status", status), sql.Named("completed_at", T(at)))
	return affectedOne(res, err)
}
