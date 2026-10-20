package store

import (
	"database/sql"
	"time"
)

// Role mining (schema/0420_role_mining.sql, issue #298).

// Mining run statuses.
const (
	MiningQueued    = "queued"
	MiningRunning   = "running"
	MiningSucceeded = "succeeded"
	MiningFailed    = "failed"
)

// Mining candidate statuses.
const (
	CandidateOpen      = "open"
	CandidateAccepted  = "accepted"
	CandidateDismissed = "dismissed"
)

// MiningRun is one role mining run.
type MiningRun struct {
	ID              string
	Status          string
	Params          string // JSON
	Algorithm       string
	SnapshotHash    string
	People          int
	Entitlements    int
	Candidates      int
	SkippedExisting int
	Truncated       bool
	Error           string
	RequestedBy     *string
	RequestedActor  string
	CreatedAt       time.Time
	StartedAt       *time.Time
	FinishedAt      *time.Time
}

// MiningCandidate is a role a run suggested. Entitlements, Members, Outliers
// and Rule are JSON.
type MiningCandidate struct {
	ID             string
	RunID          string
	Rank           int
	Name           string
	Entitlements   string
	Members        string
	Outliers       string
	Coverage       int
	Rule           *string
	Confidence     int
	Cohesion       int
	SimilarRoleID  *string
	Similarity     int
	Status         string
	DecidedBy      *string
	DecidedActor   *string
	DecidedAt      *time.Time
	DecisionReason *string
	RoleID         *string
}

const mrCols = `r.id, r.status, r.params, r.algorithm, r.snapshot_hash, r.people, r.entitlements, r.candidates,
	r.skipped_existing, r.truncated, r.error, r.requested_by, r.requested_actor, r.created_at, r.started_at, r.finished_at`

const mcCols = `c.id, c.run_id, c.rank_no, c.name, c.entitlements, c.members, c.outliers, c.coverage, c.rule, c.confidence,
	c.cohesion, c.similar_role_id, c.similarity, c.status, c.decided_by, c.decided_actor, c.decided_at, c.decision_reason,
	c.role_id`

var (
	mrInsert = tq("role_mining_runs.insert", `
		INSERT INTO role_mining_runs (id, tenant_id, status, params, algorithm, requested_by, requested_actor, created_at)
		VALUES (@id, @tenant, @status, @params, @algorithm, @requested_by, @requested_actor, @created_at)`)
	mrGet = tq("role_mining_runs.get", `
		SELECT `+mrCols+` FROM role_mining_runs r WHERE r.tenant_id = @tenant AND r.id = @id`)
	mrList = tq("role_mining_runs.list", `
		SELECT `+mrCols+` FROM role_mining_runs r WHERE r.tenant_id = @tenant ORDER BY r.created_at DESC, r.id LIMIT @limit`)
	mrActive = tq("role_mining_runs.active", `
		SELECT `+mrCols+` FROM role_mining_runs r WHERE r.tenant_id = @tenant AND r.status IN ('queued','running')
		ORDER BY r.created_at DESC, r.id LIMIT 1`)
	mrStart = tq("role_mining_runs.start", `
		UPDATE role_mining_runs SET status = 'running', started_at = @at
		WHERE tenant_id = @tenant AND id = @id AND status IN ('queued','running')`)
	mrFinish = tq("role_mining_runs.finish", `
		UPDATE role_mining_runs SET status = @status, snapshot_hash = @snapshot_hash, people = @people,
			entitlements = @entitlements, candidates = @candidates, skipped_existing = @skipped_existing,
			truncated = @truncated, error = @error, finished_at = @at
		WHERE tenant_id = @tenant AND id = @id AND status IN ('queued','running')`)

	mcInsert = tq("role_mining_candidates.insert", `
		INSERT INTO role_mining_candidates (id, tenant_id, run_id, rank_no, name, entitlements, members, outliers, coverage,
			rule, confidence, cohesion, similar_role_id, similarity)
		VALUES (@id, @tenant, @run_id, @rank_no, @name, @entitlements, @members, @outliers, @coverage, @rule, @confidence,
			@cohesion, @similar_role_id, @similarity)`)
	mcForRun = tq("role_mining_candidates.for_run", `
		SELECT `+mcCols+` FROM role_mining_candidates c WHERE c.tenant_id = @tenant AND c.run_id = @run_id
		ORDER BY c.rank_no`)
	mcGet = tq("role_mining_candidates.get", `
		SELECT `+mcCols+` FROM role_mining_candidates c WHERE c.tenant_id = @tenant AND c.id = @id`)
	mcDecide = tq("role_mining_candidates.decide", `
		UPDATE role_mining_candidates SET status = @status, decided_by = @decided_by, decided_actor = @decided_actor,
			decided_at = @decided_at, decision_reason = @decision_reason, role_id = @role_id
		WHERE tenant_id = @tenant AND id = @id AND status = 'open'`)
)

func scanMiningRun(s scanner) (*MiningRun, error) {
	var r MiningRun
	var trunc int
	var by sql.NullString
	var created, started, finished nullTime
	if err := s.Scan(&r.ID, &r.Status, &r.Params, &r.Algorithm, &r.SnapshotHash, &r.People, &r.Entitlements, &r.Candidates,
		&r.SkippedExisting, &trunc, &r.Error, &by, &r.RequestedActor, &created, &started, &finished); err != nil {
		return nil, err
	}
	r.Truncated, r.RequestedBy = trunc != 0, strp(by)
	var err error
	if r.CreatedAt, err = created.val(); err != nil {
		return nil, err
	}
	if r.StartedAt, err = started.ptr(); err != nil {
		return nil, err
	}
	r.FinishedAt, err = finished.ptr()
	return &r, err
}

func scanMiningCandidate(s scanner) (*MiningCandidate, error) {
	var c MiningCandidate
	var rule, similar, by, actor, reason, role sql.NullString
	var at nullTime
	if err := s.Scan(&c.ID, &c.RunID, &c.Rank, &c.Name, &c.Entitlements, &c.Members, &c.Outliers, &c.Coverage, &rule,
		&c.Confidence, &c.Cohesion, &similar, &c.Similarity, &c.Status, &by, &actor, &at, &reason, &role); err != nil {
		return nil, err
	}
	c.Rule, c.SimilarRoleID, c.DecidedBy, c.DecidedActor = strp(rule), strp(similar), strp(by), strp(actor)
	c.DecisionReason, c.RoleID = strp(reason), strp(role)
	var err error
	c.DecidedAt, err = at.ptr()
	return &c, err
}

// InsertMiningRun saves a new run (status and params as given).
func (tx *TenantTx) InsertMiningRun(r *MiningRun) error {
	_, err := tx.exec(mrInsert, sql.Named("id", r.ID), sql.Named("status", r.Status), sql.Named("params", r.Params),
		sql.Named("algorithm", r.Algorithm), sql.Named("requested_by", SP(r.RequestedBy)),
		sql.Named("requested_actor", r.RequestedActor), sql.Named("created_at", T(r.CreatedAt)))
	return err
}

// MiningRun returns one run, or ErrNotFound.
func (tx *TenantTx) MiningRun(id string) (*MiningRun, error) {
	return one(tx, scanMiningRun, mrGet, sql.Named("id", id))
}

// MiningRuns returns the newest runs first.
func (tx *TenantTx) MiningRuns(limit int) ([]*MiningRun, error) {
	return collect(tx, scanMiningRun, mrList, sql.Named("limit", limit))
}

// ActiveMiningRun returns the newest run that is queued or running, or ErrNotFound.
func (tx *TenantTx) ActiveMiningRun() (*MiningRun, error) {
	return one(tx, scanMiningRun, mrActive)
}

// StartMiningRun marks a queued run running (ErrNotFound when it is already finished).
func (tx *TenantTx) StartMiningRun(id string, at time.Time) error {
	return tx.execOne(mrStart, sql.Named("id", id), sql.Named("at", T(at)))
}

// FinishMiningRun records a run's outcome (ErrNotFound when it is already finished).
func (tx *TenantTx) FinishMiningRun(r *MiningRun, at time.Time) error {
	return tx.execOne(mrFinish, sql.Named("id", r.ID), sql.Named("status", r.Status),
		sql.Named("snapshot_hash", r.SnapshotHash), sql.Named("people", r.People),
		sql.Named("entitlements", r.Entitlements), sql.Named("candidates", r.Candidates),
		sql.Named("skipped_existing", r.SkippedExisting), sql.Named("truncated", B(r.Truncated)),
		sql.Named("error", r.Error), sql.Named("at", T(at)))
}

// InsertMiningCandidate saves a suggestion of a run.
func (tx *TenantTx) InsertMiningCandidate(c *MiningCandidate) error {
	_, err := tx.exec(mcInsert, sql.Named("id", c.ID), sql.Named("run_id", c.RunID), sql.Named("rank_no", c.Rank),
		sql.Named("name", c.Name), sql.Named("entitlements", c.Entitlements), sql.Named("members", c.Members),
		sql.Named("outliers", c.Outliers), sql.Named("coverage", c.Coverage), sql.Named("rule", SP(c.Rule)),
		sql.Named("confidence", c.Confidence), sql.Named("cohesion", c.Cohesion),
		sql.Named("similar_role_id", SP(c.SimilarRoleID)), sql.Named("similarity", c.Similarity))
	return err
}

// MiningCandidates returns a run's candidates by rank.
func (tx *TenantTx) MiningCandidates(runID string) ([]*MiningCandidate, error) {
	return collect(tx, scanMiningCandidate, mcForRun, sql.Named("run_id", runID))
}

// MiningCandidate returns one candidate, or ErrNotFound.
func (tx *TenantTx) MiningCandidate(id string) (*MiningCandidate, error) {
	return one(tx, scanMiningCandidate, mcGet, sql.Named("id", id))
}

// DecideMiningCandidate accepts or dismisses an open candidate (ErrNotFound
// when it is not open). roleID is the role an accept created.
func (tx *TenantTx) DecideMiningCandidate(id, status string, by *string, actor string, at time.Time, reason string, roleID *string) error {
	return tx.execOne(mcDecide, sql.Named("id", id), sql.Named("status", status), sql.Named("decided_by", SP(by)),
		sql.Named("decided_actor", actor), sql.Named("decided_at", T(at)), sql.Named("decision_reason", reason),
		sql.Named("role_id", SP(roleID)))
}
