package store

import (
	"database/sql"
	"errors"
	"time"
)

// CheckRun is a validation, scheduled or dry-run check run.
type CheckRun struct {
	ID, RevisionID string
	Kind           string // validation | scheduled | dry_run
	Simulated      bool
	Status         string // running | completed | aborted | rate_limited
	ActorID        string
	ConfigHash     string
	StartedAt      time.Time
	FinishedAt     *time.Time
}

// CheckResult is one check's result for one item.
type CheckResult struct {
	RunID, ItemID, CheckID string
	Status                 string
	Observed               string // JSON object
	Message                string
	DurationMS             int
	ItemHash               string
	Simulated              bool
}

const runCols = "r.id, r.revision_id, r.kind, r.simulated, r.status, r.actor_id, r.config_hash, r.started_at, r.finished_at"

var (
	checkRunsInsert = tq("readiness_check_runs.insert", `
		INSERT INTO readiness_check_runs (id, tenant_id, revision_id, kind, simulated, status, actor_id, config_hash,
			started_at)
		VALUES (@id, @tenant, @revision_id, @kind, @simulated, @status, @actor_id, @config_hash, @started_at)`)
	checkRunsFinish = tq("readiness_check_runs.finish", `
		UPDATE readiness_check_runs SET status = @status, finished_at = @finished_at
		WHERE tenant_id = @tenant AND id = @id`)
	checkRunsGet = tq("readiness_check_runs.get", `
		SELECT `+runCols+` FROM readiness_check_runs r WHERE r.tenant_id = @tenant AND r.id = @id`)
	// Live runs are the validation and scheduled kinds; data runs are dry runs.
	checkRunsLatestLive = tq("readiness_check_runs.latest_live", `
		SELECT `+runCols+` FROM readiness_check_runs r
		WHERE r.tenant_id = @tenant AND r.revision_id = @revision_id AND r.status <> 'running'
			AND r.kind IN ('validation', 'scheduled')
		ORDER BY r.started_at DESC, r.rowid DESC LIMIT 1`)
	checkRunsLatestDryRun = tq("readiness_check_runs.latest_dry_run", `
		SELECT `+runCols+` FROM readiness_check_runs r
		WHERE r.tenant_id = @tenant AND r.revision_id = @revision_id AND r.status <> 'running' AND r.kind = 'dry_run'
		ORDER BY r.started_at DESC, r.rowid DESC LIMIT 1`)
	checkRunsRunningLive = tq("readiness_check_runs.running_live", `
		SELECT `+runCols+` FROM readiness_check_runs r
		WHERE r.tenant_id = @tenant AND r.revision_id = @revision_id AND r.status = 'running'
			AND r.kind IN ('validation', 'scheduled')
		LIMIT 1`)
	checkRunsCountSince = tq("readiness_check_runs.count_since", `
		SELECT count(*) FROM readiness_check_runs r
		WHERE r.tenant_id = @tenant AND r.revision_id = @revision_id AND r.kind = @kind AND r.started_at >= @since`)
	checkRunsRunningDryRuns = tq("readiness_check_runs.count_running_dry_runs", `
		SELECT count(*) FROM readiness_check_runs r
		WHERE r.tenant_id = @tenant AND r.kind = 'dry_run' AND r.status = 'running'`)
	checkResultsInsert = tq("readiness_check_results.insert", `
		INSERT INTO readiness_check_results (tenant_id, run_id, item_id, check_id, status, observed, message,
			duration_ms, item_hash, simulated)
		VALUES (@tenant, @run_id, @item_id, @check_id, @status, @observed, @message, @duration_ms, @item_hash,
			@simulated)`)
	checkResultsOfRun = tq("readiness_check_results.of_run", `
		SELECT x.run_id, x.item_id, x.check_id, x.status, x.observed, x.message, x.duration_ms, x.item_hash, x.simulated
		FROM readiness_check_results x WHERE x.tenant_id = @tenant AND x.run_id = @run_id ORDER BY x.item_id, x.check_id`)
	checkResultsDelete = tq("readiness_check_results.delete_run", `
		DELETE FROM readiness_check_results WHERE tenant_id = @tenant AND run_id = @run_id`)
)

func scanRun(s scanner) (*CheckRun, error) {
	var r CheckRun
	var sim int
	var started string
	var finished sql.NullString
	if err := s.Scan(&r.ID, &r.RevisionID, &r.Kind, &sim, &r.Status, &r.ActorID, &r.ConfigHash, &started, &finished); err != nil {
		return nil, err
	}
	r.Simulated = sim != 0
	var err error
	if r.StartedAt, err = ParseRT(started); err != nil {
		return nil, err
	}
	r.FinishedAt, err = rtp(finished)
	return &r, err
}

// InsertCheckRun starts a run.
func (tx *TenantTx) InsertCheckRun(r *CheckRun) error {
	_, err := tx.exec(checkRunsInsert, sql.Named("id", r.ID), sql.Named("revision_id", r.RevisionID), sql.Named("kind", r.Kind),
		sql.Named("simulated", B(r.Simulated)), sql.Named("status", r.Status), sql.Named("actor_id", r.ActorID),
		sql.Named("config_hash", r.ConfigHash), sql.Named("started_at", RT(r.StartedAt)))
	return err
}

// FinishCheckRun records a run's outcome.
func (tx *TenantTx) FinishCheckRun(id, status string, at time.Time) error {
	_, err := tx.exec(checkRunsFinish, sql.Named("status", status), sql.Named("finished_at", RT(at)), sql.Named("id", id))
	return err
}

// CheckRun returns one run or ErrNotFound.
func (tx *TenantTx) CheckRun(id string) (*CheckRun, error) {
	return one(tx, scanRun, checkRunsGet, sql.Named("id", id))
}

func (tx *TenantTx) optionalRun(s tstmt, revisionID string) (*CheckRun, error) {
	r, err := one(tx, scanRun, s, sql.Named("revision_id", revisionID))
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return r, err
}

// LatestLiveRun returns the newest finished validation or scheduled run of a
// revision, or nil.
func (tx *TenantTx) LatestLiveRun(revisionID string) (*CheckRun, error) {
	return tx.optionalRun(checkRunsLatestLive, revisionID)
}

// LatestDryRun returns the newest finished dry run of a revision, or nil.
func (tx *TenantTx) LatestDryRun(revisionID string) (*CheckRun, error) {
	return tx.optionalRun(checkRunsLatestDryRun, revisionID)
}

// RunningLiveRun returns the in-flight validation or scheduled run of a
// revision, or nil.
func (tx *TenantTx) RunningLiveRun(revisionID string) (*CheckRun, error) {
	return tx.optionalRun(checkRunsRunningLive, revisionID)
}

// CountCheckRunsSince counts runs of a kind for a revision started at or after t.
func (tx *TenantTx) CountCheckRunsSince(revisionID, kind string, t time.Time) (int, error) {
	return tx.count(checkRunsCountSince, sql.Named("revision_id", revisionID), sql.Named("kind", kind),
		sql.Named("since", RT(t)))
}

// RunningDryRuns counts dry runs in flight in the tenant (at most one, §5.2).
func (tx *TenantTx) RunningDryRuns() (int, error) { return tx.count(checkRunsRunningDryRuns) }

// InsertCheckResult stores one result.
func (tx *TenantTx) InsertCheckResult(r *CheckResult) error {
	_, err := tx.exec(checkResultsInsert, sql.Named("run_id", r.RunID), sql.Named("item_id", r.ItemID),
		sql.Named("check_id", r.CheckID), sql.Named("status", r.Status), sql.Named("observed", r.Observed),
		sql.Named("message", r.Message), sql.Named("duration_ms", r.DurationMS), sql.Named("item_hash", r.ItemHash),
		sql.Named("simulated", B(r.Simulated)))
	return err
}

// CheckResults returns a run's results ordered by item and check.
func (tx *TenantTx) CheckResults(runID string) ([]*CheckResult, error) {
	return collect(tx, func(s scanner) (*CheckResult, error) {
		var r CheckResult
		var sim int
		if err := s.Scan(&r.RunID, &r.ItemID, &r.CheckID, &r.Status, &r.Observed, &r.Message, &r.DurationMS, &r.ItemHash, &sim); err != nil {
			return nil, err
		}
		r.Simulated = sim != 0
		return &r, nil
	}, checkResultsOfRun, sql.Named("run_id", runID))
}

// DeleteCheckResults removes a run's results (data checks are re-evaluated
// when a finding is accepted).
func (tx *TenantTx) DeleteCheckResults(runID string) error {
	_, err := tx.exec(checkResultsDelete, sql.Named("run_id", runID))
	return err
}
