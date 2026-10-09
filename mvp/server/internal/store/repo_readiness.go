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

const runCols = "id, revision_id, kind, simulated, status, actor_id, config_hash, started_at, finished_at"

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
func (c *Conn) InsertCheckRun(r *CheckRun) error {
	_, err := c.Exec(`INSERT INTO readiness_check_runs (id, tenant_id, revision_id, kind, simulated, status, actor_id,
		config_hash, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, DefaultTenantID, r.RevisionID, r.Kind, B(r.Simulated), r.Status, r.ActorID, r.ConfigHash, RT(r.StartedAt))
	return err
}

// FinishCheckRun records a run's outcome.
func (c *Conn) FinishCheckRun(id, status string, at time.Time) error {
	_, err := c.Exec("UPDATE readiness_check_runs SET status = ?, finished_at = ? WHERE tenant_id = ? AND id = ?",
		status, RT(at), DefaultTenantID, id)
	return err
}

// CheckRun returns one run or ErrNotFound.
func (c *Conn) CheckRun(id string) (*CheckRun, error) {
	return one(c, scanRun, "SELECT "+runCols+" FROM readiness_check_runs WHERE tenant_id = ? AND id = ?", DefaultTenantID, id)
}

// LatestCheckRun returns the newest finished run of the given kinds for a
// revision, or nil.
func (c *Conn) LatestCheckRun(revisionID string, kinds ...string) (*CheckRun, error) {
	q := "SELECT " + runCols + " FROM readiness_check_runs WHERE tenant_id = ? AND revision_id = ? AND status <> 'running' AND kind IN ("
	args := []any{DefaultTenantID, revisionID}
	for i, k := range kinds {
		if i > 0 {
			q += ", "
		}
		q += "?"
		args = append(args, k)
	}
	r, err := one(c, scanRun, q+") ORDER BY started_at DESC, rowid DESC LIMIT 1", args...)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return r, err
}

// RunningCheckRun returns the in-flight run of a kind for a revision, or nil.
func (c *Conn) RunningCheckRun(revisionID string, kinds ...string) (*CheckRun, error) {
	q := "SELECT " + runCols + " FROM readiness_check_runs WHERE tenant_id = ? AND revision_id = ? AND status = 'running' AND kind IN ("
	args := []any{DefaultTenantID, revisionID}
	for i, k := range kinds {
		if i > 0 {
			q += ", "
		}
		q += "?"
		args = append(args, k)
	}
	r, err := one(c, scanRun, q+") LIMIT 1", args...)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return r, err
}

// CountCheckRunsSince counts runs of a kind for a revision started at or after t.
func (c *Conn) CountCheckRunsSince(revisionID, kind string, t time.Time) (int, error) {
	return c.Count("SELECT count(*) FROM readiness_check_runs WHERE tenant_id = ? AND revision_id = ? AND kind = ? AND started_at >= ?",
		DefaultTenantID, revisionID, kind, RT(t))
}

// InsertCheckResult stores one result.
func (c *Conn) InsertCheckResult(r *CheckResult) error {
	_, err := c.Exec(`INSERT INTO readiness_check_results (tenant_id, run_id, item_id, check_id, status, observed, message,
		duration_ms, item_hash, simulated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		DefaultTenantID, r.RunID, r.ItemID, r.CheckID, r.Status, r.Observed, r.Message, r.DurationMS, r.ItemHash, B(r.Simulated))
	return err
}

// CheckResults returns a run's results ordered by item and check.
func (c *Conn) CheckResults(runID string) ([]*CheckResult, error) {
	return collect(c, func(s scanner) (*CheckResult, error) {
		var r CheckResult
		var sim int
		if err := s.Scan(&r.RunID, &r.ItemID, &r.CheckID, &r.Status, &r.Observed, &r.Message, &r.DurationMS, &r.ItemHash, &sim); err != nil {
			return nil, err
		}
		r.Simulated = sim != 0
		return &r, nil
	}, `SELECT run_id, item_id, check_id, status, observed, message, duration_ms, item_hash, simulated
		FROM readiness_check_results WHERE tenant_id = ? AND run_id = ? ORDER BY item_id, check_id`, DefaultTenantID, runID)
}
