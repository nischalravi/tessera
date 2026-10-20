// Package jobs records the run history of syncs, provisioning, validations,
// dry runs, health re-runs, JIT sweeps and audit anchoring (issue #172).
//
// A run is inserted as running in its own transaction before the job and
// finished in another, so a job whose transaction rolls back still leaves its
// failed run behind. A failed run appends job.failed to the tenant's audit
// chain, which alert rules can match.
package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Kinds.
const (
	Sync        = "sync"
	Provision   = "provision"
	Validation  = "validation"
	DryRun      = "dry_run"
	HealthRerun = "health_rerun"
	JITSweep    = "jit_sweep"
	AuditAnchor = "audit_anchor"

	// Kinds of the durable queue's recurring jobs (issue #300).
	SweepRequests       = "sweep_requests"
	SweepLifecycle      = "sweep_lifecycle"
	SweepAdminChanges   = "sweep_admin_changes"
	ContainmentRetry    = "containment_retries"
	SweepSoDMitigations = "sweep_sod_mitigations"
	SweepSSFPoll        = "ssf_poll"
	SweepDrift          = "drift_sweep"
	Maintenance         = "job_maintenance"

	// CertificateExpiry is the daily check that raises an alert 30 and 7 days before a certificate expires.
	CertificateExpiry = "certificate_expiry"

	// GuestLifecycle is the guest lifecycle sweep: reminders, transfer deadlines,
	// step-up renewals, conversions, grace and retention (issue #74).
	GuestLifecycle = "guest_lifecycle"
)

// Kinds lists every kind, for filters.
var Kinds = []string{Sync, Provision, Validation, DryRun, HealthRerun, JITSweep, AuditAnchor,
	SweepRequests, SweepLifecycle, SweepAdminChanges, ContainmentRetry, SweepSoDMitigations, SweepDrift, SweepSSFPoll, Maintenance, GuestLifecycle, CertificateExpiry}

// Idempotent reports whether running a kind again with the same input is
// safe: it reads a source and converges, or re-checks. Provisioning is not:
// it changes target systems.
func Idempotent(kind string) bool {
	switch kind {
	case Sync, Validation, DryRun, HealthRerun, JITSweep:
		return true
	}
	return false
}

const (
	maxError  = 500
	maxResult = 4 << 10
	// MaxBody is the largest request body kept for a retry.
	MaxBody = 4 << 10
)

// Start describes a run about to begin.
type Start struct {
	Kind         string
	Trigger      string // manual | schedule | retry
	ConnectionID *string
	Method       string
	Route        string
	Path         string
	Body         []byte // nil: not kept, so not retryable
	RetryOf      *string
	Actor        string
}

// Begin inserts a running run and returns its id. A retry also records
// job.retried in the same transaction.
func Begin(ctx context.Context, db *store.DB, t tenancy.ID, s Start, now time.Time) (string, error) {
	id := store.NewID()
	j := &store.JobRun{ID: id, Kind: s.Kind, Trigger: s.Trigger, Status: "running", ConnectionID: s.ConnectionID,
		RetryOf: s.RetryOf, Actor: s.Actor, StartedAt: now}
	if s.Method != "" {
		j.Method, j.Route, j.Path = &s.Method, &s.Route, &s.Path
	}
	if s.Body != nil && len(s.Body) <= MaxBody && Idempotent(s.Kind) && s.Method != "" {
		b := string(s.Body)
		j.Body, j.Retryable = &b, true
	}
	return id, db.InTenant(ctx, t, func(tx *store.TenantTx) error {
		if err := tx.InsertJobRun(j); err != nil {
			return err
		}
		if s.RetryOf != nil {
			return tx.Audit(now, s.Actor, "job.retried", ojson.Object{{Key: "job_id", Value: id},
				{Key: "retry_of", Value: *s.RetryOf}, {Key: "kind", Value: s.Kind}})
		}
		return nil
	})
}

// Finish records the outcome of run id: failed when err is not nil.
func Finish(ctx context.Context, db *store.DB, t tenancy.ID, id string, result any, runErr error, now time.Time) error {
	res := Summarize(result)
	return db.InTenant(ctx, t, func(tx *store.TenantTx) error {
		if runErr == nil {
			return tx.FinishJobRun(id, "succeeded", now, res, nil)
		}
		msg := ErrorSummary(runErr)
		if err := tx.FinishJobRun(id, "failed", now, res, &msg); err != nil {
			return err
		}
		return auditFailed(tx, id, now, msg)
	})
}

func auditFailed(tx *store.TenantTx, id string, now time.Time, msg string) error {
	j, err := tx.JobRun(id)
	if err != nil {
		return err
	}
	d := ojson.Object{{Key: "job_id", Value: id}, {Key: "kind", Value: j.Kind}, {Key: "trigger", Value: j.Trigger},
		{Key: "error", Value: msg}}
	if j.ConnectionID != nil {
		d = append(d, ojson.KV{Key: "connection_id", Value: *j.ConnectionID})
	}
	return tx.Audit(now, "system", "job.failed", d)
}

// Discard removes a run whose request was refused before the job ran
// (bad input, a blocked gate, a missing permission): it is not a job run.
func Discard(ctx context.Context, db *store.DB, t tenancy.ID, id string) error {
	return db.InTenant(ctx, t, func(tx *store.TenantTx) error {
		err := tx.DeleteRunningJobRun(id)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	})
}

// Record inserts a finished background run (scheduled jobs record only
// runs that did something or failed).
func Record(ctx context.Context, db *store.DB, t tenancy.ID, s Start, started, finished time.Time, result any, runErr error) error {
	id := store.NewID()
	j := &store.JobRun{ID: id, Kind: s.Kind, Trigger: s.Trigger, Status: "succeeded", Actor: s.Actor, StartedAt: started,
		FinishedAt: &finished, Result: Summarize(result)}
	if s.Method != "" && Idempotent(s.Kind) {
		body := "{}"
		j.Method, j.Route, j.Path, j.Body, j.Retryable = &s.Method, &s.Route, &s.Path, &body, true
	}
	var msg string
	if runErr != nil {
		msg = ErrorSummary(runErr)
		j.Status, j.Error = "failed", &msg
	}
	return db.InTenant(ctx, t, func(tx *store.TenantTx) error {
		if err := tx.InsertJobRun(j); err != nil {
			return err
		}
		if runErr != nil {
			return auditFailed(tx, id, finished, msg)
		}
		return nil
	})
}

// Maintain fails runs left running for longer than staleAfter (their
// process stopped) and deletes finished runs older than retention, in every
// active tenant.
func Maintain(ctx context.Context, db *store.DB, now time.Time, staleAfter, retention time.Duration) error {
	return db.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		return MaintainTx(tx, now, staleAfter, retention)
	})
}

// MaintainTx is Maintain for the tenant of tx.
func MaintainTx(tx *store.TenantTx, now time.Time, staleAfter, retention time.Duration) error {
	if _, err := tx.FailStaleJobRuns(now.Add(-staleAfter), now, "interrupted: the process running this job stopped before it finished"); err != nil {
		return err
	}
	_, err := tx.PruneJobRuns(now.Add(-retention))
	return err
}

// ErrorSummary is a one-line error message of at most 500 characters.
func ErrorSummary(err error) string {
	msg := strings.Join(strings.Fields(err.Error()), " ")
	if len(msg) > maxError {
		msg = msg[:maxError]
		for !utf8.ValidString(msg) {
			msg = msg[:len(msg)-1]
		}
		msg += "…"
	}
	return msg
}

// Summarize renders a job's result as JSON of at most 4 KiB: the whole
// result when it fits, else its top-level scalar fields.
func Summarize(result any) *string {
	if result == nil {
		return nil
	}
	b, err := json.Marshal(result)
	if err != nil || bytes.Equal(b, []byte("null")) {
		return nil
	}
	if len(b) > maxResult {
		var m map[string]json.RawMessage
		if json.Unmarshal(b, &m) != nil {
			return nil
		}
		small := map[string]json.RawMessage{}
		for k, v := range m {
			if len(v) > 0 && v[0] != '{' && v[0] != '[' && len(v) <= 200 {
				small[k] = v
			}
		}
		if b, err = json.Marshal(small); err != nil || len(b) > maxResult {
			return nil
		}
	}
	s := string(b)
	return &s
}

// RunFailed reports a job whose run itself says it failed: a validation or
// dry run that was aborted or rate limited (findings are not a failure).
func RunFailed(result any) error {
	b, err := json.Marshal(result)
	if err != nil {
		return nil
	}
	var v struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(b, &v) != nil {
		return nil
	}
	switch v.Status {
	case "aborted", "rate_limited":
		why := v.Error
		if why == "" {
			why = v.Detail
		}
		if why == "" {
			why = "the run ended " + strings.ReplaceAll(v.Status, "_", " ")
		}
		return errors.New(why)
	}
	return nil
}
