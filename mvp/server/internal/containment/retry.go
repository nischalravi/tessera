package containment

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// A containment step that fails does not stop a leaver. It becomes a retry
// task (store.ContainmentRetry): a background sweeper re-runs the step and its
// verification with backoff until it passes, or gives up after MaxRetryAge,
// leaving the row (status gave_up) and an audit event as the manual task.

// MaxRetryAge is how long after the first failure a task is retried.
const MaxRetryAge = 24 * time.Hour

var backoffSchedule = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}

// Backoff is the wait after attempts retries have run: 1m, 5m, 15m, 1h, then hourly.
func Backoff(attempts int) time.Duration {
	if attempts >= 0 && attempts < len(backoffSchedule) {
		return backoffSchedule[attempts]
	}
	return time.Hour
}

// Summary is the containment part of a response: status is "done" (every
// step passed), "manual" (nothing failed, but a person must still act) or
// "retrying" (a step failed and is queued for retry; containment is incomplete).
type Summary struct {
	Status   string       `json:"status"`
	RetryID  string       `json:"retry_id,omitempty"`
	RetryIDs []string     `json:"retry_ids,omitempty"`
	Failed   []StepResult `json:"failed"`
	*Report
}

// Summarize builds the response summary of a run and its retry tasks.
func Summarize(rep *Report, retries []*store.ContainmentRetry) Summary {
	s := Summary{Status: "done", Failed: rep.Failed(), Report: rep}
	if s.Failed == nil {
		s.Failed = []StepResult{}
	}
	if len(rep.Manual) > 0 {
		s.Status = "manual"
	}
	if len(s.Failed) > 0 {
		s.Status = "retrying"
	}
	for _, r := range retries {
		s.RetryIDs = append(s.RetryIDs, r.ID)
	}
	if len(s.RetryIDs) > 0 {
		s.RetryID = s.RetryIDs[0]
	}
	return s
}

// EnqueueRetries queues a retry task for every failed step of the run (one
// open task per account and step: a repeat failure reuses it) and audits each
// new task, in the caller's transaction.
func EnqueueRetries(c *store.TenantTx, now time.Time, job *Job, rep *Report) ([]*store.ContainmentRetry, error) {
	var out []*store.ContainmentRetry
	for i, st := range rep.Steps {
		if st.Outcome != OutcomeFailed || i >= len(job.Items) {
			continue
		}
		it := job.Items[i]
		open, err := c.OpenContainmentRetry(it.AccountID, it.Action)
		if err == nil {
			out = append(out, open)
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		r := &store.ContainmentRetry{IdentityID: job.IdentityID, AccountID: it.AccountID, System: it.Target.System,
			Account: it.Target.Username, Action: it.Action, Trigger: job.Trigger, NextAttemptAt: now.Add(Backoff(0)),
			LastError: st.Detail}
		if it.Connection != "" {
			cn := it.Connection
			r.ConnectionID = &cn
		}
		if err := c.InsertContainmentRetry(r, now); err != nil {
			return nil, err
		}
		if err := c.Audit(now, "containment", "containment.retry_scheduled", retryDetail(r, ojson.Object{
			{Key: "next_attempt_at", Value: timeutil.ISO(r.NextAttemptAt)}})); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func retryDetail(r *store.ContainmentRetry, more ojson.Object) ojson.Object {
	d := ojson.Object{{Key: "retry_id", Value: r.ID}, {Key: "identity_id", Value: r.IdentityID},
		{Key: "system", Value: r.System}, {Key: "account", Value: r.Account}, {Key: "action", Value: r.Action},
		{Key: "attempts", Value: r.Attempts}}
	return append(d, more...)
}

// ApplyRetry records one attempt of a pending task from the run's report (one
// step) in the caller's transaction: success ends the task, a failure
// reschedules it with backoff or, past MaxRetryAge, gives up. Every attempt
// is audited, and so are succeeded and gave_up. It returns the updated task.
func ApplyRetry(c *store.TenantTx, now time.Time, actor string, id string, rep *Report) (*store.ContainmentRetry, error) {
	r, err := c.ContainmentRetry(id)
	if err != nil {
		return nil, err
	}
	if r.Status != store.RetryPending {
		return r, nil // another attempt already settled it
	}
	if err := Record(c, now, actor, rep); err != nil {
		return nil, err
	}
	step := StepResult{Outcome: OutcomeFailed, Detail: "no result"}
	if len(rep.Steps) > 0 {
		step = rep.Steps[0]
	}
	attempts := r.Attempts + 1
	status, next, lastErr := store.RetryPending, now.Add(Backoff(attempts)), step.Detail
	switch {
	case step.Outcome == OutcomeDone:
		status, next, lastErr = store.RetrySucceeded, now, ""
	case next.Sub(r.CreatedAt) > MaxRetryAge:
		status = store.RetryGaveUp
	}
	if err := c.UpdateContainmentRetry(id, status, attempts, next, lastErr, now); err != nil {
		return nil, err
	}
	r.Status, r.Attempts, r.NextAttemptAt, r.LastError, r.UpdatedAt = status, attempts, next, lastErr, now
	if err := c.Audit(now, actor, "containment.retry_attempt", retryDetail(r, ojson.Object{
		{Key: "outcome", Value: step.Outcome}, {Key: "status", Value: status}, {Key: "error", Value: lastErr},
		{Key: "duration_ms", Value: step.DurationMS}})); err != nil {
		return nil, err
	}
	switch status {
	case store.RetrySucceeded:
		err = c.Audit(now, actor, "containment.retry_succeeded", retryDetail(r, nil))
	case store.RetryGaveUp:
		err = c.Audit(now, actor, "containment.retry_gave_up", retryDetail(r, ojson.Object{
			{Key: "error", Value: lastErr}, {Key: "manual_action", Value: fmt.Sprintf(
				"Revoke %s for %s in the %s admin console by hand: Tessera gave up after %d attempts.",
				whatOf(r.Action), r.Account, r.System, attempts)}}))
	}
	return r, err
}

func whatOf(action string) string {
	if action == ActionRevokeGrants {
		return "OAuth consents and credentials"
	}
	return "sessions and refresh tokens"
}

// RunRetries re-runs the pending retry tasks of one tenant that are due (all
// of them, or only onlyID, which must be pending, whatever its schedule),
// with no transaction open during the provider calls, then records each
// attempt. It returns the updated tasks. The sweeper and retry-now share it.
func (s *Service) RunRetries(ctx context.Context, db *store.DB, tenant tenancy.ID, actor, onlyID string) ([]*store.ContainmentRetry, error) {
	type work struct {
		r   *store.ContainmentRetry
		job *Job
		rep *Report
	}
	var todo []*work
	err := db.ReadTenant(ctx, tenant, func(c *store.TenantTx) error {
		var rows []*store.ContainmentRetry
		if onlyID != "" {
			r, err := c.ContainmentRetry(onlyID)
			if err != nil {
				return err
			}
			if r.Status != store.RetryPending {
				return &Error{"the retry is not pending"}
			}
			rows = []*store.ContainmentRetry{r}
		} else {
			var err error
			if rows, err = c.DueContainmentRetries(s.now()); err != nil {
				return err
			}
		}
		for _, r := range rows {
			w := &work{r: r}
			job, err := s.BuildJob(c, r.IdentityID, "retry", []Spec{{Action: r.Action, AccountID: r.AccountID}})
			if err != nil {
				w.rep = failedReport(r, "cannot prepare the retry: "+err.Error(), s.now())
			} else {
				w.job = job
			}
			todo = append(todo, w)
		}
		return nil
	})
	if err != nil || len(todo) == 0 {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	for _, w := range todo {
		if w.rep == nil {
			w.rep = s.Run(rctx, w.job)
		}
	}
	var out []*store.ContainmentRetry
	err = db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		for _, w := range todo {
			r, err := ApplyRetry(c, s.now(), actor, w.r.ID, w.rep)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	return out, err
}

func failedReport(r *store.ContainmentRetry, detail string, now time.Time) *Report {
	t := timeutil.ISO(now)
	st := StepResult{Action: r.Action, System: r.System, Account: r.Account, Outcome: OutcomeFailed, Detail: detail,
		StartedAt: t, FinishedAt: t}
	return &Report{IdentityID: r.IdentityID, Trigger: "retry", StartedAt: t, FinishedAt: t, Steps: []StepResult{st},
		Providers: rollUp([]StepResult{st}), Manual: []ManualTask{}}
}

// SweepRetries runs RunRetries for every active tenant; an error in one
// tenant is returned after the others ran.
func (s *Service) SweepRetries(ctx context.Context, db *store.DB, actor string) error {
	tenants, err := db.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tenants {
		if _, err := s.RunRetries(ctx, db, t.ID, actor, ""); err != nil && ctx.Err() == nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Slug, err))
		}
	}
	return errors.Join(errs...)
}

// RetryView is the API form of a retry task.
type RetryView struct {
	ID            string  `json:"id"`
	IdentityID    int64   `json:"identity_id"`
	System        string  `json:"system"`
	Account       string  `json:"account"`
	Action        string  `json:"action"`
	Trigger       string  `json:"trigger"`
	Status        string  `json:"status"`
	Attempts      int     `json:"attempts"`
	NextAttemptAt *string `json:"next_attempt_at"` // pending only
	LastError     string  `json:"last_error"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
	// ManualAction is set once Tessera gave up: what a person must do.
	ManualAction string `json:"manual_action,omitempty"`
}

// ViewRetry renders a task.
func ViewRetry(r *store.ContainmentRetry) RetryView {
	v := RetryView{ID: r.ID, IdentityID: r.IdentityID, System: r.System, Account: r.Account, Action: r.Action,
		Trigger: r.Trigger, Status: r.Status, Attempts: r.Attempts, LastError: r.LastError,
		CreatedAt: timeutil.ISO(r.CreatedAt), UpdatedAt: timeutil.ISO(r.UpdatedAt)}
	if r.Status == store.RetryPending {
		n := timeutil.ISO(r.NextAttemptAt)
		v.NextAttemptAt = &n
	}
	if r.Status == store.RetryGaveUp {
		v.ManualAction = fmt.Sprintf("Revoke %s for %s in the %s admin console by hand.", whatOf(r.Action), r.Account, r.System)
	}
	return v
}
