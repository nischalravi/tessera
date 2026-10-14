package rotation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Engine is the worker that runs rotation jobs. Each call to RunOnce visits
// every active tenant, queues the rotations its policies call for and moves
// every due job one step. A step makes its provider calls outside any
// database transaction and then records the result, the audit event and the
// owner notification in one tenant transaction, so a crash between the two
// leaves a state the next run can recover from.
type Engine struct {
	DB      *store.DB
	Service *Service
	Factory *Factory
	Clock   timeutil.Clock
	Log     *slog.Logger
	// MaxAttempts is how many times a step may fail transiently before the job
	// fails (default 5).
	MaxAttempts int
	// Lease is how long a worker owns a job it is stepping (default 5 minutes).
	Lease time.Duration
	// Batch is how many due jobs one run takes per tenant (default 25).
	Batch int
	// Sleep waits between the in-step hand-over retries (default: a timer).
	Sleep func(ctx context.Context, d time.Duration)
}

const workerName = "rotation.worker"

func (e *Engine) now() time.Time {
	if e.Clock == nil {
		return timeutil.System()
	}
	return e.Clock()
}

func (e *Engine) maxAttempts() int {
	if e.MaxAttempts <= 0 {
		return 5
	}
	return e.MaxAttempts
}

func (e *Engine) lease() time.Duration {
	if e.Lease <= 0 {
		return 5 * time.Minute
	}
	return e.Lease
}

func (e *Engine) batch() int {
	if e.Batch <= 0 {
		return 25
	}
	return e.Batch
}

func (e *Engine) log() *slog.Logger {
	if e.Log == nil {
		return slog.Default()
	}
	return e.Log
}

func (e *Engine) sleep(ctx context.Context, d time.Duration) {
	if e.Sleep != nil {
		e.Sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// backoff is how long a transiently failed step waits: 30 s, doubling, at most an hour.
func backoff(attempt int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < attempt && d < time.Hour; i++ {
		d *= 2
	}
	return min(d, time.Hour)
}

// Loop runs RunOnce every interval until ctx is done.
func (e *Engine) Loop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := e.RunOnce(ctx); err != nil && ctx.Err() == nil {
			e.log().Error("rotation run failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce visits every active tenant and returns how many job steps ran. A
// failure in one tenant is logged and does not stop the others.
func (e *Engine) RunOnce(ctx context.Context) (int, error) {
	ctx = audit.WithSystemActor(ctx, workerName)
	tenants, err := e.DB.ActiveTenants(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, t := range tenants {
		c, err := e.RunTenant(ctx, t.ID)
		n += c
		if err != nil && ctx.Err() == nil {
			e.log().Error("rotation run failed for a tenant", "tenant", t.Slug, "err", err)
		}
	}
	return n, ctx.Err()
}

// RunTenant queues the policy-triggered rotations of one tenant and steps its due jobs.
func (e *Engine) RunTenant(ctx context.Context, t tenancy.ID) (int, error) {
	now := e.now()
	var due []int64
	if err := e.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		due, err = e.Service.DueAutoRotations(tx, now)
		return err
	}); err != nil {
		return 0, err
	}
	for _, id := range due {
		if err := e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
			return e.Service.QueueDue(tx, id, workerName, now)
		}); err != nil {
			e.log().Error("queueing a policy rotation failed", "secret", id, "err", err)
		}
	}
	var jobs []*store.RotationJob
	if err := e.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		jobs, err = tx.DueRotationJobs(now, e.batch())
		return err
	}); err != nil {
		return 0, err
	}
	n := 0
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		ran, err := e.Step(ctx, t, j.ID)
		if ran {
			n++
		}
		if err != nil && ctx.Err() == nil {
			e.log().Error("rotation step failed", "job", j.ID, "err", err)
		}
	}
	return n, nil
}

// stepCtx is what a step needs, read in the transaction that claims the job.
type stepCtx struct {
	job        *store.RotationJob
	secret     *store.Secret
	acct       *store.Account
	adapterRow *store.RotationAdapter
	destRow    *store.RotationAdapter
	owner      *Owner
}

var errNotClaimed = errors.New("rotation: job not claimed")

func ownerFor(tx *store.TenantTx, acct *store.Account) (*Owner, error) {
	if acct == nil || acct.IdentityID == nil {
		return nil, nil
	}
	who, err := tx.Identity(*acct.IdentityID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if who.Type != "human" {
		if who.OwnerID == nil {
			return nil, nil // orphaned machine identity: the notification escalates
		}
		if who, err = tx.Identity(*who.OwnerID); errors.Is(err, store.ErrNotFound) {
			return nil, nil
		} else if err != nil {
			return nil, err
		}
	}
	if who.Status != "active" {
		return nil, nil // an owner who has left cannot act on a notification: it escalates
	}
	o := &Owner{IdentityID: who.ID, Name: who.Name}
	if who.Email != nil {
		o.Email = *who.Email
	}
	return o, nil
}

// Step claims one job and moves it one step. ran is false when another
// worker holds the job or it was not due.
func (e *Engine) Step(ctx context.Context, t tenancy.ID, jobID string) (ran bool, err error) {
	now := e.now()
	var sc stepCtx
	err = e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		j, err := tx.RotationJob(jobID)
		if err != nil {
			return err
		}
		ok, err := tx.ClaimRotationJob(j.ID, j.State, now, now.Add(e.lease()))
		if err != nil {
			return err
		}
		if !ok {
			return errNotClaimed
		}
		sc.job = j
		if sc.secret, err = tx.SecretByID(j.SecretID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if sc.secret != nil {
			if sc.acct, err = tx.Account(sc.secret.AccountID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		if sc.adapterRow, err = tx.RotationAdapter(j.AdapterID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if j.DestAdapterID != nil {
			if sc.destRow, err = tx.RotationAdapter(*j.DestAdapterID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		sc.owner, err = ownerFor(tx, sc.acct)
		return err
	})
	if errors.Is(err, errNotClaimed) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, e.run(ctx, t, &sc)
}

// run does the provider calls of the claimed job's current state.
func (e *Engine) run(ctx context.Context, t tenancy.ID, sc *stepCtx) error {
	j := sc.job
	from := j.State
	if sc.secret == nil || sc.adapterRow == nil {
		return e.fail(ctx, t, sc, from, fail("rotation", "missing_reference", "the secret or its adapter no longer exists", false))
	}
	built, err := e.Factory.Build(sc.adapterRow)
	if err != nil {
		e.log().Error("building a rotation adapter failed", "adapter", sc.adapterRow.Name, "err", err)
		return e.fail(ctx, t, sc, from, fail("adapter", "unavailable", "the adapter cannot be opened (credential, type or environment)", false))
	}
	var dest Destination
	if sc.destRow != nil {
		db, err := e.Factory.Build(sc.destRow)
		if err != nil || db.Destination == nil {
			if err != nil {
				e.log().Error("building a rotation destination failed", "adapter", sc.destRow.Name, "err", err)
			}
			return e.fail(ctx, t, sc, from, fail("destination", "unavailable", "the destination vault cannot be opened (credential, type or environment)", false))
		}
		dest = db.Destination
	}
	ad := built.Adapter
	target := targetOf(sc.secret, sc.acct, j.OldRef)
	if j.NewRef != nil {
		target.NewRef = *j.NewRef
	}
	switch from {
	case store.RotPending:
		return e.create(ctx, t, sc, ad, dest, target)
	case store.RotCreated:
		return e.resumeCreated(ctx, t, sc, ad, target)
	case store.RotHandedOver:
		return e.disable(ctx, t, sc, ad, target)
	case store.RotOldDisabled:
		return e.verify(ctx, t, sc, ad, target)
	case store.RotVerified:
		return e.deleteOld(ctx, t, sc, ad, target)
	}
	return nil
}

// commit writes the job's new state, an audit event and an optional extra
// (the inventory update, the owner notification) in one transaction.
func (e *Engine) commit(ctx context.Context, t tenancy.ID, sc *stepCtx, from string, action string, d ojson.Object,
	extra func(tx *store.TenantTx, now time.Time) error) error {
	now := e.now()
	return e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		if err := tx.UpdateRotationJob(sc.job, from, now); err != nil {
			return err
		}
		base := ojson.Object{{Key: "secret_id", Value: sc.job.SecretID}, {Key: "state", Value: sc.job.State}}
		if err := record(tx, now, action, "rotation_job", sc.job.ID, append(base, d...)); err != nil {
			return err
		}
		if extra != nil {
			return extra(tx, now)
		}
		return nil
	})
}

func errText(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return truncate(e.Error(), 300)
	}
	return "internal error; see the server log"
}

// fail records a failed step: a transient error schedules a retry (the job
// keeps its state) until MaxAttempts, anything else fails the job at this
// state, where Retry resumes it.
func (e *Engine) fail(ctx context.Context, t tenancy.ID, sc *stepCtx, from string, cause error) error {
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause // the lease expires; the next run retries
	}
	var ev *Error
	if !errors.As(cause, &ev) {
		e.log().Error("rotation step failed", "job", sc.job.ID, "state", from, "err", cause)
	}
	now := e.now()
	j := sc.job
	j.Attempts++
	msg := errText(cause)
	j.LastError = &msg
	if IsTransient(cause) && j.Attempts < e.maxAttempts() {
		j.NextStepAt = now.Add(backoff(j.Attempts))
		return e.commit(ctx, t, sc, from, "rotation.job.step_failed", ojson.Object{{Key: "transient", Value: true},
			{Key: "attempts", Value: j.Attempts}, {Key: "error", Value: msg}, {Key: "retry_at", Value: timeutil.ISO(j.NextStepAt)}}, nil)
	}
	j.FailedState, j.State, j.NextStepAt = &from, store.RotFailed, now
	return e.commit(ctx, t, sc, from, "rotation.job.failed", ojson.Object{{Key: "failed_at", Value: from},
		{Key: "attempts", Value: j.Attempts}, {Key: "error", Value: msg}},
		func(tx *store.TenantTx, now time.Time) error {
			return e.Service.notify(tx, e.note(sc, EventFailed,
				fmt.Sprintf("Rotation of %s failed at %s", sc.name(), from),
				msg+". The old credential has not been deleted. Fix the cause and retry the job in Tessera."))
		})
}

func (sc *stepCtx) name() string {
	if sc.secret == nil {
		return fmt.Sprintf("secret %d", sc.job.SecretID)
	}
	return sc.secret.Name
}

// note builds a notification for the claimed job's secret.
func (e *Engine) note(sc *stepCtx, event, subject, body string) Notification {
	n := Notification{Event: event, JobID: sc.job.ID, Owner: sc.owner, Subject: subject, Body: body, SecretID: sc.job.SecretID}
	if sc.job.BulkID != nil {
		n.BulkID = *sc.job.BulkID
	}
	if sc.secret != nil {
		n.SecretName, n.System, n.Kind = sc.secret.Name, sc.secret.System, sc.secret.Kind
	}
	return n
}

// create makes the new credential and hands it over in the same step, so its
// secret material only ever lives in this function.
func (e *Engine) create(ctx context.Context, t tenancy.ID, sc *stepCtx, ad Adapter, dest Destination, target Target) error {
	j := sc.job
	if ad.Capabilities().NeedsDestination && dest == nil {
		return e.fail(ctx, t, sc, store.RotPending, fail("create", "no_destination", "the job has no destination vault", false))
	}
	if err := ad.Validate(target); err != nil {
		return e.fail(ctx, t, sc, store.RotPending, fail("create", "invalid_reference", err.Error(), false))
	}
	minted, err := ad.Create(ctx, target)
	if err != nil {
		return e.fail(ctx, t, sc, store.RotPending, err)
	}
	newRef := minted.Ref
	j.NewRef = &newRef
	if minted.OldRef != "" {
		j.OldRef = minted.OldRef
	}
	j.State, j.NextStepAt = store.RotCreated, e.now()
	if err := e.commit(ctx, t, sc, store.RotPending, "rotation.job.created", ojson.Object{{Key: "new_ref", Value: newRef}}, nil); err != nil {
		// The new credential exists but is not recorded: remove it, best effort.
		if !ad.Capabilities().MaterialFree {
			if derr := ad.DeleteNew(context.WithoutCancel(ctx), target, newRef); derr != nil {
				e.log().Error("a new credential could not be recorded or removed", "job", j.ID, "new_ref", newRef)
			}
		}
		return err
	}
	target.Ref, target.NewRef = j.OldRef, newRef
	return e.handOver(ctx, t, sc, ad, dest, target, minted)
}

// handOver gives the new credential to the destination. Failing after the
// credential exists, it removes the credential again (it cannot be handed over
// later: Tessera does not keep it) so a retry starts clean.
func (e *Engine) handOver(ctx context.Context, t tenancy.ID, sc *stepCtx, ad Adapter, dest Destination, target Target, minted *Minted) error {
	j := sc.job
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		if err = ad.HandOver(ctx, target, minted, dest, j.DestPath); err == nil || !IsTransient(err) || ctx.Err() != nil {
			break
		}
		e.sleep(ctx, time.Duration(attempt)*500*time.Millisecond)
	}
	if err != nil {
		if ad.Capabilities().MaterialFree {
			return e.fail(ctx, t, sc, store.RotCreated, err) // resumable: the next run polls again
		}
		if derr := ad.DeleteNew(context.WithoutCancel(ctx), target, *j.NewRef); derr != nil {
			e.log().Error("a new credential could not be removed after a failed hand-over", "job", j.ID, "err", derr)
			return e.fail(ctx, t, sc, store.RotCreated, fail("hand over", "orphaned_new_credential",
				"the new credential "+*j.NewRef+" was created but not handed over and could not be removed; delete it by hand, then retry", false))
		}
		// removed: back to pending, as if Create had not happened
		j.NewRef = nil
		if IsTransient(err) && j.Attempts+1 < e.maxAttempts() {
			j.Attempts++
			msg := errText(err)
			j.LastError, j.State, j.NextStepAt = &msg, store.RotPending, e.now().Add(backoff(j.Attempts))
			return e.commit(ctx, t, sc, store.RotCreated, "rotation.job.step_failed", ojson.Object{{Key: "transient", Value: true},
				{Key: "attempts", Value: j.Attempts}, {Key: "error", Value: msg}, {Key: "rolled_back", Value: true}}, nil)
		}
		return e.failRolledBack(ctx, t, sc, err)
	}
	now := e.now()
	j.State, j.HandedOverAt, j.Attempts, j.LastError = store.RotHandedOver, &now, 0, nil
	j.NextStepAt = now.Add(time.Duration(j.GraceHours) * time.Hour)
	return e.commit(ctx, t, sc, store.RotCreated, "rotation.job.handed_over", ojson.Object{{Key: "destination", Value: destName(sc)},
		{Key: "dest_path", Value: j.DestPath}, {Key: "grace_hours", Value: j.GraceHours},
		{Key: "disable_after", Value: timeutil.ISO(j.NextStepAt)}}, nil)
}

func destName(sc *stepCtx) any {
	if sc.destRow == nil {
		return nil
	}
	return sc.destRow.Name
}

// failRolledBack fails a job whose created credential was removed again: it
// returns to pending, so Retry starts from the beginning.
func (e *Engine) failRolledBack(ctx context.Context, t tenancy.ID, sc *stepCtx, cause error) error {
	j := sc.job
	j.NewRef = nil
	now := e.now()
	pending := store.RotPending
	j.Attempts++
	msg := errText(cause)
	j.LastError, j.FailedState, j.State, j.NextStepAt = &msg, &pending, store.RotFailed, now
	return e.commit(ctx, t, sc, store.RotCreated, "rotation.job.failed", ojson.Object{{Key: "failed_at", Value: "hand_over"},
		{Key: "attempts", Value: j.Attempts}, {Key: "error", Value: msg}, {Key: "rolled_back", Value: true}},
		func(tx *store.TenantTx, now time.Time) error {
			return e.Service.notify(tx, e.note(sc, EventFailed,
				fmt.Sprintf("Rotation of %s failed while handing over the new credential", sc.name()),
				msg+". The new credential was removed again and the old one is untouched. Fix the cause and retry the job."))
		})
}

// resumeCreated recovers a job found in state created, which means a worker
// stopped between creating the credential and handing it over.
func (e *Engine) resumeCreated(ctx context.Context, t tenancy.ID, sc *stepCtx, ad Adapter, target Target) error {
	j := sc.job
	if ad.Capabilities().MaterialFree {
		return e.handOver(ctx, t, sc, ad, nil, target, nil)
	}
	// The new secret was only in memory and is gone: remove the credential and start over.
	if err := ad.DeleteNew(ctx, target, *j.NewRef); err != nil {
		return e.fail(ctx, t, sc, store.RotCreated, err)
	}
	ref := *j.NewRef
	j.NewRef, j.State, j.NextStepAt = nil, store.RotPending, e.now()
	return e.commit(ctx, t, sc, store.RotCreated, "rotation.job.recovered", ojson.Object{{Key: "removed_ref", Value: ref}}, nil)
}

// disable deactivates the old credential once the grace period is over.
func (e *Engine) disable(ctx context.Context, t tenancy.ID, sc *stepCtx, ad Adapter, target Target) error {
	j := sc.job
	disabled := true
	if err := ad.DisableOld(ctx, target); errors.Is(err, ErrUnsupported) {
		disabled = false
	} else if err != nil {
		return e.fail(ctx, t, sc, store.RotHandedOver, err)
	}
	now := e.now()
	j.State, j.DisabledAt, j.NextStepAt, j.Attempts, j.LastError = store.RotOldDisabled, &now, now, 0, nil
	return e.commit(ctx, t, sc, store.RotHandedOver, "rotation.job.old_disabled", ojson.Object{
		{Key: "disabled", Value: disabled}}, nil)
}

// verify re-reads the old credential and records what it found. Only a clean
// reading moves the job to verified.
func (e *Engine) verify(ctx context.Context, t tenancy.ID, sc *stepCtx, ad Adapter, target Target) error {
	j := sc.job
	obs, err := ad.ObserveOld(ctx, target)
	if err != nil {
		return e.fail(ctx, t, sc, store.RotOldDisabled, err)
	}
	now := e.now()
	ver := Verify(obs, ad.Capabilities(), j.DisabledAt, now)
	raw, err := json.Marshal(ver)
	if err != nil {
		return err
	}
	rawStr := string(raw)
	j.Verification = &rawStr
	d := ojson.Object{{Key: "verdict", Value: ver.Verdict}, {Key: "evidence", Value: ver.Evidence},
		{Key: "old_exists", Value: ver.OldExists}, {Key: "old_active", Value: ver.OldActive},
		{Key: "old_age_days", Value: intOrNil(ver.OldAgeDays)}, {Key: "last_used_known", Value: ver.LastUsedKnown},
		{Key: "old_last_used_at", Value: timeOrNil(ver.OldLastUsedAt)}}
	if ver.Verdict != VerdictOK {
		msg := truncate(ver.Verdict+": "+ver.Detail, 300)
		from := store.RotOldDisabled
		j.Attempts++
		j.LastError, j.FailedState, j.State, j.NextStepAt = &msg, &from, store.RotFailed, now
		return e.commit(ctx, t, sc, from, "rotation.job.failed", append(ojson.Object{{Key: "failed_at", Value: "verify"}}, d...),
			func(tx *store.TenantTx, now time.Time) error {
				return e.Service.notify(tx, e.note(sc, EventFailed,
					fmt.Sprintf("Rotation of %s stopped before deleting the old credential", sc.name()),
					msg+". Nothing was deleted. Move the consumers to the new credential, then retry the job."))
			})
	}
	j.State, j.VerifiedAt, j.NextStepAt, j.Attempts, j.LastError = store.RotVerified, &now, now, 0, nil
	return e.commit(ctx, t, sc, store.RotOldDisabled, "rotation.job.verified", d, nil)
}

// deleteOld deletes the verified old credential, confirms it is gone and
// completes the rotation.
func (e *Engine) deleteOld(ctx context.Context, t tenancy.ID, sc *stepCtx, ad Adapter, target Target) error {
	j := sc.job
	if j.NewRef == nil {
		return e.fail(ctx, t, sc, store.RotVerified, fail("delete", "missing_reference", "the job has no new credential", false))
	}
	if err := ad.DeleteOld(ctx, target); err != nil {
		return e.fail(ctx, t, sc, store.RotVerified, err)
	}
	obs, err := ad.ObserveOld(ctx, target)
	if err != nil {
		return e.fail(ctx, t, sc, store.RotVerified, err)
	}
	caps := ad.Capabilities()
	done, disposition := retired(caps, obs)
	if !done {
		// A stale read or a delete that did not take: re-read after the backoff
		// within the retry budget; only an observed retirement completes the job.
		msg := "the provider still lists the old credential after it was deleted"
		if caps.Retirement == RetireDeprecated {
			msg = "the old version still carries AWSCURRENT or AWSPENDING"
		}
		return e.fail(ctx, t, sc, store.RotVerified, fail("delete", "old_credential_still_present", msg, true))
	}
	now := e.now()
	j.State, j.CompletedAt, j.Attempts, j.LastError = store.RotOldDeleted, &now, 0, nil
	return e.commit(ctx, t, sc, store.RotVerified, "rotation.completed", ojson.Object{{Key: "old_ref", Value: j.OldRef},
		{Key: "new_ref", Value: refOrNil(j.NewRef)}, {Key: "old_disposition", Value: disposition},
		{Key: "old_deleted", Value: disposition == DispositionDeleted}},
		func(tx *store.TenantTx, now time.Time) error {
			ref := ad.InventoryRef(j.OldRef, *j.NewRef)
			if err := tx.ReplaceSecretCredential(sc.secret.ID, ref, now); errors.Is(err, store.ErrDuplicate) {
				err = tx.SetSecretRotated(sc.secret.ID, now) // the inventory already lists the new credential
				if err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			outcome := "deleted and observed absent"
			if disposition == DispositionDeprecated {
				outcome = "retired (deprecated, not deleted): the old version no longer carries AWSCURRENT or AWSPENDING"
			}
			return e.Service.notify(tx, e.note(sc, EventCompleted, fmt.Sprintf("Rotated %s on %s", sc.secret.Name, sc.secret.System),
				"The new credential was handed over, the old one was verified unused after the grace period and "+outcome+"."))
		})
}

func intOrNil(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func timeOrNil(p *time.Time) any {
	if p == nil {
		return nil
	}
	return timeutil.ISO(*p)
}

func refOrNil(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}
