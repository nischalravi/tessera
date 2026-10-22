package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/okta"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/scim"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Target kinds.
const (
	KindSCIM = "scim"
	KindOkta = "okta"
	KindFake = "fake"
)

// WorkerActor is the system actor of worker events.
const WorkerActor = "provisioning.worker"

// Settings are the target settings kept as JSON.
type Settings struct {
	// Dialect is the SCIM dialect: "standard" or "entra".
	Dialect string `json:"dialect,omitempty"`
	// Fault is the fake target's fault mode (dev only).
	Fault string `json:"fault,omitempty"`
	// OnDeprovision says what happens to a person's account here once the grace
	// period after their last affiliation ended has passed: "disable" (the
	// default: leave it disabled) or "delete" it in the target (issue #74).
	OnDeprovision string `json:"on_deprovision,omitempty"`
}

// Engine sends queued operations to their targets and verifies them.
type Engine struct {
	DB     *store.DB
	Sealer *seal.Sealer
	// HTTP must be an internal/safehttp client.
	HTTP  *http.Client
	Clock func() time.Time
	Log   *slog.Logger

	// MaxAttempts is how many times an operation is sent before it fails (5).
	MaxAttempts int
	// MaxVerifies is how many re-reads may disagree before a mismatch (3):
	// a target can take a moment to show a change.
	MaxVerifies int
	// Backoff is the wait after attempt n (n >= 1). Default: 5s doubling to 10 minutes.
	Backoff func(n int) time.Duration
	// Batch is how many operations one pass takes (50).
	Batch int
	// CallTimeout bounds one connector call (30s).
	CallTimeout time.Duration
	// Build creates the connector of a target (tests inject fakes).
	Build func(t *store.ProvTarget, token string) (target.Connector, error)
	// Guard, when set, runs every call to a target under that target's
	// limits and circuit breaker (internal/worker.Guard). A call it refuses
	// with a Deferred error is not an attempt: the operation waits and is
	// taken again later.
	Guard Guarder
}

// Guarder runs fn as one call to the target of connection connID, or refuses it.
type Guarder interface {
	Do(ctx context.Context, t tenancy.ID, connID string, fn func(context.Context) error) error
}

// Deferred is an error from a Guarder that says "not now": the call was not
// made, and may be tried again after DeferFor.
type Deferred interface {
	error
	DeferFor() time.Duration
}

// guarded makes one call to a connection's target: under the Guard if there
// is one, with the call timeout either way.
func (e *Engine) guarded(ctx context.Context, t tenancy.ID, connID string, fn func(context.Context) error) error {
	run := func(ctx context.Context) error {
		cctx, cancel := e.call(ctx)
		defer cancel()
		return fn(cctx)
	}
	if e.Guard == nil {
		return run(ctx)
	}
	return e.Guard.Do(ctx, t, connID, run)
}

// Stats counts what one pass did.
type Stats struct {
	Processed int `json:"processed"`
	Verified  int `json:"verified"`
	Mismatch  int `json:"mismatch"`
	Failed    int `json:"failed"`
	Retrying  int `json:"retrying"`
}

func (s *Stats) add(o Stats) {
	s.Processed += o.Processed
	s.Verified += o.Verified
	s.Mismatch += o.Mismatch
	s.Failed += o.Failed
	s.Retrying += o.Retrying
}

const (
	verifyLease = 2 * time.Minute  // a claimed re-read is not taken by another pass for this long
	staleSent   = 10 * time.Minute // a sent operation older than this was abandoned by a stopped worker
)

func (e *Engine) maxAttempts() int { return orInt(e.MaxAttempts, 5) }
func (e *Engine) maxVerifies() int { return orInt(e.MaxVerifies, 3) }

func orInt(v, d int) int {
	if v > 0 {
		return v
	}
	return d
}

func (e *Engine) backoff(n int) time.Duration {
	if e.Backoff != nil {
		return e.Backoff(n)
	}
	d := 5 * time.Second
	for i := 1; i < n && d < 10*time.Minute; i++ {
		d *= 2
	}
	return min(d, 10*time.Minute)
}

func (e *Engine) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

// SealToken seals a target credential for storage.
func SealToken(s *seal.Sealer, t tenancy.ID, targetID, token string) ([]byte, error) {
	return s.Seal([]byte(token), seal.AAD(t, "provisioning_targets", "credential_enc", targetID))
}

func (e *Engine) openToken(t tenancy.ID, pt *store.ProvTarget) (string, error) {
	if len(pt.CredentialEnc) == 0 {
		return "", nil
	}
	b, err := e.Sealer.Open(pt.CredentialEnc, seal.AAD(t, "provisioning_targets", "credential_enc", pt.ID))
	if err != nil {
		return "", errors.New("the stored credential cannot be opened with the current key")
	}
	return string(b), nil
}

func (e *Engine) build(pt *store.ProvTarget, token string) (target.Connector, error) {
	if e.Build != nil {
		return e.Build(pt, token)
	}
	if e.HTTP == nil {
		return nil, errors.New("no outbound client is configured")
	}
	var s Settings
	if err := json.Unmarshal([]byte(pt.Settings), &s); err != nil {
		return nil, fmt.Errorf("target settings are unreadable: %w", err)
	}
	switch pt.Kind {
	case KindSCIM, KindFake:
		c := &scim.Client{HTTP: e.HTTP, BaseURL: pt.BaseURL, Token: token, Dialect: s.Dialect}
		if pt.Kind == KindFake && s.Fault != "" {
			c.Header = http.Header{"X-Fake-Fault": {s.Fault}}
		}
		return c, nil
	case KindOkta:
		return &okta.Client{HTTP: e.HTTP, BaseURL: pt.BaseURL, Token: token}, nil
	}
	return nil, fmt.Errorf("unknown target kind %q", pt.Kind)
}

func (e *Engine) workerCtx(ctx context.Context) context.Context {
	return audit.AsSystem(ctx, WorkerActor)
}

// RunTenant takes the tenant's due operations and drives each as far as it
// goes: sent, then re-read at once. Operations whose target is slow stay
// pending_verification or queued with a next attempt time, to be taken by a
// later pass.
func (e *Engine) RunTenant(ctx context.Context, t tenancy.ID) (Stats, error) {
	ctx = e.workerCtx(ctx)
	now := e.now()
	var due []*store.ProvOp
	err := e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		if _, err := tx.RequeueStaleProvOps(now.Add(-staleSent), now); err != nil {
			return err
		}
		ops, err := tx.DueProvOps(now, orInt(e.Batch, 50))
		if err != nil {
			return err
		}
		for _, op := range ops { // claim: no other pass takes them
			st := store.ProvOpState{Status: op.Status, Attempts: op.Attempts, VerifyAttempts: op.VerifyAttempts,
				NextAttemptAt: now.Add(verifyLease), LastError: op.LastError, Observed: op.Observed}
			if op.Status == Queued {
				st.Status, st.Attempts, st.NextAttemptAt = Sent, op.Attempts+1, now
			} else {
				st.VerifyAttempts++
			}
			if err := tx.SetProvOpState(op.ID, op.Status, st, now); err != nil {
				return err
			}
			op.Status, op.Attempts, op.VerifyAttempts = st.Status, st.Attempts, st.VerifyAttempts
			due = append(due, op)
		}
		return nil
	})
	var stats Stats
	if err != nil {
		return stats, err
	}
	conns := map[string]target.Connector{}
	var firstErr error
	for _, op := range due {
		if ctx.Err() != nil {
			break
		}
		s, err := e.process(ctx, t, op, conns)
		stats.add(s)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return stats, firstErr
}

// connector loads the target of a connection and builds its connector.
func (e *Engine) connector(ctx context.Context, t tenancy.ID, connID string, cache map[string]target.Connector) (target.Connector, error) {
	if c, ok := cache[connID]; ok {
		return c, nil
	}
	var pt *store.ProvTarget
	err := e.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		pt, err = tx.ProvTarget(connID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, target.Permanent("the connection no longer has a provisioning target")
	}
	if err != nil {
		return nil, err
	}
	token, err := e.openToken(t, pt)
	if err != nil {
		return nil, target.Permanent("%v", err)
	}
	c, err := e.build(pt, token)
	if err != nil {
		return nil, target.Permanent("%v", err)
	}
	cache[connID] = c
	return c, nil
}

func (e *Engine) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, orDur(e.CallTimeout, 30*time.Second))
}

func orDur(v, d time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return d
}

func errText(err error) string { return jobs.ErrorSummary(err) }

func sp(s string) *string { return &s }

// process drives one claimed operation.
func (e *Engine) process(ctx context.Context, t tenancy.ID, op *store.ProvOp, conns map[string]target.Connector) (Stats, error) {
	st := Stats{Processed: 1}
	req, err := Request(op)
	if err != nil {
		return st, e.fail(ctx, t, op, err, &st)
	}
	conn, err := e.connector(ctx, t, op.ConnectionID, conns)
	if err != nil {
		if target.Retryable(err) {
			return st, e.retryLater(ctx, t, op, err, &st)
		}
		return st, e.fail(ctx, t, op, err, &st)
	}
	if op.Status == Sent {
		err := e.guarded(ctx, t, op.ConnectionID, func(cctx context.Context) error { return conn.Apply(cctx, req) })
		var def Deferred
		if errors.As(err, &def) {
			return st, e.deferOp(ctx, t, op, def, &st)
		}
		if err != nil {
			if target.Retryable(err) && op.Attempts < e.maxAttempts() {
				return st, e.retryLater(ctx, t, op, err, &st)
			}
			return st, e.fail(ctx, t, op, err, &st)
		}
		// The target accepted the change; it is not done until a re-read shows it.
		now := e.now()
		op.VerifyAttempts++
		if err := e.set(ctx, t, op, Sent, store.ProvOpState{Status: PendingVerification, Attempts: op.Attempts,
			VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now}, "provision.sent", nil); err != nil {
			return st, err
		}
		op.Status = PendingVerification
	}
	return st, e.verify(ctx, t, op, conn, req, &st)
}

// set moves an operation between statuses in one transaction, with its audit event.
func (e *Engine) set(ctx context.Context, t tenancy.ID, op *store.ProvOp, from string, to store.ProvOpState, action string,
	extra func(tx *store.TenantTx, now time.Time) (ojson.Object, error)) error {
	return e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		now := e.now()
		if err := tx.SetProvOpState(op.ID, from, to, now); err != nil {
			return err
		}
		detail := ojson.Object{{Key: "op_id", Value: op.ID}, {Key: "kind", Value: op.Kind},
			{Key: "target", Value: op.TargetRef}, {Key: "status", Value: to.Status}, {Key: "attempts", Value: to.Attempts}}
		if to.LastError != nil && to.Status == Failed {
			detail = append(detail, ojson.KV{Key: "error", Value: *to.LastError})
		}
		if extra != nil {
			more, err := extra(tx, now)
			if err != nil {
				return err
			}
			detail = append(detail, more...)
		}
		if action == "" {
			return nil
		}
		return tx.Audit(now, WorkerActor, action, detail)
	})
}

// deferOp puts back an operation whose call the target's guard refused (the
// breaker is open, or the rate limit is spent). Nothing was sent, so the
// attempt this pass counted is given back: a target that is down for an hour
// does not fail every operation queued for it.
func (e *Engine) deferOp(ctx context.Context, t tenancy.ID, op *store.ProvOp, d Deferred, st *Stats) error {
	now := e.now()
	st.Retrying++
	next := now.Add(max(d.DeferFor(), time.Second))
	msg := sp("waiting: " + errText(d))
	if op.Status == Sent {
		return e.set(ctx, t, op, Sent, store.ProvOpState{Status: Queued, Attempts: max(0, op.Attempts-1),
			VerifyAttempts: op.VerifyAttempts, NextAttemptAt: next, LastError: msg}, "", nil)
	}
	return e.set(ctx, t, op, op.Status, store.ProvOpState{Status: op.Status, Attempts: op.Attempts,
		VerifyAttempts: max(0, op.VerifyAttempts-1), NextAttemptAt: next, LastError: msg, Observed: op.Observed}, "", nil)
}

// retryLater re-queues an operation whose send failed in a way a later
// attempt may fix.
func (e *Engine) retryLater(ctx context.Context, t tenancy.ID, op *store.ProvOp, cause error, st *Stats) error {
	now := e.now()
	if op.Attempts >= e.maxAttempts() {
		return e.fail(ctx, t, op, cause, st)
	}
	st.Retrying++
	return e.set(ctx, t, op, op.Status, store.ProvOpState{Status: Queued, Attempts: op.Attempts, VerifyAttempts: op.VerifyAttempts,
		NextAttemptAt: now.Add(e.backoff(op.Attempts)), LastError: sp(errText(cause))}, "", nil)
}

// fail ends an operation: its completion never runs, so the item it was for stays open.
func (e *Engine) fail(ctx context.Context, t tenancy.ID, op *store.ProvOp, cause error, st *Stats) error {
	now := e.now()
	st.Failed++
	return e.set(ctx, t, op, op.Status, store.ProvOpState{Status: Failed, Attempts: op.Attempts, VerifyAttempts: op.VerifyAttempts,
		NextAttemptAt: now, LastError: sp(errText(cause)), CompletedAt: &now}, "provision.failed", nil)
}

// verify re-reads the target and settles the operation.
func (e *Engine) verify(ctx context.Context, t tenancy.ID, op *store.ProvOp, conn target.Connector, req target.Request, st *Stats) error {
	var v target.Verdict
	err := e.guarded(ctx, t, op.ConnectionID, func(cctx context.Context) (err error) {
		v, err = conn.Verify(cctx, req)
		return err
	})
	var def Deferred
	if errors.As(err, &def) {
		return e.deferOp(ctx, t, op, def, st)
	}
	now := e.now()
	switch {
	case err != nil:
		// The read itself failed: try again later, and give up after the same
		// number of tries a disagreeing read gets.
		if op.VerifyAttempts >= e.maxVerifies() {
			return e.fail(ctx, t, op, fmt.Errorf("could not re-read the target to verify: %w", err), st)
		}
		st.Retrying++
		return e.set(ctx, t, op, PendingVerification, store.ProvOpState{Status: PendingVerification, Attempts: op.Attempts,
			VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now.Add(e.backoff(op.VerifyAttempts)),
			LastError: sp("re-read failed: " + errText(err))}, "", nil)
	case !v.OK && op.VerifyAttempts < e.maxVerifies():
		st.Retrying++
		return e.set(ctx, t, op, PendingVerification, store.ProvOpState{Status: PendingVerification, Attempts: op.Attempts,
			VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now.Add(e.backoff(op.VerifyAttempts)),
			LastError: sp("not yet visible in the target: expected " + v.Expected + ", observed " + v.Observed),
			Observed:  sp(v.Observed)}, "", nil)
	case !v.OK:
		st.Mismatch++
		return e.mismatch(ctx, t, op, v)
	}
	// Verified: the completion and the status change commit together.
	err = e.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		now := e.now()
		if op.Completion != nil {
			if err := runCompletion(tx, now, *op.Completion); err != nil {
				return err
			}
		}
		if err := tx.SetProvOpState(op.ID, PendingVerification, store.ProvOpState{Status: Verified, Attempts: op.Attempts,
			VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now, Observed: sp(v.Observed), CompletedAt: &now}, now); err != nil {
			return err
		}
		if _, err := tx.ResolveProvFindings(op.ID, now); err != nil {
			return err
		}
		return tx.Audit(now, WorkerActor, "provision.verified", ojson.Object{{Key: "op_id", Value: op.ID},
			{Key: "kind", Value: op.Kind}, {Key: "target", Value: op.TargetRef}, {Key: "attempts", Value: op.Attempts},
			{Key: "observed", Value: v.Observed}})
	})
	if err == nil {
		st.Verified++
		return nil
	}
	// The completion could not be applied (the graph changed under it): the
	// target is right but Tessera is not; retry the re-read, then fail loudly.
	cause := fmt.Errorf("verified in the target but Tessera could not apply the change: %w", err)
	if op.VerifyAttempts >= e.maxVerifies() {
		return e.fail(ctx, t, op, cause, st)
	}
	st.Retrying++
	return e.set(ctx, t, op, PendingVerification, store.ProvOpState{Status: PendingVerification, Attempts: op.Attempts,
		VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now.Add(e.backoff(op.VerifyAttempts)), LastError: sp(errText(cause))}, "", nil)
}

func runCompletion(tx *store.TenantTx, now time.Time, raw string) error {
	var env completionEnvelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return fmt.Errorf("unreadable completion: %w", err)
	}
	fn, ok := completionFor(env.Name)
	if !ok {
		return fmt.Errorf("no completion %q is registered", env.Name)
	}
	return fn(tx, now, env.Data)
}

// mismatch ends an operation whose re-read never showed the change, and
// raises a finding.
func (e *Engine) mismatch(ctx context.Context, t tenancy.ID, op *store.ProvOp, v target.Verdict) error {
	now := e.now()
	severity := "medium"
	if op.Kind == target.DisableAccount || op.Kind == target.DeleteAccount || op.Kind == target.RemoveEntitlement {
		severity = "high" // the access that should be gone is still there
	}
	return e.set(ctx, t, op, PendingVerification, store.ProvOpState{Status: Mismatch, Attempts: op.Attempts,
		VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now, LastError: sp("the target does not show the change: expected " + v.Expected + ", observed " + v.Observed),
		Observed: sp(v.Observed), CompletedAt: &now}, "provision.mismatch",
		func(tx *store.TenantTx, now time.Time) (ojson.Object, error) {
			f := &store.ProvFinding{ID: store.NewID(), OpID: op.ID, ConnectionID: op.ConnectionID, Code: "verify_mismatch",
				Severity: severity, Title: fmt.Sprintf("Target did not apply %s for %s", strings.ReplaceAll(op.Kind, "_", " "), op.TargetRef),
				Expected: v.Expected, Observed: v.Observed}
			if err := tx.InsertProvFinding(f, now); err != nil {
				return nil, err
			}
			return ojson.Object{{Key: "finding_id", Value: f.ID}, {Key: "expected", Value: v.Expected},
				{Key: "observed", Value: v.Observed}}, nil
		})
}

// RunAll runs one pass for every active tenant. A tenant whose pass failed is
// logged and does not stop the others.
func (e *Engine) RunAll(ctx context.Context) {
	tenants, err := e.DB.ActiveTenants(ctx)
	if err != nil {
		if ctx.Err() == nil {
			e.log().Error("provisioning: tenants", "err", err)
		}
		return
	}
	for _, tn := range tenants {
		if ctx.Err() != nil {
			return
		}
		started := e.now()
		stats, err := e.RunTenant(ctx, tn.ID)
		if stats.Processed == 0 && err == nil {
			continue
		}
		if err != nil {
			e.log().Error("provisioning pass failed", "tenant", tn.Slug, "err", err)
		}
		// A failed operation is the operation's own outcome (shown in the
		// provisioning view and audited); the run fails only when the pass broke.
		rec := jobs.Start{Kind: jobs.Provision, Trigger: "schedule", Actor: WorkerActor}
		if rerr := jobs.Record(ctx, e.DB, tn.ID, rec, started, e.now(), stats, err); rerr != nil {
			e.log().Error("provisioning: record run", "tenant", tn.Slug, "err", rerr)
		}
	}
}

// Loop runs RunAll every interval until ctx is done.
func (e *Engine) Loop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		e.RunAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (e *Engine) now() time.Time {
	if e.Clock != nil {
		return e.Clock()
	}
	return time.Now().UTC()
}
