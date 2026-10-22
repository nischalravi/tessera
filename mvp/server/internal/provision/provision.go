// Package provision is the closed-loop provisioning engine (issue #103).
//
// Every change Tessera wants in a target system (create, update, disable or
// delete an account; add or remove an entitlement) becomes an operation in
// the provisioning_ops table. A worker sends it through a connector (SCIM 2.0
// or a native one) and then re-reads the target: the operation is verified
// only when the re-read shows the change, and a re-read that does not shows
// raises a finding. Until then the operation is pending_verification and
// Tessera's own records still say the old thing is true.
//
// Callers (JML execute, review revoke, JIT expiry, least-privilege revoke) do
// not edit the graph themselves when their system's connection has write-back
// on. They Submit the change with a completion: the Tessera-side change (the
// graph edit, the review decision) that the engine applies, in the same
// transaction that marks the operation verified. A failed write therefore
// leaves the item open. With write-back off (the default) Submit declines and
// the caller changes the graph at once, as before.
package provision

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Statuses of an operation.
const (
	Queued              = "queued"
	Sent                = "sent"
	PendingVerification = "pending_verification"
	Verified            = "verified"
	Mismatch            = "mismatch"
	Failed              = "failed"
	Cancelled           = "cancelled"
)

// Held is the status of the operation Enqueue returns for a disable or delete the deletion guard held:
// it is not stored and has no id; the held deletion releases it.
const Held = "held"

// Statuses lists every status, in lifecycle order.
var Statuses = []string{Queued, Sent, PendingVerification, Verified, Mismatch, Failed, Cancelled}

// Sources of an operation.
const (
	SourceJML       = "jml"
	SourceReview    = "review"
	SourceJIT       = "jit"
	SourceLeastPriv = "leastpriv"
	SourceDrift     = "drift" // a remediation policy of the reconciliation engine (issue #301)
	SourceGuest     = "guest" // a guest sponsorship's access bundle (issue #75); the key names the sponsorship
	SourceAPI       = "api"
)

// InFlightStatus reports whether an operation of this status may still change the outcome.
func InFlightStatus(s string) bool { return s == Queued || s == Sent || s == PendingVerification }

// Error is a caller error (maps to HTTP 4xx).
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

// CompletionFunc applies the Tessera-side change of a verified operation.
// It runs inside the transaction that marks the operation verified, and must
// be idempotent (a retried worker may run it for an already-applied change).
type CompletionFunc func(tx *store.TenantTx, now time.Time, data json.RawMessage) error

var (
	compMu      sync.RWMutex
	completions = map[string]CompletionFunc{}
)

// RegisterCompletion registers a completion by name. Packages that submit
// changes register theirs in init, so the engine never imports them.
func RegisterCompletion(name string, fn CompletionFunc) {
	compMu.Lock()
	defer compMu.Unlock()
	if _, dup := completions[name]; dup {
		panic("provision: duplicate completion " + name)
	}
	completions[name] = fn
}

func completionFor(name string) (CompletionFunc, bool) {
	compMu.RLock()
	defer compMu.RUnlock()
	fn, ok := completions[name]
	return fn, ok
}

type completionEnvelope struct {
	Name string          `json:"name"`
	Data json.RawMessage `json:"data"`
}

// Change is one change to make in a target system.
type Change struct {
	// System is the connection's system ("okta"): it selects the target.
	System  string
	Kind    string
	Account target.Account
	Group   target.Group
	Source  string
	// Key names the intent ("jit:12:expire"). Submitting the same key twice
	// yields one operation.
	Key string
	// Completion is the registered completion to run once verified; Data its
	// JSON-able argument.
	Completion string
	Data       any
	// NoRequeue leaves an existing operation with this key as it is, even a
	// failed one: a background job must not retry what an operator has to look at.
	NoRequeue bool
}

func (c Change) ref() string {
	if c.Kind == target.AddEntitlement || c.Kind == target.RemoveEntitlement {
		g := c.Group.Name
		if g == "" {
			g = c.Group.ExternalID
		}
		return c.Account.Username + " / " + g
	}
	return c.Account.Username
}

func validKind(k string) bool {
	for _, x := range target.Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// Route returns the target that receives changes of a system, or nil when the
// system has no connection with write-back on (the caller then changes the
// graph directly).
func Route(tx *store.TenantTx, system string) (*store.ProvTarget, error) {
	t, err := tx.ProvTargetBySystem(system)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil || !t.WriteBack {
		return nil, err
	}
	return t, nil
}

// Submit queues a change when the system's connection has write-back on, and
// reports routed. When routed is false nothing was queued and the caller
// applies the change to the graph itself.
//
// Submitting a key that already has an operation returns that operation; if
// it had failed, mismatched or been cancelled it is queued again (the
// operator is trying again), and its audit event says so.
func Submit(tx *store.TenantTx, now time.Time, c Change) (op *store.ProvOp, routed bool, err error) {
	t, err := Route(tx, c.System)
	if err != nil || t == nil {
		return nil, false, err
	}
	op, err = Enqueue(tx, now, t.ConnectionID, c)
	return op, err == nil, err
}

// Enqueue queues a change on a connection (see Submit).
func Enqueue(tx *store.TenantTx, now time.Time, connectionID string, c Change) (*store.ProvOp, error) {
	switch {
	case !validKind(c.Kind):
		return nil, &Error{400, "invalid_kind", "unknown operation kind " + c.Kind}
	case strings.TrimSpace(c.Account.Username) == "":
		return nil, &Error{400, "invalid_account", "an operation needs an account username"}
	case c.Key == "" || len(c.Key) > 200:
		return nil, &Error{400, "invalid_key", "an operation needs an idempotency key of at most 200 characters"}
	case (c.Kind == target.AddEntitlement || c.Kind == target.RemoveEntitlement) && c.Group.ExternalID == "" && c.Group.Name == "":
		return nil, &Error{400, "invalid_group", "an entitlement operation needs a group"}
	}
	if existing, err := tx.ProvOpByKey(c.Key); err == nil {
		if c.NoRequeue {
			return existing, nil
		}
		return requeueIfDone(tx, now, existing)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if held, err := guardOp(tx, now, connectionID, c); err != nil || held {
		if err != nil {
			return nil, err
		}
		// the deletion guard held it (internal/deleteguard): nothing is queued until a second admin releases it
		return &store.ProvOp{ConnectionID: connectionID, Kind: c.Kind, TargetRef: c.ref(), Source: c.Source, IdempotencyKey: c.Key, Status: Held}, nil
	}
	payload, err := json.Marshal(target.Request{Account: c.Account, Group: c.Group})
	if err != nil {
		return nil, err
	}
	var comp *string
	if c.Completion != "" {
		if _, ok := completionFor(c.Completion); !ok {
			return nil, fmt.Errorf("provision: no completion %q is registered", c.Completion)
		}
		data, err := json.Marshal(c.Data)
		if err != nil {
			return nil, err
		}
		env, err := json.Marshal(completionEnvelope{Name: c.Completion, Data: data})
		if err != nil {
			return nil, err
		}
		s := string(env)
		comp = &s
	}
	op := &store.ProvOp{ID: store.NewID(), ConnectionID: connectionID, Kind: c.Kind, TargetRef: c.ref(),
		Payload: string(payload), Completion: comp, Source: c.Source, IdempotencyKey: c.Key, RequestedBy: actorOf(tx)}
	if err := tx.InsertProvOp(op, now); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, "system", "provision.enqueued", ojson.Object{{Key: "op_id", Value: op.ID},
		{Key: "connection_id", Value: connectionID}, {Key: "kind", Value: op.Kind}, {Key: "target", Value: op.TargetRef},
		{Key: "source", Value: op.Source}, {Key: "idempotency_key", Value: op.IdempotencyKey}}); err != nil {
		return nil, err
	}
	return tx.ProvOp(op.ID)
}

// actorOf is who asked: the principal's display name or the system job.
func actorOf(tx *store.TenantTx) string {
	if ac, ok := store.AuditContextFrom(tx.Context()); ok && ac.Actor.Display != nil {
		return *ac.Actor.Display
	}
	return "system"
}

// requeueIfDone returns an operation already submitted under the same key,
// queueing it again when it ended without verifying.
func requeueIfDone(tx *store.TenantTx, now time.Time, op *store.ProvOp) (*store.ProvOp, error) {
	switch op.Status {
	case Failed, Mismatch, Cancelled:
		return Retry(tx, now, op.ID)
	}
	return op, nil
}

// InFlight returns the operation with this key when it can still change the
// outcome (queued, sent or waiting for its re-read), else nil.
func InFlight(tx *store.TenantTx, key string) (*store.ProvOp, error) {
	op, err := tx.ProvOpByKey(key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil || !InFlightStatus(op.Status) {
		return nil, err
	}
	return op, nil
}

// Retry queues a failed, mismatched or cancelled operation again.
func Retry(tx *store.TenantTx, now time.Time, id string) (*store.ProvOp, error) {
	op, err := tx.ProvOp(id)
	if err != nil {
		return nil, err
	}
	switch op.Status {
	case Failed, Mismatch, Cancelled:
	default:
		return nil, &Error{409, "not_retryable", "only a failed, mismatched or cancelled operation can be retried (this one is " + op.Status + ")"}
	}
	st := store.ProvOpState{Status: Queued, NextAttemptAt: now}
	if err := tx.SetProvOpState(id, op.Status, st, now); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, "system", "provision.retried", ojson.Object{{Key: "op_id", Value: id},
		{Key: "kind", Value: op.Kind}, {Key: "target", Value: op.TargetRef}, {Key: "was", Value: op.Status}}); err != nil {
		return nil, err
	}
	return tx.ProvOp(id)
}

// Cancel withdraws an operation that has not been applied or that ended
// without verifying. Its completion never runs, so the item it was for stays
// open.
func Cancel(tx *store.TenantTx, now time.Time, id string) (*store.ProvOp, error) {
	op, err := tx.ProvOp(id)
	if err != nil {
		return nil, err
	}
	switch op.Status {
	case Queued, Failed, Mismatch:
	default:
		return nil, &Error{409, "not_cancellable", "only a queued, failed or mismatched operation can be cancelled (this one is " + op.Status + ")"}
	}
	st := store.ProvOpState{Status: Cancelled, Attempts: op.Attempts, VerifyAttempts: op.VerifyAttempts, NextAttemptAt: now,
		LastError: op.LastError, Observed: op.Observed, CompletedAt: &now}
	if err := tx.SetProvOpState(id, op.Status, st, now); err != nil {
		return nil, err
	}
	// an agent that has not started the push must not start it now (issue #302)
	if _, err := tx.CancelAgentJobsForOp(id, "the operation was cancelled", now); err != nil {
		return nil, err
	}
	if err := tx.Audit(now, "system", "provision.cancelled", ojson.Object{{Key: "op_id", Value: id},
		{Key: "kind", Value: op.Kind}, {Key: "target", Value: op.TargetRef}, {Key: "was", Value: op.Status}}); err != nil {
		return nil, err
	}
	return tx.ProvOp(id)
}

// Request rebuilds the connector request of a stored operation.
func Request(op *store.ProvOp) (target.Request, error) {
	var r target.Request
	if err := json.Unmarshal([]byte(op.Payload), &r); err != nil {
		return r, fmt.Errorf("provision: operation %s has an unreadable payload: %w", op.ID, err)
	}
	r.Kind, r.Key = op.Kind, op.IdempotencyKey
	return r, nil
}
