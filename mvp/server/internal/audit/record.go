package audit

import (
	"context"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Option adjusts a Record call.
type Option func(*store.AuditRecord)

// Target names what the event is about (for example "identity", "42").
func Target(typ, id string) Option {
	return func(r *store.AuditRecord) { r.TargetType, r.TargetID = typ, id }
}

// Outcome sets the outcome (default success).
func Outcome(o string) Option { return func(r *store.AuditRecord) { r.Outcome = o } }

// At sets the event time (default now).
func At(t time.Time) Option { return func(r *store.AuditRecord) { r.At = t } }

// PolicyVersion records the policy version a decision used.
func PolicyVersion(v string) Option { return func(r *store.AuditRecord) { r.PolicyVersion = v } }

// LegacyActor passes the MVP helper's actor string (see store.AuditRecord).
func LegacyActor(a string) Option { return func(r *store.AuditRecord) { r.LegacyActor = a } }

// Record appends a domain event in tx, so it commits atomically with the
// change it describes (a rollback leaves no event). The actor is the one in
// the transaction's context (the request's principal, "anonymous" until PR5,
// or a job's system actor); with none, it is the system. Detail must be
// JCS-safe: see canon.Detail (floats are refused).
//
// The MVP's helper, (*store.TenantTx).Audit(now, actor, action, detail),
// keeps its call shape and is equivalent to Record(ctx, tx, action, detail,
// At(now), LegacyActor(actor)).
func Record(_ context.Context, tx *store.TenantTx, action string, detail any, opts ...Option) (Event, error) {
	r := store.AuditRecord{Action: action, Detail: detail}
	for _, o := range opts {
		o(&r)
	}
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	return tx.RecordAudit(r)
}

// WithSystemActor returns ctx attributing events to the system job id (for
// example "jit.sweeper"). Background jobs use it; HTTP requests never do.
func WithSystemActor(ctx context.Context, id string) context.Context {
	return store.WithAuditContext(ctx, store.AuditContext{
		Actor: store.AuditActor{Type: store.ActorSystem, ID: &id, Display: &id},
	})
}

// WithOperatorActor returns ctx attributing events to an operator running
// the admin CLI (the OS user name, as given).
func WithOperatorActor(ctx context.Context, id string) context.Context {
	return store.WithAuditContext(ctx, store.AuditContext{
		Actor: store.AuditActor{Type: store.ActorOperator, ID: &id, Display: &id},
	})
}

// AsSystem returns ctx attributing events to the system job id while keeping
// the request's id, address and committed-event counter: for work a request
// triggers on the system's behalf (the JIT sweep before an analysis), which
// the requester did not ask for.
func AsSystem(ctx context.Context, id string) context.Context {
	ac, _ := store.AuditContextFrom(ctx)
	ac.Actor = store.AuditActor{Type: store.ActorSystem, ID: &id, Display: &id}
	ac.SessionID, ac.ClientID, ac.Authn = nil, nil, nil
	return store.WithAuditContext(ctx, ac)
}
