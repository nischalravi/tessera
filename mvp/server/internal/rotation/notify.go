package rotation

import (
	"context"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Notification events.
const (
	EventCompleted        = "rotation.completed"
	EventFailed           = "rotation.failed"
	EventManualRequired   = "rotation.manual_required"
	EventVendorCompromise = "rotation.vendor_compromise"
)

// Notification tells a secret's owner that something happened to it. It never
// carries secret material, only names and identifiers.
type Notification struct {
	Event      string
	SecretID   int64
	SecretName string
	System     string
	Kind       string
	JobID      string // "" when no job exists (a manual item of a bulk run)
	BulkID     string
	// Owner is the human accountable for the secret: the owner of the
	// non-human identity that holds it, or the person it belongs to. nil when
	// the secret has no owner (orphaned); the notifier then escalates.
	Owner   *Owner
	Subject string
	Body    string
}

// Owner is who gets told.
type Owner struct {
	IdentityID int64
	Name       string
	Email      string // "" when the identity has none
}

// Notifier delivers owner notifications.
//
// The contract: Notify runs inside the tenant transaction that records the
// state change, so an implementation that queues a message (the notifications
// outbox, #189) inserts it atomically with the change and nothing is sent for
// a change that rolled back. It must not do network I/O, and an error rolls
// the transaction back. The default is AuditNotifier.
type Notifier interface {
	Notify(ctx context.Context, tx *store.TenantTx, n Notification) error
}

// AuditNotifier is the default Notifier: it records a rotation.owner_notified
// audit event naming the owner and the event, and sends nothing. It is what
// runs until the outbox exists; swapping it for the outbox is one line in
// cmd/tessera (Engine.Notifier and Service.Notifier).
type AuditNotifier struct{}

// Notify implements Notifier.
func (AuditNotifier) Notify(ctx context.Context, tx *store.TenantTx, n Notification) error {
	d := ojson.Object{{Key: "event", Value: n.Event}, {Key: "secret_id", Value: n.SecretID},
		{Key: "secret", Value: n.SecretName}, {Key: "system", Value: n.System}, {Key: "subject", Value: n.Subject}}
	if n.JobID != "" {
		d = append(d, ojson.KV{Key: "job_id", Value: n.JobID})
	}
	if n.BulkID != "" {
		d = append(d, ojson.KV{Key: "bulk_id", Value: n.BulkID})
	}
	if n.Owner != nil {
		d = append(d, ojson.KV{Key: "owner_identity_id", Value: n.Owner.IdentityID}, ojson.KV{Key: "owner", Value: n.Owner.Name})
	} else {
		d = append(d, ojson.KV{Key: "owner", Value: nil}, ojson.KV{Key: "escalated_to", Value: "tenant administrators"})
	}
	_, err := audit.Record(ctx, tx, "rotation.owner_notified", d, audit.Target("secret", itoa64(n.SecretID)))
	return err
}

// NopNotifier sends nothing and records nothing (tests of the engine alone).
type NopNotifier struct{}

// Notify implements Notifier.
func (NopNotifier) Notify(context.Context, *store.TenantTx, Notification) error { return nil }
