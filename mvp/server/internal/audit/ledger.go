// Package audit is Tessera's tamper-evident audit ledger (design
// docs/design/phase-0-platform-security.md §13):
//
//   - ledger.go: hashing and Append. Each tenant (and the _platform tenant)
//     has its own append-only hash chain with a gapless seq. The hash is
//     SHA-256 over a domain separator and the RFC 8785 (JCS) form of the
//     event (internal/audit/canon), so any verifier can reproduce it.
//   - record.go: Record, the domain-event call (the MVP's audit helper,
//     store.TenantTx.Audit, keeps its call shape and lands here too).
//   - middleware.go: one http.request event per request; reads whose event
//     cannot be written are refused with 503 (fail closed).
//   - checkpoint.go: signed checkpoints (EdDSA, the platform audit key)
//     anchored outside the database (append-only file now, S3 Object Lock
//     later).
//   - verify.go: chain, checkpoint and anchor verification with the exit
//     codes of `tessera audit verify`.
//   - export.go: NDJSON export of the hashed bodies, for SIEMs and offline
//     verifiers.
//
// The SQLite schema blocks UPDATE and DELETE on the ledger tables with
// triggers (internal/store/schema/0004_audit.sql).
package audit

import (
	"context"

	"github.com/nischalravi/tessera/mvp/server/internal/audit/canon"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Event is one ledger entry.
type Event = store.AuditEvent

// TimeLayout is the timestamp format of hashed bodies (UTC, microseconds).
const TimeLayout = canon.TimeLayout

// Genesis is the prev_hash of a tenant's first event.
func Genesis(t tenancy.ID) string { return canon.Genesis(t.String()) }

// EventHash recomputes an event's hash from its fields.
func EventHash(e *Event) (string, error) { return store.AuditEventHash(e) }

// Append appends e to the chain of tx's tenant, in tx: it commits or rolls
// back with whatever else tx does. It assigns seq, prev_hash and hash.
func Append(_ context.Context, tx *store.TenantTx, e Event) (Event, error) {
	return tx.AppendAudit(e)
}
