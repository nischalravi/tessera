package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// AuditTamper simulates an attacker with direct database access, so tests of
// other packages can prove the verifier detects each kind of tampering
// (design §19 PR3, §20 E2.5) and that reads fail closed when the ledger is
// broken. It exists only in test binaries: TamperForTest refuses otherwise.
type AuditTamper struct{ db *DB }

// ErrNotATest is returned by TamperForTest outside a test binary.
var ErrNotATest = errors.New("store: audit tampering is only available in tests")

// TamperForTest returns the tamper handle (test binaries only).
func (d *DB) TamperForTest() (*AuditTamper, error) {
	if !testing.Testing() {
		return nil, ErrNotATest
	}
	return &AuditTamper{db: d}, nil
}

// Fixed DDL of the tamper handle (never built from input).
const (
	tamperDropTriggers = `
		DROP TRIGGER IF EXISTS audit_events_no_update;
		DROP TRIGGER IF EXISTS audit_events_no_delete;
		DROP TRIGGER IF EXISTS audit_ckpt_immutable;
		DROP TRIGGER IF EXISTS audit_ckpt_no_delete;
		DROP TRIGGER IF EXISTS tg_audit_checkpoints_xtenant_upd;`
	tamperBreak  = `ALTER TABLE audit_events RENAME TO audit_events_broken`
	tamperRepair = `ALTER TABLE audit_events_broken RENAME TO audit_events`
)

var (
	tamperEditDetail = tq("tamper.audit_events.edit_detail", `
		UPDATE audit_events SET detail = @detail WHERE tenant_id = @tenant AND seq = @seq`)
	tamperDeleteEvent = tq("tamper.audit_events.delete", `
		DELETE FROM audit_events WHERE tenant_id = @tenant AND seq = @seq`)
	tamperCheckpointJWS = tq("tamper.audit_checkpoints.jws", `
		UPDATE audit_checkpoints SET jws = @jws WHERE tenant_id = @tenant AND seq = @seq`)
)

// DropTriggers removes the append-only triggers (as a database owner could).
// The next Open recreates them.
func (a *AuditTamper) DropTriggers(ctx context.Context) error {
	a.db.mu.Lock()
	defer a.db.mu.Unlock()
	_, err := a.db.sql.ExecContext(ctx, tamperDropTriggers)
	return err
}

func (a *AuditTamper) exec(ctx context.Context, t tenancy.ID, s tstmt, args ...sql.NamedArg) error {
	return a.db.InTenant(ctx, t, func(tx *TenantTx) error {
		res, err := tx.exec(s, args...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFound
		}
		return nil
	})
}

// EditDetail overwrites the detail of the event at seq (triggers must be dropped).
func (a *AuditTamper) EditDetail(ctx context.Context, t tenancy.ID, seq int64, detail string) error {
	return a.exec(ctx, t, tamperEditDetail, sql.Named("detail", detail), sql.Named("seq", seq))
}

// DeleteEvent deletes the event at seq (triggers must be dropped).
func (a *AuditTamper) DeleteEvent(ctx context.Context, t tenancy.ID, seq int64) error {
	return a.exec(ctx, t, tamperDeleteEvent, sql.Named("seq", seq))
}

// ReplaceCheckpointJWS overwrites the JWS of the checkpoint at seq (triggers
// must be dropped).
func (a *AuditTamper) ReplaceCheckpointJWS(ctx context.Context, t tenancy.ID, seq int64, jws string) error {
	return a.exec(ctx, t, tamperCheckpointJWS, sql.Named("jws", jws), sql.Named("seq", seq))
}

// Break makes every audit append fail (the events table disappears) while the
// rest of the database keeps working; Repair undoes it.
func (a *AuditTamper) Break(ctx context.Context) error {
	a.db.mu.Lock()
	defer a.db.mu.Unlock()
	_, err := a.db.sql.ExecContext(ctx, tamperBreak)
	return err
}

// Repair undoes Break.
func (a *AuditTamper) Repair(ctx context.Context) error {
	a.db.mu.Lock()
	defer a.db.mu.Unlock()
	_, err := a.db.sql.ExecContext(ctx, tamperRepair)
	return err
}
