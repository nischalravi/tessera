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
		DROP TRIGGER IF EXISTS tg_audit_checkpoints_xtenant_upd;
		DROP TRIGGER IF EXISTS audit_heads_forward;
		DROP TRIGGER IF EXISTS grp_events_no_update;
		DROP TRIGGER IF EXISTS grp_pit_digests_no_update;`
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
	tamperDeleteTail = tq("tamper.audit_events.delete_tail", `
		DELETE FROM audit_events WHERE tenant_id = @tenant AND seq > @seq`)
	tamperDeleteCheckpointsTail = tq("tamper.audit_checkpoints.delete_tail", `
		DELETE FROM audit_checkpoints WHERE tenant_id = @tenant AND seq > @seq`)
	tamperRewindHead = tq("tamper.audit_chain_heads.rewind", `
		UPDATE audit_chain_heads SET last_seq = @seq, last_hash = @hash WHERE tenant_id = @tenant`)
	tamperGrpEventData = tq("tamper.grp_events.edit_data", `
		UPDATE grp_events SET data = @data WHERE tenant_id = @tenant AND seq = @seq`)
	tamperGrpEventDelete = tq("tamper.grp_events.delete", `
		DELETE FROM grp_events WHERE tenant_id = @tenant AND seq = @seq`)
)

// EditGrpEventData overwrites the data of the group event at seq (triggers
// must be dropped), as an attacker rewriting history would.
func (a *AuditTamper) EditGrpEventData(ctx context.Context, t tenancy.ID, seq int64, data string) error {
	return a.exec(ctx, t, tamperGrpEventData, sql.Named("data", data), sql.Named("seq", seq))
}

// DeleteGrpEvent deletes the group event at seq.
func (a *AuditTamper) DeleteGrpEvent(ctx context.Context, t tenancy.ID, seq int64) error {
	return a.exec(ctx, t, tamperGrpEventDelete, sql.Named("seq", seq))
}

// Postgres has no DROP of a plain trigger set that Open can bring back, so the
// handle disables the user triggers on the three audit tables (as the table
// owner could) and Migrate enables them again. Only the owner pool may do
// this or touch the audit tables: the application role has neither privilege.
const tamperDisableTriggersPG = `
	ALTER TABLE audit_events DISABLE TRIGGER USER;
	ALTER TABLE audit_checkpoints DISABLE TRIGGER USER;
	ALTER TABLE audit_chain_heads DISABLE TRIGGER USER;`

// pool is the connection pool the handle writes through: the application
// pool on SQLite, the owner pool on Postgres.
func (a *AuditTamper) pool() *sql.DB {
	if a.db.d == dialectPostgres {
		return a.db.owner
	}
	return a.db.sql
}

// DropTriggers removes the append-only triggers (as a database owner could).
// The next Open recreates them.
func (a *AuditTamper) DropTriggers(ctx context.Context) error {
	defer a.db.writeLock()()
	q := tamperDropTriggers
	if a.db.d == dialectPostgres {
		q = tamperDisableTriggersPG
	}
	_, err := a.pool().ExecContext(ctx, q)
	return err
}

func (a *AuditTamper) inTenant(ctx context.Context, t tenancy.ID, fn func(*TenantTx) error) error {
	defer a.db.writeLock()()
	return a.db.inTenantOn(ctx, a.pool(), t, false, fn)
}

func (a *AuditTamper) exec(ctx context.Context, t tenancy.ID, s tstmt, args ...sql.NamedArg) error {
	return a.inTenant(ctx, t, func(tx *TenantTx) error {
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

// TruncateTail deletes every event after seq, as a careful attacker would:
// with deleteCheckpoints it also deletes the checkpoint rows after seq, and
// with rewindHead it moves the chain head back to seq, so the database alone
// shows a consistent, shorter chain (triggers must be dropped).
func (a *AuditTamper) TruncateTail(ctx context.Context, t tenancy.ID, seq int64, deleteCheckpoints, rewindHead bool) error {
	return a.inTenant(ctx, t, func(tx *TenantTx) error {
		res, err := tx.exec(tamperDeleteTail, sql.Named("seq", seq))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if deleteCheckpoints {
			if _, err := tx.exec(tamperDeleteCheckpointsTail, sql.Named("seq", seq)); err != nil {
				return err
			}
		}
		if rewindHead {
			e, err := tx.AuditEventBySeq(seq)
			if err != nil {
				return err
			}
			if _, err := tx.exec(tamperRewindHead, sql.Named("seq", seq), sql.Named("hash", e.Hash)); err != nil {
				return err
			}
		}
		return nil
	})
}

// Break makes every audit append fail (the events table disappears) while the
// rest of the database keeps working; Repair undoes it.
func (a *AuditTamper) Break(ctx context.Context) error {
	defer a.db.writeLock()()
	_, err := a.pool().ExecContext(ctx, tamperBreak)
	return err
}

// Repair undoes Break.
func (a *AuditTamper) Repair(ctx context.Context) error {
	defer a.db.writeLock()()
	_, err := a.pool().ExecContext(ctx, tamperRepair)
	return err
}
