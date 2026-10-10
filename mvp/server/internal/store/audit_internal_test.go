package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit/canon"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TestAuditTriggers_AppendOnly: with direct SQL (the store's own handle,
// as an insider with database access would have), the schema refuses every
// UPDATE and DELETE of audit_events, any change to a checkpoint's core
// fields, deleting a checkpoint or a chain head, and moving a head anywhere
// but one event forward. Only a checkpoint's anchor columns can change.
func TestAuditTriggers_AppendOnly(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	p := tenancy.Platform
	var ck AuditCheckpoint
	if err := db.InTenant(ctx, p, func(tx *TenantTx) error {
		for i := range 3 {
			if err := tx.Audit(time.Now(), "system", "test.event", ojson.Object{{Key: "i", Value: i}}); err != nil {
				return err
			}
		}
		head, err := tx.AuditHead()
		if err != nil {
			return err
		}
		ck, err = tx.InsertAuditCheckpoint(AuditCheckpoint{Seq: head.LastSeq, HeadHash: head.LastHash, JWS: "a.b.c"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	blocked := []struct{ name, sql string }{
		{"update event detail", `UPDATE audit_events SET detail = '{}' WHERE seq = 2`},
		{"update event hash", `UPDATE audit_events SET hash = 'x' WHERE seq = 2`},
		{"update event tenant", `UPDATE audit_events SET tenant_id = '00000000-0000-4000-8000-000000000999'`},
		{"delete one event", `DELETE FROM audit_events WHERE seq = 2`},
		{"delete every event", `DELETE FROM audit_events`},
		{"update checkpoint jws", `UPDATE audit_checkpoints SET jws = 'forged'`},
		{"update checkpoint seq", `UPDATE audit_checkpoints SET seq = 1`},
		{"update checkpoint head hash", `UPDATE audit_checkpoints SET head_hash = 'x'`},
		{"update checkpoint created_at", `UPDATE audit_checkpoints SET created_at = '2000-01-01T00:00:00.000000Z'`},
		{"delete checkpoint", `DELETE FROM audit_checkpoints`},
		{"delete head", `DELETE FROM audit_chain_heads`},
		{"head backwards", `UPDATE audit_chain_heads SET last_seq = 1`},
		{"head forward to a missing event", `UPDATE audit_chain_heads SET last_seq = last_seq + 1`},
		{"head to a forged hash", `UPDATE audit_chain_heads SET last_hash = 'x'`},
		{"event that skips a seq", `INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, action, outcome,
			detail, prev_hash, hash) SELECT 'fork', h.tenant_id, h.last_seq + 2, '2026-01-01T00:00:00.000000Z', 'system', 'x',
			'success', '{}', h.last_hash, 'fork' FROM audit_chain_heads h`},
		{"event forking the chain", `INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, action, outcome,
			detail, prev_hash, hash) VALUES ('fork', '` + p.String() + `', 2, '2026-01-01T00:00:00.000000Z', 'system', 'x',
			'success', '{}', 'whatever', 'fork')`},
	}
	for _, tc := range blocked {
		t.Run(tc.name, func(t *testing.T) {
			_, err := db.sql.ExecContext(ctx, tc.sql)
			if err == nil {
				t.Fatalf("%s was allowed", tc.sql)
			}
			if !strings.Contains(err.Error(), "append-only") && !strings.Contains(err.Error(), "immutable") &&
				!strings.Contains(err.Error(), "audit_chain_heads") && !strings.Contains(err.Error(), "cross-tenant") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	// the anchor columns may change
	if err := db.InTenant(ctx, p, func(tx *TenantTx) error {
		ref := "file:1"
		return tx.SetAuditCheckpointAnchor(ck.ID, AnchorAnchored, &ref, time.Now())
	}); err != nil {
		t.Errorf("anchoring a checkpoint: %v", err)
	}
	var n int
	if err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&n); err != nil || n != 3 {
		t.Errorf("events after the attempts = %d (%v), want 3", n, err)
	}
}

// TestAuditAppend_RollbackLeavesNoEvent: a domain event written in a
// transaction that rolls back leaves neither the event nor a moved head.
func TestAuditAppend_RollbackLeavesNoEvent(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	boom := errors.New("mutation failed")
	err := db.InTenant(ctx, tenancy.Platform, func(tx *TenantTx) error {
		if err := tx.Audit(time.Now(), "system", "doomed.change", nil); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	var n int
	if err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = 'doomed.change'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("rolled-back event persisted: n=%d err=%v", n, err)
	}
	var seq sql.NullInt64
	if err := db.sql.QueryRowContext(ctx, `SELECT max(last_seq) FROM audit_chain_heads`).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	if seq.Int64 != 0 {
		t.Errorf("head moved to %d by a rolled-back append", seq.Int64)
	}
	// the next append starts at seq 1 from genesis
	if err := db.InTenant(ctx, tenancy.Platform, func(tx *TenantTx) error {
		e, err := tx.RecordAudit(AuditRecord{Action: "after", LegacyActor: "system"})
		if err == nil && (e.Seq != 1 || e.PrevHash != canon.Genesis(tenancy.Platform.String())) {
			t.Errorf("first event after rollback: seq %d prev %s", e.Seq, e.PrevHash)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestTamperForTest documents the guard (this is a test binary,
// so the handle is available here).
func TestTamperForTest(t *testing.T) {
	if _, err := openTest(t).TamperForTest(); err != nil {
		t.Fatal(err)
	}
}

// TestAuditContext_Committed: the audit middleware's counter grows by the
// events of committed transactions only (never a rolled-back or read one).
func TestAuditContext_Committed(t *testing.T) {
	db := openTest(t)
	var n atomic.Int64
	ctx := WithAuditContext(context.Background(), AuditContext{Actor: AuditActor{Type: ActorAnonymous}, Committed: &n})
	_ = db.InTenant(ctx, tenancy.Platform, func(tx *TenantTx) error {
		if err := tx.Audit(time.Now(), "", "doomed", nil); err != nil {
			return err
		}
		return errors.New("rolled back")
	})
	_ = db.ReadTenant(ctx, tenancy.Platform, func(*TenantTx) error { return nil })
	_ = db.InTenant(ctx, tenancy.Platform, func(*TenantTx) error { return nil })
	if n.Load() != 0 {
		t.Fatalf("committed = %d before any recorded commit", n.Load())
	}
	if err := db.InTenant(ctx, tenancy.Platform, func(tx *TenantTx) error {
		for range 2 {
			if err := tx.Audit(time.Now(), "", "kept", nil); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 2 {
		t.Errorf("committed = %d, want 2", n.Load())
	}
}
