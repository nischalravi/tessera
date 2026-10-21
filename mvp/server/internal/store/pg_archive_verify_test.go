package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
)

// TestPG_ArchiveVerifyOnlyThroughTheFunction (issue #401, reopened): the application role cannot
// UPDATE a written segment to verified with plain SQL, even one whose claims the audit chain backs;
// only tessera_archive_mark_verified can, and it refuses a segment whose claims are not backed.
func TestPG_ArchiveVerifyOnlyThroughTheFunction(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	tenant := pgTenantA.String()
	if err := f.db.InTenant(ctx, pgTenantA, func(tx *TenantTx) error {
		for i := range 3 {
			if err := tx.Audit(time.Now(), "system", "test.event", ojson.Object{{Key: "i", Value: i}}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var from, to, n int64
	var first, last string
	f.asApp(t, tenant, func(tx *sql.Tx) {
		q := func(sqlText string, dst ...any) {
			if err := tx.QueryRowContext(ctx, sqlText).Scan(dst...); err != nil {
				t.Fatal(err)
			}
		}
		q(`SELECT min(seq), max(seq), count(*) FROM audit_events`, &from, &to, &n)
		q(`SELECT hash FROM audit_events WHERE seq = (SELECT min(seq) FROM audit_events)`, &first)
		q(`SELECT hash FROM audit_events WHERE seq = (SELECT max(seq) FROM audit_events)`, &last)
	})
	at := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	seg := func(id string, count int64) *ArchiveSegment {
		return &ArchiveSegment{ID: id, Class: "audit", SeqFrom: from, SeqTo: to, RangeFrom: "a", RangeTo: "b", Count: count,
			FirstHash: first, LastHash: last, Location: "local", ObjectKey: "k", Size: 1, SHA256: strings.Repeat("0", 64), CreatedAt: at}
	}
	const honest, forged = "00000000-0000-4000-8000-0000000000c1", "00000000-0000-4000-8000-0000000000c2"
	if err := f.db.InTenant(ctx, pgTenantA, func(tx *TenantTx) error {
		if err := tx.InsertArchiveSegment(seg(honest, n)); err != nil {
			return err
		}
		return tx.InsertArchiveSegment(seg(forged, n+5))
	}); err != nil {
		t.Fatal(err)
	}

	// plain SQL as tessera_app: refused, though the honest segment's claims are all true
	f.asApp(t, tenant, func(tx *sql.Tx) {
		_, err := tx.ExecContext(ctx, `UPDATE archive_segments SET status = 'verified', verified_at = '2026-10-20T00:00:00.000000Z' WHERE id = $1`, honest)
		if sqlState(err) != "42501" {
			t.Errorf("direct UPDATE to verified as the application role: %v", err)
		}
	})
	// the function refuses a segment the chain does not back, and a forged segment unlocks no purge
	if err := f.db.InTenant(ctx, pgTenantA, func(tx *TenantTx) error { return tx.MarkArchiveVerified(forged, at) }); err == nil {
		t.Error("a forged segment was verified")
	}
	if err := f.db.InTenant(ctx, pgTenantA, func(tx *TenantTx) error { return tx.PurgeArchivedAudit(forged) }); err == nil {
		t.Error("a forged segment unlocked a purge")
	}
	// the function verifies the honest one, once
	if err := f.db.InTenant(ctx, pgTenantA, func(tx *TenantTx) error { return tx.MarkArchiveVerified(honest, at) }); err != nil {
		t.Errorf("verify through the function: %v", err)
	}
	if err := f.db.InTenant(ctx, pgTenantA, func(tx *TenantTx) error { return tx.MarkArchiveVerified(honest, at) }); err == nil {
		t.Error("a verified segment was verified again")
	}
	// another tenant's transaction cannot verify it
	if err := f.db.InTenant(ctx, pgTenantB, func(tx *TenantTx) error { return tx.MarkArchiveVerified(forged, at) }); err == nil {
		t.Error("tenant B verified tenant A's segment")
	}
}
