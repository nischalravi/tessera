package store

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TestArchiveForgedVerifiedSegmentUnlocksNothing (issue #401): with direct SQL as the
// application role has it, a segment cannot be inserted verified, cannot become verified
// with a range or hashes the audit chain does not hold, and a verified segment takes no
// more items. A forged row therefore unlocks no delete.
func TestArchiveForgedVerifiedSegmentUnlocksNothing(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	p := tenancy.Platform
	if err := db.InTenant(ctx, p, func(tx *TenantTx) error {
		for i := range 4 {
			if err := tx.Audit(time.Now(), "system", "test.event", ojson.Object{{Key: "i", Value: i}}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	hash := func(seq int) string {
		var h string
		if err := db.sql.QueryRowContext(ctx, `SELECT hash FROM audit_events WHERE seq = `+strconv.Itoa(seq)).Scan(&h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	const cols = `(id, tenant_id, class, status, seq_from, seq_to, range_from, range_to, item_count, first_hash, last_hash,
		location, object_key, size_bytes, sha256, created_at, verified_at) VALUES `
	seg := func(id, class, status string, from, to int, fh, lh string, verified string) string {
		return `INSERT INTO archive_segments ` + cols + `('` + id + `', '` + p.String() + `', '` + class + `', '` + status + `', ` +
			strconv.Itoa(from) + `, ` + strconv.Itoa(to) + `, 'a', 'b', 2, '` + fh + `', '` + lh + `', 'local', 'k', 1, '` + strings.Repeat("0", 64) +
			`', '2026-01-01T00:00:00.000000Z', ` + verified + `)`
	}
	ts := `'2026-01-01T00:00:00.000000Z'`
	mustFail := func(name, q string) {
		t.Helper()
		if _, err := db.sql.ExecContext(ctx, q); err == nil {
			t.Errorf("%s was allowed", name)
		}
	}
	mustPass := func(name, q string) {
		t.Helper()
		if _, err := db.sql.ExecContext(ctx, q); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	del := func(seq int) error {
		_, err := db.sql.ExecContext(ctx, `DELETE FROM audit_events WHERE seq = `+strconv.Itoa(seq))
		return err
	}

	// 1. born verified or purged
	mustFail("insert verified", seg("00000000-0000-4000-8000-0000000000a1", "audit", "verified", 1, 2, hash(1), hash(2), ts))
	mustFail("insert purged", seg("00000000-0000-4000-8000-0000000000a2", "audit", "purged", 1, 2, hash(1), hash(2), ts))
	mustFail("insert written with verified_at", seg("00000000-0000-4000-8000-0000000000a3", "audit", "written", 1, 2, hash(1), hash(2), ts))
	if err := del(1); err == nil {
		t.Fatal("an event was deleted with no verified segment")
	}

	// 2. written, then verified with hashes the chain does not hold
	mustPass("insert written (forged hashes)", seg("00000000-0000-4000-8000-0000000000b1", "audit", "written", 3, 4, "fake", "fake", "NULL"))
	mustFail("verify with forged hashes", `UPDATE archive_segments SET status = 'verified', verified_at = `+ts+` WHERE id = '00000000-0000-4000-8000-0000000000b1'`)
	mustPass("insert written (range beyond the chain)", seg("00000000-0000-4000-8000-0000000000b2", "audit", "written", 50, 60, hash(1), hash(2), "NULL"))
	mustFail("verify a range the chain does not hold", `UPDATE archive_segments SET status = 'verified', verified_at = `+ts+` WHERE id = '00000000-0000-4000-8000-0000000000b2'`)
	if err := del(1); err == nil {
		t.Fatal("a forged segment unlocked a delete")
	}

	// 3. the honest segment verifies and unlocks exactly its own range
	mustPass("insert written", seg("00000000-0000-4000-8000-0000000000c1", "audit", "written", 1, 2, hash(1), hash(2), "NULL"))
	mustPass("verify", `UPDATE archive_segments SET status = 'verified', verified_at = `+ts+` WHERE id = '00000000-0000-4000-8000-0000000000c1'`)
	if err := db.InTenant(ctx, p, func(tx *TenantTx) error { return tx.PurgeArchivedAudit("00000000-0000-4000-8000-0000000000b1") }); err == nil {
		t.Error("PurgeArchivedAudit of a segment that is not verified succeeded")
	}
	if err := del(3); err == nil {
		t.Error("an event outside the verified range was deleted")
	}
	if err := db.InTenant(ctx, p, func(tx *TenantTx) error { return tx.PurgeArchivedAudit("00000000-0000-4000-8000-0000000000c1") }); err != nil {
		t.Errorf("purge of the verified range: %v", err)
	}
	var n int
	if err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&n); err != nil || n != 2 {
		t.Errorf("events left = %d (%v), want 2", n, err)
	}

	// 4. per-record classes: no verification without items, and no items after it
	req := func(id string) string { return `00000000-0000-4000-8000-0000000000` + id }
	mustPass("insert requests segment", seg(req("d1"), "requests", "written", 0, 0, "", "", "NULL"))
	mustFail("verify with no items", `UPDATE archive_segments SET status = 'verified', verified_at = `+ts+` WHERE id = '`+req("d1")+`'`)
	item := func(seg, id string) string {
		return `INSERT INTO archive_segment_items (tenant_id, segment_id, item_id) VALUES ('` + p.String() + `', '` + seg + `', '` + id + `')`
	}
	mustPass("add item to a written segment", item(req("d1"), "r1"))
	mustPass("verify with items", `UPDATE archive_segments SET status = 'verified', verified_at = `+ts+` WHERE id = '`+req("d1")+`'`)
	mustFail("add item to a verified segment", item(req("d1"), "r2"))
}
