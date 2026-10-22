package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
)

// TestPG_DefinerFunctionsIgnoreTempShadows (issue #424): a session-local table named like a real one
// must not stand in for it inside the SECURITY DEFINER functions and archive triggers. The test first
// shows TEMPORARY is revoked from the application role, then grants it back (as a DBA mistake would)
// to show the functions hold on their own: search_path ends in pg_temp and relations are qualified.
func TestPG_DefinerFunctionsIgnoreTempShadows(t *testing.T) {
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
	var to int64
	f.asApp(t, tenant, func(tx *sql.Tx) {
		if err := tx.QueryRowContext(ctx, `SELECT max(seq) FROM audit_events`).Scan(&to); err != nil {
			t.Fatal(err)
		}
	})
	const forged = "00000000-0000-4000-8000-0000000000d1"
	if err := f.db.InTenant(ctx, pgTenantA, func(tx *TenantTx) error {
		return tx.InsertArchiveSegment(&ArchiveSegment{ID: forged, Class: "audit", SeqFrom: to + 1, SeqTo: to + 5, RangeFrom: "a", RangeTo: "b",
			Count: 5, FirstHash: "h1", LastHash: "h5", Location: "local", ObjectKey: "k", Size: 1, SHA256: strings.Repeat("0", 64),
			CreatedAt: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)})
	}); err != nil {
		t.Fatal(err)
	}

	// TEMPORARY is revoked: the application role cannot create the shadow at all
	f.asApp(t, tenant, func(tx *sql.Tx) {
		_, err := tx.ExecContext(ctx, `CREATE TEMP TABLE audit_events (tenant_id text, seq bigint, hash text, prev_hash text)`)
		if sqlState(err) != "42501" {
			t.Errorf("tessera_app created a temporary table: %v", err)
		}
	})

	// grant it back: the functions must hold without relying on the revoke
	var db string
	if err := f.db.owner.QueryRowContext(ctx, `SELECT current_database()`).Scan(&db); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.owner.ExecContext(ctx, fmt.Sprintf(`GRANT TEMPORARY ON DATABASE %q TO tessera_app`, db)); err != nil { // #nosec G201 -- name from current_database()
		t.Fatal(err)
	}

	// a shadow audit_events that backs the forged segment's claims (seq to+1..to+5, hashes h1..h5)
	shadowAudit := []string{`CREATE TEMP TABLE audit_events (tenant_id text, seq bigint, hash text, prev_hash text)`}
	for i := int64(1); i <= 5; i++ {
		shadowAudit = append(shadowAudit, fmt.Sprintf(`INSERT INTO pg_temp.audit_events VALUES ('%s', %d, 'h%d', 'h%d')`, tenant, to+i, i, i-1))
	}
	// a shadow archive_segments that holds a verified copy of the forged segment
	shadowSegs := []string{
		`CREATE TEMP TABLE archive_segments (LIKE public.archive_segments)`,
		fmt.Sprintf(`INSERT INTO pg_temp.archive_segments SELECT * FROM public.archive_segments WHERE id = '%s'`, forged),
		`UPDATE pg_temp.archive_segments SET status = 'verified'`,
	}
	toVerified := `UPDATE public.archive_segments SET status = 'verified', verified_at = 'x' WHERE id = '` + forged + `'`
	markVerified := fmt.Sprintf(`SELECT tessera_archive_mark_verified('%s', '%s', '2026-10-20T00:00:00.000000Z')`, tenant, forged)
	purge := func(id string) string {
		return fmt.Sprintf(`SELECT tessera_archive_purge_audit('%s', '%s')`, tenant, id)
	}
	const missing = "00000000-0000-4000-8000-0000000000ff"
	for _, tc := range []struct {
		name    string
		setup   []string
		attack  string
		wantSQL string // required SQLSTATE of the refusal
	}{
		{"update to verified, audit_events shadowed", shadowAudit, toVerified, "42501"},
		{"update to verified, search_path without the schema", []string{`SET LOCAL search_path = pg_catalog, pg_temp`}, toVerified, "42501"},
		{"mark_verified on a forged segment, audit_events shadowed", shadowAudit, markVerified, "23000"},
		{"purge of a forged segment, archive_segments shadowed", shadowSegs, purge(forged), "23000"},
		{"purge with no segment, archive_segments shadowed", shadowSegs, purge(missing), "23000"},
		{"purge with no segment", nil, purge(missing), "23000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.asApp(t, tenant, func(tx *sql.Tx) {
				for _, s := range append([]string{`SAVEPOINT attack`}, tc.setup...) {
					if _, err := tx.ExecContext(ctx, s); err != nil {
						t.Fatalf("%s: %v", s, err)
					}
				}
				_, err := tx.ExecContext(ctx, tc.attack)
				if err == nil {
					t.Fatal("the attack was accepted")
				}
				if got := sqlState(err); got != tc.wantSQL {
					t.Errorf("refused with %q, want %q: %v", got, tc.wantSQL, err)
				}
				if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT attack`); err != nil {
					t.Fatal(err)
				}
				var status string
				if err := tx.QueryRowContext(ctx, `SELECT status FROM public.archive_segments WHERE id = $1`, forged).Scan(&status); err != nil || status != "written" {
					t.Errorf("segment status %q, %v; want written", status, err)
				}
				if n := count(t, tx, `SELECT count(*) FROM public.audit_events`); n != 3 {
					t.Errorf("audit_events has %d rows, want 3", n)
				}
			})
		})
	}
}
