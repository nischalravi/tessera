package store

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

func twoTenants(t *testing.T, db *DB) (a, b tenancy.ID) {
	t.Helper()
	if err := db.InSystem(context.Background(), "test", func(s *SystemTx) error {
		ta, err := s.CreateTenant(Tenant{Slug: "tenant-a", Name: "A"})
		if err != nil {
			return err
		}
		tb, err := s.CreateTenant(Tenant{Slug: "tenant-b", Name: "B"})
		a, b = ta.ID, tb.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return a, b
}

// TestEdgeHistoryBackfill: a grant with no span (it predates the table) gets
// one starting at its created_at when the schema is applied, and applying the
// schema again adds nothing.
func TestEdgeHistoryBackfill(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	a, _ := twoTenants(t, db)
	created := time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)
	if err := db.InTenant(ctx, a, func(tx *TenantTx) error {
		_, err := tx.tx.ExecContext(ctx, `INSERT INTO grant_edges (tenant_id, src, dst, relation, source, created_at)
			VALUES (?, 'account:1', 'group:1', 'member_of', 'connector', ?)`, a.String(), T(created))
		if err != nil {
			return err
		}
		spans, err := tx.EdgeSpans()
		if len(spans) != 0 {
			t.Errorf("a raw grant insert made %d spans", len(spans))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := db.Migrate(ctx, false); err != nil {
			t.Fatal(err)
		}
		if err := db.ReadTenant(ctx, a, func(tx *TenantTx) error {
			spans, err := tx.EdgeSpans()
			if err != nil {
				return err
			}
			if len(spans) != 1 || !spans[0].ValidFrom.Equal(created) || spans[0].ValidTo != nil || spans[0].EdgeID == nil {
				t.Errorf("migration %d: spans = %+v", i, spans)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestEdgeHistoryTriggers: a span names only its own tenant's nodes; a span's
// attributes and start are frozen while valid_to can close it.
func TestEdgeHistoryTriggers(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	a, b := twoTenants(t, db)
	var bIdentity int64
	if err := db.InTenant(ctx, b, func(tx *TenantTx) error {
		var err error
		bIdentity, err = tx.InsertIdentity(&Identity{ExternalID: "x", Name: "x", Type: "human", Status: "active"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO edge_history (tenant_id, src, dst, relation, source, valid_from) VALUES (?, ?, 'group:1', 'member_of', 'manual', ?)`
	err := db.InTenant(ctx, a, func(tx *TenantTx) error {
		_, err := tx.tx.ExecContext(ctx, insert, a.String(), "identity:"+strconv.FormatInt(bIdentity, 10), T(time.Now()))
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "cross-tenant reference: edge_history") {
		t.Errorf("a span naming another tenant's identity: err = %v", err)
	}
	err = db.InTenant(ctx, a, func(tx *TenantTx) error {
		if _, err := tx.tx.ExecContext(ctx, insert, a.String(), "account:1", T(time.Now())); err != nil {
			return err
		}
		if _, err := tx.tx.ExecContext(ctx, `UPDATE edge_history SET valid_to = ? WHERE tenant_id = ?`, T(time.Now()), a.String()); err != nil {
			t.Errorf("closing a span: %v", err)
		}
		_, err := tx.tx.ExecContext(ctx, `UPDATE edge_history SET valid_from = ? WHERE tenant_id = ?`, T(time.Now()), a.String())
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "a span is closed, not edited") {
		t.Errorf("editing a span: err = %v", err)
	}
}

// TestEvidencePackImmutable: a pack row refuses every UPDATE.
func TestEvidencePackImmutable(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	a, _ := twoTenants(t, db)
	now := time.Now().UTC()
	err := db.InTenant(ctx, a, func(tx *TenantTx) error {
		if err := tx.InsertEvidencePack(&EvidencePack{ID: "p1", Framework: "soc2", PeriodFrom: now, PeriodTo: now, GeneratedAt: now,
			GeneratedBy: "x", ManifestSHA256: "h", Manifest: []byte(`{}`), SizeBytes: 1, Content: []byte("z")}); err != nil {
			return err
		}
		_, err := tx.tx.ExecContext(ctx, `UPDATE evidence_packs SET content = x'00' WHERE tenant_id = ?`, a.String())
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "a pack is immutable") {
		t.Errorf("updating a pack: err = %v", err)
	}
}
