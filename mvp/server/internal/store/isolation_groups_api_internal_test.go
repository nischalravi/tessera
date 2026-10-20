package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TestIsolation_IdempotencyTable: grp_idempotency (schema/0376_groups_api.sql)
// is scoped to its tenant by its primary key (the same principal and key can
// exist in two tenants, never twice in one), refuses a row without a tenant
// that exists, and its stored answers are immutable.
func TestIsolation_IdempotencyTable(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Format(time.RFC3339)
	ta := tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	tb := tenancy.MustParse("00000000-0000-4000-8000-0000000000b2")
	for _, id := range []tenancy.ID{ta, tb} {
		err := db.InSystem(ctx, "test", func(s *SystemTx) error {
			_, err := s.CreateTenant(Tenant{ID: id, Slug: id.String()[30:], Name: "t", CreatedAt: time.Now()})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	insert := func(tenant, principal, key string) error {
		_, err := db.sql.ExecContext(ctx, `INSERT INTO grp_idempotency (tenant_id, principal, idem_key, request_hash, status, body, created_at, expires_at)
			VALUES (@t, @p, @k, 'h', 200, '{}', @n, @n)`, sql.Named("t", tenant), sql.Named("p", principal), sql.Named("k", key), sql.Named("n", now))
		return err
	}
	if err := insert(ta.String(), "user:1", "k"); err != nil {
		t.Fatal(err)
	}
	if err := insert(tb.String(), "user:1", "k"); err != nil {
		t.Errorf("the same principal and key in another tenant: %v", err)
	}
	if err := insert(ta.String(), "user:1", "k"); err == nil {
		t.Error("the same principal and key twice in one tenant")
	}
	if err := insert(ta.String(), "user:2", "k"); err != nil {
		t.Errorf("another principal's key of the same name: %v", err)
	}
	if err := insert(ta.String(), "user:1", ""); err == nil {
		t.Error("an empty key was stored")
	}
	if err := insert(ta.String(), "user:1", strings.Repeat("k", 256)); err == nil {
		t.Error("a key of 256 characters was stored")
	}
	for _, upd := range []string{`UPDATE grp_idempotency SET body = '{"changed":true}' WHERE tenant_id = @t`,
		`UPDATE grp_idempotency SET tenant_id = @u WHERE tenant_id = @t`} {
		_, err := db.sql.ExecContext(ctx, upd, sql.Named("t", ta.String()), sql.Named("u", tb.String()))
		if err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Errorf("%s: %v, want the immutability trigger", upd, err)
		}
	}
}
