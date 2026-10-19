package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TestIsolation_GroupsTablesGuarded: the tables without a repository yet
// (composite factors, direct memberships, the engine's dependency and level
// tables) refuse a row of tenant B that names tenant A's group, list or
// identity, and accept the same row inside tenant A.
func TestIsolation_GroupsTablesGuarded(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ta := tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	tb := tenancy.MustParse("00000000-0000-4000-8000-0000000000b2")
	var group, list string
	var ident int64
	for _, id := range []tenancy.ID{ta, tb} {
		err := db.InSystem(ctx, "test", func(s *SystemTx) error {
			_, err := s.CreateTenant(Tenant{ID: id, Slug: id.String()[30:], Name: "t", CreatedAt: now})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	err := db.InTenant(ctx, ta, func(c *TenantTx) error {
		root := &Folder{CreatedAt: now}
		if err := c.InsertGrpFolder(root); err != nil {
			return err
		}
		g := &NativeGroup{FolderID: root.ID, Extension: "g", DisplayExtension: "g", Name: "g", DisplayName: "g", CreatedAt: now}
		if err := c.InsertGrpGroup(g); err != nil {
			return err
		}
		l, err := c.EnsureGrpMembersList()
		if err != nil {
			return err
		}
		group, list = string(g.ID), string(l)
		ident, err = c.InsertIdentity(&Identity{ExternalID: "x", Name: "x", Type: "person", Status: "active", CreatedAt: now})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	exec := func(tenant tenancy.ID, q string, args ...any) error {
		_, err := db.sql.ExecContext(ctx, q, append([]any{sql.Named("t", tenant.String()), sql.Named("g", group),
			sql.Named("l", list), sql.Named("i", ident), sql.Named("n", now.Format(time.RFC3339))}, args...)...)
		return err
	}
	for name, q := range map[string]string{
		"grp_composite_factors": `INSERT INTO grp_composite_factors (tenant_id, group_id, position, factor_group_id) VALUES (@t, @g, 0, @g)`,
		"grp_direct_memberships (identity)": `INSERT INTO grp_direct_memberships (id, tenant_id, group_id, list_id, member_type, member_identity_id, source, created_at)
			VALUES ('m1', @t, @g, @l, 'identity', @i, 'manual', @n)`,
		"grp_direct_memberships (group)": `INSERT INTO grp_direct_memberships (id, tenant_id, group_id, list_id, member_type, member_group_id, source, created_at)
			VALUES ('m2', @t, @g, @l, 'group', @g, 'manual', @n)`,
		"grp_deps":   `INSERT INTO grp_deps (tenant_id, parent_group_id, child_group_id, kind, list_id) VALUES (@t, @g, @g, 'nest', @l)`,
		"grp_levels": `INSERT INTO grp_levels (tenant_id, group_id, level) VALUES (@t, @g, 0)`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := exec(tb, q); err == nil || !strings.Contains(err.Error(), "cross-tenant reference") {
				t.Errorf("tenant B naming A's rows: %v, want a cross-tenant refusal", err)
			}
			if err := exec(ta, q); err != nil {
				t.Errorf("tenant A naming its own rows: %v", err)
			}
		})
	}
}
