package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// TestIsolation_GroupProvTablesGuarded: a row of one tenant that names another
// tenant's provisioner, run, group, folder or connection is refused by the
// guard triggers of schema/0378_group_prov.sql, on insert and on update.
func TestIsolation_GroupProvTablesGuarded(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ta := tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	tb := tenancy.MustParse("00000000-0000-4000-8000-0000000000b2")
	for _, id := range []tenancy.ID{ta, tb} {
		err := db.InSystem(ctx, "test", func(s *SystemTx) error {
			_, err := s.CreateTenant(Tenant{ID: id, Slug: id.String()[30:], Name: "t", CreatedAt: now})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var group, folder string
	err := db.InTenant(ctx, ta, func(c *TenantTx) error {
		root := &Folder{CreatedAt: now}
		if err := c.InsertGrpFolder(root); err != nil {
			return err
		}
		g := &NativeGroup{FolderID: root.ID, Extension: "g", DisplayExtension: "g", Name: "g", DisplayName: "g", CreatedAt: now}
		if err := c.InsertGrpGroup(g); err != nil {
			return err
		}
		group, folder = string(g.ID), string(root.ID)
		return c.InsertConnection(&Connection{ID: "conn-a", Name: "c", ConnectorType: "okta", System: "okta", Role: "account_source",
			CreatedAt: now, UpdatedAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	stamp := now.Format(time.RFC3339)
	exec := func(tenant tenancy.ID, q string) error {
		_, err := db.sql.ExecContext(ctx, q, sql.Named("t", tenant.String()), sql.Named("g", group), sql.Named("f", folder),
			sql.Named("n", stamp))
		return err
	}
	// A's provisioner, run and an op of it, made in A
	for _, q := range []string{
		`INSERT INTO grp_provisioners (id, tenant_id, name, target_type, config, failsafe, created_at, updated_at)
			VALUES ('pa', @t, 'pa', 'scim2', '{}', '{}', @n, @n)`,
		`INSERT INTO grp_sync_runs (id, tenant_id, provisioner_id, kind, mode, status, started_at)
			VALUES ('ra', @t, 'pa', 'full', 'adopt', 'running', @n)`,
	} {
		if err := exec(ta, q); err != nil {
			t.Fatal(err)
		}
	}
	// B's own provisioner, to hang the foreign references on
	if err := exec(tb, `INSERT INTO grp_provisioners (id, tenant_id, name, target_type, config, failsafe, created_at, updated_at)
		VALUES ('pb', @t, 'pb', 'scim2', '{}', '{}', @n, @n)`); err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]string{
		"provisioner naming A's connection": `INSERT INTO grp_provisioners (id, tenant_id, name, target_type, connection_id, config, failsafe, created_at, updated_at)
			VALUES ('px', @t, 'px', 'scim2', 'conn-a', '{}', '{}', @n, @n)`,
		"mark under A's provisioner": `INSERT INTO grp_provisionable (tenant_id, provisioner_id, object_type, object_id, scope)
			VALUES (@t, 'pa', 'group', @g, 'self')`,
		"mark of A's group": `INSERT INTO grp_provisionable (tenant_id, provisioner_id, object_type, object_id, scope)
			VALUES (@t, 'pb', 'group', @g, 'self')`,
		"mark of A's folder": `INSERT INTO grp_provisionable (tenant_id, provisioner_id, object_type, object_id, scope)
			VALUES (@t, 'pb', 'folder', @f, 'sub')`,
		"sync group of A's group": `INSERT INTO grp_sync_groups (tenant_id, provisioner_id, group_id, status) VALUES (@t, 'pb', @g, 'synced')`,
		"sync group under A's provisioner": `INSERT INTO grp_sync_groups (tenant_id, provisioner_id, group_id, status)
			VALUES (@t, 'pa', @g, 'synced')`,
		"run of A's provisioner": `INSERT INTO grp_sync_runs (id, tenant_id, provisioner_id, kind, mode, status, started_at)
			VALUES ('rx', @t, 'pa', 'full', 'adopt', 'running', @n)`,
		"op of A's provisioner": `INSERT INTO grp_sync_ops (id, tenant_id, provisioner_id, op, object_ref, payload_hash, status, planned_at)
			VALUES ('ox', @t, 'pa', 'members', 'x', 'h', 'planned', @n)`,
		"op in A's run": `INSERT INTO grp_sync_ops (id, tenant_id, provisioner_id, run_id, op, object_ref, payload_hash, status, planned_at)
			VALUES ('oy', @t, 'pb', 'ra', 'members', 'x', 'h', 'planned', @n)`,
		"op on A's group": `INSERT INTO grp_sync_ops (id, tenant_id, provisioner_id, op, object_ref, group_id, payload_hash, status, planned_at)
			VALUES ('oz', @t, 'pb', 'members', 'x', @g, 'h', 'planned', @n)`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := exec(tb, q); err == nil || !strings.Contains(err.Error(), "cross-tenant reference") {
				t.Errorf("tenant B naming A's rows: %v, want a cross-tenant refusal", err)
			}
		})
	}
	// the same references made by A are fine
	for name, q := range map[string]string{
		"provisioner naming its connection": `INSERT INTO grp_provisioners (id, tenant_id, name, target_type, connection_id, config, failsafe, created_at, updated_at)
			VALUES ('px', @t, 'px', 'scim2', 'conn-a', '{}', '{}', @n, @n)`,
		"mark of its group":  `INSERT INTO grp_provisionable (tenant_id, provisioner_id, object_type, object_id, scope) VALUES (@t, 'pa', 'group', @g, 'self')`,
		"mark of its folder": `INSERT INTO grp_provisionable (tenant_id, provisioner_id, object_type, object_id, scope) VALUES (@t, 'pa', 'folder', @f, 'sub')`,
		"sync group":         `INSERT INTO grp_sync_groups (tenant_id, provisioner_id, group_id, status) VALUES (@t, 'pa', @g, 'synced')`,
		"op in its run": `INSERT INTO grp_sync_ops (id, tenant_id, provisioner_id, run_id, op, object_ref, group_id, payload_hash, status, planned_at)
			VALUES ('oa', @t, 'pa', 'ra', 'members', 'x', @g, 'h', 'planned', @n)`,
	} {
		t.Run("A: "+name, func(t *testing.T) {
			if err := exec(ta, q); err != nil {
				t.Errorf("tenant A naming its own rows: %v", err)
			}
		})
	}
	// a group mark carries no scope; a folder mark must have one
	if err := exec(ta, `INSERT INTO grp_provisionable (tenant_id, provisioner_id, object_type, object_id, scope) VALUES (@t, 'pa', 'group', 'x', 'sub')`); err == nil {
		t.Error("a group mark with scope sub was accepted")
	}
	if err := exec(ta, `INSERT INTO grp_provisionable (tenant_id, provisioner_id, object_type, object_id, scope) VALUES (@t, 'pa', 'folder', 'y', 'self')`); err == nil {
		t.Error("a folder mark with scope self was accepted")
	}
	// an update cannot move a row onto another tenant's provisioner
	if err := exec(ta, `UPDATE grp_provisionable SET provisioner_id = 'pb' WHERE provisioner_id = 'pa' AND object_type = 'group'`); err == nil ||
		!strings.Contains(err.Error(), "cross-tenant reference") {
		t.Errorf("moving a mark to B's provisioner: %v", err)
	}
}
