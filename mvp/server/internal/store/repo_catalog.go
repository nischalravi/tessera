package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// ---------------------------------------------------------------- groups

// Group is a group, team, role or security group.
type Group struct {
	ID          int64
	TenantID    tenancy.ID
	System      string
	ExternalID  string
	Name        string
	Kind        string
	Privileged  bool
	Requestable bool
	Description *string
}

const groupCols = `g.id, g.tenant_id, g.system, g.external_id, g.name, g.kind, g.privileged, g.requestable, g.description`

var (
	groupsList = tq("groups.list", `
		SELECT `+groupCols+` FROM groups g WHERE g.tenant_id = @tenant ORDER BY g.id`)
	groupsSorted = tq("groups.list_by_system_name", `
		SELECT `+groupCols+` FROM groups g WHERE g.tenant_id = @tenant ORDER BY g.system, g.name, g.id`)
	groupsSortedRequestable = tq("groups.list_by_system_name_requestable", `
		SELECT `+groupCols+` FROM groups g WHERE g.tenant_id = @tenant AND g.requestable = @requestable
		ORDER BY g.system, g.name, g.id`)
	groupsGet = tq("groups.get", `
		SELECT `+groupCols+` FROM groups g WHERE g.tenant_id = @tenant AND g.id = @id`)
	groupsByXID = tq("groups.by_external_id", `
		SELECT `+groupCols+` FROM groups g WHERE g.tenant_id = @tenant AND g.system = @system AND g.external_id = @external_id
		ORDER BY g.id LIMIT 1`)
	groupsUpsert = tq("groups.upsert", `
		INSERT INTO groups (tenant_id, system, external_id, name, kind, privileged, requestable, description)
		VALUES (@tenant, @system, @external_id, @name, @kind, @privileged, @requestable, @description)
		ON CONFLICT (tenant_id, system, external_id) DO UPDATE SET name = excluded.name, kind = excluded.kind,
			privileged = excluded.privileged, requestable = excluded.requestable, description = excluded.description`)
	groupsCountInSystem = tq("groups.count_in_system", `
		SELECT count(g.id) FROM groups g WHERE g.tenant_id = @tenant AND g.system = @system`)
)

func scanGroup(s scanner) (*Group, error) {
	var g Group
	var tid string
	var desc sql.NullString
	if err := s.Scan(&g.ID, &tid, &g.System, &g.ExternalID, &g.Name, &g.Kind, &g.Privileged, &g.Requestable, &desc); err != nil {
		return nil, err
	}
	var err error
	if g.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	g.Description = strp(desc)
	return &g, nil
}

// Groups returns every group, in id order.
func (tx *TenantTx) Groups() ([]*Group, error) { return collect(tx, scanGroup, groupsList) }

// GroupsBySystemName returns groups ordered by system then name, optionally
// only the (non-)requestable ones.
func (tx *TenantTx) GroupsBySystemName(requestable *bool) ([]*Group, error) {
	if requestable != nil {
		return collect(tx, scanGroup, groupsSortedRequestable, sql.Named("requestable", B(*requestable)))
	}
	return collect(tx, scanGroup, groupsSorted)
}

// Group returns one group by id.
func (tx *TenantTx) Group(id int64) (*Group, error) {
	return one(tx, scanGroup, groupsGet, sql.Named("id", id))
}

// GroupByXID returns the first group with the system and external id.
func (tx *TenantTx) GroupByXID(system, xid string) (*Group, error) {
	return one(tx, scanGroup, groupsByXID, sql.Named("system", system), sql.Named("external_id", xid))
}

// UpsertGroup inserts a group or updates the one with the same system and external id.
func (tx *TenantTx) UpsertGroup(g *Group) error {
	if err := tx.own(g.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(groupsUpsert, sql.Named("system", g.System), sql.Named("external_id", g.ExternalID),
		sql.Named("name", g.Name), sql.Named("kind", g.Kind), sql.Named("privileged", B(g.Privileged)),
		sql.Named("requestable", B(g.Requestable)), sql.Named("description", SP(g.Description)))
	return err
}

// ---------------------------------------------------------------- resources

// Resource is something permissions act on.
type Resource struct {
	ID          int64
	TenantID    tenancy.ID
	System      string
	ExternalID  string
	Name        string
	Kind        string
	Environment *string
	Tags        []string
}

const resourceCols = `r.id, r.tenant_id, r.system, r.external_id, r.name, r.kind, r.environment, r.tags`

var (
	resourcesList = tq("resources.list", `
		SELECT `+resourceCols+` FROM resources r WHERE r.tenant_id = @tenant ORDER BY r.id`)
	resourcesSorted = tq("resources.list_by_system_name", `
		SELECT `+resourceCols+` FROM resources r WHERE r.tenant_id = @tenant ORDER BY r.system, r.name, r.id`)
	resourcesName = tq("resources.name", `
		SELECT r.name FROM resources r WHERE r.tenant_id = @tenant AND r.id = @id`)
	resourcesUpsert = tq("resources.upsert", `
		INSERT INTO resources (tenant_id, system, external_id, name, kind, environment, tags)
		VALUES (@tenant, @system, @external_id, @name, @kind, @environment, @tags)
		ON CONFLICT (tenant_id, system, external_id) DO UPDATE SET name = excluded.name, kind = excluded.kind,
			environment = excluded.environment, tags = excluded.tags`)
	resourcesCountInSystem = tq("resources.count_in_system", `
		SELECT count(r.id) FROM resources r WHERE r.tenant_id = @tenant AND r.system = @system`)
)

func scanResource(s scanner) (*Resource, error) {
	var r Resource
	var tid string
	var env sql.NullString
	var tags string
	if err := s.Scan(&r.ID, &tid, &r.System, &r.ExternalID, &r.Name, &r.Kind, &env, &tags); err != nil {
		return nil, err
	}
	var err error
	if r.TenantID, err = tenantOf(tid); err != nil {
		return nil, err
	}
	r.Environment = strp(env)
	if err := json.Unmarshal([]byte(tags), &r.Tags); err != nil {
		return nil, fmt.Errorf("store: resource %d tags: %w", r.ID, err)
	}
	if r.Tags == nil {
		r.Tags = []string{}
	}
	return &r, nil
}

// Resources returns every resource, in id order.
func (tx *TenantTx) Resources() ([]*Resource, error) { return collect(tx, scanResource, resourcesList) }

// ResourcesBySystemName returns every resource ordered by system then name.
func (tx *TenantTx) ResourcesBySystemName() ([]*Resource, error) {
	return collect(tx, scanResource, resourcesSorted)
}

// ResourceName returns a resource's name.
func (tx *TenantTx) ResourceName(id int64) (string, error) {
	var name string
	err := tx.queryRow(resourcesName, sql.Named("id", id)).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return name, err
}

// UpsertResource inserts a resource or updates the one with the same system and external id.
func (tx *TenantTx) UpsertResource(r *Resource) error {
	if err := tx.own(r.TenantID); err != nil {
		return err
	}
	t := r.Tags
	if t == nil {
		t = []string{}
	}
	tags, err := JSON(t)
	if err != nil {
		return err
	}
	_, err = tx.exec(resourcesUpsert, sql.Named("system", r.System), sql.Named("external_id", r.ExternalID),
		sql.Named("name", r.Name), sql.Named("kind", r.Kind), sql.Named("environment", SP(r.Environment)),
		sql.Named("tags", tags))
	return err
}

// ---------------------------------------------------------------- permissions

// Permission is an action on a resource.
type Permission struct {
	ID         int64
	TenantID   tenancy.ID
	System     string
	ExternalID string
	Action     string
	ResourceID int64
	Privileged bool
}

const permissionCols = `p.id, p.tenant_id, p.system, p.external_id, p.action, p.resource_id, p.privileged`

var (
	permissionsList = tq("permissions.list", `
		SELECT `+permissionCols+` FROM permissions p WHERE p.tenant_id = @tenant ORDER BY p.id`)
	permissionsGet = tq("permissions.get", `
		SELECT `+permissionCols+` FROM permissions p WHERE p.tenant_id = @tenant AND p.id = @id`)
	permissionsUpsert = tq("permissions.upsert", `
		INSERT INTO permissions (tenant_id, system, external_id, action, resource_id, privileged)
		VALUES (@tenant, @system, @external_id, @action, @resource_id, @privileged)
		ON CONFLICT (tenant_id, system, external_id) DO UPDATE SET action = excluded.action,
			resource_id = excluded.resource_id, privileged = excluded.privileged`)
	permissionsCountInSystem = tq("permissions.count_in_system", `
		SELECT count(p.id) FROM permissions p WHERE p.tenant_id = @tenant AND p.system = @system`)
)

func scanPermission(s scanner) (*Permission, error) {
	var p Permission
	var tid string
	if err := s.Scan(&p.ID, &tid, &p.System, &p.ExternalID, &p.Action, &p.ResourceID, &p.Privileged); err != nil {
		return nil, err
	}
	var err error
	p.TenantID, err = tenantOf(tid)
	return &p, err
}

// Permissions returns every permission, in id order.
func (tx *TenantTx) Permissions() ([]*Permission, error) {
	return collect(tx, scanPermission, permissionsList)
}

// Permission returns one permission by id.
func (tx *TenantTx) Permission(id int64) (*Permission, error) {
	return one(tx, scanPermission, permissionsGet, sql.Named("id", id))
}

// UpsertPermission inserts a permission or updates the one with the same system and external id.
func (tx *TenantTx) UpsertPermission(p *Permission) error {
	if err := tx.own(p.TenantID); err != nil {
		return err
	}
	_, err := tx.exec(permissionsUpsert, sql.Named("system", p.System), sql.Named("external_id", p.ExternalID),
		sql.Named("action", p.Action), sql.Named("resource_id", p.ResourceID), sql.Named("privileged", B(p.Privileged)))
	return err
}
