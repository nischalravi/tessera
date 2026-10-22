package store

import (
	"database/sql"
	"errors"
)

// Statements for purging a soft-deleted group and for deleting a folder tree
// (docs: mvp/README.md "Purge and recursive delete"). No new table: every
// statement is bound to the transaction's tenant.

var (
	grpGroupDelete = tq("grp_groups.delete", `DELETE FROM grp_groups WHERE tenant_id = @tenant AND id = @id`)
	grpLevelDelete = tq("grp_levels.delete", `DELETE FROM grp_levels WHERE tenant_id = @tenant AND group_id = @group_id`)
	// the groups that still use a group: as a nested member or as a composite factor
	grpGroupUsers = tq("grp_groups.users", `SELECT g.id, g.name FROM grp_groups g
		WHERE g.tenant_id = @tenant AND (
			g.id IN (SELECT d.group_id FROM grp_direct_memberships d WHERE d.tenant_id = @tenant AND d.member_group_id = @id)
			OR g.id IN (SELECT f.group_id FROM grp_composite_factors f WHERE f.tenant_id = @tenant AND f.factor_group_id = @id))
		ORDER BY lower(g.name)`)
	grpFolderDeletedGroups = tq("grp_folders.deleted_group_count", `SELECT count(*) FROM grp_groups g
		WHERE g.tenant_id = @tenant AND g.folder_id = @id AND g.status = 'deleted'`)
	// configuration and history that name a group through a foreign key and that a purge does not rewrite
	grpGroupRefs = tq("grp_groups.refs", `SELECT
		CASE WHEN EXISTS (SELECT 1 FROM grp_loaders l WHERE l.tenant_id = @tenant AND l.and_group_id = g.id) THEN 1 ELSE 0 END,
		CASE WHEN EXISTS (SELECT 1 FROM grp_attest_campaigns c WHERE c.tenant_id = @tenant AND (c.group_id = g.id OR c.reviewer_group_id = g.id)) THEN 1 ELSE 0 END,
		CASE WHEN EXISTS (SELECT 1 FROM grp_attest_items i WHERE i.tenant_id = @tenant AND i.group_id = g.id) THEN 1 ELSE 0 END,
		CASE WHEN EXISTS (SELECT 1 FROM grp_attest_settings s WHERE s.tenant_id = @tenant AND s.reviewer_group_id = g.id) THEN 1 ELSE 0 END,
		CASE WHEN EXISTS (SELECT 1 FROM grp_sync_groups s WHERE s.tenant_id = @tenant AND s.group_id = g.id) THEN 1 ELSE 0 END,
		CASE WHEN EXISTS (SELECT 1 FROM grp_sync_ops o WHERE o.tenant_id = @tenant AND o.group_id = g.id) THEN 1 ELSE 0 END
		FROM grp_groups g WHERE g.tenant_id = @tenant AND g.id = @id`)
)

// DeleteGrpGroup removes a group row (ErrNotFound if this tenant has none). The
// model layer has removed everything that points at it first.
func (tx *TenantTx) DeleteGrpGroup(id GroupID) error {
	res, err := tx.exec(grpGroupDelete, sql.Named("id", string(id)))
	return rowsOrNotFound(res, err)
}

// DeleteGrpLevel removes a group's level row.
func (tx *TenantTx) DeleteGrpLevel(group GroupID) error {
	_, err := tx.exec(grpLevelDelete, sql.Named("group_id", string(group)))
	return err
}

// GrpGroupRef names a group by id and name.
type GrpGroupRef struct {
	ID   GroupID
	Name string
}

// GrpGroupUsers lists the groups that still have the group as a direct member
// or as a composite factor, by name.
func (tx *TenantTx) GrpGroupUsers(id GroupID) ([]GrpGroupRef, error) {
	rows, err := collect(tx, func(s scanner) (*GrpGroupRef, error) {
		var r GrpGroupRef
		return &r, s.Scan(&r.ID, &r.Name)
	}, grpGroupUsers, sql.Named("id", string(id)))
	out := make([]GrpGroupRef, len(rows))
	for i, r := range rows {
		out[i] = *r
	}
	return out, err
}

// grpRefLabels name, in the order of the columns of grpGroupRefs, what each one found.
var grpRefLabels = [...]string{"a loader that keeps only members of it", "an attestation campaign", "an attestation review item",
	"attestation settings that name it the reviewer", "a provisioning sync", "a provisioning operation"}

// GrpGroupRefs describes the configuration and history rows that name the group
// and that a purge leaves alone (a loader's and_group, attestation, provisioning).
func (tx *TenantTx) GrpGroupRefs(id GroupID) ([]string, error) {
	var found [len(grpRefLabels)]int
	err := tx.queryRow(grpGroupRefs, sql.Named("id", string(id))).Scan(&found[0], &found[1], &found[2], &found[3], &found[4], &found[5])
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for i, n := range found {
		if n > 0 {
			out = append(out, grpRefLabels[i])
		}
	}
	return out, nil
}

// GrpFolderDeletedGroupCount counts the soft-deleted groups directly in a folder.
func (tx *TenantTx) GrpFolderDeletedGroupCount(id FolderID) (int, error) {
	return tx.count(grpFolderDeletedGroups, sql.Named("id", string(id)))
}
