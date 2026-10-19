package store

import (
	"database/sql"
	"time"
)

// Ownership of applications, entitlements and machine identities
// (schema/0208_ownership.sql, issue #167).

// Owned object kinds.
const (
	OwnedApp      = "app"
	OwnedGroup    = "group"
	OwnedResource = "resource"
	OwnedIdentity = "identity"
)

// Ownership is who owns one object, and why it exists.
type Ownership struct {
	Kind      string
	Key       string // system name, or the object's id
	PrimaryID *int64
	BackupID  *int64
	GroupID   *int64
	Purpose   string
	UpdatedBy *string
	UpdatedAt time.Time
}

const ownershipCols = `o.object_kind, o.object_key, o.primary_owner_id, o.backup_owner_id, o.owner_group_id, o.purpose,
	o.updated_by, o.updated_at`

var (
	ownershipsList = tq("ownerships.list", `
		SELECT `+ownershipCols+` FROM ownerships o WHERE o.tenant_id = @tenant AND (@kind = '' OR o.object_kind = @kind)
		ORDER BY o.object_kind, o.object_key`)
	ownershipsGet = tq("ownerships.get", `
		SELECT `+ownershipCols+` FROM ownerships o WHERE o.tenant_id = @tenant AND o.object_kind = @kind AND o.object_key = @key`)
	ownershipsOf = tq("ownerships.of_owner", `
		SELECT `+ownershipCols+` FROM ownerships o WHERE o.tenant_id = @tenant
			AND (o.primary_owner_id = @owner OR o.backup_owner_id = @owner) ORDER BY o.object_kind, o.object_key`)
	ownershipsPut = tq("ownerships.put", `
		INSERT INTO ownerships (tenant_id, object_kind, object_key, primary_owner_id, backup_owner_id, owner_group_id, purpose,
			updated_by, updated_at)
		VALUES (@tenant, @kind, @key, @primary, @backup, @group, @purpose, @updated_by, @updated_at)
		ON CONFLICT (tenant_id, object_kind, object_key) DO UPDATE SET primary_owner_id = excluded.primary_owner_id,
			backup_owner_id = excluded.backup_owner_id, owner_group_id = excluded.owner_group_id, purpose = excluded.purpose,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
)

func scanOwnership(s scanner) (*Ownership, error) {
	var o Ownership
	var p, b, g sql.NullInt64
	var by sql.NullString
	var at nullTime
	if err := s.Scan(&o.Kind, &o.Key, &p, &b, &g, &o.Purpose, &by, &at); err != nil {
		return nil, err
	}
	o.PrimaryID, o.BackupID, o.GroupID, o.UpdatedBy = intp(p), intp(b), intp(g), strp(by)
	var err error
	o.UpdatedAt, err = at.val()
	return &o, err
}

// Ownerships lists ownership rows ("" for every kind).
func (tx *TenantTx) Ownerships(kind string) ([]*Ownership, error) {
	return collect(tx, scanOwnership, ownershipsList, sql.Named("kind", kind))
}

// Ownership returns one object's row, or ErrNotFound.
func (tx *TenantTx) Ownership(kind, key string) (*Ownership, error) {
	return one(tx, scanOwnership, ownershipsGet, sql.Named("kind", kind), sql.Named("key", key))
}

// OwnershipsOf lists the objects an identity owns as primary or backup.
func (tx *TenantTx) OwnershipsOf(identityID int64) ([]*Ownership, error) {
	return collect(tx, scanOwnership, ownershipsOf, sql.Named("owner", identityID))
}

// PutOwnership sets one object's ownership.
func (tx *TenantTx) PutOwnership(o *Ownership) error {
	_, err := tx.exec(ownershipsPut, sql.Named("kind", o.Kind), sql.Named("key", o.Key), sql.Named("primary", IP(o.PrimaryID)),
		sql.Named("backup", IP(o.BackupID)), sql.Named("group", IP(o.GroupID)), sql.Named("purpose", o.Purpose),
		sql.Named("updated_by", SP(o.UpdatedBy)), sql.Named("updated_at", T(o.UpdatedAt)))
	return err
}
