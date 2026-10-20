package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Native groups repository (schema/0280_groups.sql). Methods are prefixed Grp
// because Group and Groups already name the connected-system groups (the type
// is NativeGroup for the same reason). The
// membership and engine tables have no repository until GR-2.

// ErrVersionConflict is returned by UpdateGrpFolder and UpdateGrpGroup when the
// row's version is no longer the one the caller read (optimistic concurrency).
var ErrVersionConflict = errors.New("store: version conflict")

// membersListNS derives the fixed per-tenant id of the built-in members list.
var membersListNS = uuid.MustParse("6f1d2f0e-5d0a-4a4e-9a52-7a9c1d1f6b11")

// MembersListID is the id of the tenant's built-in "members" list: fixed per
// tenant, so GR-2 can name it without a lookup.
func MembersListID(t tenancy.ID) ListID {
	return ListID(uuid.NewSHA1(membersListNS, []byte(t.String())).String())
}

const folderCols = `f.id, f.tenant_id, f.parent_id, f.extension, f.display_extension, f.name, f.display_name,
	f.description, f.id_index, f.object_types, f.data_owner, f.managed_by, f.external_ref, f.created_at, f.created_by, f.version`

const grpGroupCols = `g.id, g.tenant_id, g.folder_id, g.extension, g.display_extension, g.name, g.display_name,
	g.description, g.id_index, g.kind, g.definition, g.composite_op, g.policy_ref, g.managed_by, g.loader_id,
	g.object_types, g.data_owner, g.member_description, g.enabled_from, g.disabled_at, g.status, g.requestable,
	g.effective_count, g.effective_version, g.recompute_state, g.external_ref, g.created_at, g.created_by, g.version`

// The prefix tests are the case-insensitive "strictly below the ':' path"
// match; @below is the lower-cased path plus ':' (see belowArg). They avoid
// LIKE, where '_' (allowed in names) is a wildcard.
const folderPrefixMatch = `substr(lower(f.name), 1, length(@below)) = @below`
const groupPrefixMatch = `substr(lower(g.name), 1, length(@below)) = @below`

// belowArg is the @below argument for a ':' path prefix; "" means no filter
// unless always is set.
func belowArg(prefix string, always bool) sql.NamedArg {
	if prefix == "" && !always {
		return sql.Named("below", "")
	}
	return sql.Named("below", strings.ToLower(prefix)+":")
}

var (
	grpFolderGet    = tq("grp_folders.get", `SELECT `+folderCols+` FROM grp_folders f WHERE f.tenant_id = @tenant AND f.id = @id`)
	grpFolderRoot   = tq("grp_folders.root", `SELECT `+folderCols+` FROM grp_folders f WHERE f.tenant_id = @tenant AND f.parent_id IS NULL`)
	grpFolderByName = tq("grp_folders.by_name", `SELECT `+folderCols+` FROM grp_folders f
		WHERE f.tenant_id = @tenant AND lower(f.name) = lower(@name)`)
	grpFolderList = tq("grp_folders.list", `SELECT `+folderCols+` FROM grp_folders f
		WHERE f.tenant_id = @tenant
		  AND (@parent_id = '' OR f.parent_id = @parent_id)
		  AND (@below = '' OR `+folderPrefixMatch+`)
		  AND (@q = '' OR instr(lower(f.name), lower(@q)) > 0 OR instr(lower(f.display_name), lower(@q)) > 0)
		  AND (@exclude_root = 0 OR f.parent_id IS NOT NULL)
		ORDER BY lower(f.name) LIMIT @limit OFFSET @offset`)
	grpFolderBelow = tq("grp_folders.below", `SELECT `+folderCols+` FROM grp_folders f
		WHERE f.tenant_id = @tenant AND `+folderPrefixMatch+` ORDER BY lower(f.name)`)
	grpFolderSubfolders = tq("grp_folders.subfolder_count", `SELECT count(*) FROM grp_folders f
		WHERE f.tenant_id = @tenant AND f.parent_id = @id`)
	grpFolderGroupCount = tq("grp_folders.group_count", `SELECT count(*) FROM grp_groups g
		WHERE g.tenant_id = @tenant AND g.folder_id = @id`)
	grpFolderMaxIndex = tq("grp_folders.max_index", `SELECT COALESCE(MAX(f.id_index), 0) FROM grp_folders f WHERE f.tenant_id = @tenant`)
	grpFolderInsert   = tq("grp_folders.insert", `
		INSERT INTO grp_folders (id, tenant_id, parent_id, extension, display_extension, name, display_name, description,
			id_index, object_types, data_owner, managed_by, external_ref, created_at, created_by, version)
		VALUES (@id, @tenant, @parent_id, @extension, @display_extension, @name, @display_name, @description,
			@id_index, @object_types, @data_owner, @managed_by, @external_ref, @created_at, @created_by, 1)`)
	grpFolderUpdate = tq("grp_folders.update", `
		UPDATE grp_folders SET parent_id = @parent_id, extension = @extension, display_extension = @display_extension,
			name = @name, display_name = @display_name, description = @description, data_owner = @data_owner,
			version = version + 1
		WHERE tenant_id = @tenant AND id = @id AND version = @version`)
	grpFolderSetManagedBy = tq("grp_folders.set_managed_by", `UPDATE grp_folders SET managed_by = @managed_by
		WHERE tenant_id = @tenant AND id = @id`)
	grpFolderDelete = tq("grp_folders.delete", `DELETE FROM grp_folders WHERE tenant_id = @tenant AND id = @id`)

	grpGroupGet    = tq("grp_groups.get", `SELECT `+grpGroupCols+` FROM grp_groups g WHERE g.tenant_id = @tenant AND g.id = @id`)
	grpGroupByName = tq("grp_groups.by_name", `SELECT `+grpGroupCols+` FROM grp_groups g
		WHERE g.tenant_id = @tenant AND lower(g.name) = lower(@name)`)
	grpGroupList = tq("grp_groups.list", `SELECT `+grpGroupCols+` FROM grp_groups g
		WHERE g.tenant_id = @tenant
		  AND (@folder_id = '' OR g.folder_id = @folder_id)
		  AND (@below = '' OR `+groupPrefixMatch+`)
		  AND (@q = '' OR instr(lower(g.name), lower(@q)) > 0 OR instr(lower(g.display_name), lower(@q)) > 0)
		  AND (@kind = '' OR g.kind = @kind)
		  AND (@include_deleted = 1 OR g.status <> 'deleted')
		ORDER BY lower(g.name) LIMIT @limit OFFSET @offset`)
	grpGroupBelow = tq("grp_groups.below", `SELECT `+grpGroupCols+` FROM grp_groups g
		WHERE g.tenant_id = @tenant AND `+groupPrefixMatch+` ORDER BY lower(g.name)`)
	grpGroupInFolder = tq("grp_groups.in_folder", `SELECT `+grpGroupCols+` FROM grp_groups g
		WHERE g.tenant_id = @tenant AND g.folder_id = @folder_id ORDER BY lower(g.name)`)
	grpGroupMaxIndex = tq("grp_groups.max_index", `SELECT COALESCE(MAX(g.id_index), 0) FROM grp_groups g WHERE g.tenant_id = @tenant`)
	grpGroupInsert   = tq("grp_groups.insert", `
		INSERT INTO grp_groups (id, tenant_id, folder_id, extension, display_extension, name, display_name, description,
			id_index, kind, definition, composite_op, policy_ref, managed_by, loader_id, object_types, data_owner,
			member_description, enabled_from, disabled_at, status, requestable, external_ref, created_at, created_by, version)
		VALUES (@id, @tenant, @folder_id, @extension, @display_extension, @name, @display_name, @description,
			@id_index, @kind, @definition, @composite_op, @policy_ref, @managed_by, @loader_id, @object_types, @data_owner,
			@member_description, @enabled_from, @disabled_at, @status, @requestable, @external_ref, @created_at, @created_by, 1)`)
	grpGroupUpdate = tq("grp_groups.update", `
		UPDATE grp_groups SET folder_id = @folder_id, extension = @extension, display_extension = @display_extension,
			name = @name, display_name = @display_name, description = @description, data_owner = @data_owner,
			member_description = @member_description, status = @status, requestable = @requestable,
			enabled_from = @enabled_from, disabled_at = @disabled_at, version = version + 1
		WHERE tenant_id = @tenant AND id = @id AND version = @version`)

	grpAliasInsert = tq("grp_name_aliases.insert", `
		INSERT INTO grp_name_aliases (tenant_id, object_type, object_id, old_name, created_at)
		VALUES (@tenant, @object_type, @object_id, @old_name, @created_at)`)
	grpAliasByName = tq("grp_name_aliases.by_name", `SELECT a.object_type, a.object_id, a.old_name, a.created_at
		FROM grp_name_aliases a WHERE a.tenant_id = @tenant AND lower(a.old_name) = lower(@name)`)
	grpAliasesOf = tq("grp_name_aliases.of", `SELECT a.object_type, a.object_id, a.old_name, a.created_at
		FROM grp_name_aliases a WHERE a.tenant_id = @tenant AND a.object_type = @object_type AND a.object_id = @object_id
		ORDER BY a.created_at, lower(a.old_name)`)
	grpAliasDelete = tq("grp_name_aliases.delete", `DELETE FROM grp_name_aliases
		WHERE tenant_id = @tenant AND object_type = @object_type AND object_id = @object_id AND lower(old_name) = lower(@name)`)
	grpAliasDeleteOf = tq("grp_name_aliases.delete_of", `DELETE FROM grp_name_aliases
		WHERE tenant_id = @tenant AND object_type = @object_type AND object_id = @object_id`)

	grpListInsert = tq("grp_lists.insert_builtin", `
		INSERT INTO grp_lists (id, tenant_id, name, read_priv, write_priv)
		VALUES (@id, @tenant, 'members', 'read', 'update')
		ON CONFLICT (tenant_id, name) DO NOTHING`)
	grpListGet = tq("grp_lists.get", `SELECT l.id FROM grp_lists l WHERE l.tenant_id = @tenant AND l.id = @id`)
)

func decodeObjectTypes(s string) ([]ObjectType, error) {
	var out []ObjectType
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func scanGrpFolder(s scanner) (*Folder, error) {
	var f Folder
	var tenant, created, objTypes, managed string
	var parent, owner, ext, by sql.NullString
	if err := s.Scan(&f.ID, &tenant, &parent, &f.Extension, &f.DisplayExtension, &f.Name, &f.DisplayName, &f.Description,
		&f.IDIndex, &objTypes, &owner, &managed, &ext, &created, &by, &f.Version); err != nil {
		return nil, err
	}
	var err error
	if f.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	if parent.Valid {
		p := FolderID(parent.String)
		f.ParentID = &p
	}
	f.ManagedBy, f.DataOwner, f.ExternalRef, f.CreatedBy = ManagedBy(managed), strp(owner), strp(ext), strp(by)
	if f.ObjectTypes, err = decodeObjectTypes(objTypes); err != nil {
		return nil, err
	}
	f.CreatedAt, err = ParseRT(created)
	return &f, err
}

func scanGrpGroup(s scanner) (*NativeGroup, error) {
	var g NativeGroup
	var tenant, created, objTypes, kind, def, managed string
	var op, policy, loader, owner, memberDesc, from, to, ext, by sql.NullString
	var requestable int
	if err := s.Scan(&g.ID, &tenant, &g.FolderID, &g.Extension, &g.DisplayExtension, &g.Name, &g.DisplayName, &g.Description,
		&g.IDIndex, &kind, &def, &op, &policy, &managed, &loader, &objTypes, &owner, &memberDesc, &from, &to, &g.Status,
		&requestable, &g.EffectiveCount, &g.EffectiveVersion, &g.RecomputeState, &ext, &created, &by, &g.Version); err != nil {
		return nil, err
	}
	var err error
	if g.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	g.Kind, g.Definition, g.ManagedBy, g.Requestable = GroupKind(kind), Definition(def), ManagedBy(managed), requestable == 1
	if op.Valid {
		o := CompositeOp(op.String)
		g.CompositeOp = &o
	}
	g.PolicyRef, g.LoaderID, g.DataOwner, g.MemberDescription = strp(policy), strp(loader), strp(owner), strp(memberDesc)
	g.ExternalRef, g.CreatedBy = strp(ext), strp(by)
	if g.ObjectTypes, err = decodeObjectTypes(objTypes); err != nil {
		return nil, err
	}
	if g.EnabledFrom, err = rtp(from); err != nil {
		return nil, err
	}
	if g.DisabledAt, err = rtp(to); err != nil {
		return nil, err
	}
	g.CreatedAt, err = ParseRT(created)
	return &g, err
}

func scanGrpAlias(s scanner) (*GrpAlias, error) {
	var a GrpAlias
	var at string
	if err := s.Scan(&a.ObjectType, &a.ObjectID, &a.OldName, &at); err != nil {
		return nil, err
	}
	var err error
	a.CreatedAt, err = ParseRT(at)
	return &a, err
}

func objectTypesJSON(ts []ObjectType) (string, error) {
	if ts == nil {
		ts = []ObjectType{}
	}
	return JSON(ts)
}

// ---------------------------------------------------------------- folders

// GrpFolder returns a folder or ErrNotFound.
func (tx *TenantTx) GrpFolder(id FolderID) (*Folder, error) {
	return one(tx, scanGrpFolder, grpFolderGet, sql.Named("id", string(id)))
}

// GrpRootFolder returns the tenant's root folder or ErrNotFound (the model
// layer creates it on the first write).
func (tx *TenantTx) GrpRootFolder() (*Folder, error) { return one(tx, scanGrpFolder, grpFolderRoot) }

// GrpFolderByName finds a folder by its full name, case-insensitively.
func (tx *TenantTx) GrpFolderByName(name string) (*Folder, error) {
	return one(tx, scanGrpFolder, grpFolderByName, sql.Named("name", name))
}

// GrpFolders lists folders by name; a zero Limit means 100.
func (tx *TenantTx) GrpFolders(f GrpFolderFilter) ([]*Folder, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	return collect(tx, scanGrpFolder, grpFolderList, sql.Named("parent_id", string(f.ParentID)), belowArg(f.Prefix, false),
		sql.Named("q", f.Q), sql.Named("exclude_root", B(f.ExcludeRoot)), sql.Named("limit", f.Limit), sql.Named("offset", f.Offset))
}

// GrpFoldersBelow lists every folder strictly below the ':' path prefix.
func (tx *TenantTx) GrpFoldersBelow(prefix string) ([]*Folder, error) {
	return collect(tx, scanGrpFolder, grpFolderBelow, belowArg(prefix, true))
}

// GrpFolderChildCounts counts a folder's subfolders and groups (deleted groups
// included: they still hold the name and can be restored).
func (tx *TenantTx) GrpFolderChildCounts(id FolderID) (folders, groups int, err error) {
	if folders, err = tx.count(grpFolderSubfolders, sql.Named("id", string(id))); err != nil {
		return 0, 0, err
	}
	groups, err = tx.count(grpFolderGroupCount, sql.Named("id", string(id)))
	return folders, groups, err
}

// InsertGrpFolder inserts f, assigning its id (when empty), id_index and
// version 1. f.TenantID must be zero or the transaction's tenant.
func (tx *TenantTx) InsertGrpFolder(f *Folder) error {
	if err := tx.own(f.TenantID); err != nil {
		return err
	}
	if f.ID == "" {
		f.ID = FolderID(uuid.NewString())
	}
	var max int64
	if err := tx.queryRow(grpFolderMaxIndex).Scan(&max); err != nil {
		return err
	}
	types, err := objectTypesJSON(f.ObjectTypes)
	if err != nil {
		return err
	}
	var parent any
	if f.ParentID != nil {
		parent = string(*f.ParentID)
	}
	if f.ManagedBy == "" {
		f.ManagedBy = ManagedByUI
	}
	f.TenantID, f.IDIndex, f.Version = tx.tenant, max+1, 1
	_, err = tx.exec(grpFolderInsert, sql.Named("id", string(f.ID)), sql.Named("parent_id", parent),
		sql.Named("extension", f.Extension), sql.Named("display_extension", f.DisplayExtension), sql.Named("name", f.Name),
		sql.Named("display_name", f.DisplayName), sql.Named("description", f.Description), sql.Named("id_index", f.IDIndex),
		sql.Named("object_types", types), sql.Named("data_owner", SP(f.DataOwner)), sql.Named("managed_by", string(f.ManagedBy)),
		sql.Named("external_ref", SP(f.ExternalRef)), sql.Named("created_at", RT(f.CreatedAt)), sql.Named("created_by", SP(f.CreatedBy)))
	return err
}

// UpdateGrpFolder writes f's parent, names, description and owner if the
// stored version is still f.Version, and bumps f.Version. ErrNotFound for a
// missing (or other tenant's) folder, ErrVersionConflict for a stale version.
func (tx *TenantTx) UpdateGrpFolder(f *Folder) error {
	var parent any
	if f.ParentID != nil {
		parent = string(*f.ParentID)
	}
	res, err := tx.exec(grpFolderUpdate, sql.Named("id", string(f.ID)), sql.Named("parent_id", parent),
		sql.Named("extension", f.Extension), sql.Named("display_extension", f.DisplayExtension), sql.Named("name", f.Name),
		sql.Named("display_name", f.DisplayName), sql.Named("description", f.Description), sql.Named("data_owner", SP(f.DataOwner)),
		sql.Named("version", f.Version))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		if _, err := tx.GrpFolder(f.ID); err != nil {
			return err
		}
		return ErrVersionConflict
	}
	f.Version++
	return nil
}

// SetGrpFolderManagedBy changes a folder's writer (an importer marks a folder
// grouper_mirror; the API refuses writes to such a folder).
func (tx *TenantTx) SetGrpFolderManagedBy(id FolderID, by ManagedBy) error {
	res, err := tx.exec(grpFolderSetManagedBy, sql.Named("id", string(id)), sql.Named("managed_by", string(by)))
	return rowsOrNotFound(res, err)
}

// DeleteGrpFolder removes a folder row (the model layer refuses a non-empty one).
func (tx *TenantTx) DeleteGrpFolder(id FolderID) error {
	res, err := tx.exec(grpFolderDelete, sql.Named("id", string(id)))
	return rowsOrNotFound(res, err)
}

func rowsOrNotFound(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- groups

// GrpGroup returns a group (any status) or ErrNotFound.
func (tx *TenantTx) GrpGroup(id GroupID) (*NativeGroup, error) {
	return one(tx, scanGrpGroup, grpGroupGet, sql.Named("id", string(id)))
}

// GrpGroupByName finds a group by its full name, case-insensitively.
func (tx *TenantTx) GrpGroupByName(name string) (*NativeGroup, error) {
	return one(tx, scanGrpGroup, grpGroupByName, sql.Named("name", name))
}

// GrpGroups lists groups by name; a zero Limit means 100. Deleted groups are
// listed only with IncludeDeleted.
func (tx *TenantTx) GrpGroups(f GrpGroupFilter) ([]*NativeGroup, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	return collect(tx, scanGrpGroup, grpGroupList, sql.Named("folder_id", string(f.FolderID)), belowArg(f.Prefix, false),
		sql.Named("q", f.Q), sql.Named("kind", string(f.Kind)), sql.Named("include_deleted", B(f.IncludeDeleted)),
		sql.Named("limit", f.Limit), sql.Named("offset", f.Offset))
}

// GrpGroupsBelow lists every group (any status) strictly below the ':' path prefix.
func (tx *TenantTx) GrpGroupsBelow(prefix string) ([]*NativeGroup, error) {
	return collect(tx, scanGrpGroup, grpGroupBelow, belowArg(prefix, true))
}

// GrpGroupsInFolder lists a folder's groups (any status).
func (tx *TenantTx) GrpGroupsInFolder(id FolderID) ([]*NativeGroup, error) {
	return collect(tx, scanGrpGroup, grpGroupInFolder, sql.Named("folder_id", string(id)))
}

// InsertGrpGroup inserts g, assigning its id (when empty), id_index and
// version 1. g.TenantID must be zero or the transaction's tenant.
func (tx *TenantTx) InsertGrpGroup(g *NativeGroup) error {
	if err := tx.own(g.TenantID); err != nil {
		return err
	}
	if g.ID == "" {
		g.ID = GroupID(uuid.NewString())
	}
	var max int64
	if err := tx.queryRow(grpGroupMaxIndex).Scan(&max); err != nil {
		return err
	}
	types, err := objectTypesJSON(g.ObjectTypes)
	if err != nil {
		return err
	}
	var op any
	if g.CompositeOp != nil {
		op = string(*g.CompositeOp)
	}
	if g.ManagedBy == "" {
		g.ManagedBy = ManagedByUI
	}
	if g.Kind == "" {
		g.Kind = KindGroup
	}
	if g.Definition == "" {
		g.Definition = DefinitionBasic
	}
	if g.Status == "" {
		g.Status = GroupActive
	}
	if g.RecomputeState == "" {
		g.RecomputeState = "clean"
	}
	g.TenantID, g.IDIndex, g.Version = tx.tenant, max+1, 1
	_, err = tx.exec(grpGroupInsert, sql.Named("id", string(g.ID)), sql.Named("folder_id", string(g.FolderID)),
		sql.Named("extension", g.Extension), sql.Named("display_extension", g.DisplayExtension), sql.Named("name", g.Name),
		sql.Named("display_name", g.DisplayName), sql.Named("description", g.Description), sql.Named("id_index", g.IDIndex),
		sql.Named("kind", string(g.Kind)), sql.Named("definition", string(g.Definition)), sql.Named("composite_op", op),
		sql.Named("policy_ref", SP(g.PolicyRef)), sql.Named("managed_by", string(g.ManagedBy)), sql.Named("loader_id", SP(g.LoaderID)),
		sql.Named("object_types", types), sql.Named("data_owner", SP(g.DataOwner)),
		sql.Named("member_description", SP(g.MemberDescription)), sql.Named("enabled_from", RTP(g.EnabledFrom)),
		sql.Named("disabled_at", RTP(g.DisabledAt)), sql.Named("status", g.Status), sql.Named("requestable", B(g.Requestable)),
		sql.Named("external_ref", SP(g.ExternalRef)), sql.Named("created_at", RT(g.CreatedAt)), sql.Named("created_by", SP(g.CreatedBy)))
	return err
}

// UpdateGrpGroup writes g's folder, names, description, owner, status,
// requestable flag and enabled and disabled dates if the stored version is still g.Version, and bumps
// g.Version. Errors as UpdateGrpFolder.
func (tx *TenantTx) UpdateGrpGroup(g *NativeGroup) error {
	res, err := tx.exec(grpGroupUpdate, sql.Named("id", string(g.ID)), sql.Named("folder_id", string(g.FolderID)),
		sql.Named("extension", g.Extension), sql.Named("display_extension", g.DisplayExtension), sql.Named("name", g.Name),
		sql.Named("display_name", g.DisplayName), sql.Named("description", g.Description), sql.Named("data_owner", SP(g.DataOwner)),
		sql.Named("member_description", SP(g.MemberDescription)), sql.Named("status", g.Status),
		sql.Named("requestable", B(g.Requestable)), sql.Named("enabled_from", RTP(g.EnabledFrom)),
		sql.Named("disabled_at", RTP(g.DisabledAt)), sql.Named("version", g.Version))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		if _, err := tx.GrpGroup(g.ID); err != nil {
			return err
		}
		return ErrVersionConflict
	}
	g.Version++
	return nil
}

// ---------------------------------------------------------------- aliases

// InsertGrpAlias records old_name as an alias of a folder or group.
func (tx *TenantTx) InsertGrpAlias(a *GrpAlias) error {
	_, err := tx.exec(grpAliasInsert, sql.Named("object_type", a.ObjectType), sql.Named("object_id", a.ObjectID),
		sql.Named("old_name", a.OldName), sql.Named("created_at", RT(a.CreatedAt)))
	return err
}

// GrpAliasByName finds the alias with this name, case-insensitively, or ErrNotFound.
func (tx *TenantTx) GrpAliasByName(name string) (*GrpAlias, error) {
	return one(tx, scanGrpAlias, grpAliasByName, sql.Named("name", name))
}

// GrpAliasesOf lists an object's aliases, oldest first.
func (tx *TenantTx) GrpAliasesOf(objectType, objectID string) ([]*GrpAlias, error) {
	return collect(tx, scanGrpAlias, grpAliasesOf, sql.Named("object_type", objectType), sql.Named("object_id", objectID))
}

// DeleteGrpAlias removes one alias of an object (when it takes the name back).
func (tx *TenantTx) DeleteGrpAlias(objectType, objectID, name string) error {
	_, err := tx.exec(grpAliasDelete, sql.Named("object_type", objectType), sql.Named("object_id", objectID), sql.Named("name", name))
	return err
}

// DeleteGrpAliasesOf removes every alias of an object (when it is deleted).
func (tx *TenantTx) DeleteGrpAliasesOf(objectType, objectID string) error {
	_, err := tx.exec(grpAliasDeleteOf, sql.Named("object_type", objectType), sql.Named("object_id", objectID))
	return err
}

// ---------------------------------------------------------------- lists

// EnsureGrpMembersList creates the tenant's built-in members list if missing
// and returns its id.
func (tx *TenantTx) EnsureGrpMembersList() (ListID, error) {
	id := MembersListID(tx.tenant)
	if _, err := tx.exec(grpListInsert, sql.Named("id", string(id))); err != nil {
		return "", err
	}
	var got string
	if err := tx.queryRow(grpListGet, sql.Named("id", string(id))).Scan(&got); err != nil {
		return "", err
	}
	return ListID(got), nil
}
