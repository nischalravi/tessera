package store

import (
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
)

// Group attribute framework repository (schema/0287_group_attrs.sql, issue #50,
// GR-7). The rules live in internal/groups/attrs; this file is only its
// statements, all bound to the transaction's tenant.

const attrDefCols = `d.id, d.tenant_id, d.folder_id, f.name, d.extension, d.display_extension, d.description, d.attr_type,
	d.value_type, d.multi_assign, d.multi_valued, d.assign_to, d.system, d.created_at, d.created_by, d.version`

// a definition is always read with its folder, whose name is the first part of its own
const attrDefFrom = `FROM grp_attr_defs d JOIN grp_folders f ON f.tenant_id = d.tenant_id AND f.id = d.folder_id`

const attrNameCols = `n.id, n.tenant_id, n.def_id, n.extension, n.display_extension, n.description, n.created_at, n.created_by`

const attrActionCols = `a.id, a.tenant_id, a.def_id, a.name, a.description, a.created_at`

const attrAssignCols = `a.id, a.tenant_id, a.def_id, a.name_id, a.action_id, a.owner_type, a.owner_id, a.disallowed,
	a.enabled_from, a.disabled_at, a.created_at, a.created_by, a.version`

const attrValueCols = `v.id, v.tenant_id, v.assign_id, v.value_string, v.value_integer, v.value_timestamp, v.value_member_id,
	v.value_key, v.position, v.created_at`

var (
	attrDefInsert = tq("grp_attr_defs.insert", `
		INSERT INTO grp_attr_defs (id, tenant_id, folder_id, extension, display_extension, description, attr_type, value_type,
			multi_assign, multi_valued, assign_to, system, created_at, created_by, version)
		VALUES (@id, @tenant, @folder_id, @extension, @display_extension, @description, @attr_type, @value_type,
			@multi_assign, @multi_valued, @assign_to, @system, @created_at, @created_by, 1)`)
	attrDefGet = tq("grp_attr_defs.get", `SELECT `+attrDefCols+` `+attrDefFrom+`
		WHERE d.tenant_id = @tenant AND f.tenant_id = @tenant AND d.id = @id`)
	attrDefByExt = tq("grp_attr_defs.by_folder_extension", `SELECT `+attrDefCols+` `+attrDefFrom+`
		WHERE d.tenant_id = @tenant AND f.tenant_id = @tenant AND d.folder_id = @folder_id AND lower(d.extension) = lower(@extension)`)
	attrDefList = tq("grp_attr_defs.list", `SELECT `+attrDefCols+` `+attrDefFrom+`
		WHERE d.tenant_id = @tenant AND f.tenant_id = @tenant
		  AND (@folder_id = '' OR d.folder_id = @folder_id)
		  AND (@below = '' OR lower(f.name) = @exact OR substr(lower(f.name), 1, length(@below)) = @below)
		  AND (@q = '' OR instr(lower(d.extension), lower(@q)) > 0 OR instr(lower(f.name), lower(@q)) > 0
		       OR instr(lower(d.display_extension), lower(@q)) > 0)
		  AND (@attr_type = '' OR d.attr_type = @attr_type)
		ORDER BY lower(f.name), lower(d.extension) LIMIT @limit OFFSET @offset`)
	attrDefCountIn = tq("grp_attr_defs.count_in_folder", `SELECT count(*) FROM grp_attr_defs d
		WHERE d.tenant_id = @tenant AND d.folder_id = @folder_id`)
	attrDefUpdate = tq("grp_attr_defs.update", `
		UPDATE grp_attr_defs SET display_extension = @display_extension, description = @description,
			multi_assign = @multi_assign, multi_valued = @multi_valued, assign_to = @assign_to, version = version + 1
		WHERE tenant_id = @tenant AND id = @id AND version = @version`)
	attrDefDelete = tq("grp_attr_defs.delete", `DELETE FROM grp_attr_defs WHERE tenant_id = @tenant AND id = @id`)

	attrNameInsert = tq("grp_attr_names.insert", `
		INSERT INTO grp_attr_names (id, tenant_id, def_id, extension, display_extension, description, created_at, created_by)
		VALUES (@id, @tenant, @def_id, @extension, @display_extension, @description, @created_at, @created_by)`)
	attrNameGet   = tq("grp_attr_names.get", `SELECT `+attrNameCols+` FROM grp_attr_names n WHERE n.tenant_id = @tenant AND n.id = @id`)
	attrNameByExt = tq("grp_attr_names.by_def_extension", `SELECT `+attrNameCols+` FROM grp_attr_names n
		WHERE n.tenant_id = @tenant AND n.def_id = @def_id AND lower(n.extension) = lower(@extension)`)
	attrNameList = tq("grp_attr_names.list", `SELECT `+attrNameCols+` FROM grp_attr_names n
		WHERE n.tenant_id = @tenant AND (@def_id = '' OR n.def_id = @def_id)
		  AND (@q = '' OR instr(lower(n.extension), lower(@q)) > 0 OR instr(lower(n.display_extension), lower(@q)) > 0)
		ORDER BY n.def_id, lower(n.extension) LIMIT @limit OFFSET @offset`)
	attrNameUpdate = tq("grp_attr_names.update", `
		UPDATE grp_attr_names SET display_extension = @display_extension, description = @description
		WHERE tenant_id = @tenant AND id = @id`)
	attrNameDelete = tq("grp_attr_names.delete", `DELETE FROM grp_attr_names WHERE tenant_id = @tenant AND id = @id`)

	attrActionInsert = tq("grp_attr_actions.insert", `
		INSERT INTO grp_attr_actions (id, tenant_id, def_id, name, description, created_at)
		VALUES (@id, @tenant, @def_id, @name, @description, @created_at)`)
	attrActionGet = tq("grp_attr_actions.get", `SELECT `+attrActionCols+` FROM grp_attr_actions a
		WHERE a.tenant_id = @tenant AND a.id = @id`)
	attrActionByName = tq("grp_attr_actions.by_def_name", `SELECT `+attrActionCols+` FROM grp_attr_actions a
		WHERE a.tenant_id = @tenant AND a.def_id = @def_id AND lower(a.name) = lower(@name)`)
	attrActionsOf = tq("grp_attr_actions.of_def", `SELECT `+attrActionCols+` FROM grp_attr_actions a
		WHERE a.tenant_id = @tenant AND a.def_id = @def_id ORDER BY lower(a.name)`)
	attrActionDelete = tq("grp_attr_actions.delete", `DELETE FROM grp_attr_actions WHERE tenant_id = @tenant AND id = @id`)

	// the closure tables: one statement set per table (the table name is not a parameter)
	nameImpliesInsert = tq("grp_attr_name_implies.insert", `
		INSERT INTO grp_attr_name_implies (tenant_id, def_id, name_id, implied_id, direct)
		VALUES (@tenant, @def_id, @from_id, @to_id, @direct)`)
	nameImpliesOfDef = tq("grp_attr_name_implies.of_def", `SELECT i.def_id, i.name_id, i.implied_id, i.direct
		FROM grp_attr_name_implies i WHERE i.tenant_id = @tenant AND i.def_id = @def_id ORDER BY i.name_id, i.implied_id`)
	nameImpliesOfName = tq("grp_attr_name_implies.of_name", `SELECT i.def_id, i.name_id, i.implied_id, i.direct
		FROM grp_attr_name_implies i WHERE i.tenant_id = @tenant AND i.name_id = @from_id ORDER BY i.implied_id`)
	nameImpliesDeleteDef = tq("grp_attr_name_implies.delete_def", `DELETE FROM grp_attr_name_implies
		WHERE tenant_id = @tenant AND def_id = @def_id`)
	actionImpliesInsert = tq("grp_attr_action_implies.insert", `
		INSERT INTO grp_attr_action_implies (tenant_id, def_id, action_id, implied_id, direct)
		VALUES (@tenant, @def_id, @from_id, @to_id, @direct)`)
	actionImpliesOfDef = tq("grp_attr_action_implies.of_def", `SELECT i.def_id, i.action_id, i.implied_id, i.direct
		FROM grp_attr_action_implies i WHERE i.tenant_id = @tenant AND i.def_id = @def_id ORDER BY i.action_id, i.implied_id`)
	actionImpliesOfAction = tq("grp_attr_action_implies.of_action", `SELECT i.def_id, i.action_id, i.implied_id, i.direct
		FROM grp_attr_action_implies i WHERE i.tenant_id = @tenant AND i.action_id = @from_id ORDER BY i.implied_id`)
	actionImpliesDeleteDef = tq("grp_attr_action_implies.delete_def", `DELETE FROM grp_attr_action_implies
		WHERE tenant_id = @tenant AND def_id = @def_id`)

	attrAssignInsert = tq("grp_attr_assigns.insert", `
		INSERT INTO grp_attr_assigns (id, tenant_id, def_id, name_id, action_id, owner_type, owner_id, disallowed, enabled_from,
			disabled_at, created_at, created_by, version)
		VALUES (@id, @tenant, @def_id, @name_id, @action_id, @owner_type, @owner_id, @disallowed, @enabled_from,
			@disabled_at, @created_at, @created_by, 1)`)
	attrAssignGet = tq("grp_attr_assigns.get", `SELECT `+attrAssignCols+` FROM grp_attr_assigns a
		WHERE a.tenant_id = @tenant AND a.id = @id`)
	attrAssignList = tq("grp_attr_assigns.list", `SELECT `+attrAssignCols+` FROM grp_attr_assigns a
		WHERE a.tenant_id = @tenant
		  AND (@owner_type = '' OR a.owner_type = @owner_type)
		  AND (@owner_id = '' OR a.owner_id = @owner_id)
		  AND (@def_id = '' OR a.def_id = @def_id)
		  AND (@name_id = '' OR a.name_id = @name_id)
		ORDER BY a.created_at, a.id LIMIT @limit OFFSET @offset`)
	attrAssignCount = tq("grp_attr_assigns.count", `SELECT count(*) FROM grp_attr_assigns a
		WHERE a.tenant_id = @tenant AND (@def_id = '' OR a.def_id = @def_id) AND (@name_id = '' OR a.name_id = @name_id)
		  AND (@action_id = '' OR a.action_id = @action_id)`)
	// the assignments of a name whose values include one key, on one kind of owner
	attrAssignByValue = tq("grp_attr_assigns.by_value", `SELECT `+attrAssignCols+` FROM grp_attr_assigns a
		JOIN grp_attr_values v ON v.tenant_id = a.tenant_id AND v.assign_id = a.id
		WHERE a.tenant_id = @tenant AND v.tenant_id = @tenant AND a.name_id = @name_id AND a.owner_type = @owner_type
		  AND v.value_key = @value_key ORDER BY a.created_at, a.id`)
	attrAssignUpdate = tq("grp_attr_assigns.update", `
		UPDATE grp_attr_assigns SET disallowed = @disallowed, enabled_from = @enabled_from, disabled_at = @disabled_at,
			version = version + 1
		WHERE tenant_id = @tenant AND id = @id AND version = @version`)
	attrAssignDelete = tq("grp_attr_assigns.delete", `DELETE FROM grp_attr_assigns WHERE tenant_id = @tenant AND id = @id`)

	attrValueInsert = tq("grp_attr_values.insert", `
		INSERT INTO grp_attr_values (id, tenant_id, assign_id, value_string, value_integer, value_timestamp, value_member_id,
			value_key, position, created_at)
		VALUES (@id, @tenant, @assign_id, @value_string, @value_integer, @value_timestamp, @value_member_id,
			@value_key, @position, @created_at)`)
	attrValuesOf = tq("grp_attr_values.of_assign", `SELECT `+attrValueCols+` FROM grp_attr_values v
		WHERE v.tenant_id = @tenant AND v.assign_id = @assign_id ORDER BY v.position, v.id`)
	attrValuesDeleteOf = tq("grp_attr_values.delete_of", `DELETE FROM grp_attr_values
		WHERE tenant_id = @tenant AND assign_id = @assign_id`)
)

func scanGrpAttrDef(s scanner) (*GrpAttrDef, error) {
	var d GrpAttrDef
	var tenant, created, assignTo string
	var multiAssign, multiValued, system int
	var by sql.NullString
	if err := s.Scan(&d.ID, &tenant, &d.FolderID, &d.FolderName, &d.Extension, &d.DisplayExtension, &d.Description, &d.AttrType,
		&d.ValueType, &multiAssign, &multiValued, &assignTo, &system, &created, &by, &d.Version); err != nil {
		return nil, err
	}
	var err error
	if d.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	d.MultiAssign, d.MultiValued, d.System, d.CreatedBy = multiAssign == 1, multiValued == 1, system == 1, strp(by)
	if err = json.Unmarshal([]byte(assignTo), &d.AssignTo); err != nil {
		return nil, err
	}
	d.CreatedAt, err = ParseRT(created)
	return &d, err
}

func scanGrpAttrName(s scanner) (*GrpAttrName, error) {
	var n GrpAttrName
	var tenant, created string
	var by sql.NullString
	if err := s.Scan(&n.ID, &tenant, &n.DefID, &n.Extension, &n.DisplayExtension, &n.Description, &created, &by); err != nil {
		return nil, err
	}
	var err error
	if n.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	n.CreatedBy = strp(by)
	n.CreatedAt, err = ParseRT(created)
	return &n, err
}

func scanGrpAttrAction(s scanner) (*GrpAttrAction, error) {
	var a GrpAttrAction
	var tenant, created string
	if err := s.Scan(&a.ID, &tenant, &a.DefID, &a.Name, &a.Description, &created); err != nil {
		return nil, err
	}
	var err error
	if a.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	a.CreatedAt, err = ParseRT(created)
	return &a, err
}

func scanGrpAttrImplies(s scanner) (*GrpAttrImplies, error) {
	var i GrpAttrImplies
	var direct int
	if err := s.Scan(&i.DefID, &i.From, &i.To, &direct); err != nil {
		return nil, err
	}
	i.Direct = direct == 1
	return &i, nil
}

func scanGrpAttrAssign(s scanner) (*GrpAttrAssign, error) {
	var a GrpAttrAssign
	var tenant, created string
	var disallowed int
	var from, to, by sql.NullString
	if err := s.Scan(&a.ID, &tenant, &a.DefID, &a.NameID, &a.ActionID, &a.OwnerType, &a.OwnerID, &disallowed, &from, &to, &created,
		&by, &a.Version); err != nil {
		return nil, err
	}
	var err error
	if a.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	a.Disallowed, a.CreatedBy = disallowed == 1, strp(by)
	if a.EnabledFrom, err = rtp(from); err != nil {
		return nil, err
	}
	if a.DisabledAt, err = rtp(to); err != nil {
		return nil, err
	}
	a.CreatedAt, err = ParseRT(created)
	return &a, err
}

func scanGrpAttrValue(s scanner) (*GrpAttrValue, error) {
	var v GrpAttrValue
	var tenant, created string
	var str, ts sql.NullString
	var num, member sql.NullInt64
	if err := s.Scan(&v.ID, &tenant, &v.AssignID, &str, &num, &ts, &member, &v.Key, &v.Position, &created); err != nil {
		return nil, err
	}
	var err error
	if v.TenantID, err = tenantOf(tenant); err != nil {
		return nil, err
	}
	v.ValueString, v.ValueInteger, v.ValueMemberID = strp(str), intp(num), intp(member)
	if v.ValueTimestamp, err = rtp(ts); err != nil {
		return nil, err
	}
	v.CreatedAt, err = ParseRT(created)
	return &v, err
}

// ---------------------------------------------------------------- definitions

// InsertGrpAttrDef adds a definition (a zero ID gets a fresh one), version 1.
func (tx *TenantTx) InsertGrpAttrDef(d *GrpAttrDef) error {
	if err := tx.own(d.TenantID); err != nil {
		return err
	}
	if d.ID == "" {
		d.ID = uuid.NewString()
	}
	assignTo, err := json.Marshal(append([]string{}, d.AssignTo...))
	if err != nil {
		return err
	}
	_, err = tx.exec(attrDefInsert, sql.Named("id", d.ID), sql.Named("folder_id", string(d.FolderID)), sql.Named("extension", d.Extension),
		sql.Named("display_extension", d.DisplayExtension), sql.Named("description", d.Description), sql.Named("attr_type", d.AttrType),
		sql.Named("value_type", d.ValueType), sql.Named("multi_assign", B(d.MultiAssign)), sql.Named("multi_valued", B(d.MultiValued)),
		sql.Named("assign_to", string(assignTo)), sql.Named("system", B(d.System)), sql.Named("created_at", RT(d.CreatedAt)),
		sql.Named("created_by", SP(d.CreatedBy)))
	if err == nil {
		d.TenantID, d.Version = tx.tenant, 1
	}
	return err
}

// GrpAttrDef returns a definition or ErrNotFound.
func (tx *TenantTx) GrpAttrDef(id string) (*GrpAttrDef, error) {
	return one(tx, scanGrpAttrDef, attrDefGet, sql.Named("id", id))
}

// GrpAttrDefByExtension finds the definition with the extension in a folder
// (case-insensitively), or ErrNotFound.
func (tx *TenantTx) GrpAttrDefByExtension(folder FolderID, extension string) (*GrpAttrDef, error) {
	return one(tx, scanGrpAttrDef, attrDefByExt, sql.Named("folder_id", string(folder)), sql.Named("extension", extension))
}

// GrpAttrDefs lists definitions by name; a zero Limit means 100. Prefix is a
// folder's name: the definitions in that folder and below it (empty: all).
func (tx *TenantTx) GrpAttrDefs(f GrpAttrDefFilter) ([]*GrpAttrDef, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	return collect(tx, scanGrpAttrDef, attrDefList, sql.Named("folder_id", string(f.FolderID)), belowArg(f.Prefix, false),
		sql.Named("exact", strings.ToLower(f.Prefix)), sql.Named("q", f.Q), sql.Named("attr_type", f.AttrType),
		sql.Named("limit", f.Limit), sql.Named("offset", f.Offset))
}

// GrpAttrDefCountIn counts the definitions that sit in a folder.
func (tx *TenantTx) GrpAttrDefCountIn(folder FolderID) (int, error) {
	return tx.count(attrDefCountIn, sql.Named("folder_id", string(folder)))
}

// UpdateGrpAttrDef writes d's display name, description and flags if the stored
// version is still d.Version, and bumps it (ErrVersionConflict otherwise).
func (tx *TenantTx) UpdateGrpAttrDef(d *GrpAttrDef) error {
	assignTo, err := json.Marshal(append([]string{}, d.AssignTo...))
	if err != nil {
		return err
	}
	res, err := tx.exec(attrDefUpdate, sql.Named("id", d.ID), sql.Named("display_extension", d.DisplayExtension),
		sql.Named("description", d.Description), sql.Named("multi_assign", B(d.MultiAssign)),
		sql.Named("multi_valued", B(d.MultiValued)), sql.Named("assign_to", string(assignTo)), sql.Named("version", d.Version))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		if _, err := tx.GrpAttrDef(d.ID); err != nil {
			return err
		}
		return ErrVersionConflict
	}
	d.Version++
	return nil
}

// DeleteGrpAttrDef removes a definition row (its names, actions and
// assignments must already be gone).
func (tx *TenantTx) DeleteGrpAttrDef(id string) error {
	res, err := tx.exec(attrDefDelete, sql.Named("id", id))
	return rowsOrNotFound(res, err)
}

// ---------------------------------------------------------------- names and actions

// InsertGrpAttrName adds a name under a definition.
func (tx *TenantTx) InsertGrpAttrName(n *GrpAttrName) error {
	if err := tx.own(n.TenantID); err != nil {
		return err
	}
	if n.ID == "" {
		n.ID = uuid.NewString()
	}
	_, err := tx.exec(attrNameInsert, sql.Named("id", n.ID), sql.Named("def_id", n.DefID), sql.Named("extension", n.Extension),
		sql.Named("display_extension", n.DisplayExtension), sql.Named("description", n.Description),
		sql.Named("created_at", RT(n.CreatedAt)), sql.Named("created_by", SP(n.CreatedBy)))
	if err == nil {
		n.TenantID = tx.tenant
	}
	return err
}

// GrpAttrName returns a name or ErrNotFound.
func (tx *TenantTx) GrpAttrName(id string) (*GrpAttrName, error) {
	return one(tx, scanGrpAttrName, attrNameGet, sql.Named("id", id))
}

// GrpAttrNameByExtension finds a definition's name by its extension, or ErrNotFound.
func (tx *TenantTx) GrpAttrNameByExtension(def, extension string) (*GrpAttrName, error) {
	return one(tx, scanGrpAttrName, attrNameByExt, sql.Named("def_id", def), sql.Named("extension", extension))
}

// GrpAttrNames lists names, of one definition when def is not empty; a zero
// limit means 100.
func (tx *TenantTx) GrpAttrNames(def, q string, limit, offset int) ([]*GrpAttrName, error) {
	if limit <= 0 {
		limit = 100
	}
	return collect(tx, scanGrpAttrName, attrNameList, sql.Named("def_id", def), sql.Named("q", q), sql.Named("limit", limit),
		sql.Named("offset", offset))
}

// UpdateGrpAttrName writes a name's display name and description.
func (tx *TenantTx) UpdateGrpAttrName(n *GrpAttrName) error {
	return tx.execOne(attrNameUpdate, sql.Named("id", n.ID), sql.Named("display_extension", n.DisplayExtension),
		sql.Named("description", n.Description))
}

// DeleteGrpAttrName removes a name row (its implication rows and assignments
// must already be gone).
func (tx *TenantTx) DeleteGrpAttrName(id string) error {
	res, err := tx.exec(attrNameDelete, sql.Named("id", id))
	return rowsOrNotFound(res, err)
}

// InsertGrpAttrAction adds an action to a definition.
func (tx *TenantTx) InsertGrpAttrAction(a *GrpAttrAction) error {
	if err := tx.own(a.TenantID); err != nil {
		return err
	}
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	_, err := tx.exec(attrActionInsert, sql.Named("id", a.ID), sql.Named("def_id", a.DefID), sql.Named("name", a.Name),
		sql.Named("description", a.Description), sql.Named("created_at", RT(a.CreatedAt)))
	if err == nil {
		a.TenantID = tx.tenant
	}
	return err
}

// GrpAttrAction returns an action or ErrNotFound.
func (tx *TenantTx) GrpAttrAction(id string) (*GrpAttrAction, error) {
	return one(tx, scanGrpAttrAction, attrActionGet, sql.Named("id", id))
}

// GrpAttrActionByName finds a definition's action by name, or ErrNotFound.
func (tx *TenantTx) GrpAttrActionByName(def, name string) (*GrpAttrAction, error) {
	return one(tx, scanGrpAttrAction, attrActionByName, sql.Named("def_id", def), sql.Named("name", name))
}

// GrpAttrActionsOf lists a definition's actions by name.
func (tx *TenantTx) GrpAttrActionsOf(def string) ([]*GrpAttrAction, error) {
	return collect(tx, scanGrpAttrAction, attrActionsOf, sql.Named("def_id", def))
}

// DeleteGrpAttrAction removes an action row (its implication rows must already be gone).
func (tx *TenantTx) DeleteGrpAttrAction(id string) error {
	res, err := tx.exec(attrActionDelete, sql.Named("id", id))
	return rowsOrNotFound(res, err)
}

// ---------------------------------------------------------------- implication closures

// Kinds of implication closure.
const (
	ImpliesNames   = "name"
	ImpliesActions = "action"
)

func impliesStmts(kind string) (insert, ofDef, deleteDef tstmt) {
	if kind == ImpliesActions {
		return actionImpliesInsert, actionImpliesOfDef, actionImpliesDeleteDef
	}
	return nameImpliesInsert, nameImpliesOfDef, nameImpliesDeleteDef
}

// GrpAttrImpliesOfDef lists every closure row of a definition's names or actions.
func (tx *TenantTx) GrpAttrImpliesOfDef(kind, def string) ([]*GrpAttrImplies, error) {
	_, ofDef, _ := impliesStmts(kind)
	return collect(tx, scanGrpAttrImplies, ofDef, sql.Named("def_id", def))
}

// GrpAttrImpliesOf lists what one name or action implies (its closure rows).
func (tx *TenantTx) GrpAttrImpliesOf(kind, id string) ([]*GrpAttrImplies, error) {
	s := nameImpliesOfName
	if kind == ImpliesActions {
		s = actionImpliesOfAction
	}
	return collect(tx, scanGrpAttrImplies, s, sql.Named("from_id", id))
}

// ReplaceGrpAttrImplies swaps a definition's closure rows for rows (the attrs
// package computes the closure from the direct edges).
func (tx *TenantTx) ReplaceGrpAttrImplies(kind, def string, rows []GrpAttrImplies) error {
	insert, _, deleteDef := impliesStmts(kind)
	if _, err := tx.exec(deleteDef, sql.Named("def_id", def)); err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := tx.exec(insert, sql.Named("def_id", def), sql.Named("from_id", r.From), sql.Named("to_id", r.To),
			sql.Named("direct", B(r.Direct))); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- assignments and values

// InsertGrpAttrAssign adds an assignment (a zero ID gets a fresh one), version 1.
func (tx *TenantTx) InsertGrpAttrAssign(a *GrpAttrAssign) error {
	if err := tx.own(a.TenantID); err != nil {
		return err
	}
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	_, err := tx.exec(attrAssignInsert, sql.Named("id", a.ID), sql.Named("def_id", a.DefID), sql.Named("name_id", a.NameID),
		sql.Named("action_id", a.ActionID), sql.Named("owner_type", a.OwnerType), sql.Named("owner_id", a.OwnerID),
		sql.Named("disallowed", B(a.Disallowed)), sql.Named("enabled_from", RTP(a.EnabledFrom)),
		sql.Named("disabled_at", RTP(a.DisabledAt)), sql.Named("created_at", RT(a.CreatedAt)), sql.Named("created_by", SP(a.CreatedBy)))
	if err == nil {
		a.TenantID, a.Version = tx.tenant, 1
	}
	return err
}

// GrpAttrAssign returns an assignment or ErrNotFound.
func (tx *TenantTx) GrpAttrAssign(id string) (*GrpAttrAssign, error) {
	return one(tx, scanGrpAttrAssign, attrAssignGet, sql.Named("id", id))
}

// GrpAttrAssigns lists assignments, oldest first; a zero Limit means 100.
func (tx *TenantTx) GrpAttrAssigns(f GrpAttrAssignFilter) ([]*GrpAttrAssign, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	return collect(tx, scanGrpAttrAssign, attrAssignList, sql.Named("owner_type", f.OwnerType), sql.Named("owner_id", f.OwnerID),
		sql.Named("def_id", f.DefID), sql.Named("name_id", f.NameID), sql.Named("limit", f.Limit), sql.Named("offset", f.Offset))
}

// GrpAttrAssignCount counts the assignments of a definition, a name or an
// action (an empty argument does not filter).
func (tx *TenantTx) GrpAttrAssignCount(def, name, action string) (int, error) {
	return tx.count(attrAssignCount, sql.Named("def_id", def), sql.Named("name_id", name), sql.Named("action_id", action))
}

// GrpAttrAssignsByValue lists the assignments of a name on owners of a type
// that carry the value (by its canonical key).
func (tx *TenantTx) GrpAttrAssignsByValue(name, ownerType, key string) ([]*GrpAttrAssign, error) {
	return collect(tx, scanGrpAttrAssign, attrAssignByValue, sql.Named("name_id", name), sql.Named("owner_type", ownerType),
		sql.Named("value_key", key))
}

// UpdateGrpAttrAssign writes the assignment's flag and dates if the stored
// version is still a.Version, and bumps it (ErrVersionConflict otherwise).
func (tx *TenantTx) UpdateGrpAttrAssign(a *GrpAttrAssign) error {
	res, err := tx.exec(attrAssignUpdate, sql.Named("id", a.ID), sql.Named("disallowed", B(a.Disallowed)),
		sql.Named("enabled_from", RTP(a.EnabledFrom)), sql.Named("disabled_at", RTP(a.DisabledAt)), sql.Named("version", a.Version))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		if _, err := tx.GrpAttrAssign(a.ID); err != nil {
			return err
		}
		return ErrVersionConflict
	}
	a.Version++
	return nil
}

// DeleteGrpAttrAssign removes an assignment row (its values and the
// assignments on it must already be gone).
func (tx *TenantTx) DeleteGrpAttrAssign(id string) error {
	res, err := tx.exec(attrAssignDelete, sql.Named("id", id))
	return rowsOrNotFound(res, err)
}

// InsertGrpAttrValue adds a value to an assignment.
func (tx *TenantTx) InsertGrpAttrValue(v *GrpAttrValue) error {
	if err := tx.own(v.TenantID); err != nil {
		return err
	}
	if v.ID == "" {
		v.ID = uuid.NewString()
	}
	var ts any
	if v.ValueTimestamp != nil {
		ts = RT(*v.ValueTimestamp)
	}
	_, err := tx.exec(attrValueInsert, sql.Named("id", v.ID), sql.Named("assign_id", v.AssignID), sql.Named("value_string", SP(v.ValueString)),
		sql.Named("value_integer", IP(v.ValueInteger)), sql.Named("value_timestamp", ts), sql.Named("value_member_id", IP(v.ValueMemberID)),
		sql.Named("value_key", v.Key), sql.Named("position", v.Position), sql.Named("created_at", RT(v.CreatedAt)))
	if err == nil {
		v.TenantID = tx.tenant
	}
	return err
}

// GrpAttrValuesOf lists an assignment's values in order.
func (tx *TenantTx) GrpAttrValuesOf(assign string) ([]*GrpAttrValue, error) {
	return collect(tx, scanGrpAttrValue, attrValuesOf, sql.Named("assign_id", assign))
}

// DeleteGrpAttrValuesOf removes every value of an assignment and returns how many there were.
func (tx *TenantTx) DeleteGrpAttrValuesOf(assign string) (int64, error) {
	res, err := tx.exec(attrValuesDeleteOf, sql.Named("assign_id", assign))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
