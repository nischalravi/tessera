package store

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Group privileges (schema/0286_group_privs.sql, issue #47, GR-4; design
// docs/design/groups-grouper-parity.md §7). The rules (implication, dynamic
// inheritance, checks) live in internal/groups/privs; this is the stored row.

// Holder types of a privilege row.
const (
	HolderIdentity = "identity"
	HolderGroup    = "group"
	HolderEveryone = "everyone"
)

// Privilege sources.
const (
	PrivSourceUI             = "ui"
	PrivSourceAPI            = "api"
	PrivSourceCreatorDefault = "creator_default"
	PrivSourceGrouperImport  = "grouper_import"
	PrivSourceTemplate       = "template"
)

// GrpPrivilege is one row of grp_privileges: Holder holds Privilege on the
// object (ObjectType, ObjectID). AppliesTo "self" says the row is about that
// object only; "groups", "folders" or "attr_defs" (folder objects only) says it
// is inherited, at check time, by the objects of that kind below the folder
// (Scope one: its direct children; sub: everything below).
type GrpPrivilege struct {
	ID         string
	TenantID   tenancy.ID
	ObjectType string // folder | group | attr_def
	ObjectID   string
	Privilege  string
	HolderType string // identity | group | everyone
	// HolderIdentity is set for an identity holder, HolderGroup for a group.
	HolderIdentity *int64
	HolderGroup    *GroupID
	AppliesTo      string // self | groups | folders | attr_defs
	Scope          string // self | one | sub
	Source         string
	CreatedBy      *string // platform user id
	CreatedAt      time.Time
}

// GrpPrivSettings is the tenant's raw privilege settings (JSON, validated by
// internal/groups/privs).
type GrpPrivSettings struct {
	Body      string
	UpdatedAt time.Time
	UpdatedBy *string
}
