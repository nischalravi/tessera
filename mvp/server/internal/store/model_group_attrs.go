package store

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Group attribute framework (schema/0287_group_attrs.sql, issue #50, GR-7;
// design docs/design/groups-grouper-parity.md §10.9). The rules (types,
// closures, assignment checks, privileges) live in internal/groups/attrs; these
// are the stored rows.

// Attribute definition types (G-43).
const (
	AttrTypeAttr    = "attr"
	AttrTypeLimit   = "limit"
	AttrTypePerm    = "perm"
	AttrTypeType    = "type"
	AttrTypeService = "service"
)

// Attribute value types. Floating values are decimal strings in ValueString.
const (
	AttrValueMarker    = "marker"
	AttrValueString    = "string"
	AttrValueInteger   = "integer"
	AttrValueFloating  = "floating"
	AttrValueTimestamp = "timestamp"
	AttrValueMemberID  = "member_id"
)

// Owner types of an attribute assignment. An effective membership is derived
// and read-only: a definition may list it, but no row names one.
const (
	AttrOwnerFolder              = "folder"
	AttrOwnerGroup               = "group"
	AttrOwnerIdentity            = "identity"
	AttrOwnerMembership          = "membership"
	AttrOwnerEffectiveMembership = "effective_membership"
	AttrOwnerAttrDef             = "attr_def"
	AttrOwnerAssignment          = "assignment"
)

// GrpAttrDef is an attribute definition. It lives in FolderID; its full name is
// the folder's name, ':' and Extension (Name).
type GrpAttrDef struct {
	ID               string
	TenantID         tenancy.ID
	FolderID         FolderID
	FolderName       string // the folder's name, read with the row
	Extension        string
	DisplayExtension string
	Description      string
	AttrType         string
	ValueType        string
	MultiAssign      bool
	MultiValued      bool
	AssignTo         []string // owner types
	System           bool
	CreatedAt        time.Time
	CreatedBy        *string
	Version          int64
}

// Name is the definition's full name.
func (d *GrpAttrDef) Name() string {
	if d.FolderName == "" {
		return d.Extension
	}
	return d.FolderName + ":" + d.Extension
}

// GrpAttrName is an attribute name under a definition.
type GrpAttrName struct {
	ID               string
	TenantID         tenancy.ID
	DefID            string
	Extension        string
	DisplayExtension string
	Description      string
	CreatedAt        time.Time
	CreatedBy        *string
}

// GrpAttrAction is an action of a definition.
type GrpAttrAction struct {
	ID          string
	TenantID    tenancy.ID
	DefID       string
	Name        string
	Description string
	CreatedAt   time.Time
}

// GrpAttrImplies is one row of an implication closure: From implies To. Direct
// rows are the edges a person set.
type GrpAttrImplies struct {
	DefID  string
	From   string
	To     string
	Direct bool
}

// GrpAttrAssign is an assignment of an attribute name (with an action) to an
// owner.
type GrpAttrAssign struct {
	ID         string
	TenantID   tenancy.ID
	DefID      string
	NameID     string
	ActionID   string
	OwnerType  string
	OwnerID    string
	Disallowed bool
	// EnabledFrom and DisabledAt bound the assignment; nil is unbounded.
	EnabledFrom *time.Time
	DisabledAt  *time.Time
	CreatedAt   time.Time
	CreatedBy   *string
	Version     int64
}

// GrpAttrValue is one value of an assignment. Exactly one of the four typed
// fields is set; a floating value is a decimal string in ValueString, so the
// audit hash never sees a float.
type GrpAttrValue struct {
	ID             string
	TenantID       tenancy.ID
	AssignID       string
	ValueString    *string
	ValueInteger   *int64
	ValueTimestamp *time.Time
	ValueMemberID  *int64
	// Key is the canonical text of the value (unique within an assignment).
	Key       string
	Position  int
	CreatedAt time.Time
}

// GrpAttrDefFilter selects definitions for GrpAttrDefs. Empty fields do not filter.
type GrpAttrDefFilter struct {
	FolderID FolderID
	// Prefix is a folder's name: the definitions in that folder and below it.
	Prefix   string
	Q        string
	AttrType string
	Limit    int
	Offset   int
}

// GrpAttrAssignFilter selects assignments. Empty fields do not filter.
type GrpAttrAssignFilter struct {
	OwnerType string
	OwnerID   string
	DefID     string
	NameID    string
	Limit     int
	Offset    int
}
