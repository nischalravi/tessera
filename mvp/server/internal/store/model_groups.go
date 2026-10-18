package store

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Native groups (schema/0280_groups.sql; design docs/design/groups-grouper-parity.md
// §5.2). They are owned by Tessera and are not the connected-system Group of
// model_*.go, which holds groups read from Okta, AWS and so on.

// FolderID, GroupID and ListID are UUID text primary keys.
type (
	FolderID string
	GroupID  string
	ListID   string
)

// ObjectType is a folder or group object type (design §10.9); GR-7 defines the
// vocabulary, so GR-1 stores whatever the column holds ('[]' for now).
type ObjectType string

// ManagedBy says which writer owns a folder or group.
type ManagedBy string

// Writers. Only ui is created through the API in GR-1.
const (
	ManagedByUI            ManagedBy = "ui"
	ManagedByPolicyRepo    ManagedBy = "policy_repo"
	ManagedByLoader        ManagedBy = "loader"
	ManagedByGrouperMirror ManagedBy = "grouper_mirror"
	ManagedByConnector     ManagedBy = "connector"
)

// Group kinds, definitions and composite operations.
type (
	GroupKind   string
	Definition  string
	CompositeOp string
)

// Values of GroupKind, Definition and the group status.
const (
	KindGroup GroupKind = "group"
	KindRole  GroupKind = "role"

	DefinitionBasic     Definition = "basic"
	DefinitionComposite Definition = "composite"
	DefinitionPolicy    Definition = "policy"

	GroupActive   = "active"
	GroupDisabled = "disabled"
	GroupDeleted  = "deleted"
)

// Folder is a node of the folder tree (Grouper's stem). The root has a nil
// ParentID, an empty Extension and an empty Name.
type Folder struct {
	ID               FolderID
	TenantID         tenancy.ID
	ParentID         *FolderID
	Extension        string
	DisplayExtension string
	Name             string // full ':' path, unique per tenant, case-insensitively
	DisplayName      string
	Description      string
	IDIndex          int64
	ObjectTypes      []ObjectType
	DataOwner        *string
	ManagedBy        ManagedBy
	ExternalRef      *string
	CreatedAt        time.Time
	CreatedBy        *string // platform user id
	Version          int64   // optimistic concurrency
}

// NativeGroup is a native group or role. The design (§5.2) calls it Group; that
// name is taken by the connected-system Group, so this one carries the prefix.
type NativeGroup struct {
	ID                GroupID
	TenantID          tenancy.ID
	FolderID          FolderID
	Extension         string
	DisplayExtension  string
	Name              string
	DisplayName       string
	Description       string
	IDIndex           int64
	Kind              GroupKind
	Definition        Definition
	CompositeOp       *CompositeOp
	PolicyRef         *string // JSON {path, commit, compiled_sha256}
	ManagedBy         ManagedBy
	LoaderID          *string
	ObjectTypes       []ObjectType
	DataOwner         *string
	MemberDescription *string
	EnabledFrom       *time.Time
	DisabledAt        *time.Time
	Status            string // active | disabled | deleted
	Requestable       bool
	EffectiveCount    int64
	EffectiveVersion  int64
	RecomputeState    string // clean | pending | failed
	ExternalRef       *string
	CreatedAt         time.Time
	CreatedBy         *string
	Version           int64
}

// MemberType is what a direct membership names.
type MemberType string

// Member types.
const (
	MemberIdentity MemberType = "identity"
	MemberGroup    MemberType = "group"
)

// DirectMembership is a stored membership row; the engine (GR-2) owns writing it.
type DirectMembership struct {
	ID             string
	TenantID       tenancy.ID
	GroupID        GroupID
	ListID         ListID
	MemberType     MemberType
	MemberIdentity *int64
	MemberGroup    *GroupID
	EnabledFrom    *time.Time
	DisabledAt     *time.Time
	Source         string
	SourceRef      *string
	Reason         *string
	CreatedBy      *string
	CreatedAt      time.Time
}

// EffectiveMembership is a materialized member of a group (GR-2).
type EffectiveMembership struct {
	GroupID  GroupID
	ListID   ListID
	Identity int64
	Support  int32
	Since    time.Time
}

// GrpAlias is an old name of a folder or group.
type GrpAlias struct {
	ObjectType string // folder | group
	ObjectID   string
	OldName    string
	CreatedAt  time.Time
}

// Alias object types.
const (
	AliasFolder = "folder"
	AliasGroup  = "group"
)

// GrpFolderFilter selects folders for GrpFolders. Empty fields do not filter.
type GrpFolderFilter struct {
	ParentID FolderID // direct children of this folder
	Prefix   string   // names strictly below this ':' path (for scope=sub)
	Q        string   // case-insensitive substring of name or display name
	// ExcludeRoot leaves the tenant root out (a scope=sub listing of the root).
	ExcludeRoot bool
	Limit       int
	Offset      int
}

// GrpGroupFilter selects groups for GrpGroups. Empty fields do not filter.
type GrpGroupFilter struct {
	FolderID       FolderID
	Prefix         string
	Q              string
	Kind           GroupKind
	IncludeDeleted bool
	Limit          int
	Offset         int
}
