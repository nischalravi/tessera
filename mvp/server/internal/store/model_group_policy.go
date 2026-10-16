package store

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Policy groups as code (schema/0289_group_policy.sql, issue #52, GR-9; design
// docs/design/groups-grouper-parity.md §8). The rules (the Cedar fragment, the
// compiler, the indexer) live in internal/groups/policygroups; these are the
// stored rows.

// Origins of a policy group's text.
const (
	PolicyOriginRepo = "repo"
	PolicyOriginUI   = "ui"
)

// Kinds of a compiled policy node. The first three are internal composite
// groups; attr and has are attribute groups kept current by the indexer; empty
// is the group with no members.
const (
	NodeUnion        = "union"
	NodeIntersection = "intersection"
	NodeComplement   = "complement"
	NodeAttr         = "attr"
	NodeHas          = "has"
	NodeEmpty        = "empty"
)

// GrpPolicySource is the source of one policy group.
type GrpPolicySource struct {
	TenantID       tenancy.ID
	GroupID        GroupID
	Origin         string
	Path           string
	CommitSHA      string
	Cedar          string
	CedarSHA256    string
	AllowNode      string
	DenyNode       string
	CompiledSHA256 string
	AppliedAt      time.Time
	AppliedBy      *string
}

// GrpPolicyNode is a hash-consed node of compiled policy; GroupID is the native
// group that holds its members.
type GrpPolicyNode struct {
	TenantID  tenancy.ID
	Hash      string
	Kind      string
	Attr      string
	Value     string
	GroupID   GroupID
	CreatedAt time.Time
}
