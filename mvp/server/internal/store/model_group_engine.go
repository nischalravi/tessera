package store

import "time"

// Types of the membership engine's tables (schema/0280_groups.sql engine
// section, 0284_groups_engine.sql; design docs/design/groups-grouper-parity.md
// §6). The engine itself is internal/groups/engine.

// DepKind says why a child group feeds a parent group.
type DepKind string

// Dependency kinds: the parent lists the child as a member, or the parent is a
// composite and the child is one of its factors.
const (
	DepNest   DepKind = "nest"
	DepFactor DepKind = "factor"
)

// Composite operations: n-ary union and intersection, and binary complement
// (the left factor minus the right one).
const (
	CompUnion        CompositeOp = "union"
	CompIntersection CompositeOp = "intersection"
	CompComplement   CompositeOp = "complement"
)

// GrpDep is one edge of the dependency DAG: Child feeds Parent in List.
type GrpDep struct {
	Parent GroupID
	Child  GroupID
	Kind   DepKind
	List   ListID
}

// GrpClosureRow is one row of the transitive closure: Ancestor depends on
// Descendant through Paths distinct paths, the shortest of MinDepth edges.
type GrpClosureRow struct {
	Ancestor   GroupID
	Descendant GroupID
	Paths      int64
	MinDepth   int
}

// GrpLevel is a group's level (longest path from a leaf; leaves are 0).
type GrpLevel struct {
	Group GroupID
	Level int
}

// EngineJob is a queued piece of engine work (grp_engine_queue). Seq is the
// operation id the API returns with 202.
type EngineJob struct {
	Seq        int64
	Kind       string
	Payload    string
	EnqueuedAt time.Time
}

// Engine job kinds.
const JobRecomputeGroup = "recompute_group"

// EngineState is a tenant's engine bookkeeping (grp_engine_state).
type EngineState struct {
	NextSeq    int64
	WheelAt    *time.Time
	VerifiedAt *time.Time
}

// Operation states of GrpOpState.
const (
	OpPending = "pending"
	OpDone    = "done"
	OpUnknown = "unknown"
)

// GrpDirectFilter selects direct memberships for GrpDirect. Empty fields do
// not filter.
type GrpDirectFilter struct {
	Group      GroupID
	List       ListID
	MemberType MemberType
	Limit      int
	Offset     int
}

// GrpEffectiveRow is a materialized member as listed by GrpEffectiveList.
type GrpEffectiveRow struct {
	Identity int64
	Support  int32
	Since    time.Time
}
