package store

import (
	"encoding/json"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Types of the group event outbox and point-in-time history (schema/0282,
// issue #46, GR-3; design docs/design/groups-grouper-parity.md §10.1, §10.2).
// The rules live in internal/groups/events and internal/groups/pit.

// Event object types.
const (
	EventObjFolder       = "folder"
	EventObjGroup        = "group"
	EventObjPrivilege    = "privilege"
	EventObjAttribute    = "attribute"
	EventObjLoader       = "loader"
	EventObjProvisioning = "provisioning"
	EventObjAttestation  = "attestation"
	EventObjRule         = "rule"
)

// Event causes.
const (
	CauseAPI        = "api"
	CauseLoader     = "loader"
	CauseRule       = "rule"
	CauseEngine     = "engine"
	CauseTimewheel  = "timewheel"
	CausePolicyRepo = "policy_repo"
	CauseImport     = "import"
	CauseRetention  = "retention"
)

// GrpEvent is one row of grp_events. Seq is assigned by AppendGrpEvent: per
// tenant, from 1, without gaps.
type GrpEvent struct {
	TenantID    tenancy.ID
	Seq         int64
	Type        string
	ObjectType  string
	ObjectID    string
	Identity    *int64
	MemberGroup string // "" when none
	List        string // "" when none
	Data        json.RawMessage
	CauseType   string
	CauseRef    string // "" when none
	AuditSeq    *int64
	OccurredAt  time.Time
}

// GrpEventHead is the tenant's event counter: the last seq issued and the
// highest seq the retention job has removed.
type GrpEventHead struct {
	LastSeq   int64
	PrunedSeq int64
}

// PitObject is an interval of a folder's or group's snapshot.
type PitObject struct {
	ObjectType string
	ObjectID   string
	Snapshot   json.RawMessage
	StartAt    time.Time
	EndAt      *time.Time
	StartSeq   int64
	EndSeq     *int64
}

// PitDirect is an interval of one direct membership row, with the row's own
// dates while the interval lasted.
type PitDirect struct {
	Group       string
	List        string
	MemberType  MemberType
	MemberKey   string // the identity id or the group id
	Identity    *int64
	MemberGroup string
	Source      string
	EnabledFrom *time.Time
	DisabledAt  *time.Time
	StartAt     time.Time
	EndAt       *time.Time
	StartSeq    int64
	EndSeq      *int64
}

// PitEffective is an interval of an identity being a member of a group's list.
type PitEffective struct {
	Group    string
	List     string
	Identity int64
	StartAt  time.Time
	EndAt    *time.Time
	StartSeq int64
	EndSeq   *int64
}

// PitPrivilege is an interval of a privilege grant.
type PitPrivilege struct {
	PrivilegeID string
	Snapshot    json.RawMessage
	StartAt     time.Time
	EndAt       *time.Time
	StartSeq    int64
	EndSeq      *int64
}

// PitDigest is a day's Merkle root over grp_events (K9).
type PitDigest struct {
	Day        string // YYYY-MM-DD, UTC
	FirstSeq   int64
	LastSeq    int64
	EventCount int64
	MerkleRoot string
	AuditSeq   int64
	CreatedAt  time.Time
}

// PitTotals counts the rows of the four PIT interval tables in a scope.
type PitTotals struct {
	Objects, Direct, Effective, Privileges int64
}
