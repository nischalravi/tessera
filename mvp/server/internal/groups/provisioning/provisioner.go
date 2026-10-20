// Package provisioning pushes the effective membership of native groups to
// target systems (design docs/design/groups-grouper-parity.md §9.2, issue #54).
//
// The framework is target-neutral. For one provisioner it
//
//   - computes the desired state: which groups are provisionable (marks with
//     folder inheritance), each group's target name and attributes (translation
//     templates) and its members as the identities' accounts in the target;
//   - reads the target (a full read, or a targeted read of the groups an event
//     batch touched), diffs, and turns the difference into ops;
//   - checks the failsafes, then applies the ops and re-reads every touched
//     group: an op is "verified" only when the re-read shows the change
//     (README rule 4), is retried with backoff otherwise, and after three
//     attempts becomes "drift";
//   - in adopt mode records what exists and what it would change, and changes
//     nothing; in dry_run mode records the plan and applies nothing.
//
// Targets implement Provisioner: ldap and ad (LDAP v3, ranged attributes),
// scim2 (generic, AWS Identity Center and GitHub EMU profiles), sql (a SQLite
// table) and webhook (signed CloudEvents).
package provisioning

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Capabilities says what a target can do (design §9.2).
type Capabilities struct {
	// Groups: the target has group objects. A target without them (a SQL
	// membership table) has groups only as sets of members: a group is created
	// by its first member and gone with its last.
	Groups bool
	// Entities: the target has user objects the framework can read.
	Entities bool
	// Memberships: the target holds group memberships.
	Memberships bool
	// EntityAttributes: the target takes isMemberOf-style values on users.
	EntityAttributes bool
	CreateEntities   bool
	// Incremental: a targeted Read of a few groups is cheap.
	Incremental bool
	// MaxBatch is the most ops one Apply call takes (0: no limit).
	MaxBatch int
	// Readable: the target can be read back, so ops can be verified. A target
	// that cannot (a webhook with no read endpoint) leaves ops "applied".
	Readable bool
	// ChangeTokens: the target implements TokenReader, so a full sync can skip
	// re-reading groups whose token is unchanged (sync-back, G-69).
	ChangeTokens bool
}

// Scope narrows a full read. The zero value is every group the provisioner
// manages; Names is a hint that only these groups are needed.
type Scope struct{ Names []string }

// TargetRef names a group on the target: its name, and its target-side id
// (a DN, a SCIM id) when known.
type TargetRef struct{ Name, ID string }

// TargetGroup is a group as read from the target.
type TargetGroup struct {
	Ref TargetRef
	// Attrs are the managed attributes as read, by the key the translation
	// templates use.
	Attrs map[string][]string
	// Members are member references in the target's own form (a DN, a SCIM
	// user id, a username).
	Members []string
	// Token is the target's change token for this group state, when it has one.
	Token string
}

// TargetState is what a read returns, by Key(name).
type TargetState struct{ Groups map[string]*TargetGroup }

// NewState returns an empty state.
func NewState() TargetState { return TargetState{Groups: map[string]*TargetGroup{}} }

// Key is the map key of a group name: names match case-insensitively.
func Key(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// OpKind is what an op does on the target.
type OpKind string

// Op kinds.
const (
	OpCreate  OpKind = "create"  // create the group with Attrs and the members in Add
	OpUpdate  OpKind = "update"  // replace the managed attributes
	OpMembers OpKind = "members" // add and remove members
	OpDelete  OpKind = "delete"  // delete the group
)

// Op is one change to one group on the target.
type Op struct {
	ID     string
	Kind   OpKind
	Ref    TargetRef
	Attrs  map[string][]string
	Add    []string
	Remove []string
}

// OpResult is the outcome of one op. Err is nil when the target accepted it
// (which is not yet verification). Ref carries the target id of a created group.
type OpResult struct {
	ID  string
	Ref TargetRef
	Err error
}

// Provisioner is a target system (design §9.2).
type Provisioner interface {
	Capabilities() Capabilities
	// ReadAll reads every group the target holds in the provisioner's container.
	ReadAll(ctx context.Context, scope Scope) (TargetState, error)
	// Read re-reads the named groups, the targeted read that verification uses.
	// A group that does not exist is absent from the state.
	Read(ctx context.Context, refs []TargetRef) (TargetState, error)
	// Apply runs ops in order and returns one result per op.
	Apply(ctx context.Context, ops []Op) ([]OpResult, error)
	// Close releases the target's connection.
	Close() error
}

// TokenReader is implemented by targets with change tokens: it returns the
// current token of every group, by Key(name), without reading their members.
type TokenReader interface {
	Tokens(ctx context.Context, scope Scope) (map[string]string, error)
}

// Errors.
var (
	// ErrConfig is a provisioner configuration that cannot be used.
	ErrConfig = errors.New("provisioning: invalid configuration")
	// ErrBusy: a run of this provisioner is already in progress.
	ErrBusy = errors.New("provisioning: a run is already in progress")
	// ErrNotActive: incremental sync needs mode active (and a finished full sync).
	ErrNotActive = errors.New("provisioning: the provisioner is not active")
	// ErrPaused: the provisioner is paused.
	ErrPaused = errors.New("provisioning: the provisioner is paused")
	// ErrReviewRequired: a provisioner is enabled (mode active) only after a full
	// sync has completed in adopt or dry_run mode, so there is a diff to review.
	ErrReviewRequired = errors.New("provisioning: run a full sync in adopt or dry_run mode and review it before enabling the provisioner")
	// ErrNeedsFull: the events seen need a full sync.
	ErrNeedsFull = errors.New("provisioning: a full sync is needed")
)

// cfgErr formats an ErrConfig.
func cfgErr(format string, args ...any) error {
	return &configError{msg: fmt.Sprintf(format, args...)}
}

type configError struct{ msg string }

func (e *configError) Error() string { return ErrConfig.Error() + ": " + e.msg }
func (e *configError) Unwrap() error { return ErrConfig }
