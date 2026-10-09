// Package connectors defines the connector interface and the demo connectors.
//
// A connector translates one source system (Okta, AWS, GitHub, ...) into
// Tessera's normalized records. It never writes to the database itself; the
// ingest package upserts what Discover returns and what StreamEvents yields.
//
// Cross-system references use Ref{Kind, System, ExternalID}, so a connector can
// point at objects owned by another connector (e.g. an Okta group mapped to an
// AWS role via SAML federation). Identities are referenced by IdentityRef,
// which ingest correlates by external id first, then by email.
package connectors

import (
	"context"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
)

// Ref points at an account, group or permission ("perm") in any system.
type Ref struct {
	Kind       string // account | group | perm
	System     string
	ExternalID string
}

// IdentityRef points at an identity by external id and/or email.
type IdentityRef struct {
	ExternalID string
	Email      string
}

// IdentityRecord is a person, service or AI agent.
type IdentityRecord struct {
	ExternalID   string
	Name         string
	Type         string // human | service | ai_agent
	Email        *string
	Department   *string
	Title        *string
	Status       string
	Manager      *IdentityRef
	Owner        *IdentityRef
	Description  *string
	HiredAt      *time.Time
	TerminatedAt *time.Time
}

// AccountRecord is an account in one system.
type AccountRecord struct {
	System      string
	ExternalID  string
	Username    string
	Identity    *IdentityRef
	Kind        string
	Status      string
	CreatedAt   *time.Time
	LastLoginAt *time.Time
}

// GroupRecord is a group, team, role or security group.
type GroupRecord struct {
	System      string
	ExternalID  string
	Name        string
	Kind        string
	Privileged  bool
	Requestable bool
	Description *string
}

// ResourceRecord is something permissions act on.
type ResourceRecord struct {
	System      string
	ExternalID  string
	Name        string
	Kind        string
	Environment *string
	Tags        []string
}

// PermissionRecord is an action on a resource.
type PermissionRecord struct {
	System             string
	ExternalID         string
	Action             string
	ResourceExternalID string
	Privileged         bool
}

// EdgeRecord is a grant relationship: member_of | maps_to | grants | direct_grant.
type EdgeRecord struct {
	Src, Dst Ref
	Relation string
}

// SecretRecord is a credential bound to an account.
type SecretRecord struct {
	System        string
	ExternalID    string
	Account       Ref
	Kind          string
	Name          string
	CreatedAt     time.Time
	LastRotatedAt *time.Time
	LastUsedAt    *time.Time
}

// DelegationRecord is an AI agent acting on behalf of a principal.
type DelegationRecord struct {
	Agent     IdentityRef
	Principal IdentityRef
	Scopes    []string
	ExpiresAt *time.Time
}

// DiscoveryResult is a full snapshot of one system.
type DiscoveryResult struct {
	Identities  []IdentityRecord
	Accounts    []AccountRecord
	Groups      []GroupRecord
	Resources   []ResourceRecord
	Permissions []PermissionRecord
	Edges       []EdgeRecord
	Secrets     []SecretRecord
	Delegations []DelegationRecord
}

// Event is either a *UsageRecord or a *HrisEventRecord.
type Event interface{ isEvent() }

// UsageRecord is aggregated usage: Identity exercised Permission Count times on Day.
type UsageRecord struct {
	Identity   IdentityRef
	Permission Ref
	Day        time.Time
	Count      int
	Account    *Ref
}

// HrisEventRecord is a joiner/mover/leaver event from the HR system.
type HrisEventRecord struct {
	ExternalID  string
	Type        string // joiner | mover | leaver
	Identity    *IdentityRef
	EffectiveAt time.Time
	// Payload is a JSON object, kept as ordered key/value pairs.
	Payload ojson.Object
}


func (*UsageRecord) isEvent()     {}
func (*HrisEventRecord) isEvent() {}

// Connector is implemented by every source-system connector.
type Connector interface {
	// System is the short system name, e.g. "okta".
	System() string
	// DisplayName is the human-readable name for the UI.
	DisplayName() string
	// TypeName identifies the implementation (shown by GET /api/connectors).
	TypeName() string
	// Discover returns a full snapshot of identities, accounts, entitlements and resources.
	Discover(ctx context.Context) (*DiscoveryResult, error)
	// StreamEvents calls yield for every usage / lifecycle event after since
	// (all events when since is nil). Returning an error from yield stops the stream.
	StreamEvents(ctx context.Context, since *time.Time, yield func(Event) error) error
}
