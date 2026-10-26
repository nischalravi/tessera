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
	// Attributes holds the source attributes the readiness template maps
	// (correlation, status and lifecycle attributes), never the whole entry.
	// Optional: ingest ignores it; dry runs stage it.
	Attributes map[string]string
}

// AuthSignals are what a source reports about how one account signs in.
// Each fact is tri-state: nil is unknown. They are recorded as reported,
// never inferred, and a connector that has no such field leaves them out.
type AuthSignals struct {
	Account          Ref   // kind account
	HasLocalPassword *bool // the account can sign in with a password held by the app itself
	MFAEnabled       *bool // the app enforces or has registered MFA for the account
	SSOEnforced      *bool // the account can only sign in through the IdP
}

// AuthMethodRecord is one registered authentication method of an account.
// Strength is a mfa.Strength value and Kind a mfa.Kind* value, set by the
// connector's classifier.
type AuthMethodRecord struct {
	Account    Ref // kind account
	ExternalID string
	Strength   string
	Kind       string
	Label      string
	EnrolledAt *time.Time
}

// AuthMethodSource says whether a connector read registered methods in this
// run. Unavailable (for example a missing Graph scope) means no methods were
// read: ingest keeps what it stored and the report shows the gap, so a missing
// permission never looks like "nobody has MFA".
type AuthMethodSource struct {
	System      string
	Unavailable bool
	Detail      string
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
	// Evaluation is set on an edge the AWS evaluator confirmed (design §11.2);
	// ingest then stores the edge with source "evaluator" and these fields.
	// Nil for every other edge.
	Evaluation *EdgeEvaluation
}

// EdgeEvaluation says what the evaluator established about an edge:
// ExplanationID names its trace, Outcome is "allow" or "conditional", and
// Fidelity is "exact", "approximate" or "unsupported".
type EdgeEvaluation struct {
	ExplanationID, Outcome, Fidelity string
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

// AgentRecord is what a source system says about how an AI agent came to be:
// the system it was found in, who created it and who sponsors it (issue #116).
// The agent itself is an ai_agent IdentityRecord (the sponsor is its Owner, so
// the nhi-ownership policy applies), its account is an AccountRecord of kind
// "agent" and its credentials are SecretRecords; this record adds provenance.
type AgentRecord struct {
	// System is the source system ("entra", "okta", "aws-agentcore").
	System string
	// ExternalID is the agent's id in that system.
	ExternalID string
	// Identity is the ai_agent identity this record describes.
	Identity IdentityRef
	// Kind says what the agent is in the source: entra_agent_identity,
	// okta_service_app or bedrock_agentcore_runtime.
	Kind    string
	Creator *IdentityRef
	Sponsor *IdentityRef
	// CreatorRef and SponsorRef are the source's own words for them (a UPN, an
	// e-mail address, a principal ARN), kept when they do not resolve to an
	// identity. They are never credentials.
	CreatorRef string
	SponsorRef string
	// BlueprintAppID is the AppID of the BlueprintRecord the agent was created from (Entra
	// agentIdentityBlueprintId is the blueprint's appId, not its object id). ManagerApplications
	// are the application ids that manage the agent (Entra managerApplications): applications,
	// not people (issue #478).
	BlueprintAppID      string
	ManagerApplications []string
}

// BlueprintRecord is an agent blueprint, the template agent identities are
// created from (Entra Agent ID, issue #478), with its sponsor.
type BlueprintRecord struct {
	System     string
	ExternalID string
	AppID      string
	Name       string
	CreatorRef string
	Sponsor    *IdentityRef
	SponsorRef string
}

// MCPFindingRecord is one finding from scanning source code for MCP server
// configurations and agent credentials (issue #116). It holds the location, a
// fingerprint and the secret TYPE, never a secret value: Fingerprint is a
// truncated hash made by the scanner.
type MCPFindingRecord struct {
	// System is the scanning connector ("github").
	System string
	// Kind is mcp_server or agent_credential.
	Kind string
	Org  string
	Repo string
	Path string
	// Location is where in the file: a JSON path ("mcpServers.github.env.TOKEN")
	// or a line ("L12").
	Location string
	// Server is the MCP server's name in the config, Transport is stdio, http,
	// sse or unknown and Target is the command name or the URL host.
	Server    string
	Transport string
	Target    string
	// SecretType is the kind of secret ("github_token", "anthropic_api_key"),
	// empty for an mcp_server finding without one.
	SecretType  string
	Fingerprint string
	// Owner is who the finding is linked to: Ref is a source-side name
	// ("@team", "github:login", an e-mail address), Source says how it was
	// found (codeowners, committer or none).
	OwnerRef    string
	OwnerSource string
	Owner       *IdentityRef
	CommitSHA   string
}

// DiscoveryResult is a full snapshot of one system.
type DiscoveryResult struct {
	// System is the connector's system, set by the sync that ran it. The deletion guard resolves it to the
	// connection (SourceID, which a caller may set instead) to apply that source's own settings and keep
	// its last good record counts; a result with neither is judged under the tenant's settings alone.
	System   string
	SourceID string
	// Partial, when set, says the read was partial or failed part way (why): the deletion guard then
	// holds every removal this result would cause (internal/deleteguard).
	Partial string
	// EdgeSnapshotOf lists the systems whose permission edges (edges into a permission of the system)
	// this result lists completely, so ingest may remove a stored edge the result no longer reports
	// (issue #577). A complete read (Partial empty) covers every permission of the system; a Partial
	// one covers only the permissions on the resources in EdgeScopesRead (the scopes read in full).
	// Absence from a read that did not cover a scope is never evidence of removal.
	EdgeSnapshotOf []string
	// EdgeScopesRead are the external ids of the resources (scopes) whose grants were read in full:
	// no denied call, failed page or truncation.
	EdgeScopesRead []string
	Identities     []IdentityRecord
	Accounts       []AccountRecord
	Groups         []GroupRecord
	Resources      []ResourceRecord
	Permissions    []PermissionRecord
	Edges          []EdgeRecord
	Secrets        []SecretRecord
	Delegations    []DelegationRecord
	// AuthMethods are the registered authentication methods of the accounts
	// in AuthSource.System. Optional.
	AuthMethods []AuthMethodRecord
	// AuthSource is set by a connector that reads authentication methods.
	AuthSource *AuthMethodSource
	// AuthSignals are per-account password, MFA and SSO facts of apps and
	// data platforms (Snowflake, GitHub, AWS IAM users). Optional.
	AuthSignals []AuthSignals
	// Agents and MCPFindings are the agent-discovery records (issue #116).
	// AgentSnapshotOf names the systems for which this result is the complete
	// list of both: ingest replaces what it holds for those systems, so an
	// agent or finding that is gone from the source is gone from Tessera.
	Agents     []AgentRecord
	Blueprints []BlueprintRecord
	// BlueprintSnapshotOf lists the systems whose blueprints were listed completely; only then may
	// blueprints missing from Blueprints be removed.
	BlueprintSnapshotOf []string
	MCPFindings         []MCPFindingRecord
	AgentSnapshotOf     []string
	// Stats are per-object-class attribute fill counts computed by the
	// connector, so fill rates need no attribute values. Optional.
	Stats *DiscoveryStats
}

// DiscoveryStats are attribute fill counts per object class.
type DiscoveryStats struct {
	Classes map[string]*ClassStats
}

// ClassStats counts the objects of one class and how many carry each attribute.
type ClassStats struct {
	Total      int
	Attributes map[string]AttrStat
}

// AttrStat is how many objects have an attribute, and how many distinct values it has.
type AttrStat struct {
	Present  int
	Distinct int
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
