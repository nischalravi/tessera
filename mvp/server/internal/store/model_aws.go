package store

import (
	"encoding/json"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// AWS evaluator persistence (schema/0321_aws_snapshots.sql; design
// docs/design/aws-effective-permission-evaluator.md §6.2). The store holds
// plain values: internal/connectors/awsorg maps its model.Snapshot to and
// from these rows, so the store imports nothing from the evaluator.

// AWS snapshot sources.
const (
	AWSSourceConnector = "connector"
	AWSSourcePRSim     = "pr-sim"
	AWSSourceHarness   = "harness"
)

// AWS connector states.
const (
	AWSConnectorIdle   = "idle"
	AWSConnectorOK     = "ok"
	AWSConnectorFailed = "failed"
)

// AWS collection finding kinds.
const (
	AWSFindingPolicyUnparseable = "policy_unparseable"
	AWSFindingStatementDropped  = "statement_dropped"
	AWSFindingAccountError      = "account_error"
)

// AWS snapshot entity kinds (the JSON bodies of what §6.2's tables do not
// hold: see schema/0321_aws_snapshots.sql).
const (
	AWSEntityPrincipal      = "principal"
	AWSEntityResource       = "resource"
	AWSEntityResourcePolicy = "resource_policy"
	AWSEntityKMSGrant       = "kms_grant"
	AWSEntityS3Bucket       = "s3_bucket"
	AWSEntityVPCEPolicy     = "vpce_policy"
	AWSEntityCanonicalID    = "canonical_id"
	AWSEntityIdentityCenter = "identity_center"
	AWSEntityOrg            = "org"
)

// AWSConnector is one read-only AWS connector of a tenant. CredentialsEnc is
// the sealed access key pair (internal/seal); it is never returned by the API.
type AWSConnector struct {
	ID             string
	TenantID       tenancy.ID
	Name           string
	Config         json.RawMessage
	ExternalID     string
	CredentialsEnc []byte
	Status         string
	LastSnapshotID string
	LastRunAt      *time.Time
	LastError      string
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// AWSSnapshot is a snapshot's header. ID is the content hash.
type AWSSnapshot struct {
	ID             string
	TakenAt        time.Time
	OrgID          string
	AccountIDs     []string
	CatalogVersion string
	Source         string
	ConnectorID    string
}

// AWSPolicyDocument is an immutable, content-addressed policy document.
type AWSPolicyDocument struct {
	ID         string
	Kind       string
	SourceARN  string
	VersionID  string
	RawJSON    []byte
	Normalized json.RawMessage
	FetchedAt  time.Time
}

// AWSAttachment links a policy to its target within a snapshot.
type AWSAttachment struct {
	SnapshotID     string
	PolicyID       string
	TargetARN      string
	AttachmentType string
	Via            []string
}

// AWSOrgNode is a root, OU or account of a snapshot's organization.
type AWSOrgNode struct {
	SnapshotID string
	ID         string
	Kind       string
	ParentID   string
	Name       string
}

// AWSEntity is one JSON-encoded snapshot entity.
type AWSEntity struct {
	SnapshotID string
	Kind       string
	Key        string
	Body       json.RawMessage
}

// AWSFinding is something the collector could not take at face value.
type AWSFinding struct {
	SnapshotID string
	Kind       string
	SourceARN  string
	PolicyKind string
	Code       string
	Detail     string
	Scope      json.RawMessage // which decisions the finding could affect
}

// AWSTrustEdge is a materialized "who can become role R" fact (design §11.4).
type AWSTrustEdge struct {
	SnapshotID    string
	FromARN       string
	ToRoleARN     string
	Mechanism     string
	Outcome       string
	Residual      json.RawMessage
	ExplanationID string
}

// AWSEffective is one materialized effective-permission cell (design §12.4).
type AWSEffective struct {
	SnapshotID     string
	PrincipalARN   string
	ActionAtom     int64
	ResourceAtom   int64
	Outcome        string
	Residual       json.RawMessage // nil unless conditional
	Fidelity       string
	ExplanationID  string
	EngineVersion  string
	CatalogVersion string
}

// AWSExplanation is a content-addressed decision trace.
type AWSExplanation struct {
	ID    string
	Trace json.RawMessage
}
