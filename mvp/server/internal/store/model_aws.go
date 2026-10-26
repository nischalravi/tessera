package store

import (
	"encoding/json"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// AWS evaluator persistence (schema/0319_aws_snapshots.sql; design
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
// hold: see schema/0319_aws_snapshots.sql).
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

// AWSPRCommentSettings is a tenant's switch for the access-diff comment on a
// GitHub pull request (schema/0321_aws_integration.sql). A tenant with no row
// has it off. TokenEnc is the sealed token; it is never returned by the API.
type AWSPRCommentSettings struct {
	Enabled   bool
	Repo      string // "owner/name"
	TokenEnc  []byte
	UpdatedBy string
	UpdatedAt time.Time
}

// AWSExplanation is a content-addressed decision trace.
type AWSExplanation struct {
	ID    string
	Trace json.RawMessage
}

// AWS collection run states and triggers (schema/0914_aws_collection_runs.sql).
const (
	AWSRunQueued    = "queued"
	AWSRunRunning   = "running"
	AWSRunSucceeded = "succeeded"
	AWSRunUnchanged = "unchanged"
	AWSRunFailed    = "failed"

	AWSRunManual   = "manual"
	AWSRunSchedule = "schedule"
)

// AWSCollectionRun is one collection of an AWS connector. Result is a JSON
// summary (counts only); SnapshotID is the snapshot the run collected.
type AWSCollectionRun struct {
	ID          string
	ConnectorID string
	Trigger     string
	Status      string
	RequestedBy string
	QueuedAt    time.Time
	StartedAt   *time.Time
	FinishedAt  *time.Time
	SnapshotID  string
	Changed     bool
	Result      json.RawMessage
	Error       string
}

// AWS usage sources and S3 data-event states (schema/0915_aws_usage.sql).
const (
	AWSUsageCloudTrail     = "cloudtrail"
	AWSUsageAccessAdvisor  = "access_advisor"
	AWSDataEventsEnabled   = "enabled"
	AWSDataEventsDisabled  = "disabled"
	AWSDataEventsUnknown   = "unknown"
	AWSUsageScopeAnywhere  = "*"
	MaxAWSUsageCursorBytes = 1 << 20
)

// AWSUsageDay is one row of aws_usage_daily: what a principal did on a day.
// Day is YYYY-MM-DD (UTC).
type AWSUsageDay struct {
	ConnectorID   string
	PrincipalARN  string
	Action        string
	ResourceScope string
	Day           string
	Source        string
	Count         int64
	LastSeen      time.Time
}

// AWSUsageState is a connector's ingest state for one source.
type AWSUsageState struct {
	ConnectorID  string
	Source       string
	Cursor       json.RawMessage
	CoveredFrom  string
	CoveredTo    string
	S3DataEvents string
	UpdatedAt    time.Time
}

// AWSUsageGap is something a source could not ingest. Ref names it (an S3 key,
// a principal ARN, "trail"); Day is the day it affects, or "".
type AWSUsageGap struct {
	ConnectorID string
	Source      string
	Ref         string
	Code        string
	Detail      string
	Day         string
	RecordedAt  time.Time
}
