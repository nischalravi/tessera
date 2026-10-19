package eval

import "errors"

// EngineVersion is recorded on every decision (§6.1). Bump it when a change
// can alter a decision or a trace.
const EngineVersion = "aws-eval/0.2.0"

// Catalog is the engine's view of the action, resource and condition-key
// catalog (§10). internal/aws/catalog satisfies it; the engine never reads
// files, so tests use a fake. All methods must be pure.
type Catalog interface {
	// Version identifies the catalog snapshot; it is recorded on every decision.
	Version() string
	// CanonicalAction case-folds an action ("S3:getobject" to "s3:GetObject")
	// and reports whether the service prefix and action name exist.
	CanonicalAction(action string) (canonical string, ok bool)
	// RCPSupportedService reports whether resource control policies cover the
	// service prefix (§7.5, §10.3).
	RCPSupportedService(prefix string) bool
	// MultivaluedKey reports whether a lower-cased condition key is multivalued
	// (an ArrayOf* type or a global multivalued key).
	MultivaluedKey(lowerKey string) bool
	// ResourceTagsSupported reports whether the service supports aws:ResourceTag
	// for the action. When false every resource tag key is absent (§9.2).
	ResourceTagsSupported(action string) bool
	// RequiresExplicitRBP reports whether a same-account request to a resource
	// policy of this service needs an explicit Allow naming the account (§7.4.3).
	// verified is false for a service no probe or doc has covered; the engine
	// then applies the union rule and flags SERVICE_RBP_RULE_UNVERIFIED.
	RequiresExplicitRBP(servicePrefix string) (explicit, verified bool)
	// KMSCrossAccountOp reports whether a kms: action can be authorized across
	// accounts: the cryptographic operations, CreateGrant, DescribeKey,
	// GetKeyRotationStatus, GetPublicKey, ListGrants, RetireGrant and
	// RevokeGrant (§7.6.1; overlay kms_xacct_ops.yaml). Any other kms: action
	// on a key in another account is a guardrail deny.
	KMSCrossAccountOp(action string) bool
	// S3ACLActions lists the access-policy actions an ACL permission ("READ",
	// "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL") stands for at a scope
	// (§7.6.2; overlay s3_acl_map.yaml).
	S3ACLActions(scope S3ACLScope, permission string) []string
	// S3ACLGroup describes a predefined ACL group by URI.
	S3ACLGroup(uri string) (S3ACLGroup, bool)
	// S3PublicFixedKey reports whether a lower-cased condition key can make a
	// statement of a public-looking policy non-public, and how
	// (overlay s3_public_fixed_keys.yaml).
	S3PublicFixedKey(lowerKey string) (S3PublicKeyRule, bool)
}

// S3ACLScope is where an ACL lives: on a bucket or on an object.
type S3ACLScope uint8

const (
	S3ACLBucket S3ACLScope = iota
	S3ACLObject
)

// S3ACLGroup is a predefined ACL grantee group.
type S3ACLGroup struct {
	Name   string // "AllUsers", "AuthenticatedUsers", "LogDelivery"
	Public bool   // AllUsers and AuthenticatedUsers
}

// S3PublicRuleKind says how a condition key pins a policy statement.
type S3PublicRuleKind uint8

const (
	// S3FixedValue: every value is fixed (no wildcard, no variable).
	S3FixedValue S3PublicRuleKind = iota
	// S3IPRange: every range is no broader than the CIDR limits, or private.
	S3IPRange
)

// S3PublicKeyRule is one entry of s3_public_fixed_keys.yaml.
type S3PublicKeyRule struct {
	Kind S3PublicRuleKind
	// ExceptPatterns are values that do not pin the key (aws:userid
	// "AROLEID:*": a role id with any session name).
	ExceptPatterns []string
	// IPv4MaxCIDR and IPv6MaxCIDR: a range with a shorter prefix is public.
	IPv4MaxCIDR, IPv6MaxCIDR int
	// BucketPoliciesOnly: the key counts for bucket policies, not for access
	// point policies.
	BucketPoliciesOnly bool
}

// SessionSpec describes a hypothetical session (§7.3): it overrides what the
// snapshot records for the requester. Nil fields keep the snapshot's values.
type SessionSpec struct {
	PolicyIDs      []string          // session policy documents (PolicyDoc ids)
	Tags           map[string]string // session tags
	SourceIdentity string
}

// EvaluationRequest is one question: may PrincipalARN do Action on ResourceARN?
// It implements authz.Request.
type EvaluationRequest struct {
	// PrincipalARN is the requester: a user, root, session (assumed-role or
	// federated-user) ARN, a role ARN (answered for a session with no session
	// policy, §7.3), a service name such as "sns.amazonaws.com", "*" or
	// "anonymous", or an OIDC/SAML provider ARN (the caller of
	// AssumeRoleWith*).
	PrincipalARN string `json:"principal_arn"`
	Action       string `json:"action"`
	// ResourceARN is "" or "*" for an action with no resource-level support.
	ResourceARN string `json:"resource_arn"`
	// Context holds caller-supplied keys (any case); they override derived keys.
	Context map[string]ContextValue `json:"context"`
	Mode    Mode                    `json:"mode"`
	// Profile pins keys for a symbolic query (§9.4); see Profile.
	Profile map[string]ContextValue `json:"profile"`
	Session *SessionSpec            `json:"session"`
	// ViaVPCE is the VPC endpoint id the request came through, if any.
	ViaVPCE string `json:"via_vpce"`
	// ViaAWSService marks a call made by an AWS service on the principal's
	// behalf; otherwise aws:ViaAWSService and aws:CalledVia* are absent.
	ViaAWSService bool `json:"via_aws_service"`
	// S3ObjectOwner is the account that owns the object, when it is not the
	// bucket owner (§7.6.2 object context). Empty means the bucket owner is
	// assumed, and the decision carries S3_OBJECT_OWNER_UNKNOWN if that matters.
	S3ObjectOwner string `json:"s3_object_owner"`
}

// Platform implements authz.Request.
func (*EvaluationRequest) Platform() string { return "aws" }

// Options tunes one evaluation.
type Options struct {
	// Fast stops at the first decisive explicit deny and skips the
	// outcome-sensitivity re-runs of §7.9. It is for bulk enumeration (§12);
	// fidelity is then not downgraded for ambiguities.
	Fast bool
}

// Errors returned for a request the engine cannot answer.
var (
	ErrNoSnapshot       = errors.New("eval: nil snapshot")
	ErrNoCatalog        = errors.New("eval: nil catalog")
	ErrInvalidRequest   = errors.New("eval: invalid request")
	ErrUnknownPrincipal = errors.New("eval: principal is not in the snapshot")
)

// Reason codes the engine adds beyond internal/authz's list.
const (
	// reasonResourceAccountUnknown: the resource's owning account is not in the
	// snapshot, so same-account was assumed.
	reasonResourceAccountUnknown = "RESOURCE_ACCOUNT_UNKNOWN"
	// reasonS3ObjectOwnerUnknown: an object action on a bucket whose ACLs are
	// enabled; Tessera does not inventory objects, so the object owner is
	// assumed to be the bucket owner (§7.6.2).
	reasonS3ObjectOwnerUnknown = "S3_OBJECT_OWNER_UNKNOWN"
)
