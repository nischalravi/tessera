package eval

import "errors"

// EngineVersion is recorded on every decision (§6.1). Bump it when a change
// can alter a decision or a trace.
const EngineVersion = "aws-eval/0.1.0"

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
)
