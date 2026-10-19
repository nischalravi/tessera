// Package model holds the in-memory types the AWS evaluator works over
// (docs/design/aws-effective-permission-evaluator.md §6.1).
//
// Conventions:
//   - An empty string means "none" for ARNs, ids and names. A nil pointer or
//     nil slice means "absent" where empty and absent differ (for example
//     Actions versus NotActions).
//   - JSON field names are the v1 snake_case names.
//   - A Snapshot is built only by snapshot.Builder (PR-5) and never written
//     after Build(). This package does no I/O and reads no clock.
package model

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
)

// Span is a statement's position in its policy's raw JSON.
type Span = authz.Span

// Principal is a requester or an entity that can become one.
type Principal struct {
	ARN               string            `json:"arn"` // requester ARN (the session ARN for sessions)
	Kind              PrincipalKind     `json:"kind"`
	AccountID         string            `json:"account_id"`          // "" for service and anonymous
	EntityARN         string            `json:"entity_arn"`          // role ARN for role sessions; the IAM user's ARN for federated sessions
	UniqueID          string            `json:"unique_id"`           // AIDA…/AROA…, for trust-policy principal-ID matching
	Path              string            `json:"path"`                // default "/"
	IsServiceLinked   bool              `json:"is_service_linked"`   // role path /aws-service-role/
	Tags              map[string]string `json:"tags"`                // entity tags
	SessionTags       map[string]string `json:"session_tags"`        // override entity tags with the same key
	TransitiveTagKeys []string          `json:"transitive_tag_keys"` // sorted, unique
	SessionPolicyIDs  []string          `json:"session_policy_ids"`  // PolicyDoc ids (inline + PolicyArns)
	SourceIdentity    string            `json:"source_identity"`
	GroupARNs         []string          `json:"group_arns"`          // users only
	BoundaryPolicyID  string            `json:"boundary_policy_id"`  // "" if no boundary
	IdentityPolicyIDs []string          `json:"identity_policy_ids"` // resolved attachments (user + groups, or role)
	FederatedProvider string            `json:"federated_provider"`  // OIDC/SAML provider ARN
	Chain             []string          `json:"chain"`               // role-chain ARNs, oldest first
}

// PolicyDoc is one parsed policy document.
type PolicyDoc struct {
	ID              string     `json:"id"` // stable: sha256(kind | source_arn | version_id | raw bytes)
	Kind            PolicyKind `json:"kind"`
	SourceARN       string     `json:"source_arn"`       // policy ARN, "<resource-arn>#policy" or "<role-arn>#trust"
	VersionID       string     `json:"version_id"`       // managed-policy default version, or SCP/RCP content hash; "" if none
	LanguageVersion string     `json:"language_version"` // "2012-10-17", "2008-10-17" or ""; anything but 2012-10-17 → variables are literal
	// IDElement is the policy's own "Id" element ("" if absent). It is not in the
	// design's struct; it is kept so the canonical serialization round-trips.
	IDElement  string      `json:"id_element"`
	RawJSON    []byte      `json:"raw_json"` // verbatim bytes as fetched
	Statements []Statement `json:"statements"`
	AWSManaged bool        `json:"aws_managed"`
	FetchedAt  time.Time   `json:"fetched_at"` // for staleness; zero if unknown
	// Unparseable is "" for a document that parsed cleanly. Otherwise it says why
	// the document cannot be trusted (a parse error, or a statement dropped as an
	// ingest anomaly) and the engine fails closed (§3.3): every decision this
	// document could affect is UNSUPPORTED with POLICY_UNPARSEABLE. A document
	// that failed to parse keeps its raw bytes and has no statements.
	Unparseable string `json:"unparseable"`
}

// VariablesEnabled reports whether policy variables are substituted in this
// document: only when Version is exactly "2012-10-17" (§4.1 fact 10, §9.3).
func (d *PolicyDoc) VariablesEnabled() bool { return d.LanguageVersion == LanguageVersion2012 }

// The two policy language versions AWS accepts.
const (
	LanguageVersion2012 = "2012-10-17"
	LanguageVersion2008 = "2008-10-17"
)

// Statement is one statement of a policy document.
type Statement struct {
	PolicyID      string        `json:"policy_id"`
	Index         int           `json:"index"` // 0-based position in the raw Statement array
	Sid           string        `json:"sid"`
	Effect        Effect        `json:"effect"`
	Actions       *PatternSet   `json:"actions"` // exactly one of Actions / NotActions is non-nil (validated at parse)
	NotActions    *PatternSet   `json:"not_actions"`
	Resources     *PatternSet   `json:"resources"` // both nil in a resource policy ⇒ implied "this resource"
	NotResources  *PatternSet   `json:"not_resources"`
	Principals    *PrincipalSet `json:"principals"` // resource policies only
	NotPrincipals *PrincipalSet `json:"not_principals"`
	Condition     []authz.Atom  `json:"condition"` // conjunction; variables still unresolved (resolved per request)
	Span          *Span         `json:"span"`      // position in RawJSON; nil if unknown
}

// PatternSet is the value of Action, NotAction, Resource or NotResource: the
// raw patterns in document order. Patterns are matched raw at evaluation
// (actions case-insensitively, ARNs case-sensitively, §8.1); the parser does
// not rewrite them. A JSON string and a one-element list are the same set.
//
// Completed is set only for Resource and NotResource in policy kinds where AWS
// completes an incomplete ARN (fewer than six segments) with "*" for every
// missing segment (§8.3): identity and boundary policies, and SCPs by
// over-approximation (ambiguity A21). It then has one entry per pattern, in
// the same order: the completed pattern, or the pattern itself when it needs
// no completion. Completed is nil otherwise, including when no pattern in the
// set is incomplete.
type PatternSet struct {
	Patterns  []string `json:"patterns"`
	Completed []string `json:"completed"`
}

// MatchPatterns returns the patterns the matcher uses: Completed when set,
// otherwise Patterns. Explanations show Patterns, the policy's own spelling.
func (p *PatternSet) MatchPatterns() []string {
	if p == nil {
		return nil
	}
	if p.Completed != nil {
		return p.Completed
	}
	return p.Patterns
}

// PrincipalSet is the value of Principal or NotPrincipal.
//
// The raw per-type lists are kept in document order (nil means the key was
// absent), and Entries holds the normalized form of §8.4.1 in the order
// "*", AWS, CanonicalUser, Federated, Service.
//
// Star records only the spelling: it is true for the bare string form
// "Principal": "*" and false for {"AWS": "*"}, which instead yields an AWS
// entry of kind PrincipalWildcard. The two match the same requesters (§8.4.1),
// so matching must use Entries (or HasWildcard), never Star. Star matters only
// where AWS distinguishes the spelling, such as the RCP rule that allows the
// bare "*" alone, and for the canonical serialization.
type PrincipalSet struct {
	Star          bool             `json:"star"` // the bare "Principal": "*" form only; see the type comment
	AWS           []string         `json:"aws"`
	CanonicalUser []string         `json:"canonical_user"`
	Federated     []string         `json:"federated"`
	Service       []string         `json:"service"`
	Entries       []PrincipalEntry `json:"entries"`
}

// HasWildcard reports whether the set contains "*" in either spelling.
func (p *PrincipalSet) HasWildcard() bool {
	if p == nil {
		return false
	}
	for _, e := range p.Entries {
		if e.Kind == PrincipalWildcard {
			return true
		}
	}
	return false
}

// PrincipalEntry is one normalized principal value.
type PrincipalEntry struct {
	Kind PrincipalEntryKind `json:"kind"`
	// Value is the raw value as written ("*" for a wildcard, the 12-digit
	// account id for an account principal in either spelling).
	Value string `json:"value"`
	// AccountID is the account an ARN or account principal belongs to; "" for
	// wildcard, unique-id, service, federated and canonical-user entries.
	AccountID string `json:"account_id"`
}

// PolicyAttachment links a policy to its target.
type PolicyAttachment struct {
	PolicyID       string         `json:"policy_id"`
	TargetARN      string         `json:"target_arn"` // user / group / role / OU / account / root / resource
	Via            []string       `json:"via"`        // provenance path, e.g. ["user/alice", "group/eng"]
	AttachmentType AttachmentType `json:"attachment_type"`
}

// OrgNode is a root, OU or account in an organization.
type OrgNode struct {
	ID       string      `json:"id"` // r-xxxx / ou-xxxx / 123456789012
	Kind     OrgNodeKind `json:"kind"`
	ParentID string      `json:"parent_id"` // "" for the root
	Name     string      `json:"name"`
	SCPIDs   []string    `json:"scp_ids"` // SCPs attached at THIS level
	RCPIDs   []string    `json:"rcp_ids"` // RCPs attached at THIS level
}

// Organization is an AWS Organizations tree.
type Organization struct {
	OrgID               string              `json:"org_id"`
	ManagementAccountID string              `json:"management_account_id"`
	Nodes               map[string]*OrgNode `json:"nodes"`
	SCPEnabled          bool                `json:"scp_enabled"`
	RCPEnabled          bool                `json:"rcp_enabled"`
}

// PathTo returns the nodes from the root down to the account (root → … →
// account), or nil if the account is not in the organization or the parent
// chain is broken or cyclic.
func (o *Organization) PathTo(accountID string) []*OrgNode {
	if o == nil {
		return nil
	}
	n, ok := o.Nodes[accountID]
	if !ok || n == nil || n.Kind != OrgAccount {
		return nil
	}
	var rev []*OrgNode
	for steps := 0; n != nil; steps++ {
		if steps > len(o.Nodes) {
			return nil // cycle
		}
		rev = append(rev, n)
		if n.ParentID == "" {
			if n.Kind != OrgRoot {
				return nil
			}
			break
		}
		n = o.Nodes[n.ParentID]
		if n == nil {
			return nil
		}
	}
	out := make([]*OrgNode, len(rev))
	for i, v := range rev {
		out[len(rev)-1-i] = v
	}
	return out
}

// Boundary is a convenience view: a boundary is a PolicyDoc plus an attachment.
type Boundary struct {
	EntityARN string `json:"entity_arn"`
	PolicyID  string `json:"policy_id"`
}

// ResourcePolicy attaches a resource-based policy to a resource.
type ResourcePolicy struct {
	ResourceARN           string     `json:"resource_arn"`
	Kind                  PolicyKind `json:"kind"` // PolicyResource / PolicyTrust / PolicyKMSKey / PolicyS3AccessPoint / PolicyVPCE
	PolicyID              string     `json:"policy_id"`
	RequiresExplicitAllow bool       `json:"requires_explicit_allow"` // trust policies, KMS key policies, and the §7.4.3 table
}

// KMSGrant is one KMS grant.
type KMSGrant struct {
	KeyARN                  string            `json:"key_arn"`
	GrantID                 string            `json:"grant_id"`
	GranteePrincipal        string            `json:"grantee_principal"`         // "" if none
	GranteeServicePrincipal string            `json:"grantee_service_principal"` // "" if none
	Operations              []string          `json:"operations"`                // sorted set: "Decrypt", "GenerateDataKey", ...
	ConstraintsECEquals     map[string]string `json:"constraints_ec_equals"`     // nil if absent
	ConstraintsECSubset     map[string]string `json:"constraints_ec_subset"`     // nil if absent
	ConstraintSourceARN     string            `json:"constraint_source_arn"`
	RetiringPrincipal       string            `json:"retiring_principal"`
	CreatedAt               time.Time         `json:"created_at"`
}

// ACLGrant is one S3 ACL grant (PR-6 fills in the evaluation).
type ACLGrant struct {
	GranteeType string `json:"grantee_type"` // "CanonicalUser" | "Group" | "AmazonCustomerByEmail"
	Grantee     string `json:"grantee"`      // canonical id, group URI or email
	Permission  string `json:"permission"`   // "READ" | "WRITE" | "READ_ACP" | "WRITE_ACP" | "FULL_CONTROL"
}

// BPA is one level of S3 Block Public Access settings.
type BPA struct {
	BlockPublicAcls       bool `json:"block_public_acls"`
	IgnorePublicAcls      bool `json:"ignore_public_acls"`
	BlockPublicPolicy     bool `json:"block_public_policy"`
	RestrictPublicBuckets bool `json:"restrict_public_buckets"`
}

// S3BucketState is the S3-specific state of one bucket.
type S3BucketState struct {
	BucketARN       string     `json:"bucket_arn"`
	OwnerAccount    string     `json:"owner_account"`
	ObjectOwnership string     `json:"object_ownership"` // "BucketOwnerEnforced" | "BucketOwnerPreferred" | "ObjectWriter"
	BucketACL       []ACLGrant `json:"bucket_acl"`
	BPABucket       BPA        `json:"bpa_bucket"`
	BPAAccount      BPA        `json:"bpa_account"`
	BPAOrg          *bool      `json:"bpa_org"`          // org level is all-or-none; nil if unknown
	PolicyIsPublic  bool       `json:"policy_is_public"` // computed per §7.6.2
}

// Resource is what the snapshot knows about one resource.
type Resource struct {
	ARN       string            `json:"arn"`
	Type      string            `json:"type"` // catalog resource type, e.g. "bucket", "object", "key"
	AccountID string            `json:"account_id"`
	Region    string            `json:"region"`
	Tags      map[string]string `json:"tags"`
}

// TrustEdge is a materialized "who can become role R" fact (§11.4).
type TrustEdge struct {
	FromPrincipalARN string         `json:"from_principal_arn"` // user / role / provider / service / account root
	ToRoleARN        string         `json:"to_role_arn"`
	Mechanism        TrustMechanism `json:"mechanism"`
	Decision         authz.Outcome  `json:"decision"` // Allow or Conditional
	Residual         authz.Residual `json:"residual"` // e.g. sts:ExternalId == "x", or token sub like "repo:org/*"
	ExplanationID    string         `json:"explanation_id"`
}

// Snapshot is the immutable input to evaluation.
type Snapshot struct {
	ID               string                      `json:"id"` // content hash
	TakenAt          time.Time                   `json:"taken_at"`
	Org              *Organization               `json:"org"`        // nil if the accounts are not in an organization
	Principals       map[string]*Principal       `json:"principals"` // entities plus synthetic session templates
	Policies         map[string]*PolicyDoc       `json:"policies"`
	Attachments      []PolicyAttachment          `json:"attachments"`
	ResourcePolicies map[string][]ResourcePolicy `json:"resource_policies"` // by resource ARN
	KMSGrants        map[string][]KMSGrant       `json:"kms_grants"`
	S3               map[string]*S3BucketState   `json:"s3"`
	Resources        map[string]*Resource        `json:"resources"`     // arn → type, account, region, tags
	VPCEPolicies     map[string]string           `json:"vpce_policies"` // VPC endpoint id → PolicyDoc id
	CanonicalIDs     map[string]string           `json:"canonical_ids"` // S3 canonical user id → account id
}
