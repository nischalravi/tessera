package eval

import (
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// This file exports the few engine facts that internal/aws/index needs to group
// requesters, resources and actions into equivalence classes (§12.2) without
// copying the engine's rules. Each function is a thin wrapper over what
// Evaluate itself uses, so the two cannot drift apart.

// RequesterClass says which grant rule of §7.2 step 4 applies to a requester.
type RequesterClass uint8

// The requester classes.
const (
	RequesterIAM       = RequesterClass(classIAM)       // user, root, role session, federated-user session
	RequesterService   = RequesterClass(classService)   // service principal
	RequesterAnonymous = RequesterClass(classAnonymous) // unsigned request
	RequesterProvider  = RequesterClass(classProvider)  // OIDC or SAML provider calling AssumeRoleWith*
)

// ResolveRequester returns the principal Evaluate answers for when it is given
// arn and no SessionSpec: a role ARN stands for a session with no session
// policy, and a session takes its missing facts from its entity.
func ResolveRequester(snap *model.Snapshot, arn string) (*model.Principal, RequesterClass, error) {
	p, class, err := resolvePrincipal(snap, arn)
	if err != nil {
		return nil, 0, err
	}
	return effectivePrincipal(snap, p, nil), RequesterClass(class), nil
}

// ResourceFacts is what the engine derives from a resource ARN and the snapshot.
type ResourceFacts struct {
	None         bool   // "" or "*": an action without resource-level permissions
	Account      string // owning account ("" when unknown)
	AccountKnown bool
	Type, Region string
	Tags         map[string]string
	// PolicyKeys are the resource ARNs whose resource policies apply (the
	// resource itself, and for an S3 object its bucket).
	PolicyKeys []string
}

// ResolveResource is the engine's resolve_resource (§7.2).
func ResolveResource(snap *model.Snapshot, arn string) ResourceFacts {
	r := resolveResource(snap, arn)
	return ResourceFacts{None: r.none, Account: r.account, AccountKnown: r.accountKnown, Type: r.typ,
		Region: r.region, Tags: r.tags, PolicyKeys: r.policyKeys}
}

// S3Resource splits an S3 ARN into its bucket ARN and whether it names an object.
func S3Resource(arn string) (bucketARN string, isObject, ok bool) { return s3Resource(arn) }

// SCPApplies reports whether SCPs gate requests of p (§7.5).
func SCPApplies(snap *model.Snapshot, p *model.Principal, class RequesterClass) bool {
	return snap.Org != nil && scpGate(snap.Org, principalClass(class), p) == ""
}

// RCPApplies reports whether RCPs of the organization can gate a request for a
// resource owned by account: the action-independent part of §7.5. The engine
// also skips RCPs for kms:RetireGrant and for services outside the RCP list
// (the latter evaluates them only for the alternative reading A14), so a
// caller that groups by this must treat those two cases as "may apply".
func RCPApplies(org *model.Organization, account string, serviceLinked bool) bool {
	return org != nil && org.RCPEnabled && org.PathTo(account) != nil &&
		account != org.ManagementAccountID && !serviceLinked
}

// SpecialAction reports whether the engine treats the action (lower-cased) by
// name, not only through the policies and catalog: the trust-policy actions,
// kms:RetireGrant and the S3 actions whose PUT-time rules need the request.
func SpecialAction(lower string) bool {
	switch lower {
	case "kms:retiregrant", "s3:putobject", "s3:putbucketpolicy", "s3:putbucketacl", "s3:putobjectacl":
		return true
	}
	return trustActions[lower]
}

// scpGate returns why SCPs do not apply to the requester, or "" when they do.
// org must not be nil.
func scpGate(org *model.Organization, class principalClass, p *model.Principal) string {
	switch {
	case !org.SCPEnabled:
		return "SCPs are not enabled in the organization"
	case class != classIAM:
		return "SCPs do not apply to service principals, anonymous callers or federation providers"
	case org.PathTo(p.AccountID) == nil:
		return "the principal's account is outside the organization, so its SCPs do not apply"
	case p.AccountID == org.ManagementAccountID:
		return "SCPs do not apply to the management account"
	case p.IsServiceLinked:
		return "SCPs do not apply to service-linked roles"
	}
	return ""
}
