package awsorg

import (
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The fail-closed contract of design §3.3, enforced at ingest.
//
// A stored policy that fails to parse, a statement dropped as an ingest
// anomaly, and a read that fails are never skipped silently: skipping a Deny
// or a resource policy can turn a denial into a confident Allow. Each becomes
// a Finding that names what it covers (Scope). Findings.Unsupported answers,
// for a request, which findings could change its decision; the evaluator
// returns such a decision as best effort with fidelity UNSUPPORTED and reason
// POLICY_UNPARSEABLE (authz.ReasonPolicyUnparseable), whose detail names the
// policy and the error.

// ScopeType says which requests a Finding could affect.
type ScopeType string

const (
	// ScopeResources: requests on these resource ARNs (a resource, trust, key,
	// access point or endpoint policy). An S3 bucket also covers its objects.
	ScopeResources ScopeType = "resources"
	// ScopeResourcePrefix: requests on resources whose ARN starts with one of
	// the targets (a list call that failed: every resource of that service in
	// that account and region is unknown).
	ScopeResourcePrefix ScopeType = "resource_prefix"
	// ScopePrincipals: requests by these IAM users and roles, and by sessions
	// of these roles (an identity or boundary policy, with the principals it
	// is attached to, groups expanded).
	ScopePrincipals ScopeType = "principals"
	// ScopeRequesterAccounts: requests by principals of these accounts (an SCP,
	// with the accounts under every node it is attached to).
	ScopeRequesterAccounts ScopeType = "requester_accounts"
	// ScopeResourceAccounts: requests on resources of these accounts (an RCP).
	ScopeResourceAccounts ScopeType = "resource_accounts"
	// ScopeAccounts: any request by a principal of, or on a resource of, these
	// accounts (an account that could not be read).
	ScopeAccounts ScopeType = "accounts"
)

// Scope is a ScopeType and its targets (ARNs or account ids), sorted.
type Scope struct {
	Type    ScopeType `json:"type"`
	Targets []string  `json:"targets"`
}

// Finding is something collection could not take at face value.
type Finding struct {
	Kind       string `json:"kind"`        // store.AWSFinding*
	SourceARN  string `json:"source_arn"`  // the policy's source ARN, or the resource or account that could not be read
	PolicyKind string `json:"policy_kind"` // model.PolicyKind name, "" for a read that failed outside a policy
	Code       string `json:"code"`        // parse error code, anomaly code, or AWS error code
	Detail     string `json:"detail"`
	Scope      Scope  `json:"scope"`
}

// Findings is a snapshot's findings.
type Findings []Finding

// Request names the facts of a request that decide which findings can affect
// it. Accounts are 12-digit ids ("" when unknown, which is conservative: an
// unknown account matches every account-scoped finding).
type Request struct {
	PrincipalARN     string
	PrincipalAccount string
	ResourceARN      string
	ResourceAccount  string
}

// Unsupported returns one FidelityReason (code POLICY_UNPARSEABLE) per finding
// that could change the decision of r. It is empty when no finding applies.
// Every reason is outcome-sensitive: a policy that is not read could hold the
// Deny or the Allow that settles the request.
func (fs Findings) Unsupported(r Request) []authz.FidelityReason {
	var out []authz.FidelityReason
	for _, f := range fs {
		if f.Scope.affects(r) {
			out = append(out, authz.FidelityReason{Code: authz.ReasonPolicyUnparseable, OutcomeSensitive: true,
				Detail: f.SourceARN + ": " + f.Code + ": " + f.Detail})
		}
	}
	return out
}

func (s Scope) affects(r Request) bool {
	switch s.Type {
	case ScopeResources:
		for _, t := range s.Targets {
			if resourceCovered(t, r.ResourceARN) {
				return true
			}
		}
	case ScopeResourcePrefix:
		return r.ResourceARN != "" && slices.ContainsFunc(s.Targets, func(t string) bool { return strings.HasPrefix(r.ResourceARN, t) })
	case ScopePrincipals:
		k := entityKey(r.PrincipalARN)
		return k != "" && slices.ContainsFunc(s.Targets, func(t string) bool { return entityKey(t) == k })
	case ScopeRequesterAccounts:
		return accountMatches(s.Targets, r.PrincipalAccount)
	case ScopeResourceAccounts:
		return accountMatches(s.Targets, r.ResourceAccount)
	case ScopeAccounts:
		return accountMatches(s.Targets, r.PrincipalAccount) || accountMatches(s.Targets, r.ResourceAccount)
	}
	return false
}

func accountMatches(targets []string, account string) bool {
	if account == "" {
		return len(targets) > 0
	}
	return slices.Contains(targets, account)
}

// resourceCovered reports whether a request on arn is governed by the policy
// of resource target: the resource itself, and for an S3 bucket its objects.
func resourceCovered(target, arn string) bool {
	if target == "" || arn == "" {
		return false
	}
	return arn == target || (strings.HasPrefix(target, "arn:aws:s3:::") && !strings.Contains(target[len("arn:aws:s3:::"):], "/") &&
		strings.HasPrefix(arn, target+"/"))
}

// entityKey identifies the IAM user or role a principal ARN names, as
// "kind:account:name", and the role behind a session ARN. "" if it names
// neither (a service principal, an account root, an anonymous request).
func entityKey(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return ""
	}
	account, res := parts[4], parts[5]
	switch {
	case parts[2] == "iam" && strings.HasPrefix(res, "role/"):
		return "role:" + account + ":" + res[strings.LastIndex(res, "/")+1:]
	case parts[2] == "iam" && strings.HasPrefix(res, "user/"):
		return "user:" + account + ":" + res[strings.LastIndex(res, "/")+1:]
	case parts[2] == "sts" && strings.HasPrefix(res, "assumed-role/"):
		segs := strings.Split(res, "/")
		if len(segs) >= 2 {
			return "role:" + account + ":" + segs[1]
		}
	}
	return ""
}

// storeFindings converts findings to rows of snapshotID.
func (fs Findings) storeRows(snapshotID string) ([]*store.AWSFinding, error) {
	out := make([]*store.AWSFinding, 0, len(fs))
	for _, f := range fs {
		sc, err := jsonMarshal(f.Scope)
		if err != nil {
			return nil, err
		}
		out = append(out, &store.AWSFinding{SnapshotID: snapshotID, Kind: f.Kind, SourceARN: f.SourceARN, PolicyKind: f.PolicyKind,
			Code: f.Code, Detail: f.Detail, Scope: sc})
	}
	return out, nil
}
