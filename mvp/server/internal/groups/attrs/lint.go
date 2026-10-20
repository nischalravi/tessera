package attrs

import (
	"fmt"
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Lint rules (design §10.9: object types "drive UI badges and lint warnings, for
// example 'policy group has 312 direct members'"). The rules are a closed list:
// each reads the object types and a few counts, and only warns. They change
// nothing and need no code from a tenant (K6).

// Rule names.
const (
	RulePolicyDirectMembers = "policy_direct_members"
	RuleBundleDirectMembers = "bundle_direct_members"
	RuleMissingDataOwner    = "missing_data_owner"
	RuleServiceNoPolicy     = "service_without_policy_groups"
)

// Severities of a finding.
const (
	SeverityWarning = "warning"
	SeverityInfo    = "info"
)

// PolicyDirectMax is the number of direct identity members above which a policy
// group is flagged: a policy group's members should come from other groups or
// attributes, not from a list kept by hand.
const PolicyDirectMax = 10

// Finding is one lint result.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// LintGroup applies the group rules to a group, by its object types.
func LintGroup(tx *store.TenantTx, g *store.NativeGroup) ([]Finding, error) {
	types, err := ObjectTypesOf(tx, Owner{store.AttrOwnerGroup, string(g.ID)})
	if err != nil || len(types) == 0 {
		return nil, err
	}
	direct, err := tx.GrpDirectCount(store.GrpDirectFilter{Group: g.ID, MemberType: store.MemberIdentity})
	if err != nil {
		return nil, err
	}
	var out []Finding
	if slices.Contains(types, TypePolicy) && direct > PolicyDirectMax {
		out = append(out, Finding{RulePolicyDirectMembers, SeverityWarning,
			fmt.Sprintf("policy group has %d direct members; build it from other groups or attributes (more than %d is flagged)", direct, PolicyDirectMax)})
	}
	if slices.Contains(types, TypeBundle) && direct > 0 {
		out = append(out, Finding{RuleBundleDirectMembers, SeverityWarning,
			fmt.Sprintf("bundle group has %d direct identity members; a bundle holds only other groups", direct)})
	}
	if (slices.Contains(types, "ref") || slices.Contains(types, "basis") || slices.Contains(types, TypePolicy)) &&
		(g.DataOwner == nil || *g.DataOwner == "") {
		out = append(out, Finding{RuleMissingDataOwner, SeverityInfo, "the group has no data owner"})
	}
	return out, nil
}

// LintFolder applies the folder rules to a folder, by its object types.
func LintFolder(tx *store.TenantTx, f *store.Folder) ([]Finding, error) {
	types, err := ObjectTypesOf(tx, Owner{store.AttrOwnerFolder, string(f.ID)})
	if err != nil || !slices.Contains(types, TypeService) {
		return nil, err
	}
	policy, err := PolicyGroupsBelow(tx, f)
	if err != nil {
		return nil, err
	}
	if len(policy) == 0 {
		return []Finding{{RuleServiceNoPolicy, SeverityWarning, "service folder holds no policy group, so no one can be granted the service"}}, nil
	}
	return nil, nil
}
