package tfplan

import (
	"slices"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// Estate is what the mapping knows about the AWS estate a plan is applied to: the snapshot, indexed by the names a
// Terraform resource uses (a role's name, a bucket's name, an organization policy's id). It only reads the snapshot.
type Estate struct {
	snap      *model.Snapshot
	byName    map[string]map[string][]string // "user" | "role" | "group" -> name -> ARNs, sorted
	managed   map[string]bool                // source ARNs of identity and boundary documents
	inline    map[string]bool                // "<entity ARN>#inline/<name>" sources
	accounts  []string
	partition string
}

// NewEstate indexes a snapshot. A nil snapshot is an estate with nothing in it.
func NewEstate(snap *model.Snapshot) *Estate {
	e := &Estate{snap: snap, byName: map[string]map[string][]string{"user": {}, "role": {}, "group": {}},
		managed: map[string]bool{}, inline: map[string]bool{}, partition: "aws"}
	if snap == nil {
		return e
	}
	accts, parts := map[string]bool{}, map[string]bool{}
	for _, p := range snap.Principals {
		kind, name, ok := entityOf(p.ARN)
		if ok && (p.Kind == model.IAMUser || p.Kind == model.IAMRole) {
			e.add(kind, name, p.ARN)
			if p.AccountID != "" {
				accts[p.AccountID] = true
			}
			parts[partitionOf(p.ARN)] = true
		}
		for _, g := range p.GroupARNs {
			if k, n, ok := entityOf(g); ok && k == "group" {
				e.add("group", n, g)
			}
		}
	}
	for _, d := range snap.Policies {
		switch {
		case d.Kind == model.PolicyIdentity && strings.Contains(d.SourceARN, "#inline/"):
			e.inline[d.SourceARN] = true
		case d.Kind == model.PolicyIdentity || d.Kind == model.PolicyBoundary:
			e.managed[d.SourceARN] = true
		}
	}
	for p := range parts {
		if e.partition == "aws" || p < e.partition {
			e.partition = p
		}
	}
	for a := range accts {
		e.accounts = append(e.accounts, a)
	}
	sort.Strings(e.accounts)
	return e
}

func (e *Estate) add(kind, name, arn string) {
	if !slices.Contains(e.byName[kind][name], arn) {
		e.byName[kind][name] = append(e.byName[kind][name], arn)
		sort.Strings(e.byName[kind][name])
	}
}

// entityOf splits an IAM entity ARN into its kind (user, role, group) and name (the last path segment).
func entityOf(arn string) (kind, name string, ok bool) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" {
		return "", "", false
	}
	k, rest, found := strings.Cut(parts[5], "/")
	if !found || (k != "user" && k != "role" && k != "group") {
		return "", "", false
	}
	return k, rest[strings.LastIndexByte(rest, '/')+1:], true
}

func accountOf(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

func partitionOf(arn string) string {
	parts := strings.SplitN(arn, ":", 3)
	if len(parts) < 3 || parts[1] == "" {
		return "aws"
	}
	return parts[1]
}

// find returns the ARN of the user, role or group of a name, restricted to an account when one is given. ok is
// false and n says how many matched (0 or more than 1) when it is not exactly one.
func (e *Estate) find(kind, name, account string) (arn string, n int) {
	var hit []string
	for _, a := range e.byName[kind][name] {
		if account == "" || accountOf(a) == account {
			hit = append(hit, a)
		}
	}
	if len(hit) == 1 {
		return hit[0], 1
	}
	return "", len(hit)
}

func (e *Estate) hasPrincipal(arn string) bool {
	if e.snap == nil {
		return false
	}
	p := e.snap.Principals[arn]
	return p != nil && (p.Kind == model.IAMUser || p.Kind == model.IAMRole)
}

func (e *Estate) hasGroup(arn string) bool {
	k, n, ok := entityOf(arn)
	return ok && k == "group" && slices.Contains(e.byName["group"][n], arn)
}

func (e *Estate) principal(arn string) *model.Principal {
	if e.snap == nil {
		return nil
	}
	return e.snap.Principals[arn]
}

// hasOrgPolicy reports whether the snapshot holds an SCP or RCP with this ARN.
func (e *Estate) hasOrgPolicy(kind model.PolicyKind, arn string) bool {
	if e.snap == nil {
		return false
	}
	for _, d := range e.snap.Policies {
		if d.Kind == kind && d.SourceARN == arn {
			return true
		}
	}
	return false
}

func (e *Estate) hasManaged(arn string) bool { return e.managed[arn] }

func (e *Estate) hasInline(target, name string) bool { return e.inline[target+"#inline/"+name] }

// docSource is the source of a policy document by id.
func (e *Estate) docSource(id string) string {
	if d := e.snap.Policies[id]; d != nil {
		return d.SourceARN
	}
	return ""
}

// attached reports whether the managed policy is attached to the user or role, or to a group through its members.
func (e *Estate) attached(target, policyARN string) bool {
	if e.snap == nil {
		return false
	}
	if p := e.snap.Principals[target]; p != nil {
		for _, id := range p.IdentityPolicyIDs {
			if e.docSource(id) == policyARN {
				return true
			}
		}
		return false
	}
	_, name, ok := entityOf(target)
	if !ok {
		return false
	}
	via := "group/" + name
	for _, a := range e.snap.Attachments {
		if a.AttachmentType == model.AttachManaged && slices.Contains(a.Via, via) && e.docSource(a.PolicyID) == policyARN {
			return true
		}
	}
	return false
}

func (e *Estate) hasResource(arn string) bool {
	return e.snap != nil && e.snap.Resources[arn] != nil
}

// hasResourcePolicy reports whether a resource has a resource-based policy (not a trust policy).
func (e *Estate) hasResourcePolicy(arn string) bool {
	if e.snap == nil {
		return false
	}
	for _, rp := range e.snap.ResourcePolicies[arn] {
		if rp.Kind != model.PolicyTrust {
			return true
		}
	}
	return false
}

// orgEnabled reports whether the organization exists and has the policy type enabled.
func (e *Estate) orgEnabled(kind model.PolicyKind) bool {
	if e.snap == nil || e.snap.Org == nil {
		return false
	}
	if kind == model.PolicyRCP {
		return e.snap.Org.RCPEnabled
	}
	return e.snap.Org.SCPEnabled
}

func (e *Estate) orgNode(id string) *model.OrgNode {
	if e.snap == nil || e.snap.Org == nil {
		return nil
	}
	return e.snap.Org.Nodes[id]
}

// orgPolicyByID finds the SCP or RCP whose ARN ends in the policy id (p-...), with its kind.
func (e *Estate) orgPolicyByID(id string) (model.PolicyKind, string, bool) {
	if e.snap == nil || id == "" {
		return 0, "", false
	}
	var best *model.PolicyDoc
	for _, d := range e.snap.Policies {
		if (d.Kind == model.PolicySCP || d.Kind == model.PolicyRCP) && strings.HasSuffix(d.SourceARN, "/"+id) {
			if best == nil || d.SourceARN < best.SourceARN || (d.SourceARN == best.SourceARN && d.Kind < best.Kind) {
				best = d
			}
		}
	}
	if best == nil {
		return 0, "", false
	}
	return best.Kind, best.SourceARN, true
}

// orgAttached reports whether an SCP or RCP is attached at a node.
func (e *Estate) orgAttached(kind model.PolicyKind, nodeID, policyARN string) bool {
	n := e.orgNode(nodeID)
	if n == nil {
		return false
	}
	ids := n.SCPIDs
	if kind == model.PolicyRCP {
		ids = n.RCPIDs
	}
	for _, id := range ids {
		if e.docSource(id) == policyARN {
			return true
		}
	}
	return false
}
