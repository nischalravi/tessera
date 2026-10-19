package eval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// principalClass says which grant rule of §7.2 step 4 applies to the requester.
type principalClass uint8

const (
	classIAM       principalClass = iota // user, root, role session, federated-user session
	classService                         // service principal (§7.8)
	classAnonymous                       // unsigned request (§7.8)
	classProvider                        // an OIDC or SAML provider calling AssumeRoleWith* (§7.4.1)
)

const serviceLinkedPath = "/aws-service-role/"

// splitARN splits an ARN into at most six parts; ok is false when it has fewer.
func splitARN(arn string) (parts [6]string, ok bool) {
	rest := arn
	for i := 0; i < 5; i++ {
		seg, next, found := strings.Cut(rest, ":")
		if !found {
			return parts, false
		}
		parts[i], rest = seg, next
	}
	parts[5] = rest
	return parts, parts[0] == "arn"
}

// resolvePrincipal implements §7.3. It returns the requester as the snapshot
// knows it; effectivePrincipal then merges a session with its entity.
func resolvePrincipal(snap *model.Snapshot, arn string) (*model.Principal, principalClass, error) {
	switch {
	case arn == "":
		return nil, 0, fmt.Errorf("%w: empty principal", ErrInvalidRequest)
	case arn == "*" || arn == "anonymous":
		return &model.Principal{ARN: "*", Kind: model.Anonymous}, classAnonymous, nil
	case !strings.HasPrefix(arn, "arn:") && strings.HasSuffix(arn, ".amazonaws.com"):
		return &model.Principal{ARN: arn, Kind: model.Service}, classService, nil
	}
	parts, ok := splitARN(arn)
	if !ok {
		return nil, 0, fmt.Errorf("%w: principal %q is not an ARN, a service name or \"*\"", ErrInvalidRequest, clip(arn))
	}
	account, res := parts[4], parts[5]
	if known := snap.Principals[arn]; known != nil {
		switch known.Kind {
		case model.IAMRole:
			return sessionTemplate(known), classIAM, nil
		case model.Service:
			return known, classService, nil
		case model.Anonymous:
			return known, classAnonymous, nil
		}
		return known, classIAM, nil
	}
	switch parts[2] {
	case "iam":
		switch {
		case res == "root":
			return &model.Principal{ARN: arn, Kind: model.Root, AccountID: account, UniqueID: account}, classIAM, nil
		case strings.HasPrefix(res, "oidc-provider/") || strings.HasPrefix(res, "saml-provider/"):
			return &model.Principal{ARN: arn, Kind: model.Anonymous, AccountID: account, FederatedProvider: arn}, classProvider, nil
		}
	case "sts":
		if name, ok := strings.CutPrefix(res, "assumed-role/"); ok {
			role, _, _ := strings.Cut(name, "/")
			if ent := findRole(snap, account, role); ent != nil {
				return &model.Principal{ARN: arn, Kind: model.RoleSession, AccountID: account, EntityARN: ent.ARN}, classIAM, nil
			}
		}
	}
	return nil, 0, fmt.Errorf("%w: %s", ErrUnknownPrincipal, clip(arn))
}

// sessionTemplate synthesizes "arn:aws:sts::A:assumed-role/R/*" for a role ARN:
// a session with no session policy (§7.3).
func sessionTemplate(role *model.Principal) *model.Principal {
	parts, _ := splitARN(role.ARN)
	name := role.ARN
	if i := strings.LastIndex(parts[5], "/"); i >= 0 {
		name = parts[5][i+1:]
	}
	return &model.Principal{
		ARN:       "arn:" + parts[1] + ":sts::" + role.AccountID + ":assumed-role/" + name + "/*",
		Kind:      model.RoleSession,
		AccountID: role.AccountID,
		EntityARN: role.ARN,
	}
}

// findRole finds the role named name in account, whatever its path. When
// several share the name (different paths) the lowest ARN wins; AWS forbids it.
func findRole(snap *model.Snapshot, account, name string) *model.Principal {
	var best *model.Principal
	for _, p := range snap.Principals {
		if p == nil || p.Kind != model.IAMRole || p.AccountID != account {
			continue
		}
		parts, ok := splitARN(p.ARN)
		if !ok || !strings.HasPrefix(parts[5], "role/") {
			continue
		}
		if parts[5][strings.LastIndex(parts[5], "/")+1:] != name {
			continue
		}
		if best == nil || p.ARN < best.ARN {
			best = p
		}
	}
	return best
}

// effectivePrincipal returns a copy of p with a session's missing facts taken
// from its entity: identity policies, boundary, path, tags (session tags
// overlay entity tags), unique id. The snapshot is never written.
func effectivePrincipal(snap *model.Snapshot, p *model.Principal, spec *SessionSpec) *model.Principal {
	q := *p
	q.Tags = map[string]string{}
	if p.Kind == model.RoleSession || p.Kind == model.FederatedUserSession {
		if ent := snap.Principals[p.EntityARN]; ent != nil {
			for k, v := range ent.Tags {
				q.Tags[k] = v
			}
			if len(q.IdentityPolicyIDs) == 0 {
				q.IdentityPolicyIDs = ent.IdentityPolicyIDs
			}
			if q.BoundaryPolicyID == "" {
				q.BoundaryPolicyID = ent.BoundaryPolicyID
			}
			if q.UniqueID == "" {
				q.UniqueID = ent.UniqueID
			}
			if q.Path == "" {
				q.Path = ent.Path
			}
			q.IsServiceLinked = q.IsServiceLinked || ent.IsServiceLinked
			if len(q.GroupARNs) == 0 {
				q.GroupARNs = ent.GroupARNs
			}
		}
		q.IsServiceLinked = q.IsServiceLinked || strings.HasPrefix(q.Path, serviceLinkedPath)
	}
	for k, v := range p.Tags {
		q.Tags[k] = v
	}
	if spec != nil {
		if spec.PolicyIDs != nil {
			q.SessionPolicyIDs = spec.PolicyIDs
		}
		if spec.Tags != nil {
			q.SessionTags = spec.Tags
		}
		if spec.SourceIdentity != "" {
			q.SourceIdentity = spec.SourceIdentity
		}
	}
	return &q
}

// resolvedResource is what the engine knows about the request's resource.
type resolvedResource struct {
	arn          string // "" when the action has no resource
	none         bool
	account      string
	accountKnown bool
	typ          string
	region       string
	tags         map[string]string
	policyKeys   []string // resource ARNs whose resource policies apply
}

// resolveResource implements resolve_resource of §7.2: the owning account,
// where an S3 object belongs to its bucket's owner, and the ARNs whose
// resource policies apply.
func resolveResource(snap *model.Snapshot, arn string) resolvedResource {
	if arn == "" || arn == "*" {
		return resolvedResource{none: true}
	}
	r := resolvedResource{arn: arn, policyKeys: []string{arn}}
	parts, ok := splitARN(arn)
	if info := snap.Resources[arn]; info != nil {
		r.account, r.typ, r.region, r.tags = info.AccountID, info.Type, info.Region, info.Tags
	}
	if ok {
		if r.account == "" {
			r.account = parts[4]
		}
		if r.region == "" {
			r.region = parts[3]
		}
		if parts[2] == "s3" {
			bucket := "arn:" + parts[1] + ":s3:::" + strings.SplitN(parts[5], "/", 2)[0]
			if bucket != arn {
				r.policyKeys = append(r.policyKeys, bucket)
			}
			if st := snap.S3[bucket]; st != nil && st.OwnerAccount != "" {
				r.account = st.OwnerAccount
			} else if info := snap.Resources[bucket]; info != nil && r.account == "" {
				r.account = info.AccountID
			}
		}
	}
	r.accountKnown = r.account != ""
	return r
}

// orgFacts returns the organization id and the aws:*OrgPaths value of an
// account ("o-x/r-1/ou-a/"); "" when the account is not in the organization.
func orgFacts(org *model.Organization, account string) (orgID string, paths []string) {
	nodes := org.PathTo(account)
	if len(nodes) == 0 {
		return "", nil
	}
	var b strings.Builder
	b.WriteString(org.OrgID + "/")
	for _, n := range nodes[:len(nodes)-1] {
		b.WriteString(n.ID + "/")
	}
	return org.OrgID, []string{b.String()}
}

// sortedPolicyIDs returns ids ordered by the document's source ARN, then id, so
// statement order does not depend on how the snapshot was assembled. Duplicates
// are dropped.
func sortedPolicyIDs(snap *model.Snapshot, ids []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := snap.Policies[out[i]], snap.Policies[out[j]]
		var sa, sb string
		if a != nil {
			sa = a.SourceARN
		}
		if b != nil {
			sb = b.SourceARN
		}
		if sa != sb {
			return sa < sb
		}
		return out[i] < out[j]
	})
	return out
}
