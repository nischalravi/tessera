package awsorg

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

const awsManagedPrefix = "arn:aws:iam::aws:policy/"

type groupPolicy struct {
	ref polRef
	typ model.AttachmentType
}

// addIAM maps one account's GetAccountAuthorizationDetails to principals,
// policy documents, attachments, trust policies and resources.
func (b *builder) addIAM(account string, d *authDetails) {
	managed := make(map[string]*xmlManagedPolicy, len(d.Policies))
	for i := range d.Policies {
		managed[d.Policies[i].ARN] = &d.Policies[i]
	}

	// group policies are parsed once and attached to each member
	groups := map[string][]groupPolicy{}
	groupARN := map[string]string{}
	for _, g := range d.Groups {
		groupARN[g.GroupName] = g.ARN
		groups[g.GroupName] = b.entityPolicies(g.ARN, g.Inline, g.Attached, managed)
	}

	for _, u := range d.Users {
		p := &model.Principal{ARN: u.ARN, Kind: model.IAMUser, AccountID: account, UniqueID: u.UserID, Path: pathOrRoot(u.Path), CreateDate: createDate(u.CreateDate),
			Tags: tagMap(u.Tags)}
		b.snap.Principals[p.ARN] = p
		b.snap.Resources[p.ARN] = &model.Resource{ARN: p.ARN, Type: "user", AccountID: account}
		for _, ref := range b.entityPolicies(u.ARN, u.Inline, u.Attached, managed) {
			b.attach(ref.ref, p, ref.typ, nil)
		}
		for _, name := range sortedStrings(u.Groups) {
			if arn, ok := groupARN[name]; ok {
				p.GroupARNs = append(p.GroupARNs, arn)
			}
			for _, ref := range groups[name] {
				b.attach(ref.ref, p, ref.typ, []string{"group/" + name})
			}
		}
		b.boundary(p, u.BoundaryAR, managed)
	}

	for _, r := range d.Roles {
		p := &model.Principal{ARN: r.ARN, Kind: model.IAMRole, AccountID: account, UniqueID: r.RoleID, Path: pathOrRoot(r.Path), CreateDate: createDate(r.CreateDate),
			IsServiceLinked: strings.HasPrefix(r.Path, "/aws-service-role/"), Tags: tagMap(r.Tags)}
		b.snap.Principals[p.ARN] = p
		b.snap.Resources[p.ARN] = &model.Resource{ARN: p.ARN, Type: "role", AccountID: account}
		for _, ref := range b.entityPolicies(r.ARN, r.Inline, r.Attached, managed) {
			b.attach(ref.ref, p, ref.typ, nil)
		}
		b.boundary(p, r.BoundaryAR, managed)
		b.trust(account, r)
	}
}

// entityPolicies parses an entity's inline and attached managed policies, in a
// fixed order (inline by name, then managed by ARN). A parse failure is a
// finding with an empty target list; attach fills it in as principals are found.
func (b *builder) entityPolicies(entityARN string, inline []xmlInline, attached []xmlAttached, managed map[string]*xmlManagedPolicy) []groupPolicy {
	var out []groupPolicy
	in := slices.Clone(inline)
	sort.Slice(in, func(i, j int) bool { return in[i].PolicyName < in[j].PolicyName })
	for _, p := range in {
		src := entityARN + "#inline/" + p.PolicyName
		raw, err := decodeIAMDocument(p.PolicyDocument)
		if err != nil {
			i := b.addFinding(Finding{Kind: store.AWSFindingPolicyUnparseable, SourceARN: src, PolicyKind: model.PolicyIdentity.String(),
				Code: "bad_encoding", Detail: errDetail(err), Scope: Scope{Type: ScopePrincipals}})
			out = append(out, groupPolicy{polRef{fail: i}, model.AttachInline})
			continue
		}
		out = append(out, groupPolicy{b.parseDoc(model.PolicyIdentity, src, "", raw, false, Scope{Type: ScopePrincipals}), model.AttachInline})
	}
	att := slices.Clone(attached)
	sort.Slice(att, func(i, j int) bool { return att[i].PolicyARN < att[j].PolicyARN })
	for _, a := range att {
		out = append(out, groupPolicy{b.managedRef(model.PolicyIdentity, a.PolicyARN, managed), model.AttachManaged})
	}
	return out
}

// managedRef parses a managed policy's default version for a use (identity or
// boundary), once per (policy, use).
func (b *builder) managedRef(kind model.PolicyKind, arn string, managed map[string]*xmlManagedPolicy) polRef {
	key := arn + "|" + kind.String()
	if r, ok := b.managed[key]; ok {
		return r
	}
	scope := Scope{Type: ScopePrincipals}
	var ref polRef
	mp := managed[arn]
	if mp == nil {
		// attached but not listed: its content is unknown, so it is a gap
		i := b.addFinding(Finding{Kind: store.AWSFindingAccountError, SourceARN: arn, PolicyKind: kind.String(),
			Code: "ManagedPolicyMissing", Detail: "attached managed policy is not in GetAccountAuthorizationDetails", Scope: scope})
		ref = polRef{fail: i}
	} else if v := defaultVersion(mp); v == nil {
		i := b.addFinding(Finding{Kind: store.AWSFindingPolicyUnparseable, SourceARN: arn, PolicyKind: kind.String(),
			Code: "NoDefaultVersion", Detail: "managed policy has no default version document", Scope: scope})
		ref = polRef{fail: i}
	} else if raw, err := decodeIAMDocument(v.Document); err != nil {
		i := b.addFinding(Finding{Kind: store.AWSFindingPolicyUnparseable, SourceARN: arn, PolicyKind: kind.String(),
			Code: "bad_encoding", Detail: errDetail(err), Scope: scope})
		ref = polRef{fail: i}
	} else {
		ref = b.parseDoc(kind, arn, v.VersionID, raw, strings.HasPrefix(arn, awsManagedPrefix), scope)
	}
	b.managed[key] = ref
	return ref
}

func defaultVersion(mp *xmlManagedPolicy) *xmlPolicyVersion {
	for i := range mp.Versions {
		if mp.Versions[i].IsDefault || (mp.DefaultVer != "" && mp.Versions[i].VersionID == mp.DefaultVer) {
			return &mp.Versions[i]
		}
	}
	return nil
}

// boundary attaches an entity's permissions boundary.
func (b *builder) boundary(p *model.Principal, arn string, managed map[string]*xmlManagedPolicy) {
	if arn == "" {
		return
	}
	ref := b.managedRef(model.PolicyBoundary, arn, managed)
	b.addTargets(ref, p.ARN)
	if !ref.ok() {
		return
	}
	p.BoundaryPolicyID = ref.id
	b.snap.Attachments = append(b.snap.Attachments, model.PolicyAttachment{PolicyID: ref.id, TargetARN: p.ARN, AttachmentType: model.AttachBoundary})
}

// trust parses a role's trust policy as the role's resource policy.
func (b *builder) trust(account string, r xmlRole) {
	src := r.ARN + "#trust"
	scope := Scope{Type: ScopeResources, Targets: []string{r.ARN}}
	raw, err := decodeIAMDocument(r.Trust)
	if err != nil {
		b.addFinding(Finding{Kind: store.AWSFindingPolicyUnparseable, SourceARN: src, PolicyKind: model.PolicyTrust.String(),
			Code: "bad_encoding", Detail: errDetail(err), Scope: scope})
		return
	}
	ref := b.parseDoc(model.PolicyTrust, src, "", raw, false, scope)
	if !ref.ok() {
		return
	}
	b.snap.ResourcePolicies[r.ARN] = append(b.snap.ResourcePolicies[r.ARN],
		model.ResourcePolicy{ResourceARN: r.ARN, Kind: model.PolicyTrust, PolicyID: ref.id, RequiresExplicitAllow: true})
	b.snap.Attachments = append(b.snap.Attachments, model.PolicyAttachment{PolicyID: ref.id, TargetARN: r.ARN, AttachmentType: model.AttachTrust})
}

// createDate normalizes an IAM CreateDate to RFC 3339 UTC; "" when absent or
// unreadable (the confidence model then caps at medium).
func createDate(s string) string {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func pathOrRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func tagMap(ts []xmlTag) map[string]string {
	if len(ts) == 0 {
		return nil
	}
	m := make(map[string]string, len(ts))
	for _, t := range ts {
		m[t.Key] = t.Value
	}
	return m
}

func sortedStrings(s []string) []string {
	out := slices.Clone(s)
	sort.Strings(out)
	return out
}
