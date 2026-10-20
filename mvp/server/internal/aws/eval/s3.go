package eval

import (
	"net/netip"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

// This file is the S3 part of §7.6.2: ACL grants by Object Ownership mode,
// effective Block Public Access, policy_is_public, the RestrictPublicBuckets
// gate, the PUT-time BPA checks and the object context.

const (
	aclAllUsers           = "AllUsers"
	aclAuthenticatedUsers = "AuthenticatedUsers"
	ownershipEnforced     = "BucketOwnerEnforced"

	// requestedPolicyKey carries the policy document of an s3:PutBucketPolicy
	// request, for the BlockPublicPolicy check.
	requestedPolicyKey = "tessera:requestedpolicy"
)

// publicCannedACLs are the canned ACLs that grant to a public group.
var publicCannedACLs = []string{"public-read", "public-read-write", "authenticated-read"}

// aclGrantHeaders are the request keys that carry ACL grants.
var aclGrantHeaders = []string{
	"s3:x-amz-grant-read", "s3:x-amz-grant-write", "s3:x-amz-grant-read-acp",
	"s3:x-amz-grant-write-acp", "s3:x-amz-grant-full-control",
}

// effectiveBPA is the most restrictive of the org, account and bucket
// settings (A16): a setting is on if it is on at any level.
func effectiveBPA(st *model.S3BucketState) model.BPA {
	if st == nil {
		return model.BPA{}
	}
	b := model.BPA{
		BlockPublicAcls:       st.BPAAccount.BlockPublicAcls || st.BPABucket.BlockPublicAcls,
		IgnorePublicAcls:      st.BPAAccount.IgnorePublicAcls || st.BPABucket.IgnorePublicAcls,
		BlockPublicPolicy:     st.BPAAccount.BlockPublicPolicy || st.BPABucket.BlockPublicPolicy,
		RestrictPublicBuckets: st.BPAAccount.RestrictPublicBuckets || st.BPABucket.RestrictPublicBuckets,
	}
	if st.BPAOrg != nil && *st.BPAOrg {
		b = model.BPA{BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true}
	}
	return b
}

// s3Resource splits an S3 bucket or object ARN. ok is false for any other ARN,
// including access point ARNs (they carry a region).
func s3Resource(arn string) (bucketARN string, isObject, ok bool) {
	parts, good := splitARN(arn)
	if !good || parts[2] != "s3" || parts[3] != "" || parts[4] != "" {
		return "", false, false
	}
	name, key, found := strings.Cut(parts[5], "/")
	if name == "" {
		return "", false, false
	}
	return "arn:" + parts[1] + ":s3:::" + name, found && key != "", true
}

// PolicyIsPublic is S3's "meaning of public" (§7.6.2; Bouchet et al. 2020): a
// policy is public if some Allow statement names "*" as principal and its
// conditions do not pin the caller. A condition pins it only if it is a
// positive, non-IfExists operator (not ForAllValues) on a key of the catalog's
// fixed-key list, with only fixed values. bucketPolicy is false for an access
// point policy, where the keys marked bucket-policies-only do not count.
// Actions are not looked at: S3 treats an unknown action as public too.
func PolicyIsPublic(doc *model.PolicyDoc, cat Catalog, bucketPolicy bool) bool {
	if doc == nil {
		return false
	}
	for i := range doc.Statements {
		st := &doc.Statements[i]
		if st.Effect != model.EffectAllow || !st.Principals.HasWildcard() {
			continue
		}
		pinned := false
		for _, a := range st.Condition {
			if atomPins(a, cat, bucketPolicy) {
				pinned = true
				break
			}
		}
		if !pinned {
			return true
		}
	}
	return false
}

var pinningOps = map[string]bool{
	"StringEquals": true, "StringEqualsIgnoreCase": true, "StringLike": true, "ArnEquals": true, "ArnLike": true,
}

func atomPins(a authz.Atom, cat Catalog, bucketPolicy bool) bool {
	if a.Negated || a.IfExists || a.Qualifier == authz.ForAllValues || len(a.Values) == 0 {
		return false
	}
	rule, ok := cat.S3PublicFixedKey(asciiLower(a.Key))
	if !ok || (rule.BucketPoliciesOnly && !bucketPolicy) {
		return false
	}
	switch rule.Kind {
	case S3IPRange:
		if a.Op != "IpAddress" {
			return false
		}
		for _, v := range a.Values {
			if !ipValueIsNarrow(v, rule) {
				return false
			}
		}
		return true
	default:
		if !pinningOps[a.Op] {
			return false
		}
		for _, v := range a.Values {
			if !fixedValue(v, rule) {
				return false
			}
		}
		return true
	}
}

// fixedValue: no wildcard, no variable, and not one of the rule's exceptions.
// A rule that applies to bucket policies only (s3:DataAccessPointArn) needs the
// account segment of the ARN fixed; the rest of the ARN may use wildcards.
func fixedValue(v string, rule S3PublicKeyRule) bool {
	if v == "" || strings.Contains(v, "${") {
		return false
	}
	for _, ex := range rule.ExceptPatterns {
		if v == ex || sameShapeAsException(v, ex) {
			return false
		}
	}
	if rule.BucketPoliciesOnly {
		parts, ok := splitARN(v)
		return ok && parts[4] != "" && !strings.ContainsAny(parts[4], "*?")
	}
	return !strings.ContainsAny(v, "*?")
}

// sameShapeAsException reads an exception such as "AROLEID:*" the way the S3
// docs mean it: AROLEID stands for a role's unique id, so any "<fixed id>:*"
// (a role id with every session name) is the excepted pattern.
func sameShapeAsException(v, ex string) bool {
	idEx, ok := strings.CutSuffix(ex, ":*")
	if !ok || strings.ContainsAny(idEx, "*?") {
		return false
	}
	idV, ok := strings.CutSuffix(v, ":*")
	return ok && idV != "" && !strings.ContainsAny(idV, "*?:")
}

var rfc1918 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
}

// ipValueIsNarrow: the range is no broader than the rule's limits, or lies
// inside a private RFC 1918 range. An unparseable value never pins.
func ipValueIsNarrow(v string, rule S3PublicKeyRule) bool {
	p, ok := parseIPPolicy(v)
	if !ok {
		return false
	}
	if p.Addr().Is4() {
		for _, r := range rfc1918 {
			if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
				return true
			}
		}
		return p.Bits() >= rule.IPv4MaxCIDR
	}
	return p.Bits() >= rule.IPv6MaxCIDR
}

// s3Terms computes the S3 inputs of the grant and guardrail steps for the
// request: ACL grants, the object context and the BPA gate.
func (e *evaluator) s3Terms() {
	s := &e.spec
	s.aclPublic, s.aclAccount, s.objCtx, s.objCtxAlt, s.bpa = authz.F, authz.F, authz.T, authz.T, authz.T
	if e.prefix != "s3" || e.res.none || e.class == classProvider {
		return
	}
	bucketARN, isObj, ok := s3Resource(e.res.arn)
	if !ok {
		return
	}
	s.isS3 = true
	st := e.snap.S3[bucketARN]
	s.eff = effectiveBPA(st)
	ownership := ownershipEnforced
	if st != nil && st.ObjectOwnership != "" {
		ownership = st.ObjectOwnership
	}
	s.aclsOn = ownership != ownershipEnforced

	e.aclTerms(st, isObj)
	// s3:PutObject creates the object, so the requester will own it: there is
	// no existing owner whose grants could be required.
	if s.aclsOn && isObj && e.class != classService && asciiLower(e.action) != "s3:putobject" {
		alt := s.aclAccount.Or(s.aclPublic)
		switch owner := e.req.S3ObjectOwner; {
		case owner == "":
			s.objFlag, s.objCtxAlt = true, alt
		case owner != e.res.account:
			s.objCtx = authz.Bool(e.p.AccountID != "" && e.p.AccountID == owner).Or(alt)
			s.objCtxAlt = s.objCtx
		}
	}
	e.bpaGate()
}

// aclTerms is the ACL part of special_resource_grants (§7.6.2). The terms are
// raw: whether an ACL may grant at all (cross-account or anonymous only, §4.1
// fact 5) is decided where they are used.
func (e *evaluator) aclTerms(st *model.S3BucketState, isObj bool) {
	s := &e.spec
	if st == nil {
		return
	}
	if !s.aclsOn {
		if len(st.BucketACL) > 0 || len(st.ObjectACLs[e.res.arn]) > 0 {
			s.aclSteps = append(s.aclSteps, authz.ExplanationStep{Stage: authz.StageS3ACL, Result: authz.ResultNotApplicable,
				Note: "ACLs are disabled by Object Ownership BucketOwnerEnforced"})
		}
		return
	}
	type scoped struct {
		scope  S3ACLScope
		grants []model.ACLGrant
	}
	lists := []scoped{{S3ACLBucket, st.BucketACL}}
	if isObj {
		lists = append(lists, scoped{S3ACLObject, st.ObjectACLs[e.res.arn]})
	}
	for _, l := range lists {
		for _, g := range l.grants {
			if !e.aclGrantCovers(l.scope, g.Permission) {
				continue
			}
			e.aclGrant(g, l.scope)
		}
	}
}

func (e *evaluator) aclGrantCovers(scope S3ACLScope, perm string) bool {
	for _, a := range e.cat.S3ACLActions(scope, perm) {
		if asciiLower(a) == asciiLower(e.action) {
			return true
		}
	}
	return false
}

func (e *evaluator) aclGrant(g model.ACLGrant, scope S3ACLScope) {
	s := &e.spec
	scopeName := map[S3ACLScope]string{S3ACLBucket: "bucket", S3ACLObject: "object"}[scope]
	step := authz.ExplanationStep{Stage: authz.StageS3ACL,
		MatchedOn: map[string]string{"grantee": g.Grantee, "permission": g.Permission, "scope": scopeName}}
	switch g.GranteeType {
	case "Group":
		grp, ok := e.cat.S3ACLGroup(g.Grantee)
		if !ok || !grp.Public {
			return // LogDelivery and unknown groups grant nothing to a caller
		}
		// AllUsers covers anonymous and signed callers; AuthenticatedUsers
		// only signed ones.
		if e.class == classAnonymous && grp.Name != aclAllUsers {
			return
		}
		if e.class != classAnonymous && e.class != classIAM {
			return
		}
		if s.eff.IgnorePublicAcls {
			s.aclIgnored = true
			step.Result, step.Note = authz.ResultNotApplicable, "IgnorePublicAcls ignores the public ACL grant to "+grp.Name
		} else {
			s.aclPublic = authz.T
			step.Result, step.Note = authz.ResultAllow, "the "+scopeName+" ACL grants "+g.Permission+" to "+grp.Name
		}
	case "CanonicalUser":
		acct := e.snap.CanonicalIDs[g.Grantee]
		if acct == "" || e.p.AccountID == "" || acct != e.p.AccountID {
			return
		}
		s.aclAccount = authz.T
		step.Result, step.Note = authz.ResultAllow, "the "+scopeName+" ACL grants "+g.Permission+" to account "+acct
	default:
		return
	}
	s.aclSteps = append(s.aclSteps, step)
}

// bpaGate is s3_bpa_gate (§7.6.2): RestrictPublicBuckets and the PUT-time
// checks. It sets spec.bpa and says why in spec.bpaWhy when it is false.
func (e *evaluator) bpaGate() {
	s := &e.spec
	if s.eff.RestrictPublicBuckets {
		public := false
		for _, d := range e.rbp {
			switch d.doc.Kind {
			case model.PolicyResource:
				public = public || PolicyIsPublic(d.doc, e.cat, true)
			case model.PolicyS3AccessPoint:
				public = public || PolicyIsPublic(d.doc, e.cat, false)
			}
		}
		allowed := e.class == classService || (e.p.AccountID != "" && e.p.AccountID == e.res.account)
		if public && !allowed {
			s.bpa, s.bpaWhy = authz.F, "RestrictPublicBuckets limits a bucket with a public policy to AWS services and the bucket owner's account"
			return
		}
	}
	lower := asciiLower(e.action)
	if lower == "s3:putbucketpolicy" && s.eff.BlockPublicPolicy {
		if t := e.requestedPolicyPublic(); !t.IsFalse() {
			s.bpa, s.bpaWhy = t.Not(), "BlockPublicPolicy rejects a public bucket policy"
			return
		}
	}
	if (lower == "s3:putbucketacl" || lower == "s3:putobjectacl" || lower == "s3:putobject") && s.eff.BlockPublicAcls {
		if t := e.requestACLPublic(); !t.IsFalse() {
			s.bpa, s.bpaWhy = t.Not(), "BlockPublicAcls rejects a request that sets a public ACL"
		}
	}
}

// requestedPolicyPublic: is the policy in the request public. False when the
// request carries none.
func (e *evaluator) requestedPolicyPublic() authz.Tri {
	cv := e.ctx.Lookup(requestedPolicyKey)
	switch cv.State {
	case Unknown:
		return authz.U(authz.Atom{Op: "Bool", Key: "tessera:requestedpolicyispublic", RawKey: "tessera:RequestedPolicyIsPublic", Values: []string{"true"}})
	case Present:
		if len(cv.Values) == 0 {
			return authz.F
		}
		res, err := policy.Parse([]byte(cv.Values[0]), policy.Options{Kind: model.PolicyResource, SourceARN: e.res.arn + "#requested", MultivaluedKey: e.cat.MultivaluedKey})
		if err != nil {
			e.addReason(string(authz.ReasonPolicyUnparseable), "the policy in the request: "+clip(err.Error()), true)
			return authz.F
		}
		return authz.Bool(PolicyIsPublic(res.Doc, e.cat, true))
	}
	return authz.F
}

// requestACLPublic: does the request set an ACL that grants to a public group,
// through a canned ACL or a grant header.
func (e *evaluator) requestACLPublic() authz.Tri {
	t := e.ctxAtom("StringEquals", "s3:x-amz-acl", publicCannedACLs...)
	for _, h := range aclGrantHeaders {
		t = t.Or(e.ctxAtom("StringLike", h, "*/groups/global/AllUsers*", "*/groups/global/AuthenticatedUsers*"))
	}
	return t
}

func (s *special) aclAny() authz.Tri { return s.aclPublic.Or(s.aclAccount) }
