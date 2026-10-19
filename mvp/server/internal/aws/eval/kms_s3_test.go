package eval_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

// pj decodes a JSON policy into the generic form the case builder takes.
func pj(s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		panic(err)
	}
	return v
}

func boolp(b bool) *bool { return &b }

const (
	keyARN    = goldenKeyARN
	bktARN    = "arn:aws:s3:::tsr-bkt"
	objARN    = "arn:aws:s3:::tsr-bkt/a.txt"
	daveARN   = "arn:aws:iam::222222222222:user/dave"
	emptyKP   = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/kadmin"},"Action":"kms:*","Resource":"*"}]}`
	allowKMS  = `{"Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*"}]}`
	publicGet = `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`
)

type specCase struct {
	name string
	c    goldenCase
	r    goldenReq
	x    goldenExpect
}

func runSpecs(t *testing.T, specs []specCase) {
	t.Helper()
	for _, s := range specs {
		t.Run(s.name, func(t *testing.T) {
			s.c.ID = "T-" + s.name
			w := buildWorld(t, s.c, nil)
			d, err := eval.Evaluate(context.Background(), w.snap, fakeCatalog{}, s.c.request(w, s.r), eval.Options{})
			if err != nil {
				t.Fatal(err)
			}
			checkExpect(t, s.name, s.c, d, &s.x)
		})
	}
}

func grant(grantee string, ops ...string) *goldenGrant {
	return &goldenGrant{Grantee: grantee, Operations: ops}
}

func ecEquals(g *goldenGrant, m map[string]string) *goldenGrant {
	g.Constraints.EncryptionContextEquals = m
	return g
}

func TestKMSGrants(t *testing.T) {
	dec := goldenReq{Action: "kms:Decrypt", Resource: keyARN}
	withCtx := func(m map[string]any) goldenReq { r := dec; r.Context = m; return r }
	boundaryS3 := pj(`{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
	specs := []specCase{
		{"user ARN grantee is not capped by a boundary",
			goldenCase{Principal: "U", Boundary: boundaryS3, KeyPolicy: pj(emptyKP), Grant: grant("U", "Decrypt")},
			dec, goldenExpect{Outcome: "ALLOW", Stage: "kms_grant", Fidelity: "exact"}},
		{"role ARN grantee is capped by the boundary (A12b)",
			goldenCase{Principal: "RS", Boundary: boundaryS3, KeyPolicy: pj(emptyKP), Grant: grant("R", "Decrypt")},
			dec, goldenExpect{Outcome: "DENY", DenyKind: "implicit", Fidelity: "approximate", Reasons: []string{"AMBIGUITY:A12b"}}},
		{"role ARN grantee within its boundary",
			goldenCase{Principal: "RS", Boundary: pj(allowKMS), KeyPolicy: pj(emptyKP), Grant: grant("R", "Decrypt")},
			dec, goldenExpect{Outcome: "ALLOW", Stage: "kms_grant", Fidelity: "exact"}},
		{"cross-account grant needs no identity allow (A12)",
			goldenCase{Principal: daveARN, Grant: grant(daveARN, "Encrypt")},
			goldenReq{Action: "kms:Encrypt", Resource: keyARN},
			goldenExpect{Outcome: "ALLOW", Stage: "kms_grant", Fidelity: "approximate", Reasons: []string{"AMBIGUITY:A12"}}},
		{"cross-account grant still obeys an identity deny",
			goldenCase{Principal: daveARN, Identity: []any{pj(`{"Statement":[{"Effect":"Deny","Action":"kms:*","Resource":"*"}]}`)}, Grant: grant(daveARN, "Encrypt")},
			goldenReq{Action: "kms:Encrypt", Resource: keyARN},
			goldenExpect{Outcome: "DENY", DenyKind: "explicit"}},
		{"cross-account grant does not lift the operation allowlist",
			goldenCase{Principal: daveARN, Grant: grant(daveARN, "ScheduleKeyDeletion")},
			goldenReq{Action: "kms:ScheduleKeyDeletion", Resource: keyARN},
			goldenExpect{Outcome: "DENY", DenyKind: "guardrail", Stage: "special_rule"}},
		{"grant to another principal does not apply",
			goldenCase{Principal: "U", KeyPolicy: pj(emptyKP), Grant: grant(daveARN, "Decrypt")},
			dec, goldenExpect{Outcome: "DENY", DenyKind: "implicit"}},
		{"operation not in the grant",
			goldenCase{Principal: "U", KeyPolicy: pj(emptyKP), Grant: grant("U", "Encrypt")},
			dec, goldenExpect{Outcome: "DENY", DenyKind: "implicit"}},
		{"operation names are case-insensitive",
			goldenCase{Principal: "U", KeyPolicy: pj(emptyKP), Grant: grant("U", "decrypt")},
			dec, goldenExpect{Outcome: "ALLOW"}},
		{"EncryptionContextEquals rejects an extra request key",
			goldenCase{Principal: "U", KeyPolicy: pj(emptyKP), Grant: ecEquals(grant("U", "Decrypt"), map[string]string{"dept": "fin"})},
			withCtx(map[string]any{"kms:EncryptionContext:dept": "fin", "kms:EncryptionContext:team": "x"}),
			goldenExpect{Outcome: "DENY", DenyKind: "implicit"}},
		{"EncryptionContextEquals with no request context",
			goldenCase{Principal: "U", KeyPolicy: pj(emptyKP), Grant: ecEquals(grant("U", "Decrypt"), map[string]string{"dept": "fin"})},
			dec, goldenExpect{Outcome: "DENY", DenyKind: "implicit"}},
		{"EncryptionContextSubset accepts an extra request key",
			goldenCase{Principal: "U", KeyPolicy: pj(emptyKP), Grant: func() *goldenGrant {
				g := grant("U", "Decrypt")
				g.Constraints.EncryptionContextSubset = map[string]string{"dept": "fin"}
				return g
			}()},
			withCtx(map[string]any{"kms:EncryptionContext:dept": "fin", "kms:EncryptionContext:team": "x"}),
			goldenExpect{Outcome: "ALLOW", Stage: "kms_grant"}},
		{"SourceArn constraint matches aws:SourceArn",
			goldenCase{Principal: "U", KeyPolicy: pj(emptyKP), Grant: func() *goldenGrant {
				g := grant("U", "Decrypt")
				g.Constraints.SourceArn = "arn:aws:s3:::src"
				return g
			}()},
			withCtx(map[string]any{"aws:SourceArn": "arn:aws:s3:::src"}),
			goldenExpect{Outcome: "ALLOW"}},
		{"SourceArn constraint with the key absent",
			goldenCase{Principal: "U", KeyPolicy: pj(emptyKP), Grant: func() *goldenGrant {
				g := grant("U", "Decrypt")
				g.Constraints.SourceArn = "arn:aws:s3:::src"
				return g
			}()},
			dec, goldenExpect{Outcome: "DENY", DenyKind: "implicit"}},
		{"the retiring principal may retire the grant",
			goldenCase{Principal: "U", KeyPolicy: pj(emptyKP), Grant: &goldenGrant{Grantee: daveARN, Retiring: "U"}},
			goldenReq{Action: "kms:RetireGrant", Resource: keyARN},
			goldenExpect{Outcome: "ALLOW", Stage: "kms_grant"}},
		{"another principal may not retire it",
			goldenCase{Principal: "U", KeyPolicy: pj(emptyKP), Grant: &goldenGrant{Grantee: daveARN, Retiring: daveARN}},
			goldenReq{Action: "kms:RetireGrant", Resource: keyARN},
			goldenExpect{Outcome: "DENY", DenyKind: "implicit"}},
		{"a grant to the account root delegates and needs the identity allow",
			goldenCase{Principal: "U", Identity: []any{pj(allowKMS)}, KeyPolicy: pj(emptyKP), Grant: grant("arn:aws:iam::111111111111:root", "Decrypt")},
			dec, goldenExpect{Outcome: "ALLOW", Fidelity: "approximate", Reasons: []string{"AMBIGUITY:A12"}}},
		{"a grant to the account root without an identity allow",
			goldenCase{Principal: "U", KeyPolicy: pj(emptyKP), Grant: grant("arn:aws:iam::111111111111:root", "Decrypt")},
			dec, goldenExpect{Outcome: "DENY", DenyKind: "implicit"}},
		{"same-account non-cryptographic operation is not guarded",
			goldenCase{Principal: "U", Identity: []any{pj(allowKMS)}, KeyPolicy: pj(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"kms:*","Resource":"*"}]}`)},
			goldenReq{Action: "kms:ScheduleKeyDeletion", Resource: keyARN}, goldenExpect{Outcome: "ALLOW"}},
		{"cross-account cryptographic operation is allowed by key policy and identity",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, KeyPolicy: pj(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"kms:*","Resource":"*"}]}`)},
			dec, goldenExpect{Outcome: "ALLOW", Stage: "cross_account"}},
		{"symbolic mode leaves a constrained grant conditional",
			goldenCase{Principal: "RS", Mode: "symbolic", KeyPolicy: pj(emptyKP), Grant: ecEquals(grant("R", "Decrypt"), map[string]string{"dept": "fin"})},
			dec, goldenExpect{Outcome: "CONDITIONAL", ResidualChecks: []residualCheck{
				{Context: map[string]any{"kms:EncryptionContext:dept": "fin"}, Holds: true},
				{Context: map[string]any{"kms:EncryptionContext:dept": "hr"}, Holds: false},
			}}},
	}
	runSpecs(t, specs)
}

func TestS3ACLsAndBPA(t *testing.T) {
	get := goldenReq{Action: "s3:GetObject", Resource: objARN}
	list := goldenReq{Action: "s3:ListBucket", Resource: bktARN}
	aclBucket := func(own string, bpa goldenBPA, acls ...goldenACL) *goldenBucket {
		b := &goldenBucket{ObjectOwnership: own, BucketACL: acls}
		b.BPA.Bucket = bpa
		return b
	}
	objACL := func(own string, bpa goldenBPA, acls ...goldenACL) *goldenBucket {
		b := &goldenBucket{ObjectOwnership: own, ObjectACL: map[string][]goldenACL{objARN: acls}}
		b.BPA.Bucket = bpa
		return b
	}
	canon := goldenACL{Grantee: "canonical(222222222222)", Perm: "READ"}
	specs := []specCase{
		{"cross-account bucket ACL grants ListBucket",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, Bucket: aclBucket("ObjectWriter", goldenBPA{}, canon)},
			list, goldenExpect{Outcome: "ALLOW", Stage: "s3_acl", Fidelity: "exact"}},
		{"FULL_CONTROL covers ListBucket",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, Bucket: aclBucket("BucketOwnerPreferred", goldenBPA{}, goldenACL{Grantee: "canonical(222222222222)", Perm: "FULL_CONTROL"})},
			list, goldenExpect{Outcome: "ALLOW", Stage: "s3_acl"}},
		{"READ does not cover GetBucketAcl",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, Bucket: aclBucket("ObjectWriter", goldenBPA{}, canon)},
			goldenReq{Action: "s3:GetBucketAcl", Resource: bktARN}, goldenExpect{Outcome: "DENY", DenyKind: "implicit", Stage: "resource_policy"}},
		{"an ACL grant to another account does not apply",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, Bucket: aclBucket("ObjectWriter", goldenBPA{}, goldenACL{Grantee: "canonical(333333333333)", Perm: "READ"})},
			list, goldenExpect{Outcome: "DENY", DenyKind: "implicit"}},
		{"a cross-account ACL grant still needs the caller's identity allow",
			goldenCase{Principal: daveARN, Bucket: aclBucket("ObjectWriter", goldenBPA{}, canon)},
			list, goldenExpect{Outcome: "DENY", DenyKind: "implicit", Stage: "identity"}},
		{"ACLs cannot grant within the same account",
			goldenCase{Principal: "U", Bucket: aclBucket("ObjectWriter", goldenBPA{}, goldenACL{Grantee: "canonical(111111111111)", Perm: "READ"})},
			list, goldenExpect{Outcome: "DENY", DenyKind: "implicit"}},
		{"AuthenticatedUsers grants a signed cross-account caller",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, Bucket: objACL("ObjectWriter", goldenBPA{}, goldenACL{Grantee: "AuthenticatedUsers", Perm: "READ"})},
			get, goldenExpect{Outcome: "ALLOW", Stage: "s3_acl", Fidelity: "exact"}},
		{"AuthenticatedUsers does not grant an anonymous caller",
			goldenCase{Principal: "anonymous", Bucket: objACL("ObjectWriter", goldenBPA{}, goldenACL{Grantee: "AuthenticatedUsers", Perm: "READ"})},
			get, goldenExpect{Outcome: "DENY", DenyKind: "implicit"}},
		{"IgnorePublicAcls drops AuthenticatedUsers for a signed caller",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, Bucket: objACL("ObjectWriter", goldenBPA{IgnorePublicAcls: true}, goldenACL{Grantee: "AuthenticatedUsers", Perm: "READ"})},
			get, goldenExpect{Outcome: "DENY", DenyKind: "implicit"}},
		{"a public-read ACL works for anonymous callers with BPA off",
			goldenCase{Principal: "anonymous", Bucket: objACL("ObjectWriter", goldenBPA{}, goldenACL{Grantee: "AllUsers", Perm: "READ"})},
			get, goldenExpect{Outcome: "ALLOW", Stage: "s3_acl"}},
		{"the account-level IgnorePublicAcls applies",
			goldenCase{Principal: "anonymous", Bucket: func() *goldenBucket {
				b := objACL("ObjectWriter", goldenBPA{}, goldenACL{Grantee: "AllUsers", Perm: "READ"})
				b.BPA.Account.IgnorePublicAcls = true
				return b
			}()},
			get, goldenExpect{Outcome: "DENY", DenyKind: "implicit", Stage: "s3_acl"}},
		{"org-level BPA is most restrictive",
			goldenCase{Principal: "anonymous", Bucket: func() *goldenBucket {
				b := objACL("ObjectWriter", goldenBPA{}, goldenACL{Grantee: "AllUsers", Perm: "READ"})
				b.BPAOrg = boolp(true)
				return b
			}()},
			get, goldenExpect{Outcome: "DENY", DenyKind: "implicit", Stage: "s3_acl"}},
		{"RestrictPublicBuckets leaves a non-public cross-account policy alone",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, Bucket: aclBucket("", goldenBPA{RestrictPublicBuckets: true}),
				BucketPolicy: pj(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`)},
			get, goldenExpect{Outcome: "ALLOW"}},
		{"RestrictPublicBuckets keeps a public policy open to the owner account",
			goldenCase{Principal: "U", Identity: []any{"allow_all"}, Bucket: aclBucket("", goldenBPA{RestrictPublicBuckets: true}), BucketPolicy: pj(publicGet)},
			get, goldenExpect{Outcome: "ALLOW"}},
		{"RestrictPublicBuckets blocks an anonymous caller of a public policy",
			goldenCase{Principal: "anonymous", Bucket: aclBucket("", goldenBPA{RestrictPublicBuckets: true}), BucketPolicy: pj(publicGet)},
			get, goldenExpect{Outcome: "DENY", DenyKind: "guardrail", Stage: "s3_bpa"}},
		{"RestrictPublicBuckets set at the account level",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, BucketPolicy: pj(publicGet), Bucket: func() *goldenBucket {
				b := aclBucket("", goldenBPA{})
				b.BPA.Account.RestrictPublicBuckets = true
				return b
			}()},
			get, goldenExpect{Outcome: "DENY", DenyKind: "guardrail", Stage: "s3_bpa"}},
		{"a pinned condition makes the policy non-public",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, Bucket: aclBucket("", goldenBPA{RestrictPublicBuckets: true}),
				BucketPolicy: pj(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*","Condition":{"StringEquals":{"aws:PrincipalAccount":"222222222222"}}}]}`)},
			get, goldenExpect{Outcome: "ALLOW"}},
		{"BlockPublicPolicy rejects a public PutBucketPolicy",
			goldenCase{Principal: "U", Identity: []any{"allow_all"}, Bucket: aclBucket("", goldenBPA{BlockPublicPolicy: true})},
			goldenReq{Action: "s3:PutBucketPolicy", Resource: bktARN, Context: map[string]any{"tessera:RequestedPolicy": publicGet}},
			goldenExpect{Outcome: "DENY", DenyKind: "guardrail", Stage: "s3_bpa"}},
		{"BlockPublicPolicy accepts a non-public PutBucketPolicy",
			goldenCase{Principal: "U", Identity: []any{"allow_all"}, Bucket: aclBucket("", goldenBPA{BlockPublicPolicy: true})},
			goldenReq{Action: "s3:PutBucketPolicy", Resource: bktARN, Context: map[string]any{"tessera:RequestedPolicy": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`}},
			goldenExpect{Outcome: "ALLOW"}},
		{"BlockPublicPolicy with no policy in the request",
			goldenCase{Principal: "U", Identity: []any{"allow_all"}, Bucket: aclBucket("", goldenBPA{BlockPublicPolicy: true})},
			goldenReq{Action: "s3:PutBucketPolicy", Resource: bktARN}, goldenExpect{Outcome: "ALLOW"}},
		{"BlockPublicPolicy is off",
			goldenCase{Principal: "U", Identity: []any{"allow_all"}},
			goldenReq{Action: "s3:PutBucketPolicy", Resource: bktARN, Context: map[string]any{"tessera:RequestedPolicy": publicGet}},
			goldenExpect{Outcome: "ALLOW"}},
		{"an unparseable requested policy is UNSUPPORTED",
			goldenCase{Principal: "U", Identity: []any{"allow_all"}, Bucket: aclBucket("", goldenBPA{BlockPublicPolicy: true})},
			goldenReq{Action: "s3:PutBucketPolicy", Resource: bktARN, Context: map[string]any{"tessera:RequestedPolicy": `{"Statement":`}},
			goldenExpect{Outcome: "ALLOW", Fidelity: "unsupported", Reasons: []string{"POLICY_UNPARSEABLE"}}},
		{"BlockPublicAcls rejects PutObject with a public canned ACL",
			goldenCase{Principal: "U", Identity: []any{"allow_all"}, Bucket: aclBucket("ObjectWriter", goldenBPA{BlockPublicAcls: true})},
			goldenReq{Action: "s3:PutObject", Resource: objARN, Context: map[string]any{"s3:x-amz-acl": "public-read"}},
			goldenExpect{Outcome: "DENY", DenyKind: "guardrail", Stage: "s3_bpa"}},
		{"BlockPublicAcls accepts a private canned ACL",
			goldenCase{Principal: "U", Identity: []any{"allow_all"}, Bucket: aclBucket("ObjectWriter", goldenBPA{BlockPublicAcls: true})},
			goldenReq{Action: "s3:PutObject", Resource: objARN, Context: map[string]any{"s3:x-amz-acl": "private"}},
			goldenExpect{Outcome: "ALLOW"}},
		{"BlockPublicAcls rejects a grant header naming AllUsers",
			goldenCase{Principal: "U", Identity: []any{"allow_all"}, Bucket: aclBucket("ObjectWriter", goldenBPA{BlockPublicAcls: true})},
			goldenReq{Action: "s3:PutBucketAcl", Resource: bktARN, Context: map[string]any{"s3:x-amz-grant-read": `uri="http://acs.amazonaws.com/groups/global/AllUsers"`}},
			goldenExpect{Outcome: "DENY", DenyKind: "guardrail", Stage: "s3_bpa"}},
		{"BlockPublicAcls does not touch a read",
			goldenCase{Principal: "U", Identity: []any{"allow_all"}, Bucket: aclBucket("ObjectWriter", goldenBPA{BlockPublicAcls: true})},
			goldenReq{Action: "s3:GetObject", Resource: objARN, Context: map[string]any{"s3:x-amz-acl": "public-read"}},
			goldenExpect{Outcome: "ALLOW", Fidelity: "approximate", Reasons: []string{"S3_OBJECT_OWNER_UNKNOWN"}}},
	}
	runSpecs(t, specs)
}

// TestS3ObjectContext covers §7.6.2's object context: the owner of an object
// the bucket owner did not write must allow through its ACL.
func TestS3ObjectContext(t *testing.T) {
	policyDave := pj(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`)
	bucket := func(own string) *goldenBucket { return &goldenBucket{ObjectOwnership: own} }
	get := func(owner string) goldenReq {
		return goldenReq{Action: "s3:GetObject", Resource: objARN, ObjectOwner: owner}
	}
	specs := []specCase{
		{"owner unknown on an ACL-enabled bucket is flagged and outcome-sensitive",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, BucketPolicy: policyDave, Bucket: bucket("ObjectWriter")},
			get(""), goldenExpect{Outcome: "ALLOW", Fidelity: "approximate", Reasons: []string{"S3_OBJECT_OWNER_UNKNOWN"}}},
		{"owner unknown on a BucketOwnerEnforced bucket is exact",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, BucketPolicy: policyDave, Bucket: bucket("BucketOwnerEnforced")},
			get(""), goldenExpect{Outcome: "ALLOW", Fidelity: "exact"}},
		{"the owner is the requester's own account",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, BucketPolicy: policyDave, Bucket: bucket("ObjectWriter")},
			get("222222222222"), goldenExpect{Outcome: "ALLOW", Fidelity: "exact"}},
		{"the owner is a third account that grants nothing",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, BucketPolicy: policyDave, Bucket: bucket("ObjectWriter")},
			get("333333333333"), goldenExpect{Outcome: "DENY", DenyKind: "implicit", Fidelity: "exact"}},
		{"the owner is the bucket owner",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, BucketPolicy: policyDave, Bucket: bucket("ObjectWriter")},
			get("111111111111"), goldenExpect{Outcome: "ALLOW", Fidelity: "exact"}},
		{"a third-account owner whose ACL grants the requester's account",
			goldenCase{Principal: daveARN, Identity: []any{"allow_all"}, BucketPolicy: policyDave, Bucket: &goldenBucket{
				ObjectOwnership: "ObjectWriter",
				ObjectACL:       map[string][]goldenACL{objARN: {{Grantee: "canonical(222222222222)", Perm: "READ"}}}}},
			get("333333333333"), goldenExpect{Outcome: "ALLOW", Fidelity: "exact"}},
	}
	runSpecs(t, specs)
}

func TestPolicyIsPublic(t *testing.T) {
	stmt := func(principal, cond string) string {
		c := ""
		if cond != "" {
			c = `,"Condition":` + cond
		}
		return `{"Statement":[{"Effect":"Allow","Principal":` + principal + `,"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"` + c + `}]}`
	}
	star := `"*"`
	tests := []struct {
		name   string
		doc    string
		bucket bool // a bucket policy; false is an access point policy
		want   bool
	}{
		// The S3 "meaning of public" examples.
		{"principal star", stmt(star, ""), true, true},
		{"principal AWS star", stmt(`{"AWS":"*"}`, ""), true, true},
		{"principal AWS star in a list", stmt(`{"AWS":["arn:aws:iam::123456789012:root","*"]}`, ""), true, true},
		{"fixed account principal", stmt(`{"AWS":"123456789012"}`, ""), true, false},
		{"service principal", stmt(`{"Service":"cloudtrail.amazonaws.com"}`, ""), true, false},
		{"unknown action is still public", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:NoSuchAction","Resource":"*"}]}`, true, true},
		{"a Deny never makes a policy public", `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}`, true, false},
		{"pinned to a VPC", stmt(star, `{"StringEquals":{"aws:SourceVpc":"vpc-1a2b3c4d"}}`), true, false},
		{"pinned to a VPC endpoint", stmt(star, `{"StringEquals":{"aws:SourceVpce":"vpce-1a2b3c4d"}}`), true, false},
		{"pinned to an org", stmt(star, `{"StringEquals":{"aws:PrincipalOrgID":"o-abcdefghij"}}`), true, false},
		{"pinned to an account", stmt(star, `{"StringEquals":{"aws:SourceAccount":"123456789012"}}`), true, false},
		{"pinned to an owner", stmt(star, `{"StringEquals":{"aws:SourceOwner":"123456789012"}}`), true, false},
		{"pinned to a source ARN", stmt(star, `{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:us-east-1:123456789012:topic"}}`), true, false},
		{"pinned to a principal ARN", stmt(star, `{"ArnEquals":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/r"}}`), true, false},
		{"a pin among other conditions", stmt(star, `{"Bool":{"aws:SecureTransport":"true"},"StringEquals":{"aws:SourceAccount":"123456789012"}}`), true, false},
		{"another key does not pin", stmt(star, `{"Bool":{"aws:SecureTransport":"true"}}`), true, true},
		// Bouchet et al. 2020: the ways a condition fails to pin.
		{"wildcard in a pinned value", stmt(star, `{"StringLike":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/*"}}`), true, true},
		{"fully wild account", stmt(star, `{"StringLike":{"aws:SourceAccount":"*"}}`), true, true},
		{"one wild value among fixed ones", stmt(star, `{"StringLike":{"aws:SourceAccount":["123456789012","12*"]}}`), true, true},
		{"policy variable", stmt(star, `{"StringEquals":{"aws:SourceAccount":"${aws:PrincipalAccount}"}}`), true, true},
		{"negated operator", stmt(star, `{"StringNotEquals":{"aws:SourceAccount":"123456789012"}}`), true, true},
		{"IfExists operator", stmt(star, `{"StringEqualsIfExists":{"aws:SourceAccount":"123456789012"}}`), true, true},
		{"ForAllValues", stmt(star, `{"ForAllValues:StringEquals":{"aws:SourceVpce":"vpce-1a2b3c4d"}}`), true, true},
		{"Null does not pin", stmt(star, `{"Null":{"aws:SourceAccount":"false"}}`), true, true},
		// aws:SourceIp.
		{"narrow IPv4 range", stmt(star, `{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}`), true, false},
		{"single IPv4 address", stmt(star, `{"IpAddress":{"aws:SourceIp":"192.0.2.7"}}`), true, false},
		{"IPv4 /8", stmt(star, `{"IpAddress":{"aws:SourceIp":"8.0.0.0/8"}}`), true, false},
		{"IPv4 /7", stmt(star, `{"IpAddress":{"aws:SourceIp":"8.0.0.0/7"}}`), true, true},
		{"the whole Internet", stmt(star, `{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}`), true, true},
		{"a broad and a narrow range", stmt(star, `{"IpAddress":{"aws:SourceIp":["192.0.2.0/24","0.0.0.0/0"]}}`), true, true},
		{"RFC 1918 range", stmt(star, `{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`), true, false},
		{"IPv6 /32", stmt(star, `{"IpAddress":{"aws:SourceIp":"2001:db8::/32"}}`), true, false},
		{"IPv6 /16", stmt(star, `{"IpAddress":{"aws:SourceIp":"2001:db8::/16"}}`), true, true},
		{"NotIpAddress does not pin", stmt(star, `{"NotIpAddress":{"aws:SourceIp":"192.0.2.0/24"}}`), true, true},
		// aws:userid and the AROLEID:* pattern.
		{"fixed user id", stmt(star, `{"StringEquals":{"aws:userid":"AIDAEXAMPLE"}}`), true, false},
		{"role id with any session is not a pin", stmt(star, `{"StringLike":{"aws:userid":"AROAEXAMPLE:*"}}`), true, true},
		{"role id and a fixed session", stmt(star, `{"StringEquals":{"aws:userid":"AROAEXAMPLE:session"}}`), true, false},
		// Access points.
		{"access point ARN with a fixed account, bucket policy", stmt(star, `{"ArnLike":{"s3:DataAccessPointArn":"arn:aws:s3:us-east-1:123456789012:accesspoint/*"}}`), true, false},
		{"access point ARN with a wild account", stmt(star, `{"ArnLike":{"s3:DataAccessPointArn":"arn:aws:s3:*:*:accesspoint/*"}}`), true, true},
		{"access point ARN does not pin an access point policy", stmt(star, `{"ArnLike":{"s3:DataAccessPointArn":"arn:aws:s3:us-east-1:123456789012:accesspoint/*"}}`), false, true},
		{"access point account", stmt(star, `{"StringEquals":{"s3:DataAccessPointAccount":"123456789012"}}`), false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := policy.Parse([]byte(tc.doc), policy.Options{Kind: model.PolicyResource, SourceARN: "arn:aws:s3:::b#policy"})
			if err != nil {
				t.Fatal(err)
			}
			if got := eval.PolicyIsPublic(res.Doc, fakeCatalog{}, tc.bucket); got != tc.want {
				t.Errorf("PolicyIsPublic = %v, want %v", got, tc.want)
			}
		})
	}
	if eval.PolicyIsPublic(nil, fakeCatalog{}, true) {
		t.Error("a nil document is not public")
	}
}
