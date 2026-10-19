package eval_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
)

// The golden corpus (design §14): the YAML in testdata/aws/golden, run with no
// AWS credentials. TestGolden has one subtest per case id.

const (
	acctA, acctB, acctMgmt, acctX = "111111111111", "222222222222", "999999999999", "333333333333"
	orgID                         = "o-sbx"
	allowAll                      = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
)

var principalAliases = map[string]string{
	"U":  "arn:aws:iam::111111111111:user/alice",
	"R":  "arn:aws:iam::111111111111:role/app",
	"RS": "arn:aws:sts::111111111111:assumed-role/app/s1",
}

// goldenCase is one case of the corpus. The field names follow §14.1; fields
// the design writes in prose are given a structured form here.
type goldenCase struct {
	ID        string `yaml:"id"`
	Title     string `yaml:"title"`
	Principal string `yaml:"principal"`
	// Identity lists the identity policies of the user, or of the role the
	// session was issued from. The token "allow_all" is the design's Allow*.
	Identity      []any             `yaml:"identity"`
	PrincipalTags map[string]string `yaml:"principal_tags"`
	Boundary      any               `yaml:"boundary"`
	SessionPolicy any               `yaml:"session_policy"`
	RolePath      string            `yaml:"role_path"`
	PrincipalOrg  string            `yaml:"principal_org"` // aws:PrincipalOrgID when the account is in another organization
	Buckets       map[string]string `yaml:"buckets"`       // bucket name to owner account; others belong to account A
	BucketPolicy  any               `yaml:"bucket_policy"`
	ResPolicies   []struct {
		Resource string `yaml:"resource"`
		Kind     string `yaml:"kind"` // resource (default) or trust
		Policy   any    `yaml:"policy"`
	} `yaml:"resource_policies"`
	Org        *goldenOrg    `yaml:"org"`
	Mode       string        `yaml:"mode"`
	Request    *goldenReq    `yaml:"request"`
	Requests   []goldenReq   `yaml:"requests"`
	Expect     *goldenExpect `yaml:"expect"`
	Why        string        `yaml:"why"`
	Verified   string        `yaml:"verified"`
	KnownFlags []string      `yaml:"known_flags"` // ambiguity ids a verified:doc case is allowed to carry
	Note       string        `yaml:"note"`
	// KMS and S3 state (PR-6). The key is goldenKeyARN; the bucket is tsr-bkt.
	KeyPolicy any           `yaml:"key_policy"`
	Grant     *goldenGrant  `yaml:"grant"`
	Bucket    *goldenBucket `yaml:"bucket"`
}

const goldenKeyARN = "arn:aws:kms:us-east-1:111111111111:key/k1"

// goldenGrant is one KMS grant on the key.
type goldenGrant struct {
	Grantee     string   `yaml:"grantee"`
	Retiring    string   `yaml:"retiring"` // the retiring principal, if any
	Operations  []string `yaml:"operations"`
	Constraints struct {
		EncryptionContextEquals map[string]string `yaml:"EncryptionContextEquals"`
		EncryptionContextSubset map[string]string `yaml:"EncryptionContextSubset"`
		SourceArn               string            `yaml:"SourceArn"`
	} `yaml:"constraints"`
}

// goldenBucket is the S3 state of tsr-bkt. Absent fields keep the defaults of
// §14.1: BucketOwnerEnforced and no Block Public Access.
type goldenBucket struct {
	ObjectOwnership string `yaml:"object_ownership"`
	BPA             struct {
		Account goldenBPA `yaml:"account"`
		Bucket  goldenBPA `yaml:"bucket"`
	} `yaml:"bpa"`
	BPAOrg    *bool                  `yaml:"bpa_org"` // org-level Block Public Access, all or none
	BucketACL []goldenACL            `yaml:"bucket_acl"`
	ObjectACL map[string][]goldenACL `yaml:"object_acl"` // by object ARN
}

type goldenBPA struct {
	BlockPublicAcls       bool `yaml:"BlockPublicAcls"`
	IgnorePublicAcls      bool `yaml:"IgnorePublicAcls"`
	BlockPublicPolicy     bool `yaml:"BlockPublicPolicy"`
	RestrictPublicBuckets bool `yaml:"RestrictPublicBuckets"`
}

func (b goldenBPA) model() model.BPA { return model.BPA(b) }

// goldenACL grants Perm to Grantee: AllUsers, AuthenticatedUsers, LogDelivery
// or canonical(<account>).
type goldenACL struct {
	Grantee string `yaml:"grantee"`
	Perm    string `yaml:"perm"`
}

func (a goldenACL) model() model.ACLGrant {
	if rest, ok := strings.CutPrefix(a.Grantee, "canonical("); ok {
		return model.ACLGrant{GranteeType: "CanonicalUser", Grantee: "canonical-" + strings.TrimSuffix(rest, ")"), Permission: a.Perm}
	}
	uri := map[string]string{
		"AllUsers":           "http://acs.amazonaws.com/groups/global/AllUsers",
		"AuthenticatedUsers": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
		"LogDelivery":        "http://acs.amazonaws.com/groups/s3/LogDelivery",
	}[a.Grantee]
	return model.ACLGrant{GranteeType: "Group", Grantee: uri, Permission: a.Perm}
}

func aclModels(in []goldenACL) []model.ACLGrant {
	var out []model.ACLGrant
	for _, a := range in {
		out = append(out, a.model())
	}
	return out
}

// bucketState is the snapshot state of a bucket; spec is nil for buckets the
// case does not describe.
func bucketState(arn, owner string, spec *goldenBucket) *model.S3BucketState {
	st := &model.S3BucketState{BucketARN: arn, OwnerAccount: owner, ObjectOwnership: "BucketOwnerEnforced"}
	if spec == nil {
		return st
	}
	if spec.ObjectOwnership != "" {
		st.ObjectOwnership = spec.ObjectOwnership
	}
	st.BPAAccount, st.BPABucket, st.BPAOrg = spec.BPA.Account.model(), spec.BPA.Bucket.model(), spec.BPAOrg
	st.BucketACL = aclModels(spec.BucketACL)
	if len(spec.ObjectACL) > 0 {
		st.ObjectACLs = map[string][]model.ACLGrant{}
		for k, v := range spec.ObjectACL {
			st.ObjectACLs[k] = aclModels(v)
		}
	}
	return st
}

// goldenOrg is the shared fixture O1 plus per-case changes.
type goldenOrg struct {
	Base   string           `yaml:"base"`
	SCPAdd map[string][]any `yaml:"scp_add"` // node id to extra SCPs
	RCPAdd map[string][]any `yaml:"rcp_add"`
	SCPSet map[string][]any `yaml:"scp_set"` // node id to the SCPs that replace its own
}

type goldenReq struct {
	Action   string         `yaml:"action"`
	Resource string         `yaml:"resource"`
	Context  map[string]any `yaml:"context"`
	Mode     string         `yaml:"mode"`
	Caller   string         `yaml:"caller"` // "provider": the OIDC provider calls AssumeRoleWithWebIdentity
	// ObjectOwner is the account that owns the S3 object (eval.EvaluationRequest.S3ObjectOwner).
	ObjectOwner string        `yaml:"object_owner"`
	Expect      *goldenExpect `yaml:"expect"`
}

type goldenExpect struct {
	Outcome        string          `yaml:"outcome"`
	DenyKind       string          `yaml:"deny_kind"` // "none" for the design's null
	Stage          string          `yaml:"stage"`
	Decisive       string          `yaml:"decisive"` // "<policy kind>#<statement index>"
	DecisiveLevel  string          `yaml:"decisive_level"`
	BlockingLevel  string          `yaml:"blocking_level"`
	MatchKind      string          `yaml:"match_kind"`
	PolicyKind     string          `yaml:"policy_kind"`
	Fidelity       string          `yaml:"fidelity"`
	Reasons        []string        `yaml:"reasons"`
	SCP            string          `yaml:"scp"`
	RCP            string          `yaml:"rcp"`
	Residual       string          `yaml:"residual"` // the design's wording, for readers
	ResidualChecks []residualCheck `yaml:"residual_checks"`
	NHIFlag        string          `yaml:"nhi_flag"` // PR-11 (internal/nhi); not checked here
}

// residualCheck pins a residual semantically: it must hold (or not) under a context.
type residualCheck struct {
	Context map[string]any `yaml:"context"`
	Holds   bool           `yaml:"holds"`
}

// fakeCatalog is the test stand-in for internal/aws/catalog (PR-2).
type fakeCatalog struct{}

var fakeServices = map[string]bool{"s3": true, "ec2": true, "iam": true, "sts": true, "sqs": true, "sns": true, "lambda": true, "kms": true}
var fakeRCPServices = map[string]bool{"s3": true, "sts": true, "sqs": true, "kms": true}

func (fakeCatalog) Version() string { return "fake-1" }
func (fakeCatalog) CanonicalAction(a string) (string, bool) {
	svc, _, ok := strings.Cut(a, ":")
	return a, ok && fakeServices[strings.ToLower(svc)]
}
func (fakeCatalog) RCPSupportedService(p string) bool { return fakeRCPServices[p] }
func (fakeCatalog) MultivaluedKey(k string) bool      { return policy.IsGlobalMultivaluedKey(k) }
func (fakeCatalog) ResourceTagsSupported(string) bool { return true }
func (fakeCatalog) RequiresExplicitRBP(p string) (bool, bool) {
	if p == "iam" || p == "kms" {
		return true, true
	}
	return false, false
}

// The overlay facts of catalog/aws/overlays (PR-2): kms_xacct_ops.yaml,
// s3_acl_map.yaml and s3_public_fixed_keys.yaml.
var fakeKMSCrossAccountOps = map[string]bool{
	"kms:creategrant": true, "kms:decrypt": true, "kms:derivesharedsecret": true, "kms:describekey": true,
	"kms:encrypt": true, "kms:generatedatakey": true, "kms:generatedatakeypair": true,
	"kms:generatedatakeypairwithoutplaintext": true, "kms:generatedatakeywithoutplaintext": true,
	"kms:generatemac": true, "kms:getkeyrotationstatus": true, "kms:getpublickey": true, "kms:listgrants": true,
	"kms:reencryptfrom": true, "kms:reencryptto": true, "kms:retiregrant": true, "kms:revokegrant": true,
	"kms:sign": true, "kms:verify": true, "kms:verifymac": true,
}

var fakeACLMap = map[eval.S3ACLScope]map[string][]string{
	eval.S3ACLBucket: {
		"READ":         {"s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:ListBucketVersions"},
		"WRITE":        {"s3:DeleteObject", "s3:PutObject"},
		"READ_ACP":     {"s3:GetBucketAcl"},
		"WRITE_ACP":    {"s3:PutBucketAcl"},
		"FULL_CONTROL": {"s3:DeleteObject", "s3:GetBucketAcl", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:ListBucketVersions", "s3:PutBucketAcl", "s3:PutObject"},
	},
	eval.S3ACLObject: {
		"READ":         {"s3:GetObject", "s3:GetObjectVersion"},
		"WRITE":        {},
		"READ_ACP":     {"s3:GetObjectAcl", "s3:GetObjectVersionAcl"},
		"WRITE_ACP":    {"s3:PutObjectAcl", "s3:PutObjectVersionAcl"},
		"FULL_CONTROL": {"s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectVersion", "s3:GetObjectVersionAcl", "s3:PutObjectAcl", "s3:PutObjectVersionAcl"},
	},
}

var fakeACLGroups = map[string]eval.S3ACLGroup{
	"http://acs.amazonaws.com/groups/global/AllUsers":           {Name: "AllUsers", Public: true},
	"http://acs.amazonaws.com/groups/global/AuthenticatedUsers": {Name: "AuthenticatedUsers", Public: true},
	"http://acs.amazonaws.com/groups/s3/LogDelivery":            {Name: "LogDelivery"},
}

var fakePublicKeys = map[string]eval.S3PublicKeyRule{
	"aws:principalarn":     {Kind: eval.S3FixedValue},
	"aws:principalaccount": {Kind: eval.S3FixedValue},
	"aws:principalorgid":   {Kind: eval.S3FixedValue},
	"aws:userid":           {Kind: eval.S3FixedValue, ExceptPatterns: []string{"AROLEID:*"}},
	"aws:sourceip":         {Kind: eval.S3IPRange, IPv4MaxCIDR: 8, IPv6MaxCIDR: 32},
	"aws:sourcearn":        {Kind: eval.S3FixedValue},
	"aws:sourcevpc":        {Kind: eval.S3FixedValue},
	"aws:sourcevpce":       {Kind: eval.S3FixedValue},
	"aws:sourceowner":      {Kind: eval.S3FixedValue},
	"aws:sourceaccount":    {Kind: eval.S3FixedValue},
	// The account must be fixed; the rest of the ARN may use wildcards.
	"s3:dataaccesspointarn":     {Kind: eval.S3FixedValue, BucketPoliciesOnly: true},
	"s3:dataaccesspointaccount": {Kind: eval.S3FixedValue},
}

func (fakeCatalog) KMSCrossAccountOp(a string) bool {
	return fakeKMSCrossAccountOps[strings.ToLower(a)]
}
func (fakeCatalog) S3ACLActions(s eval.S3ACLScope, perm string) []string {
	return fakeACLMap[s][perm]
}
func (fakeCatalog) S3ACLGroup(uri string) (eval.S3ACLGroup, bool) {
	g, ok := fakeACLGroups[uri]
	return g, ok
}
func (fakeCatalog) S3PublicFixedKey(k string) (eval.S3PublicKeyRule, bool) {
	r, ok := fakePublicKeys[k]
	return r, ok
}

func loadCases(t testing.TB) []goldenCase {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "testdata", "aws", "golden", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden files: %v", err)
	}
	sort.Strings(files)
	var all []goldenCase
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- a fixed testdata glob
		if err != nil {
			t.Fatal(err)
		}
		var cs []goldenCase
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&cs); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		all = append(all, cs...)
	}
	return all
}

func docBytes(t testing.TB, v any) []byte {
	t.Helper()
	if s, ok := v.(string); ok && s == "allow_all" {
		return docBytes(t, mustJSON(t, allowAll))
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("policy is %T, want a mapping", v)
	}
	if _, has := m["Version"]; !has {
		m["Version"] = "2012-10-17"
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustJSON(t testing.TB, s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// goldenWorld builds the snapshot of one case and the requests' principal.
type goldenWorld struct {
	snap      *model.Snapshot
	principal string
}

func buildWorld(t testing.TB, c goldenCase, shuffle func([]func())) *goldenWorld {
	t.Helper()
	b := snapshot.NewBuilder()
	var steps []func()
	do := func(f func()) { steps = append(steps, f) }

	pArn := c.Principal
	if a, ok := principalAliases[pArn]; ok {
		pArn = a
	}
	docID := func(kind model.PolicyKind, src string, v any) string {
		raw := docBytes(t, v)
		do(func() { b.AddPolicy(policy.Options{Kind: kind, SourceARN: src}, raw) })
		return policy.DocumentID(kind, src, "", raw)
	}

	// The principal and its policies.
	parts := strings.SplitN(pArn, ":", 6)
	var identityIDs []string
	for i, p := range c.Identity {
		identityIDs = append(identityIDs, docID(model.PolicyIdentity, fmt.Sprintf("arn:aws:iam::%s:policy/%s-id%d", acctOf(pArn), c.ID, i), p))
	}
	boundaryID := ""
	if c.Boundary != nil {
		boundaryID = docID(model.PolicyBoundary, fmt.Sprintf("arn:aws:iam::%s:policy/%s-pb", acctOf(pArn), c.ID), c.Boundary)
	}
	var sessionIDs []string
	if c.SessionPolicy != nil {
		sessionIDs = []string{docID(model.PolicySession, "session/"+c.ID, c.SessionPolicy)}
	}
	if len(parts) == 6 {
		acct, res := parts[4], parts[5]
		switch {
		case parts[2] == "iam" && strings.HasPrefix(res, "user/"):
			name := strings.TrimPrefix(res, "user/")
			do(func() {
				b.AddPrincipal(&model.Principal{ARN: pArn, Kind: model.IAMUser, AccountID: acct, UniqueID: "AIDA" + strings.ToUpper(name), Path: "/",
					Tags: c.PrincipalTags, IdentityPolicyIDs: identityIDs, BoundaryPolicyID: boundaryID})
			})
		case parts[2] == "sts" && strings.HasPrefix(res, "assumed-role/"):
			role := strings.Split(strings.TrimPrefix(res, "assumed-role/"), "/")[0]
			path := "/"
			if c.RolePath != "" {
				path = c.RolePath
			}
			roleArn := "arn:aws:iam::" + acct + ":role" + path + role
			do(func() {
				b.AddPrincipal(&model.Principal{ARN: roleArn, Kind: model.IAMRole, AccountID: acct, UniqueID: "AROA" + strings.ToUpper(role), Path: path,
					Tags: c.PrincipalTags, IdentityPolicyIDs: identityIDs, BoundaryPolicyID: boundaryID})
			})
			if sessionIDs != nil {
				do(func() {
					b.AddPrincipal(&model.Principal{ARN: pArn, Kind: model.RoleSession, AccountID: acct, EntityARN: roleArn, SessionPolicyIDs: sessionIDs})
				})
			}
		case parts[2] == "sts" && strings.HasPrefix(res, "federated-user/"):
			name := strings.TrimPrefix(res, "federated-user/")
			userArn := "arn:aws:iam::" + acct + ":user/" + name
			do(func() {
				b.AddPrincipal(&model.Principal{ARN: userArn, Kind: model.IAMUser, AccountID: acct, UniqueID: "AIDA" + strings.ToUpper(name), Path: "/", IdentityPolicyIDs: identityIDs})
				b.AddPrincipal(&model.Principal{ARN: pArn, Kind: model.FederatedUserSession, AccountID: acct, EntityARN: userArn, SessionPolicyIDs: sessionIDs})
			})
		case parts[2] == "iam" && strings.HasPrefix(res, "role/"):
			do(func() {
				b.AddPrincipal(&model.Principal{ARN: pArn, Kind: model.IAMRole, AccountID: acct, Path: "/", IdentityPolicyIDs: identityIDs, BoundaryPolicyID: boundaryID})
			})
		}
	}

	// Resource policies.
	attach := func(resource string, kind model.PolicyKind, explicit bool, v any, i int) {
		id := docID(kind, fmt.Sprintf("%s#policy%d", resource, i), v)
		do(func() {
			b.AddResourcePolicy(model.ResourcePolicy{ResourceARN: resource, Kind: kind, PolicyID: id, RequiresExplicitAllow: explicit})
		})
	}
	if c.BucketPolicy != nil {
		attach("arn:aws:s3:::tsr-bkt", model.PolicyResource, false, c.BucketPolicy, 0)
	}
	for i, rp := range c.ResPolicies {
		if rp.Kind == "trust" {
			attach(rp.Resource, model.PolicyTrust, true, rp.Policy, i+1)
		} else {
			attach(rp.Resource, model.PolicyResource, false, rp.Policy, i+1)
		}
	}

	if c.KeyPolicy != nil {
		attach(goldenKeyARN, model.PolicyKMSKey, true, c.KeyPolicy, 0)
	}
	if g := c.Grant; g != nil {
		alias := func(s string) string {
			if a, ok := principalAliases[s]; ok {
				return a
			}
			return s
		}
		grantee := alias(g.Grantee)
		do(func() {
			b.AddKMSGrant(model.KMSGrant{KeyARN: goldenKeyARN, GrantID: "grant-1", GranteePrincipal: grantee, Operations: g.Operations,
				ConstraintsECEquals: g.Constraints.EncryptionContextEquals, ConstraintsECSubset: g.Constraints.EncryptionContextSubset,
				ConstraintSourceARN: g.Constraints.SourceArn, RetiringPrincipal: alias(g.Retiring)})
		})
	}
	for _, acct := range []string{acctA, acctB, acctX} {
		do(func() { b.SetCanonicalID("canonical-"+acct, acct) })
	}

	// Buckets mentioned by any request (and tsr-bkt) belong to account A unless the case says otherwise.
	buckets := map[string]string{"tsr-bkt": acctA}
	reqs := c.allRequests()
	for _, r := range reqs {
		if rest, ok := strings.CutPrefix(r.Resource, "arn:aws:s3:::"); ok {
			name := strings.SplitN(rest, "/", 2)[0]
			if _, ok := buckets[name]; !ok {
				buckets[name] = acctA
			}
		}
	}
	for k, v := range c.Buckets {
		buckets[k] = v
	}
	for name, owner := range buckets {
		arn := "arn:aws:s3:::" + name
		var spec *goldenBucket
		if name == "tsr-bkt" {
			spec = c.Bucket
		}
		do(func() { b.AddS3Bucket(bucketState(arn, owner, spec)) })
	}

	if c.Org != nil {
		buildOrg(t, b, c, docID, do)
	}
	if shuffle != nil {
		shuffle(steps)
	}
	for _, f := range steps {
		f()
	}
	snap, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return &goldenWorld{snap: snap, principal: pArn}
}

func acctOf(arn string) string {
	p := strings.SplitN(arn, ":", 6)
	if len(p) == 6 {
		return p[4]
	}
	return acctA
}

func (c goldenCase) allRequests() []goldenReq {
	if c.Request != nil {
		r := *c.Request
		if r.Expect == nil {
			r.Expect = c.Expect
		}
		return []goldenReq{r}
	}
	return c.Requests
}

var scpFull = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
var rcpFull = `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`
var scpEC2Only = `{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`

// buildOrg builds O1 (§14.1) and applies the case's changes.
func buildOrg(t testing.TB, b *snapshot.Builder, c goldenCase, docID func(model.PolicyKind, string, any) string, do func(func())) {
	t.Helper()
	if c.Org.Base != "O1" {
		t.Fatalf("%s: unknown org base %q", c.ID, c.Org.Base)
	}
	nodes := map[string]*model.OrgNode{
		"r-1":      {ID: "r-1", Kind: model.OrgRoot, Name: "Root"},
		"ou-prod":  {ID: "ou-prod", Kind: model.OrgOU, ParentID: "r-1", Name: "Prod"},
		"ou-allow": {ID: "ou-allow", Kind: model.OrgOU, ParentID: "r-1", Name: "Allow"},
		acctA:      {ID: acctA, Kind: model.OrgAccount, ParentID: "ou-prod", Name: "A"},
		acctB:      {ID: acctB, Kind: model.OrgAccount, ParentID: "ou-allow", Name: "B"},
		acctMgmt:   {ID: acctMgmt, Kind: model.OrgAccount, ParentID: "r-1", Name: "Management"},
	}
	fullSCP := docID(model.PolicySCP, "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess", mustJSON(t, scpFull))
	fullRCP := docID(model.PolicyRCP, "arn:aws:organizations::aws:policy/resource_control_policy/p-RCPFullAWSAccess", mustJSON(t, rcpFull))
	ec2Only := docID(model.PolicySCP, "arn:aws:organizations::"+acctMgmt+":policy/o-sbx/service_control_policy/p-AllowEC2Only", mustJSON(t, scpEC2Only))
	for _, id := range []string{"r-1", "ou-prod", acctA, acctB, "ou-allow"} {
		nodes[id].SCPIDs = []string{fullSCP}
		nodes[id].RCPIDs = []string{fullRCP}
	}
	nodes["ou-allow"].SCPIDs = []string{ec2Only}
	nodes[acctMgmt].SCPIDs, nodes[acctMgmt].RCPIDs = []string{fullSCP}, []string{fullRCP}

	extra := func(m map[string][]any, kind model.PolicyKind, label string, set bool) {
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, node := range keys {
			var ids []string
			for i, p := range m[node] {
				ids = append(ids, docID(kind, fmt.Sprintf("arn:aws:organizations::%s:policy/o-sbx/%s/p-%s-%s%d", acctMgmt, label, c.ID, node, i), p))
			}
			if set {
				nodes[node].SCPIDs = ids
			} else if kind == model.PolicySCP {
				nodes[node].SCPIDs = append(nodes[node].SCPIDs, ids...)
			} else {
				nodes[node].RCPIDs = append(nodes[node].RCPIDs, ids...)
			}
		}
	}
	extra(c.Org.SCPSet, model.PolicySCP, "service_control_policy", true)
	extra(c.Org.SCPAdd, model.PolicySCP, "service_control_policy", false)
	extra(c.Org.RCPAdd, model.PolicyRCP, "resource_control_policy", false)
	org := &model.Organization{OrgID: orgID, ManagementAccountID: acctMgmt, Nodes: nodes, SCPEnabled: true, RCPEnabled: true}
	do(func() { b.SetOrg(org) })
}

func ctxValues(m map[string]any) map[string]eval.ContextValue {
	if m == nil {
		return nil
	}
	out := map[string]eval.ContextValue{}
	for k, v := range m {
		switch x := v.(type) {
		case []any:
			var vs []string
			for _, e := range x {
				vs = append(vs, fmt.Sprint(e))
			}
			out[strings.ToLower(k)] = eval.PresentValues(vs...)
		case string:
			if x == "absent" {
				out[strings.ToLower(k)] = eval.AbsentValue
			} else {
				out[strings.ToLower(k)] = eval.PresentValues(x)
			}
		default:
			out[strings.ToLower(k)] = eval.PresentValues(fmt.Sprint(x))
		}
	}
	return out
}

func (c goldenCase) request(w *goldenWorld, r goldenReq) *eval.EvaluationRequest {
	req := &eval.EvaluationRequest{PrincipalARN: w.principal, Action: r.Action, ResourceARN: r.Resource, Context: ctxValues(r.Context)}
	req.S3ObjectOwner = r.ObjectOwner
	if r.Caller == "provider" {
		req.PrincipalARN = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
	}
	mode := r.Mode
	if mode == "" {
		mode = c.Mode
	}
	if mode == "symbolic" {
		req.Mode = eval.Symbolic
	}
	if c.PrincipalOrg != "" {
		if req.Context == nil {
			req.Context = map[string]eval.ContextValue{}
		}
		req.Context["aws:principalorgid"] = eval.PresentValues(c.PrincipalOrg)
	}
	return req
}

func TestGolden(t *testing.T) {
	cases := loadCases(t)
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.ID] {
			t.Fatalf("duplicate case id %s", c.ID)
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			w := buildWorld(t, c, nil)
			reqs := c.allRequests()
			if len(reqs) == 0 {
				t.Fatal("case has no request")
			}
			for i, r := range reqs {
				if r.Expect == nil {
					t.Fatalf("request %d has no expectation", i)
				}
				d, err := eval.Evaluate(context.Background(), w.snap, fakeCatalog{}, c.request(w, r), eval.Options{})
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				checkExpect(t, fmt.Sprintf("%s request %d (%s %s)", c.ID, i, r.Action, r.Resource), c, d, r.Expect)
			}
		})
	}
	for _, want := range goldenRequired() {
		if !seen[want] {
			t.Errorf("golden case %s is missing from the corpus", want)
		}
	}
}

// goldenRequired lists GC-01..GC-74: PR-5 covers all but GC-60..68, the KMS and
// S3 cases of PR-6.
func goldenRequired() []string {
	var ids []string
	for i := 1; i <= 74; i++ {
		ids = append(ids, fmt.Sprintf("GC-%02d", i))
	}
	return ids
}

func facts(d *authz.Decision) map[string]string {
	return d.Steps[len(d.Steps)-1].MatchedOn
}

func checkExpect(t *testing.T, label string, c goldenCase, d *authz.Decision, x *goldenExpect) {
	t.Helper()
	fail := func(format string, a ...any) {
		t.Errorf("%s: %s\n  summary: %s", label, fmt.Sprintf(format, a...), eval.Summary(d))
	}
	if !strings.EqualFold(d.Outcome.String(), x.Outcome) {
		fail("outcome %s, want %s", d.Outcome, x.Outcome)
		return
	}
	if x.DenyKind != "" {
		want := x.DenyKind
		if want == "none" {
			want = ""
		}
		if d.DenyKind.String() != want {
			fail("deny kind %q, want %q", d.DenyKind, want)
		}
	}
	f := facts(d)
	if x.Stage != "" && f["decisive_stage"] != x.Stage {
		fail("decisive stage %q, want %q", f["decisive_stage"], x.Stage)
	}
	if x.Decisive != "" {
		got := ""
		if len(d.Decisive) > 0 {
			got = fmt.Sprintf("%s#%d", d.Decisive[0].PolicyKind, d.Decisive[0].StatementIndex)
		}
		if got != x.Decisive {
			fail("decisive statement %q, want %q", got, x.Decisive)
		}
	}
	if x.PolicyKind != "" && (len(d.Decisive) == 0 || d.Decisive[0].PolicyKind != x.PolicyKind) {
		fail("decisive policy kind %v, want %s", d.Decisive, x.PolicyKind)
	}
	if x.DecisiveLevel != "" && (len(d.Decisive) == 0 || d.Decisive[0].OrgLevel != x.DecisiveLevel) {
		fail("decisive level %v, want %s", d.Decisive, x.DecisiveLevel)
	}
	if x.BlockingLevel != "" && f["blocking_level"] != x.BlockingLevel {
		fail("blocking level %q, want %q", f["blocking_level"], x.BlockingLevel)
	}
	if x.MatchKind != "" && f["match_kind"] != x.MatchKind {
		fail("match kind %q, want %q", f["match_kind"], x.MatchKind)
	}
	for stage, want := range map[authz.Stage]string{authz.StageSCP: x.SCP, authz.StageRCP: x.RCP} {
		if want == "" {
			continue
		}
		found := false
		for _, s := range d.Steps {
			if s.Stage == stage && string(s.Result) == want {
				found = true
			}
		}
		if !found {
			fail("no %s step with result %s", stage, want)
		}
	}
	checkFidelity(t, label, c, d, x, fail)
	for _, rc := range x.ResidualChecks {
		if d.Outcome != authz.Conditional {
			fail("residual checks need a CONDITIONAL decision")
			break
		}
		cx := &eval.Context{Mode: eval.Concrete, Values: ctxValues(rc.Context)}
		got := eval.EvalResidual(d.Residual, cx, true)
		if got.IsTrue() != rc.Holds || got.IsUnknown() {
			fail("residual %s under %v is %v, want holds=%v", authz.Render(d.Residual, authz.RenderOptions{}), rc.Context, got, rc.Holds)
		}
	}
}

func checkFidelity(t *testing.T, label string, c goldenCase, d *authz.Decision, x *goldenExpect, fail func(string, ...any)) {
	var sensitive []string
	for _, r := range d.FidelityReasons {
		if r.OutcomeSensitive {
			sensitive = append(sensitive, string(r.Code))
		}
	}
	sort.Strings(sensitive)
	if x.Fidelity != "" {
		if d.Fidelity.String() != x.Fidelity {
			fail("fidelity %s, want %s (reasons %v)", d.Fidelity, x.Fidelity, sensitive)
		}
		if x.Reasons != nil {
			want := append([]string(nil), x.Reasons...)
			sort.Strings(want)
			if strings.Join(want, ",") != strings.Join(sensitive, ",") {
				fail("outcome-sensitive reasons %v, want %v", sensitive, want)
			}
		}
		return
	}
	// The design lists no fidelity: the decision is EXACT, except for the
	// ambiguities the case itself names (pending-probe or known_flags).
	allowed := map[string]bool{}
	for _, id := range c.KnownFlags {
		allowed["AMBIGUITY:"+id] = true
	}
	if id, ok := strings.CutPrefix(c.Verified, "pending-probe:"); ok {
		allowed["AMBIGUITY:"+id] = true
	}
	for _, code := range sensitive {
		if !allowed[code] {
			fail("fidelity %s with unexpected outcome-sensitive reason %s; the design expects exact", d.Fidelity, code)
		}
	}
}
