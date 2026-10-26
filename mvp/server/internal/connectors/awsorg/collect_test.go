package awsorg

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/awsreplay"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

const (
	acctMgmt   = "111111111111"
	acctMember = "222222222222"
	acctOld    = "333333333333"
)

func TestCollect_Organization(t *testing.T) {
	col, r := collectFixtures(t)
	s := col.Snapshot

	if !slices.Equal(col.AccountIDs, []string{acctMgmt, acctMember}) {
		t.Errorf("AccountIDs = %v", col.AccountIDs)
	}
	if s.ID == "" || !s.TakenAt.Equal(testNow) {
		t.Errorf("ID %q, TakenAt %v", s.ID, s.TakenAt)
	}

	// ---- organization: tree, SCPs, RCPs
	org := s.Org
	if org == nil || org.OrgID != "o-example12345" || org.ManagementAccountID != acctMgmt || !org.SCPEnabled || !org.RCPEnabled {
		t.Fatalf("org = %+v", org)
	}
	for id, want := range map[string]struct {
		kind   model.OrgNodeKind
		parent string
	}{"r-ab12": {model.OrgRoot, ""}, "ou-ab12-prod0001": {model.OrgOU, "r-ab12"}, acctMgmt: {model.OrgAccount, "r-ab12"},
		acctOld: {model.OrgAccount, "r-ab12"}, acctMember: {model.OrgAccount, "ou-ab12-prod0001"}} {
		n := org.Nodes[id]
		if n == nil || n.Kind != want.kind || n.ParentID != want.parent {
			t.Errorf("node %s = %+v, want %v under %q", id, n, want.kind, want.parent)
		}
	}
	if got := org.PathTo(acctMember); len(got) != 3 || got[0].ID != "r-ab12" || got[1].ID != "ou-ab12-prod0001" {
		t.Errorf("PathTo(member) = %v", got)
	}
	if n := org.Nodes["r-ab12"]; len(n.SCPIDs) != 1 || len(n.RCPIDs) != 1 {
		t.Errorf("root SCPs %v RCPs %v; want FullAWSAccess and the RCP", n.SCPIDs, n.RCPIDs)
	}
	ou := org.Nodes["ou-ab12-prod0001"]
	if len(ou.SCPIDs) != 1 {
		t.Fatalf("OU SCPs = %v; want only the region deny (the broken SCP is not attached as an empty policy)", ou.SCPIDs)
	}
	if d := s.Policies[ou.SCPIDs[0]]; d == nil || d.Kind != model.PolicySCP || d.SourceARN != "arn:aws:organizations::111111111111:policy/o-example12345/service_control_policy/p-deny0001" ||
		len(d.Statements) != 1 || d.Statements[0].Effect != model.EffectDeny {
		t.Errorf("OU SCP = %+v", d)
	}
	if d := s.Policies[org.Nodes["r-ab12"].SCPIDs[0]]; d == nil || !d.AWSManaged {
		t.Errorf("FullAWSAccess = %+v, want AWS managed", d)
	}

	// ---- IAM
	alice := s.Principals["arn:aws:iam::111111111111:user/alice"]
	if alice == nil || alice.Kind != model.IAMUser || alice.AccountID != acctMgmt || alice.UniqueID != "AIDAEXAMPLEALICE" || alice.Path != "/" ||
		alice.Tags["team"] != "data" || !slices.Equal(alice.GroupARNs, []string{"arn:aws:iam::111111111111:group/eng"}) {
		t.Fatalf("alice = %+v", alice)
	}
	if alice.CreateDate != "2024-01-01T00:00:00Z" {
		t.Errorf("alice.CreateDate = %q", alice.CreateDate)
	}
	for in, want := range map[string]string{"2024-01-01T00:00:00Z": "2024-01-01T00:00:00Z", "2024-01-01T02:00:00+02:00": "2024-01-01T00:00:00Z", "": "", "yesterday": ""} {
		if got := createDate(in); got != want {
			t.Errorf("createDate(%q) = %q, want %q", in, got, want)
		}
	}
	if len(alice.IdentityPolicyIDs) != 3 {
		t.Fatalf("alice has %d identity policies, want inline + managed + the group's", len(alice.IdentityPolicyIDs))
	}
	wantActions := []string{"s3:GetObject", "kms:Decrypt", "sqs:SendMessage"} // inline, managed (default version v2, not v1), group inline
	for i, id := range alice.IdentityPolicyIDs {
		d := s.Policies[id]
		if d == nil || d.Kind != model.PolicyIdentity || d.Statements[0].Actions.Patterns[0] != wantActions[i] {
			t.Errorf("alice policy %d = %+v, want %s", i, d, wantActions[i])
		}
	}
	if d := s.Policies[alice.BoundaryPolicyID]; d == nil || d.Kind != model.PolicyBoundary || d.SourceARN != "arn:aws:iam::111111111111:policy/DataBoundary" {
		t.Errorf("alice boundary = %+v", d)
	}
	eng := s.Principals["arn:aws:iam::111111111111:role/DataEngineer"]
	if eng == nil || eng.Kind != model.IAMRole || eng.Tags["env"] != "prod" || len(eng.IdentityPolicyIDs) != 1 || eng.BoundaryPolicyID == "" {
		t.Fatalf("DataEngineer = %+v", eng)
	}
	if d := s.Policies[eng.IdentityPolicyIDs[0]]; !d.AWSManaged || d.SourceARN != "arn:aws:iam::aws:policy/ReadOnlyAccess" {
		t.Errorf("ReadOnlyAccess = %+v", d)
	}
	trust := s.ResourcePolicies["arn:aws:iam::111111111111:role/DataEngineer"]
	if len(trust) != 1 || trust[0].Kind != model.PolicyTrust || !trust[0].RequiresExplicitAllow {
		t.Fatalf("trust = %+v", trust)
	}
	if d := s.Policies[trust[0].PolicyID]; d.SourceARN != "arn:aws:iam::111111111111:role/DataEngineer#trust" {
		t.Errorf("trust doc = %+v", d)
	}
	sso := s.Principals["arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_0123456789abcdef"]
	if sso == nil || sso.Path != "/aws-reserved/sso.amazonaws.com/" {
		t.Errorf("SSO role = %+v", sso)
	}
	// the policy of every attachment is a document of the snapshot
	for _, a := range s.Attachments {
		if s.Policies[a.PolicyID] == nil {
			t.Errorf("attachment %+v names a missing document", a)
		}
	}
	// documents keep the bytes AWS sent, URL-decoded
	if d := s.Policies[alice.IdentityPolicyIDs[0]]; string(d.RawJSON) !=
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::prod-pii/*"}]}` {
		t.Errorf("alice inline raw = %s", d.RawJSON)
	}

	// ---- S3
	pii := s.S3["arn:aws:s3:::prod-pii"]
	if pii == nil || pii.OwnerAccount != acctMgmt || pii.ObjectOwnership != "BucketOwnerEnforced" ||
		pii.BPABucket != (model.BPA{BlockPublicAcls: true, IgnorePublicAcls: true, RestrictPublicBuckets: true}) ||
		pii.BPAAccount != (model.BPA{BlockPublicAcls: true, BlockPublicPolicy: true}) ||
		len(pii.BucketACL) != 1 || pii.BucketACL[0].GranteeType != "CanonicalUser" || pii.BucketACL[0].Permission != "FULL_CONTROL" {
		t.Errorf("prod-pii = %+v", pii)
	}
	if rp := s.ResourcePolicies["arn:aws:s3:::prod-pii"]; len(rp) != 1 || rp[0].Kind != model.PolicyResource || rp[0].RequiresExplicitAllow {
		t.Errorf("prod-pii policy = %+v", rp)
	}
	legacy := s.S3["arn:aws:s3:::legacy.logs"]
	if legacy == nil || legacy.ObjectOwnership != "ObjectWriter" || legacy.BPABucket != (model.BPA{}) ||
		len(legacy.BucketACL) != 1 || legacy.BucketACL[0].Grantee != "http://acs.amazonaws.com/groups/global/AllUsers" {
		t.Errorf("legacy.logs = %+v (no ownership controls means ObjectWriter; no bucket policy is not an error)", legacy)
	}
	if len(s.ResourcePolicies["arn:aws:s3:::legacy.logs"]) != 0 {
		t.Error("legacy.logs has a policy")
	}
	if s.CanonicalIDs["79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"] != acctMgmt {
		t.Errorf("canonical ids = %v", s.CanonicalIDs)
	}
	ap := "arn:aws:s3:us-east-1:111111111111:accesspoint/ap-data"
	if rp := s.ResourcePolicies[ap]; len(rp) != 1 || rp[0].Kind != model.PolicyS3AccessPoint {
		t.Errorf("access point policy = %+v", rp)
	}

	// ---- KMS
	key := "arn:aws:kms:us-east-1:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	if rp := s.ResourcePolicies[key]; len(rp) != 1 || rp[0].Kind != model.PolicyKMSKey || !rp[0].RequiresExplicitAllow {
		t.Errorf("key policy = %+v", rp)
	}
	gs := s.KMSGrants[key]
	if len(gs) != 2 || gs[0].GrantID != "grant-1" || gs[0].GranteePrincipal != "arn:aws:iam::111111111111:role/DataEngineer" ||
		!slices.Equal(gs[0].Operations, []string{"Decrypt", "GenerateDataKey"}) || gs[0].ConstraintsECSubset["app"] != "pii" ||
		gs[0].RetiringPrincipal != "arn:aws:iam::111111111111:root" || !gs[0].CreatedAt.Equal(time.Unix(1760000000, 0).UTC()) ||
		gs[1].GranteeServicePrincipal != "lambda.amazonaws.com" || gs[1].GranteePrincipal != "" {
		t.Errorf("grants = %+v", gs)
	}

	// ---- the other resource policies, VPC endpoint policies
	for _, arn := range []string{"arn:aws:sqs:us-east-1:111111111111:jobs", "arn:aws:sns:us-east-1:111111111111:alerts",
		"arn:aws:secretsmanager:us-east-1:111111111111:secret:db-AbCdEf", "arn:aws:lambda:us-east-1:111111111111:function:ingest",
		"arn:aws:ecr:us-east-1:111111111111:repository/app"} {
		if rp := s.ResourcePolicies[arn]; len(rp) != 1 || rp[0].Kind != model.PolicyResource {
			t.Errorf("policy of %s = %+v", arn, rp)
		}
		if res := s.Resources[arn]; res == nil || res.AccountID != acctMgmt || res.Region != "us-east-1" {
			t.Errorf("resource %s = %+v", arn, res)
		}
	}
	if id := s.VPCEPolicies["vpce-0abc"]; id == "" || s.Policies[id] == nil || s.Policies[id].Kind != model.PolicyVPCE {
		t.Errorf("vpce policies = %v", s.VPCEPolicies)
	}

	// ---- Identity Center
	if len(col.IdentityCenter) != 1 {
		t.Fatalf("identity center = %+v", col.IdentityCenter)
	}
	if a := col.IdentityCenter[0]; a.AccountID != acctMgmt || a.PermissionSetName != "Admin" || a.PrincipalType != "GROUP" || a.PrincipalID != "g-0000000001" ||
		a.RoleARN != sso.ARN {
		t.Errorf("assignment = %+v", a)
	}

	// ---- findings (design §3.3): nothing unreadable is skipped silently
	if f := findFinding(col.Findings, store.AWSFindingAccountError, acctOld); f == nil || f.Code != "AccountNotActive" ||
		f.Scope.Type != ScopeAccounts || !slices.Equal(f.Scope.Targets, []string{acctOld}) {
		t.Errorf("suspended account finding = %+v", f)
	}
	if f := findFinding(col.Findings, store.AWSFindingPolicyUnparseable, "p-broken01"); f == nil || f.Scope.Type != ScopeRequesterAccounts ||
		!slices.Equal(f.Scope.Targets, []string{acctMember}) || f.PolicyKind != "scp" {
		t.Errorf("broken SCP finding = %+v (want every account under the OU it is attached to)", f)
	}
	worker := "arn:aws:iam::222222222222:role/Worker"
	if f := findFinding(col.Findings, store.AWSFindingPolicyUnparseable, "#inline/broken"); f == nil || f.Code != "duplicate_key" ||
		f.Scope.Type != ScopePrincipals || !slices.Equal(f.Scope.Targets, []string{worker}) {
		t.Errorf("broken inline finding = %+v", f)
	}
	if f := findFinding(col.Findings, store.AWSFindingStatementDropped, "#inline/mixed"); f == nil || f.Code != "INVALID_ELEMENT_MIX" ||
		!slices.Equal(f.Scope.Targets, []string{worker}) {
		t.Errorf("dropped statement finding = %+v", f)
	}
	if f := findFinding(col.Findings, store.AWSFindingAccountError, "policy/Vanished"); f == nil || f.Code != "ManagedPolicyMissing" ||
		!slices.Equal(f.Scope.Targets, []string{worker}) {
		t.Errorf("missing managed policy finding = %+v", f)
	}
	// a policy that did not parse is not in the snapshot, not even as an empty document
	for _, d := range s.Policies {
		if strings.Contains(d.SourceARN, "p-broken01") || strings.HasSuffix(d.SourceARN, "#inline/broken") {
			t.Errorf("unparseable policy %s is in the snapshot", d.SourceARN)
		}
	}
	if len(col.Findings) != 5 {
		t.Errorf("findings = %d, want 5: %+v", len(col.Findings), col.Findings)
	}

	// ---- how it was fetched
	if n := r.Calls("sts/AssumeRole"); n != 2 {
		t.Errorf("AssumeRole called %d times, want once per account read (the management session is reused)", n)
	}
	if n := r.Calls("iam/GetAccountAuthorizationDetails"); n != 3 {
		t.Errorf("GetAccountAuthorizationDetails called %d times, want 2 pages + 1", n)
	}
	for _, q := range r.Requests() {
		isSTS := q.Service == "sts"
		if isSTS && (q.AccessKeyID != baseKeyID || q.SessionToken != "") {
			t.Errorf("AssumeRole signed with %s token %q; want the base keys", q.AccessKeyID, q.SessionToken)
		}
		if !isSTS && (q.AccessKeyID != sessionKeyID || q.SessionToken == "") {
			t.Errorf("%s/%s signed with %s, token %q; want the assumed role's session", q.Service, q.Operation, q.AccessKeyID, q.SessionToken)
		}
	}
	for _, q := range r.Requests() {
		if q.Service == "sts" {
			arn := q.Form.Get("RoleArn")
			if (arn != "arn:aws:iam::111111111111:role/TesseraReader" && arn != "arn:aws:iam::222222222222:role/TesseraReader") ||
				q.Form.Get("ExternalId") != externalID || q.Form.Get("RoleSessionName") == "" || q.Form.Get("DurationSeconds") != "3600" {
				t.Errorf("AssumeRole form = %v", q.Form)
			}
		}
	}
}

// TestCollect_UsesOnlyReaderActions: every call the connector makes is one of
// ReaderActions, and every ReaderAction is used: the policy the customer is
// asked to attach is neither too small nor too big.
func TestCollect_UsesOnlyReaderActions(t *testing.T) {
	_, r := collectFixtures(t)
	control := map[string]string{"GetPublicAccessBlock": "s3:GetAccountPublicAccessBlock", "ListAccessPoints": "s3:ListAccessPoints",
		"GetAccessPointPolicy": "s3:GetAccessPointPolicy"}
	used := map[string]bool{}
	for _, q := range r.Requests() {
		if q.Service == "sts" {
			continue // the caller's permission, in the role's trust policy
		}
		action := q.Service + ":" + q.Operation
		if q.Service == "s3" && strings.Contains(q.Host, ".s3-control.") {
			action = control[q.Operation]
		}
		if !slices.Contains(ReaderActions, action) {
			t.Errorf("the connector called %s, which ReaderActions does not allow", action)
		}
		used[action] = true
	}
	for _, a := range ReaderActions {
		if a == "iam:SimulatePrincipalPolicy" {
			continue // the shadow agreement's, not the collection's: TestSimulator_AsksTheAccountOfThePrincipal
		}
		if !used[a] && !usageActions[a] && !verifyActions[a] { // those are called by the usage ingest (TestCollectUsage_UsesOnlyReaderActions)
			t.Errorf("ReaderActions has %s, which the fixture run never calls", a)
		}
	}
}

func TestCollect_RequestShapes(t *testing.T) {
	_, r := collectFixtures(t)
	var pii, legacy, ctrl, org bool
	for _, q := range r.Requests() {
		switch {
		case q.Service == "s3" && q.Operation == "GetBucketPolicy" && q.Host == "prod-pii.s3.us-east-1.amazonaws.com":
			pii = q.Path == "/" && q.Method == "GET"
			if _, ok := q.Query["policy"]; !ok {
				t.Errorf("GetBucketPolicy query = %v", q.Query)
			}
		case q.Service == "s3" && q.Operation == "GetBucketPolicy" && q.Host == "s3.us-east-1.amazonaws.com":
			legacy = q.Path == "/legacy.logs" // a dot in the name: path-style, the wildcard certificate would not match
		case q.Operation == "GetPublicAccessBlock":
			ctrl = q.Host == "111111111111.s3-control.us-east-1.amazonaws.com" || q.Host == "222222222222.s3-control.us-east-1.amazonaws.com"
		case q.Service == "organizations":
			org = q.Host == "organizations.us-east-1.amazonaws.com" && q.Region == "us-east-1"
		case q.Service == "iam":
			if q.Host != "iam.amazonaws.com" || q.Region != "us-east-1" || q.Form.Get("Version") != "2010-05-08" || q.Form.Get("MaxItems") != "1000" {
				t.Errorf("iam request = %+v", q)
			}
		}
	}
	if !pii || !legacy || !ctrl || !org {
		t.Errorf("request shapes: virtual-hosted %v, path-style %v, s3control %v, organizations %v", pii, legacy, ctrl, org)
	}
	// the second IAM page carries the marker of the first
	var markers []string
	for _, q := range r.Requests() {
		if q.Service == "iam" {
			markers = append(markers, q.Form.Get("Marker"))
		}
	}
	if !slices.Equal(markers, []string{"", "PAGE2MARKER", ""}) {
		t.Errorf("IAM markers = %q", markers)
	}
}

// TestCollect_ContentIDStable: the snapshot id is the content hash. It does not
// depend on when the run happened, and it changes with any policy change.
func TestCollect_ContentIDStable(t *testing.T) {
	a, _ := collectFixtures(t)

	r := newReplay(t)
	c := newCollector(t, r, orgConfig())
	c.Now = func() time.Time { return testNow.Add(48 * time.Hour) }
	b, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.Snapshot.ID != b.Snapshot.ID {
		t.Errorf("same estate, different ids: %s vs %s", a.Snapshot.ID, b.Snapshot.ID)
	}
	if a.Snapshot.TakenAt.Equal(b.Snapshot.TakenAt) {
		t.Error("TakenAt did not change")
	}

	// one bucket policy changes: another id
	r2 := newReplay(t)
	r2.Enqueue("s3/GetBucketPolicy",
		awsreplay.Response{Body: `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::prod-pii/*"}]}`},
		awsreplay.Response{Status: 404, Body: fixture(t, "s3/GetBucketPolicy/2.404.xml")})
	d, err := newCollector(t, r2, orgConfig()).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.Snapshot.ID == d.Snapshot.ID {
		t.Error("a changed bucket policy kept the snapshot id")
	}

	// an unreadable policy is part of the content too
	r3 := newReplay(t)
	r3.Enqueue("s3/GetBucketPolicy", awsreplay.Response{Status: 403, Body: `<Error><Code>AccessDenied</Code><Message>no</Message></Error>`},
		awsreplay.Response{Status: 404, Body: fixture(t, "s3/GetBucketPolicy/2.404.xml")})
	e, err := newCollector(t, r3, orgConfig()).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.Snapshot.ID == e.Snapshot.ID {
		t.Error("a gap kept the snapshot id")
	}
}

func TestCollect_FailureModes(t *testing.T) {
	sts := fixture(t, "sts/AssumeRole/1.xml")
	denied := awsreplay.Response{Status: 403, Body: `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not authorized to assume</Message></Error></ErrorResponse>`}

	t.Run("one account refuses the role", func(t *testing.T) {
		r := newReplay(t)
		r.Enqueue("sts/AssumeRole", awsreplay.Response{Body: sts}, denied)
		col, err := newCollector(t, r, orgConfig()).Collect(context.Background())
		if err != nil {
			t.Fatalf("a per-account AccessDenied aborted the run: %v", err)
		}
		if !slices.Equal(col.AccountIDs, []string{acctMgmt}) {
			t.Errorf("AccountIDs = %v", col.AccountIDs)
		}
		f := findFinding(col.Findings, store.AWSFindingAccountError, acctMember)
		if f == nil || f.Code != "AccessDenied" || f.Scope.Type != ScopeAccounts || !slices.Equal(f.Scope.Targets, []string{acctMember}) {
			t.Errorf("finding = %+v", f)
		}
		// everything about the account that could not be read is UNSUPPORTED, nothing about the others
		if got := col.Findings.Unsupported(Request{PrincipalARN: "arn:aws:iam::222222222222:role/Worker", PrincipalAccount: acctMember}); len(got) == 0 {
			t.Error("a principal of the unread account is not UNSUPPORTED")
		}
		if got := col.Findings.Unsupported(Request{PrincipalARN: "arn:aws:iam::111111111111:user/alice", PrincipalAccount: acctMgmt,
			ResourceARN: "arn:aws:sqs:us-east-1:111111111111:jobs", ResourceAccount: acctMgmt}); len(got) != 0 {
			t.Errorf("a request within the read account has reasons: %v", got)
		}
	})

	t.Run("the management account refuses the role", func(t *testing.T) {
		r := newReplay(t)
		r.Enqueue("sts/AssumeRole", denied)
		if _, err := newCollector(t, r, orgConfig()).Collect(context.Background()); err == nil || !IsAccessDenied(err) {
			t.Errorf("err = %v, want the AccessDenied of the management account", err)
		}
	})

	t.Run("the organization cannot be read", func(t *testing.T) {
		r := newReplay(t)
		r.Enqueue("organizations/ListRoots", awsreplay.Response{Status: 400, Body: `{"__type":"AccessDeniedException","Message":"no"}`})
		if _, err := newCollector(t, r, orgConfig()).Collect(context.Background()); err == nil || !IsAccessDenied(err) {
			t.Errorf("err = %v, want AccessDenied (SCPs of an unread tree are unknown: the run fails)", err)
		}
	})

	t.Run("no account can be read", func(t *testing.T) {
		r := newReplay(t)
		cfg := &Config{Regions: []string{"us-east-1"}, AccountIDs: []string{acctMember}}
		r.Enqueue("sts/AssumeRole", denied)
		if _, err := newCollector(t, r, cfg).Collect(context.Background()); err == nil || !strings.Contains(err.Error(), "no account could be read") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("a policy that cannot be read is a gap over its resource only", func(t *testing.T) {
		r := newReplay(t)
		r.Enqueue("s3/GetBucketPolicy",
			awsreplay.Response{Status: 403, Body: `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`},
			awsreplay.Response{Status: 404, Body: fixture(t, "s3/GetBucketPolicy/2.404.xml")})
		r.Enqueue("kms/ListKeys", awsreplay.Response{Status: 400, Body: `{"__type":"AccessDeniedException","message":"region denied by an SCP"}`},
			awsreplay.Response{Body: `{"Keys":[],"Truncated":false}`})
		col, err := newCollector(t, r, orgConfig()).Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		bucket := findFinding(col.Findings, store.AWSFindingAccountError, "arn:aws:s3:::prod-pii")
		if bucket == nil || bucket.Code != "AccessDenied" || bucket.Scope.Type != ScopeResources {
			t.Fatalf("bucket finding = %+v", bucket)
		}
		if len(col.Snapshot.ResourcePolicies["arn:aws:s3:::prod-pii"]) != 0 {
			t.Error("a policy that could not be read was recorded as present")
		}
		// the objects of the bucket are covered, another bucket is not
		req := func(resource, account string) Request {
			return Request{PrincipalARN: "arn:aws:iam::" + account + ":user/u", PrincipalAccount: account, ResourceARN: resource, ResourceAccount: account}
		}
		if got := col.Findings.Unsupported(req("arn:aws:s3:::prod-pii/data/x.csv", acctMgmt)); len(got) != 1 ||
			got[0].Code != authz.ReasonPolicyUnparseable || !got[0].OutcomeSensitive || !strings.Contains(got[0].Detail, "arn:aws:s3:::prod-pii") {
			t.Errorf("object of the bucket: %+v", got)
		}
		if got := col.Findings.Unsupported(req("arn:aws:s3:::prod-pii-other/x", acctMgmt)); len(got) != 0 {
			t.Errorf("a bucket whose name only starts with this one's: %+v", got)
		}
		// a failed list is a gap over every key of that region and account
		if got := col.Findings.Unsupported(req("arn:aws:kms:us-east-1:111111111111:key/abc", acctMgmt)); len(got) != 1 {
			t.Errorf("a key of the unlisted region: %+v", got)
		}
		if got := col.Findings.Unsupported(req("arn:aws:kms:us-east-1:222222222222:key/abc", acctMember)); len(got) != 1 {
			t.Errorf("a key of the other account: %+v (only the broken SCP of its account applies)", got)
		}
	})
}

func TestCollect_NonOrganizationMode(t *testing.T) {
	r := newReplay(t)
	cfg := &Config{Regions: []string{"us-east-1"}, AccountIDs: []string{acctMember, acctMgmt, acctMember}}
	col, err := newCollector(t, r, cfg).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if col.Snapshot.Org != nil || r.Calls("organizations/DescribeOrganization") != 0 {
		t.Error("an organization was read with no management account configured")
	}
	if !slices.Equal(col.AccountIDs, []string{acctMgmt, acctMember}) { // sorted, de-duplicated
		t.Errorf("AccountIDs = %v", col.AccountIDs)
	}
	if r.Calls("sso/ListInstances") != 0 {
		t.Error("Identity Center was read with no management account")
	}
}
