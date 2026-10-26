package awsorg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// verifyActions are the ReaderActions the write target's re-reads use (TestWriteTarget_ReadsAreTheReaders).
var verifyActions = map[string]bool{
	"iam:GetRolePolicy": true, "iam:GetUserPolicy": true, "iam:GetGroupPolicy": true,
	"iam:ListAttachedRolePolicies": true, "iam:ListAttachedUserPolicies": true, "iam:ListAttachedGroupPolicies": true,
	"iam:GetPolicy": true, "iam:GetPolicyVersion": true, "iam:ListPolicyVersions": true, "iam:ListGroupsForUser": true,
	"sso:DescribeAccountAssignmentCreationStatus": true, "sso:DescribeAccountAssignmentDeletionStatus": true,
}

const (
	wAcct      = "111111111111"
	wReaderKey = "ASIAREADERREADER001"
	wWriterKey = "ASIAWRITERWRITER001"
	wSecret    = "secretsecretsecretsecretsecret0123456789"
	wRole      = "arn:aws:iam::" + wAcct + ":role/Analyst"
	wUser      = "arn:aws:iam::" + wAcct + ":user/alice"
	wPolicy    = "arn:aws:iam::" + wAcct + ":policy/S3Read"
	wInstance  = "arn:aws:sso:::instance/ssoins-0123456789abcdef"
	wPermSet   = "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-0123456789abcdef"
	wPrincipal = "90670f6f2f-1234abcd-5678-90ab-cdef12345678"

	docWide   = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	docOther  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`
	docNarrow = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/k"}]}`
)

// fakeAWS is a stateful AWS: it answers the IAM, STS and Identity Center calls of the write target, checks the SigV4
// signature of each, and lets only the writer role's credentials write and only the reader role's read.
type fakeAWS struct {
	mu sync.Mutex
	// state
	attached    map[string][]string // "role/Analyst" -> policy ARNs
	inline      map[string]string   // "role/Analyst/Inline" -> document
	defaultVer  map[string]string   // policy ARN -> default version id
	versions    map[string]map[string]string
	groups      map[string][]string // user name -> groups
	assignments map[string]bool     // principal id
	ssoStatus   string              // what a Describe*Status says (default SUCCEEDED)
	ssoFail     bool                // Create/DeleteAccountAssignment answers FAILED
	// faults
	dropWrites bool // accept a write and do nothing
	deny       map[string]bool
	failOnce   map[string]int // action -> HTTP status to answer the next time
	// record
	calls  []fakeCall
	errors []string
}

type fakeCall struct{ Action, Key string }

func newFakeAWS() *fakeAWS {
	return &fakeAWS{
		attached:    map[string][]string{"role/Analyst": {wPolicy, "arn:aws:iam::aws:policy/ReadOnlyAccess"}},
		inline:      map[string]string{"role/Analyst/Inline": docWide},
		defaultVer:  map[string]string{wPolicy: "v1"},
		versions:    map[string]map[string]string{wPolicy: {"v1": docWide}},
		groups:      map[string][]string{"alice": {"Devs", "Ops"}},
		assignments: map[string]bool{wPrincipal: true},
		deny:        map[string]bool{}, failOnce: map[string]int{},
	}
}

func iamDoc(doc string) string { return url.PathEscape(doc) }

func xmlOK(action, result string) string {
	return fmt.Sprintf(`<%sResponse><%sResult>%s</%sResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></%sResponse>`,
		action, action, result, action, action)
}

func xmlErr(code string) string {
	return `<ErrorResponse><Error><Type>Sender</Type><Code>` + code + `</Code><Message>fake ` + code + `</Message></Error></ErrorResponse>`
}

func (f *fakeAWS) Do(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	reply := func(status int, b string) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(b)), Request: req}, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var action string
	var q url.Values
	if t := req.Header.Get("X-Amz-Target"); t != "" {
		action = t[strings.LastIndex(t, ".")+1:]
	} else {
		var err error
		if q, err = url.ParseQuery(string(body)); err != nil {
			return reply(400, xmlErr("MalformedInput"))
		}
		action = q.Get("Action")
	}
	service := strings.SplitN(req.URL.Host, ".", 2)[0]
	if service == "sts" {
		key := wReaderKey
		if strings.Contains(q.Get("RoleArn"), "/"+DefaultWriterRoleName) {
			key = wWriterKey
		}
		if q.Get("WebIdentityToken") == "" || action != "AssumeRoleWithWebIdentity" {
			f.errors = append(f.errors, "sts call without a web identity token")
		}
		return reply(200, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>`+key+
			`</AccessKeyId><SecretAccessKey>`+wSecret+`</SecretAccessKey><SessionToken>tok-`+key+`</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`)
	}
	// signed with the reader's or the writer's credentials, and the signature is right
	auth := req.Header.Get("Authorization")
	key := ""
	if i := strings.Index(auth, "Credential="); i >= 0 {
		key = strings.SplitN(auth[i+len("Credential="):], "/", 2)[0]
	}
	var scope []string
	if i := strings.Index(auth, "Credential="); i >= 0 {
		scope = strings.Split(strings.SplitN(auth[i+len("Credential="):], ",", 2)[0], "/")
	}
	if key != wReaderKey && key != wWriterKey || len(scope) < 4 {
		f.errors = append(f.errors, "unknown key "+key)
		return reply(403, xmlErr("InvalidClientTokenId"))
	}
	if err := checkSig(req, body, key, scope[2], service); err != nil {
		f.errors = append(f.errors, err.Error())
	}
	full := service + ":" + action
	f.calls = append(f.calls, fakeCall{full, key})
	write := slices.Contains(WriterActions, full) || slices.Contains(RestoreActions, full)
	if write != (key == wWriterKey) || (!write && !slices.Contains(ReaderActions, full)) {
		f.errors = append(f.errors, fmt.Sprintf("%s was called with the wrong role's credentials (%s)", full, key))
		return reply(403, xmlErr("AccessDenied"))
	}
	if f.deny[full] {
		return reply(403, xmlErr("AccessDenied"))
	}
	if st := f.failOnce[full]; st != 0 {
		delete(f.failOnce, full)
		return reply(st, xmlErr("InternalFailure"))
	}
	if write && f.dropWrites {
		return reply(200, xmlOK(action, ""))
	}
	if service == "sso" {
		return f.sso(req, body, action, reply)
	}
	return f.iam(q, action, reply)
}

func checkSig(req *http.Request, body []byte, key, region, service string) error {
	date, err := time.Parse(sigv4.TimeLayout, req.Header.Get("X-Amz-Date"))
	if err != nil {
		return errors.New("missing or bad X-Amz-Date")
	}
	cp := req.Clone(req.Context())
	cp.Header = http.Header{}
	for k, v := range req.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Authorization", "X-Amz-Date", "X-Amz-Security-Token", "X-Amz-Content-Sha256", "User-Agent":
		default:
			cp.Header[k] = v
		}
	}
	c := sigv4.Credentials{AccessKeyID: key, SecretAccessKey: wSecret, SessionToken: req.Header.Get("X-Amz-Security-Token")}
	if err := sigv4.Sign(cp, body, c, region, service, date); err != nil {
		return err
	}
	if got, want := req.Header.Get("Authorization"), cp.Header.Get("Authorization"); got != want {
		return fmt.Errorf("signature mismatch for %s", service)
	}
	return nil
}

func (f *fakeAWS) iam(q url.Values, action string, reply func(int, string) (*http.Response, error)) (*http.Response, error) {
	principal := func() string {
		for _, k := range []string{"role/RoleName", "user/UserName", "group/GroupName"} {
			kind, p, _ := strings.Cut(k, "/")
			if v := q.Get(p); v != "" && strings.Contains(action, titleKind(kind)) {
				return kind + "/" + v
			}
		}
		return ""
	}
	switch {
	case strings.HasPrefix(action, "ListAttached"):
		p := principal()
		as, ok := f.attached[p]
		if !ok {
			return reply(404, xmlErr("NoSuchEntity"))
		}
		var b strings.Builder
		for _, a := range as {
			b.WriteString("<member><PolicyName>x</PolicyName><PolicyArn>" + a + "</PolicyArn></member>")
		}
		return reply(200, xmlOK(action, "<AttachedPolicies>"+b.String()+"</AttachedPolicies><IsTruncated>false</IsTruncated>"))
	case strings.HasPrefix(action, "Detach"):
		p := principal()
		f.attached[p] = slices.DeleteFunc(f.attached[p], func(a string) bool { return a == q.Get("PolicyArn") })
	case strings.HasPrefix(action, "Attach"):
		p := principal()
		f.attached[p] = append(f.attached[p], q.Get("PolicyArn"))
	case strings.HasPrefix(action, "Get") && strings.HasSuffix(action, "Policy") && action != "GetPolicy":
		d, ok := f.inline[principal()+"/"+q.Get("PolicyName")]
		if !ok {
			return reply(404, xmlErr("NoSuchEntity"))
		}
		return reply(200, xmlOK(action, "<PolicyDocument>"+iamDoc(d)+"</PolicyDocument>"))
	case strings.HasPrefix(action, "Delete") && strings.HasSuffix(action, "Policy"):
		delete(f.inline, principal()+"/"+q.Get("PolicyName"))
	case strings.HasPrefix(action, "Put") && strings.HasSuffix(action, "Policy"):
		f.inline[principal()+"/"+q.Get("PolicyName")] = q.Get("PolicyDocument")
	case action == "GetPolicy":
		d, ok := f.defaultVer[q.Get("PolicyArn")]
		if !ok {
			return reply(404, xmlErr("NoSuchEntity"))
		}
		return reply(200, xmlOK(action, "<Policy><DefaultVersionId>"+d+"</DefaultVersionId></Policy>"))
	case action == "GetPolicyVersion":
		d, ok := f.versions[q.Get("PolicyArn")][q.Get("VersionId")]
		if !ok {
			return reply(404, xmlErr("NoSuchEntity"))
		}
		return reply(200, xmlOK(action, "<PolicyVersion><Document>"+iamDoc(d)+"</Document><VersionId>"+q.Get("VersionId")+"</VersionId></PolicyVersion>"))
	case action == "ListPolicyVersions":
		var b strings.Builder
		for id := range f.versions[q.Get("PolicyArn")] {
			b.WriteString("<member><VersionId>" + id + "</VersionId></member>")
		}
		return reply(200, xmlOK(action, "<Versions>"+b.String()+"</Versions>"))
	case action == "CreatePolicyVersion":
		arn := q.Get("PolicyArn")
		id := fmt.Sprintf("v%d", len(f.versions[arn])+1)
		f.versions[arn][id] = q.Get("PolicyDocument")
		if q.Get("SetAsDefault") == "true" {
			f.defaultVer[arn] = id
		}
	case action == "SetDefaultPolicyVersion":
		f.defaultVer[q.Get("PolicyArn")] = q.Get("VersionId")
	case action == "ListGroupsForUser":
		gs, ok := f.groups[q.Get("UserName")]
		if !ok {
			return reply(404, xmlErr("NoSuchEntity"))
		}
		var b strings.Builder
		for _, g := range gs {
			b.WriteString("<member><GroupName>" + g + "</GroupName></member>")
		}
		return reply(200, xmlOK(action, "<Groups>"+b.String()+"</Groups><IsTruncated>false</IsTruncated>"))
	case action == "RemoveUserFromGroup":
		f.groups[q.Get("UserName")] = slices.DeleteFunc(f.groups[q.Get("UserName")], func(g string) bool { return g == q.Get("GroupName") })
	case action == "AddUserToGroup":
		f.groups[q.Get("UserName")] = append(f.groups[q.Get("UserName")], q.Get("GroupName"))
	default:
		f.errors = append(f.errors, "unhandled IAM action "+action)
		return reply(400, xmlErr("InvalidAction"))
	}
	return reply(200, xmlOK(action, ""))
}

func (f *fakeAWS) sso(req *http.Request, body []byte, action string, reply func(int, string) (*http.Response, error)) (*http.Response, error) {
	var in map[string]any
	_ = json.Unmarshal(body, &in)
	switch action {
	case "ListAccountAssignments":
		var b []string
		for id := range f.assignments {
			b = append(b, fmt.Sprintf(`{"AccountId":"%s","PermissionSetArn":"%s","PrincipalId":"%s","PrincipalType":"USER"}`, wAcct, wPermSet, id))
		}
		return reply(200, `{"AccountAssignments":[`+strings.Join(b, ",")+`]}`)
	case "DeleteAccountAssignment", "CreateAccountAssignment":
		st, key := "IN_PROGRESS", "AccountAssignmentCreationStatus"
		if action[0] == 'D' {
			key = "AccountAssignmentDeletionStatus"
		}
		if f.ssoFail {
			st = "FAILED"
		} else {
			f.assignments[fmt.Sprint(in["PrincipalId"])] = action[0] == 'C'
			if !f.assignments[fmt.Sprint(in["PrincipalId"])] {
				delete(f.assignments, fmt.Sprint(in["PrincipalId"]))
			}
		}
		return reply(200, `{"`+key+`":{"Status":"`+st+`","RequestId":"req-1","FailureReason":"no capacity"}}`)
	case "DescribeAccountAssignmentDeletionStatus", "DescribeAccountAssignmentCreationStatus":
		st := f.ssoStatus
		if st == "" {
			st = "SUCCEEDED"
		}
		key := "AccountAssignmentCreationStatus"
		if strings.Contains(action, "Deletion") {
			key = "AccountAssignmentDeletionStatus"
		}
		return reply(200, `{"`+key+`":{"Status":"`+st+`","RequestId":"req-1","FailureReason":"capacity"}}`)
	}
	f.errors = append(f.errors, "unhandled SSO action "+action)
	return reply(400, `{"__type":"InvalidAction","message":"x"}`)
}

func (f *fakeAWS) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if c.Key == wWriterKey {
			out = append(out, c.Action)
		}
	}
	return out
}

func (f *fakeAWS) clean(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.errors) > 0 {
		t.Errorf("the fake AWS saw: %v", f.errors)
	}
}

func newWriteTarget(t *testing.T, f *fakeAWS) *WriteTarget {
	t.Helper()
	cfg := &Config{Regions: []string{"us-east-1"}, AccountIDs: []string{wAcct}, ManagementAccountID: wAcct, IdentityCenterRegion: "us-east-1"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	tok := func(context.Context) (string, error) { return "web-identity-token", nil }
	return &WriteTarget{Client: testClient(f, nil), Config: cfg, ReaderToken: tok, WriterToken: tok, Now: func() time.Time { return testNow }}
}

func wreq(kind, who string, aw target.AWSChange) target.Request {
	return target.Request{Kind: kind, Key: "k-" + kind, Account: target.Account{Username: who}, AWS: &aw}
}

// applyVerify applies a request and re-reads it.
func applyVerify(t *testing.T, w *WriteTarget, r target.Request) (target.Verdict, error) {
	t.Helper()
	if err := w.Apply(context.Background(), r); err != nil {
		return target.Verdict{}, err
	}
	return w.Verify(context.Background(), r)
}

func inlineChange(doc string) target.AWSChange {
	return target.AWSChange{PolicyName: "Inline", Prior: doc, PriorSHA256: target.DocDigest(doc)}
}

// Every revoking kind changes the estate, and the re-read by the reader role shows it; the restore kind puts back
// what was there. The fake refuses a write made with the reader's credentials and a read with the writer's, so the
// roles are separate on the wire, and it checks each signature.
func TestWriteTarget_RevokeVerifyRestore(t *testing.T) {
	narrowSHA := target.DocDigest(docNarrow)
	for _, tc := range []struct {
		name        string
		revoke, who string
		aw          target.AWSChange
		wantWrite   string
		restore     string
		check       func(f *fakeAWS) bool // the estate after the revoke
		back        func(f *fakeAWS) bool // the estate after the restore
	}{
		{"detach", target.AWSDetachPolicy, wRole, target.AWSChange{PolicyARN: wPolicy}, "iam:DetachRolePolicy", target.AWSAttachPolicy,
			func(f *fakeAWS) bool { return !slices.Contains(f.attached["role/Analyst"], wPolicy) },
			func(f *fakeAWS) bool { return slices.Contains(f.attached["role/Analyst"], wPolicy) }},
		{"delete inline", target.AWSDeleteInlinePolicy, wRole, inlineChange(docWide), "iam:DeleteRolePolicy", target.AWSPutInlinePolicy,
			func(f *fakeAWS) bool { _, ok := f.inline["role/Analyst/Inline"]; return !ok },
			func(f *fakeAWS) bool { return f.inline["role/Analyst/Inline"] == docWide }},
		{"right-size", target.AWSSetPolicyVersion, wRole, target.AWSChange{PolicyARN: wPolicy, Document: docNarrow, Prior: docWide,
			PriorSHA256: target.DocDigest(docWide), PriorVersionID: "v1"}, "iam:CreatePolicyVersion", target.AWSRestorePolicyVersion,
			func(f *fakeAWS) bool { return f.defaultVer[wPolicy] == "v2" && len(f.versions[wPolicy]) == 2 },
			func(f *fakeAWS) bool { return f.defaultVer[wPolicy] == "v1" && len(f.versions[wPolicy]) == 2 }},
		{"group", target.AWSRemoveFromGroup, wUser, target.AWSChange{Group: "Devs"}, "iam:RemoveUserFromGroup", target.AWSAddToGroup,
			func(f *fakeAWS) bool { return !slices.Contains(f.groups["alice"], "Devs") },
			func(f *fakeAWS) bool { return slices.Contains(f.groups["alice"], "Devs") }},
		{"assignment", target.AWSDeleteAssignment, wPrincipal, target.AWSChange{AccountID: wAcct, InstanceARN: wInstance, PermissionSetARN: wPermSet,
			SSOPrincipalType: "USER", PriorSHA256: narrowSHA}, "sso:DeleteAccountAssignment", target.AWSCreateAssignment,
			func(f *fakeAWS) bool { return !f.assignments[wPrincipal] },
			func(f *fakeAWS) bool { return f.assignments[wPrincipal] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAWS()
			w := newWriteTarget(t, f)
			r := wreq(tc.revoke, tc.who, tc.aw)
			v, err := applyVerify(t, w, r)
			if err != nil || !v.OK {
				t.Fatalf("revoke: %+v, %v", v, err)
			}
			if !tc.check(f) {
				t.Fatalf("the estate did not change")
			}
			if got := f.writes(); !slices.Equal(got, []string{tc.wantWrite}) {
				t.Errorf("writes = %v, want [%s]", got, tc.wantWrite)
			}
			// the same change again converges: nothing is written twice
			if v, err := applyVerify(t, w, r); err != nil || !v.OK || len(f.writes()) != 1 {
				t.Errorf("a repeated revoke: %+v, %v, writes %v", v, err, f.writes())
			}
			// restore
			rr := wreq(tc.restore, tc.who, tc.aw)
			if tc.restore == target.AWSPutInlinePolicy {
				rr.AWS.Document = tc.aw.Prior
			}
			if v, err := applyVerify(t, w, rr); err != nil || !v.OK {
				t.Fatalf("restore: %+v, %v", v, err)
			}
			if !tc.back(f) {
				t.Errorf("the restore did not put the state back")
			}
			f.clean(t)
		})
	}
}

// A write the target accepted but did not make (or made differently) is found by the re-read: the verdict is not OK
// and says what was expected and what was observed. This is what the engine turns into a failed step with a finding
// and an audit event.
func TestWriteTarget_MismatchIsFound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		r      target.Request
		expect string
	}{
		{"detach", wreq(target.AWSDetachPolicy, wRole, target.AWSChange{PolicyARN: wPolicy}), "attached"},
		{"delete inline", wreq(target.AWSDeleteInlinePolicy, wRole, inlineChange(docWide)), "still present"},
		{"right-size", wreq(target.AWSSetPolicyVersion, wRole, target.AWSChange{PolicyARN: wPolicy, Document: docNarrow, Prior: docWide,
			PriorSHA256: target.DocDigest(docWide), PriorVersionID: "v1"}), "default version v1"},
		{"group", wreq(target.AWSRemoveFromGroup, wUser, target.AWSChange{Group: "Devs"}), "is in group Devs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAWS()
			f.dropWrites = true
			w := newWriteTarget(t, f)
			v, err := applyVerify(t, w, tc.r)
			if err != nil || v.OK || !strings.Contains(v.Observed, tc.expect) || v.Expected == "" {
				t.Errorf("verdict %+v, err %v", v, err)
			}
			f.clean(t)
		})
	}
}

// A policy whose new default version is not the document the change was meant to leave is a mismatch, even when a
// version was created; and a right-size that deleted the old version is one too (restore needs it).
func TestWriteTarget_RightSizeKeepsTheOldVersion(t *testing.T) {
	f := newFakeAWS()
	w := newWriteTarget(t, f)
	r := wreq(target.AWSSetPolicyVersion, wRole, target.AWSChange{PolicyARN: wPolicy, Document: docNarrow, Prior: docWide,
		PriorSHA256: target.DocDigest(docWide), PriorVersionID: "v1"})
	if v, err := applyVerify(t, w, r); err != nil || !v.OK {
		t.Fatalf("%+v %v", v, err)
	}
	delete(f.versions[wPolicy], "v1") // something deleted the old version after the write
	if v, err := w.Verify(context.Background(), r); err != nil || v.OK || !strings.Contains(v.Observed, "gone") {
		t.Errorf("verdict %+v, err %v", v, err)
	}
	f.versions[wPolicy]["v2"] = docWide // or the default holds some other document
	if v, err := w.Verify(context.Background(), r); err != nil || v.OK || !strings.Contains(v.Observed, "digest") {
		t.Errorf("verdict %+v, err %v", v, err)
	}
}

// A revoke is not made when the estate is no longer what it was evaluated against, and a restore is not made from a
// payload that does not match its digest.
func TestWriteTarget_RefusesDriftAndTampering(t *testing.T) {
	good := target.AWSChange{PolicyARN: wPolicy, Document: docNarrow, Prior: docWide, PriorSHA256: target.DocDigest(docWide), PriorVersionID: "v1"}
	for _, tc := range []struct {
		name  string
		setup func(f *fakeAWS)
		r     target.Request
		want  string
	}{
		{"inline policy changed", func(f *fakeAWS) { f.inline["role/Analyst/Inline"] = docNarrow },
			wreq(target.AWSDeleteInlinePolicy, wRole, inlineChange(docWide)), "was changed since"},
		{"default version moved", func(f *fakeAWS) { f.defaultVer[wPolicy] = "v9"; f.versions[wPolicy]["v9"] = docOther },
			wreq(target.AWSSetPolicyVersion, wRole, good), "was changed since"},
		{"five versions", func(f *fakeAWS) {
			for _, v := range []string{"v2", "v3", "v4", "v5"} {
				f.versions[wPolicy][v] = docWide
			}
		}, wreq(target.AWSSetPolicyVersion, wRole, good), "five versions"},
		{"prior altered", nil, wreq(target.AWSDeleteInlinePolicy, wRole, target.AWSChange{PolicyName: "Inline", Prior: docNarrow, PriorSHA256: target.DocDigest(docWide)}),
			"does not match its recorded digest"},
		{"restore document altered", nil, wreq(target.AWSPutInlinePolicy, wRole, target.AWSChange{PolicyName: "Inline", Document: docWide + " ", PriorSHA256: target.DocDigest(docNarrow)}),
			"does not match the digest"},
		{"restore of a version whose document changed", func(f *fakeAWS) {
			f.versions[wPolicy]["v1"] = docNarrow
			f.defaultVer[wPolicy] = "v2"
			f.versions[wPolicy]["v2"] = docNarrow
		},
			wreq(target.AWSRestorePolicyVersion, wRole, good), "no longer holds"},
		{"restore of a deleted version", func(f *fakeAWS) {
			delete(f.versions[wPolicy], "v1")
			f.defaultVer[wPolicy] = "v2"
			f.versions[wPolicy]["v2"] = docNarrow
		},
			wreq(target.AWSRestorePolicyVersion, wRole, good), "no longer exists"},
		{"another policy of that name", func(f *fakeAWS) {}, wreq(target.AWSPutInlinePolicy, wRole, target.AWSChange{PolicyName: "Inline", Document: docNarrow, PriorSHA256: target.DocDigest(docNarrow)}),
			"not overwritten"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAWS()
			if tc.setup != nil {
				tc.setup(f)
			}
			err := newWriteTarget(t, f).Apply(context.Background(), tc.r)
			if err == nil || !strings.Contains(err.Error(), tc.want) || target.Retryable(err) {
				t.Fatalf("err = %v, want a permanent %q", err, tc.want)
			}
			if w := f.writes(); len(w) != 0 {
				t.Errorf("a refused change wrote %v", w)
			}
			f.clean(t)
		})
	}
}

// The target refuses what its bounds do not allow before it makes a call: Tessera's own roles, Identity Center and
// service-linked roles, another account, an AWS-managed policy to right-size, malformed names.
func TestWriteTarget_RefusesWhatItMayNotTouch(t *testing.T) {
	other := "arn:aws:iam::222222222222:role/Analyst"
	for name, r := range map[string]target.Request{
		"the reader role":     wreq(target.AWSDetachPolicy, "arn:aws:iam::"+wAcct+":role/"+DefaultRoleName, target.AWSChange{PolicyARN: wPolicy}),
		"the writer role":     wreq(target.AWSDetachPolicy, "arn:aws:iam::"+wAcct+":role/"+DefaultWriterRoleName, target.AWSChange{PolicyARN: wPolicy}),
		"an SSO role":         wreq(target.AWSDetachPolicy, "arn:aws:iam::"+wAcct+":role/AWSReservedSSO_Admin_0123", target.AWSChange{PolicyARN: wPolicy}),
		"a service-linked":    wreq(target.AWSDetachPolicy, "arn:aws:iam::"+wAcct+":role/aws-service-role/x.amazonaws.com/Y", target.AWSChange{PolicyARN: wPolicy}),
		"another account":     wreq(target.AWSDetachPolicy, other, target.AWSChange{PolicyARN: wPolicy}),
		"not an ARN":          wreq(target.AWSDetachPolicy, "alice", target.AWSChange{PolicyARN: wPolicy}),
		"another partition":   wreq(target.AWSDetachPolicy, "arn:aws-cn:iam::"+wAcct+":role/A", target.AWSChange{PolicyARN: wPolicy}),
		"no policy":           wreq(target.AWSDetachPolicy, wRole, target.AWSChange{}),
		"a role in a group":   wreq(target.AWSRemoveFromGroup, wRole, target.AWSChange{Group: "Devs"}),
		"bad group":           wreq(target.AWSRemoveFromGroup, wUser, target.AWSChange{Group: "De vs;"}),
		"aws-managed resize":  wreq(target.AWSSetPolicyVersion, wRole, target.AWSChange{PolicyARN: "arn:aws:iam::aws:policy/ReadOnlyAccess", Document: docNarrow, Prior: docWide, PriorSHA256: target.DocDigest(docWide), PriorVersionID: "v1"}),
		"policy of another":   wreq(target.AWSSetPolicyVersion, wRole, target.AWSChange{PolicyARN: "arn:aws:iam::222222222222:policy/P", Document: docNarrow, Prior: docWide, PriorSHA256: target.DocDigest(docWide), PriorVersionID: "v1"}),
		"no prior version":    wreq(target.AWSSetPolicyVersion, wRole, target.AWSChange{PolicyARN: wPolicy, Document: docNarrow, Prior: docWide, PriorSHA256: target.DocDigest(docWide)}),
		"sso bad account":     wreq(target.AWSDeleteAssignment, wPrincipal, target.AWSChange{AccountID: "222222222222", InstanceARN: wInstance, PermissionSetARN: wPermSet, SSOPrincipalType: "USER"}),
		"sso bad type":        wreq(target.AWSDeleteAssignment, wPrincipal, target.AWSChange{AccountID: wAcct, InstanceARN: wInstance, PermissionSetARN: wPermSet, SSOPrincipalType: "ROLE"}),
		"sso bad instance":    wreq(target.AWSDeleteAssignment, wPrincipal, target.AWSChange{AccountID: wAcct, InstanceARN: "arn:aws:iam::1:role/x", PermissionSetARN: wPermSet, SSOPrincipalType: "USER"}),
		"unknown kind":        {Kind: "aws_nuke", Account: target.Account{Username: wRole}, AWS: &target.AWSChange{}},
		"no aws part":         {Kind: target.AWSDetachPolicy, Account: target.Account{Username: wRole}},
		"oversized document":  wreq(target.AWSPutInlinePolicy, wRole, target.AWSChange{PolicyName: "I", Document: strings.Repeat("x", maxDocBytes+1), PriorSHA256: "x"}),
		"mismatched kind tag": wreq(target.AWSDetachPolicy, wRole, target.AWSChange{PolicyARN: wPolicy, PrincipalType: "user"}),
	} {
		f := newFakeAWS()
		err := newWriteTarget(t, f).Apply(context.Background(), r)
		if err == nil || target.Retryable(err) {
			t.Errorf("%s: err = %v, want a permanent refusal", name, err)
		}
		if len(f.calls) != 0 {
			t.Errorf("%s: a refused change made %d AWS calls", name, len(f.calls))
		}
	}
	// no management account: Identity Center changes are refused
	f := newFakeAWS()
	w := newWriteTarget(t, f)
	w.Config.ManagementAccountID = ""
	if err := w.Apply(context.Background(), wreq(target.AWSDeleteAssignment, wPrincipal, target.AWSChange{AccountID: wAcct, InstanceARN: wInstance, PermissionSetARN: wPermSet, SSOPrincipalType: "USER"})); err == nil {
		t.Error("an Identity Center change without a management account was accepted")
	}
}

// AWS's refusal is permanent, its trouble is worth another try, and no error holds the web identity token.
func TestWriteTarget_Errors(t *testing.T) {
	f := newFakeAWS()
	f.deny["iam:DetachRolePolicy"] = true
	w := newWriteTarget(t, f)
	r := wreq(target.AWSDetachPolicy, wRole, target.AWSChange{PolicyARN: wPolicy})
	err := w.Apply(context.Background(), r)
	if err == nil || target.Retryable(err) || !strings.Contains(err.Error(), "denied") {
		t.Errorf("access denied: %v", err)
	}
	f = newFakeAWS()
	f.failOnce["iam:ListAttachedRolePolicies"] = 500
	w = newWriteTarget(t, f)
	w.Client.MaxAttempts = 1
	err = w.Apply(context.Background(), r)
	if err == nil || !target.Retryable(err) {
		t.Errorf("server error: %v", err)
	}
	// a principal that does not exist
	err = newWriteTarget(t, newFakeAWS()).Apply(context.Background(), wreq(target.AWSDetachPolicy, "arn:aws:iam::"+wAcct+":role/Ghost", target.AWSChange{PolicyARN: wPolicy}))
	if err == nil || target.Retryable(err) || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("unknown role: %v", err)
	}
	// a connector with no federation source cannot write
	w = newWriteTarget(t, newFakeAWS())
	w.WriterToken, w.ReaderToken = nil, nil
	if err := w.Apply(context.Background(), r); err == nil || target.Retryable(err) {
		t.Errorf("no tokens: %v", err)
	}
	// a token source that fails is retried, and its error is not echoed back with the token
	w = newWriteTarget(t, newFakeAWS())
	w.ReaderToken = func(context.Context) (string, error) { return "", errors.New("signing key unavailable") }
	if err := w.Apply(context.Background(), r); err == nil || !target.Retryable(err) {
		t.Errorf("token failure: %v", err)
	}
}

// Identity Center changes are asynchronous: while the request is in progress the re-read says so (the engine tries
// again), a request that failed is a mismatch with the reason, and once it succeeded the assignment list decides.
func TestWriteTarget_IdentityCenterStatus(t *testing.T) {
	aw := target.AWSChange{AccountID: wAcct, InstanceARN: wInstance, PermissionSetARN: wPermSet, SSOPrincipalType: "USER"}
	r := wreq(target.AWSDeleteAssignment, wPrincipal, aw)
	f := newFakeAWS()
	f.ssoStatus = "IN_PROGRESS"
	w := newWriteTarget(t, f)
	if v, err := applyVerify(t, w, r); err != nil || v.OK || !strings.Contains(v.Observed, "in progress") {
		t.Errorf("in progress: %+v %v", v, err)
	}
	f.ssoStatus = "SUCCEEDED"
	if v, err := w.Verify(context.Background(), r); err != nil || !v.OK {
		t.Errorf("succeeded: %+v %v", v, err)
	}
	f.ssoStatus = "FAILED"
	if v, err := w.Verify(context.Background(), r); err != nil || v.OK || !strings.Contains(v.Observed, "failed") {
		t.Errorf("failed status: %+v %v", v, err)
	}
	f = newFakeAWS()
	f.ssoFail = true
	if err := newWriteTarget(t, f).Apply(context.Background(), r); err == nil || target.Retryable(err) || !strings.Contains(err.Error(), "refused the request") {
		t.Errorf("a refused request: %v", err)
	}
	f.clean(t)
}

// Reads are made with the reader role and are ReaderActions; writes are WriterActions or RestoreActions made with
// the writer role. The fake enforces both on every call, so a run of every kind with no fake error proves it.
func TestWriteTarget_ReadsAreTheReaders(t *testing.T) {
	for a := range verifyActions {
		if !slices.Contains(ReaderActions, a) {
			t.Errorf("%s is not a ReaderAction", a)
		}
	}
	f := newFakeAWS()
	w := newWriteTarget(t, f)
	for _, r := range []target.Request{
		wreq(target.AWSDetachPolicy, wRole, target.AWSChange{PolicyARN: wPolicy}),
		wreq(target.AWSDeleteInlinePolicy, wRole, inlineChange(docWide)),
		wreq(target.AWSRemoveFromGroup, wUser, target.AWSChange{Group: "Ops"}),
		wreq(target.AWSDeleteAssignment, wPrincipal, target.AWSChange{AccountID: wAcct, InstanceARN: wInstance, PermissionSetARN: wPermSet, SSOPrincipalType: "USER"}),
		wreq(target.AWSSetPolicyVersion, wRole, target.AWSChange{PolicyARN: wPolicy, Document: docNarrow, Prior: docWide, PriorSHA256: target.DocDigest(docWide), PriorVersionID: "v1"}),
	} {
		if v, err := applyVerify(t, w, r); err != nil || !v.OK {
			t.Fatalf("%s: %+v %v", r.Kind, v, err)
		}
	}
	for _, c := range f.calls {
		if c.Key == wReaderKey && !verifyActions[c.Action] && c.Action != "sso:ListAccountAssignments" {
			t.Errorf("the reader role was used for %s, which is not a re-read", c.Action)
		}
	}
	f.clean(t)
}

// The writer's permissions policy is exactly the contract: only the writer and restore actions, no wildcard, an
// explicit Deny of creation and escalation, an explicit Deny on protected resources. None of its allowed actions is a
// reader action, and the reader's trust cannot be used for it.
func TestWriterPolicyContract(t *testing.T) {
	if err := CheckWriterPolicy(WriterPolicy()); err != nil {
		t.Fatal(err)
	}
	for _, a := range append(slices.Clone(WriterActions), RestoreActions...) {
		if slices.Contains(ReaderActions, a) {
			t.Errorf("%s is in both the reader and the writer policy", a)
		}
		for _, d := range WriterDenyActions {
			if d == a || strings.HasSuffix(d, ":*") && strings.HasPrefix(a, strings.TrimSuffix(d, "*")) {
				t.Errorf("%s is both allowed and denied", a)
			}
		}
	}
	for name, mutate := range map[string]func(p string) string{
		"extra allow": func(p string) string {
			return strings.Replace(p, `"iam:DetachRolePolicy"`, `"iam:DetachRolePolicy", "iam:CreateRole"`, 1)
		},
		"wildcard allow": func(p string) string { return strings.Replace(p, `"iam:DetachRolePolicy"`, `"iam:*"`, 1) },
		"no protected deny": func(p string) string {
			return strings.Replace(p, `"aws:ResourceTag/tessera:protected"`, `"aws:ResourceTag/other"`, 1)
		},
		"deny shrunk": func(p string) string { return strings.Replace(p, `"sts:*"`, `"sts:GetCallerIdentity"`, 1) },
		"not json":    func(p string) string { return "x" },
	} {
		if err := CheckWriterPolicy([]byte(mutate(string(WriterPolicy())))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
