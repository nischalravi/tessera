package containment

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The AWS tests replay recorded AWS JSON answers (testdata/aws.json, one
// scenario each, errors included) from an httptest server keyed by the
// X-Amz-Target header, and check that every request is SigV4 signed.

const awsUser = "c2a7e8f4-1031-70b2-9a64-0b5d8f6e3a11"

type awsRoute struct {
	Target       string        `json:"target"`
	BodyContains []string      `json:"body_contains"`
	Responses    []fixtureResp `json:"responses"`
}

type awsReplay struct {
	t      *testing.T
	srv    *httptest.Server
	routes []awsRoute
	mu     sync.Mutex
	next   map[int]int
	calls  []string
	bodies map[string][]string
}

func newAWSReplay(t *testing.T, scenario string) *awsReplay {
	t.Helper()
	raw, err := os.ReadFile("testdata/aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var all map[string][]awsRoute
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	routes, ok := all[scenario]
	if !ok {
		t.Fatalf("aws.json has no scenario %q", scenario)
	}
	r := &awsReplay{t: t, routes: routes, next: map[int]int{}, bodies: map[string][]string{}}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

// signedFor is the service name each target's request must be signed for.
var signedFor = map[string]string{"AWSOrganizationsV20161128": "organizations", "AWSIdentityStore": "identitystore",
	"SWBExternalService": "sso"}

func (r *awsReplay) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	body, _ := io.ReadAll(req.Body)
	target := req.Header.Get("X-Amz-Target")
	auth := req.Header.Get("Authorization")
	svc := signedFor[strings.SplitN(target, ".", 2)[0]]
	region := "us-east-1"
	if req.Method != http.MethodPost || req.URL.Path != "/" || req.Header.Get("Content-Type") != "application/x-amz-json-1.1" ||
		!strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE1234567/20261014/"+region+"/"+svc+"/aws4_request, SignedHeaders=") ||
		!strings.Contains(auth, "content-type;host;x-amz-date;x-amz-target") || req.Header.Get("X-Amz-Date") != "20261014T120000Z" {
		r.t.Errorf("%s: not a signed AWS JSON request: %s %s %q", target, req.Method, req.URL.Path, auth)
	}
	r.calls = append(r.calls, target[strings.Index(target, ".")+1:])
	r.bodies[target] = append(r.bodies[target], string(body))
	for i, rt := range r.routes {
		if rt.Target != target {
			continue
		}
		ok := true
		for _, want := range rt.BodyContains {
			ok = ok && strings.Contains(string(body), want)
		}
		if !ok {
			continue
		}
		n := r.next[i]
		if n >= len(rt.Responses) {
			n = len(rt.Responses) - 1
		} else {
			r.next[i]++
		}
		resp := rt.Responses[n]
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(resp.Status)
		_, _ = w.Write(resp.Body)
		return
	}
	if target == "AWSOrganizationsV20161128.ListTargetsForPolicy" {
		// a scenario that does not script it has the policy attached to the root
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"Targets":[{"TargetId":"r-ab12","Name":"Root","Type":"ROOT"}]}`))
		return
	}
	r.t.Errorf("fixture holds no answer for %s with body %s", target, body)
	http.Error(w, "no fixture", 599)
}

func (r *awsReplay) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func awsCredJSON(t *testing.T, mod func(*AWSCredential)) string {
	t.Helper()
	c := AWSCredential{AccessKeyID: "AKIDEXAMPLE1234567", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region: "us-east-1", PolicyID: "p-0a1b2c3d4e", IdentityStoreID: "d-1234567890",
		InstanceARN: "arn:aws:sso:::instance/ssoins-7223a1b2c3d4e5f6"}
	if mod != nil {
		mod(&c)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func runAWS(t *testing.T, scenario string) (StepResult, *Report, *awsReplay, []time.Duration) {
	t.Helper()
	svc, sleeps := testService(t)
	svc.Clock = func() time.Time { return time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC) }
	rp := newAWSReplay(t, scenario)
	it := Item{Action: ActionRevokeSessions, AccountID: 1, Connection: "conn-aws",
		Target: Target{System: AWSIdentityCenter, UserID: awsUser, Username: "alice@larkspur.example"},
		cred:   &Credential{BaseURL: rp.srv.URL, Token: awsCredJSON(t, nil)}}
	rep := svc.Run(context.Background(), &Job{IdentityID: 7, Identity: "Alice", Trigger: "ssf", Items: []Item{it}})
	if len(rep.Steps) != 1 {
		t.Fatalf("steps = %d", len(rep.Steps))
	}
	return rep.Steps[0], rep, rp, *sleeps
}

func TestAWSIdentityCenter(t *testing.T) {
	ms := time.Millisecond
	cases := []struct {
		name, scenario string
		outcome        string
		revoked        int
		detail         string
		calls          []string
		sleeps         []time.Duration
		manual         int
	}{
		{name: "revoke: deny entry, assignments deleted, verified", scenario: "revoke", outcome: OutcomeDone, revoked: 3, manual: 3,
			calls: []string{"DescribeUser", "ListTargetsForPolicy", "DescribePolicy", "UpdatePolicy", "DescribePolicy",
				"ListAccountAssignmentsForPrincipal", "DeleteAccountAssignment", "DescribeAccountAssignmentDeletionStatus",
				"DeleteAccountAssignment", "DescribeAccountAssignmentDeletionStatus", "ListTargetsForPolicy", "DescribePolicy",
				"ListAccountAssignmentsForPrincipal"},
			sleeps: []time.Duration{250 * ms, 250 * ms}},
		{name: "already denied: no policy update", scenario: "already_denied", outcome: OutcomeDone, revoked: 1, manual: 3,
			calls: []string{"DescribeUser", "ListTargetsForPolicy", "DescribePolicy", "ListAccountAssignmentsForPrincipal",
				"ListTargetsForPolicy", "DescribePolicy", "ListAccountAssignmentsForPrincipal"}},
		{name: "throttled twice, then ok", scenario: "throttled_then_ok", outcome: OutcomeDone, revoked: 1, manual: 3,
			sleeps: []time.Duration{250 * ms, 500 * ms}},
		{name: "throttle exhausted", scenario: "throttle_exhausted", outcome: OutcomeFailed, detail: "rate limit",
			sleeps: []time.Duration{250 * ms, 500 * ms, time.Second}},
		{name: "concurrent modification is retried from a fresh read", scenario: "concurrent_modification", outcome: OutcomeDone,
			revoked: 1, manual: 3,
			calls: []string{"DescribeUser", "ListTargetsForPolicy", "DescribePolicy", "UpdatePolicy", "DescribePolicy", "UpdatePolicy",
				"DescribePolicy", "ListAccountAssignmentsForPrincipal", "ListTargetsForPolicy", "DescribePolicy",
				"ListAccountAssignmentsForPrincipal"},
			sleeps: []time.Duration{250 * ms}},
		{name: "policy too large", scenario: "policy_too_large", outcome: OutcomeFailed, detail: "Deny service control policy is full"},
		{name: "unknown identity store user", scenario: "user_not_found", outcome: OutcomeFailed, detail: "does not know this user"},
		{name: "policy without the Deny statement", scenario: "no_deny_statement", outcome: OutcomeFailed,
			detail: "no Deny statement with the identitystore:userId condition"},
		{name: "AWS refuses the call", scenario: "access_denied", outcome: OutcomeFailed,
			detail: "aws organizations DescribePolicy answered 400 AccessDeniedException"},
		{name: "assignment deletion fails", scenario: "assignment_delete_failed", outcome: OutcomeFailed,
			detail: "could not delete an account assignment: Internal error", sleeps: []time.Duration{250 * ms}},
		{name: "assignments on several pages", scenario: "paged_assignments", outcome: OutcomeDone, revoked: 3, manual: 3,
			sleeps: []time.Duration{250 * ms, 250 * ms}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, rep, rp, sleeps := runAWS(t, tc.scenario)
			if st.Outcome != tc.outcome || st.Revoked != tc.revoked && tc.outcome == OutcomeDone {
				t.Fatalf("step %+v", st)
			}
			if tc.outcome == OutcomeDone && (!st.Verified || len(st.Notes) != 1) {
				t.Errorf("a done step must be verified and carry the unverified note: %+v", st)
			}
			if !strings.Contains(st.Detail, tc.detail) {
				t.Errorf("detail %q does not contain %q", st.Detail, tc.detail)
			}
			if tc.calls != nil && strings.Join(rp.Calls(), ",") != strings.Join(tc.calls, ",") {
				t.Errorf("calls\n got %v\nwant %v", rp.Calls(), tc.calls)
			}
			if tc.sleeps != nil && strings.Join(durs(sleeps), ",") != strings.Join(durs(tc.sleeps), ",") {
				t.Errorf("sleeps %v, want %v", sleeps, tc.sleeps)
			}
			if len(rep.Manual) != tc.manual {
				t.Errorf("manual tasks %d, want %d: %v", len(rep.Manual), tc.manual, rep.Manual)
			}
			if tc.outcome == OutcomeFailed && rep.OK {
				t.Error("a failed step must fail the report")
			}
			// no credential ever reaches a report
			raw, _ := json.Marshal(rep)
			if strings.Contains(string(raw), "wJalrXUtnFEMI") || strings.Contains(string(raw), "AKIDEXAMPLE1234567") {
				t.Errorf("report leaks the credential: %s", raw)
			}
		})
	}
}

func durs(ds []time.Duration) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.String()
	}
	return out
}

// The revoke puts the user id into the Deny list (next to the placeholder)
// and deletes exactly the user's own assignments.
func TestAWSRequestBodies(t *testing.T) {
	_, _, rp, _ := runAWS(t, "revoke")
	var upd struct{ PolicyId, Content string }
	if err := json.Unmarshal([]byte(rp.bodies["AWSOrganizationsV20161128.UpdatePolicy"][0]), &upd); err != nil || upd.PolicyId != "p-0a1b2c3d4e" {
		t.Fatalf("UpdatePolicy body: %v %+v", err, upd)
	}
	has, err := policyHasUser(upd.Content, awsUser)
	if err != nil || !has || !strings.Contains(upd.Content, `"identitystore:userId":["Add user ID here","`+awsUser+`"]`) ||
		!strings.Contains(upd.Content, `"Effect":"Deny"`) {
		t.Errorf("updated policy %s (%v)", upd.Content, err)
	}
	dels := rp.bodies["SWBExternalService.DeleteAccountAssignment"]
	if len(dels) != 2 || !strings.Contains(dels[0], `"TargetId":"111122223333"`) || !strings.Contains(dels[1], `"TargetId":"444455556666"`) ||
		!strings.Contains(dels[0], `"PrincipalId":"`+awsUser+`"`) || !strings.Contains(dels[0], `"PrincipalType":"USER"`) {
		t.Errorf("DeleteAccountAssignment bodies %v", dels)
	}
}

func TestAWSVerifyOnly(t *testing.T) {
	for _, tc := range []struct {
		scenario string
		sessions int
	}{{"verify_clean", 0}, {"verify_leftovers", 2}} {
		svc, _ := testService(t)
		svc.Clock = func() time.Time { return time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC) }
		rp := newAWSReplay(t, tc.scenario)
		rv, err := svc.revoker(tenancy.ID{}, AWSIdentityCenter, Credential{BaseURL: rp.srv.URL, Token: awsCredJSON(t, nil)})
		if err != nil {
			t.Fatal(err)
		}
		rem, err := rv.Verify(context.Background(), Target{System: AWSIdentityCenter, UserID: awsUser}, t0, CheckSessions)
		if err != nil || rem.Sessions != tc.sessions {
			t.Errorf("%s: Verify = %+v, %v; want %d remaining", tc.scenario, rem, err, tc.sessions)
		}
	}
}

func TestAWSCredentialValidation(t *testing.T) {
	svc, _ := testService(t)
	for name, tc := range map[string]struct {
		token, base string
		wantErr     string
	}{
		"not json":           {"nope", "", "not readable"},
		"unknown field":      {`{"access_key_id":"AKIDEXAMPLE1234567","x":1}`, "", "not readable"},
		"bad region":         {awsCredJSON(t, func(c *AWSCredential) { c.Region = "mars" }), "", "region is required"},
		"bad policy id":      {awsCredJSON(t, func(c *AWSCredential) { c.PolicyID = "x" }), "", "policy_id is required"},
		"bad instance arn":   {awsCredJSON(t, func(c *AWSCredential) { c.InstanceARN = "arn:x" }), "", "instance_arn is required"},
		"no secret":          {awsCredJSON(t, func(c *AWSCredential) { c.SecretAccessKey = "" }), "", "secret_access_key is required"},
		"bad endpoint":       {awsCredJSON(t, nil), "ftp://x", "base_url"},
		"endpoint with user": {awsCredJSON(t, nil), "https://u:p@x", "base_url"},
	} {
		if _, err := svc.revoker(tenancy.ID{}, AWSIdentityCenter, Credential{BaseURL: tc.base, Token: tc.token}); err == nil ||
			!strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.wantErr)
		}
	}
	if _, err := svc.revoker(tenancy.ID{}, AWSIdentityCenter, Credential{Token: awsCredJSON(t, func(c *AWSCredential) { c.SessionToken = "tok" })}); err != nil {
		t.Errorf("valid credential with a session token: %v", err)
	}
}

func TestAWSBadTargetAndGrants(t *testing.T) {
	svc, _ := testService(t)
	rv, err := svc.revoker(tenancy.ID{}, AWSIdentityCenter, Credential{Token: awsCredJSON(t, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rv.RevokeSessions(context.Background(), Target{System: AWSIdentityCenter, UserID: `x"},{"`}); err != ErrBadTarget {
		t.Errorf("hostile user id: %v", err)
	}
	if _, err := rv.RevokeGrants(context.Background(), Target{System: AWSIdentityCenter, UserID: awsUser}); err == nil {
		t.Error("aws has no revoke_grants")
	}
	if GrantCapable(AWSIdentityCenter) || !SessionCapable(AWSIdentityCenter) {
		t.Error("aws is session capable only")
	}
}

func TestAddUserToPolicy(t *testing.T) {
	const single = `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringEquals":{"identitystore:userId":"Add user ID here"}}}}`
	out, changed, err := addUserToPolicy(single, "u-1")
	if err != nil || !changed || !strings.Contains(out, `["Add user ID here","u-1"]`) {
		t.Errorf("single statement object: %s %v %v", out, changed, err)
	}
	if _, changed, _ := addUserToPolicy(out, "u-1"); changed {
		t.Error("adding a present user changed the policy")
	}
	big := `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringEquals":{"identitystore:userId":["` + strings.Repeat("a", 5100) + `"]}}}]}`
	if _, _, err := addUserToPolicy(big, "u-2"); err != ErrPolicyTooLarge {
		t.Errorf("full policy: %v", err)
	}
	if _, _, err := addUserToPolicy(`{"Statement":[{"Effect":"Allow"}]}`, "u"); err != errNoDenyStatement {
		t.Errorf("no deny statement: %v", err)
	}
	if _, _, err := addUserToPolicy(`not json`, "u"); err == nil {
		t.Error("invalid JSON accepted")
	}
}
