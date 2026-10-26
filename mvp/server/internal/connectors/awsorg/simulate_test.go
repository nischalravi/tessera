package awsorg

import (
	"context"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awsreplay"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

const simRole = "arn:aws:iam::111111111111:role/app"

func simReplay(t *testing.T, result string) *awsreplay.Replay {
	t.Helper()
	sts, err := os.ReadFile("testdata/http/sts/AssumeRole/1.xml")
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{
		"sts/AssumeRole/1.xml": {Data: sts},
		"iam/SimulatePrincipalPolicy/1.xml": {Data: []byte(`<SimulatePrincipalPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <SimulatePrincipalPolicyResult><IsTruncated>false</IsTruncated><EvaluationResults>` + result + `</EvaluationResults></SimulatePrincipalPolicyResult>
</SimulatePrincipalPolicyResponse>`)},
	}
	r := awsreplay.NewReplay(fsys)
	r.RepeatLast = true
	r.Verify(baseKeyID, baseSecret).Verify(sessionKeyID, sessionSecret)
	return r
}

func TestSimulator_AsksTheAccountOfThePrincipal(t *testing.T) {
	cases := []struct {
		name, result, resource string
		want                   SimAnswer
		wantErr                string
	}{
		{"allowed", `<member><EvalActionName>s3:GetObject</EvalActionName><EvalResourceName>arn:aws:s3:::b/k</EvalResourceName><EvalDecision>allowed</EvalDecision></member>`,
			"arn:aws:s3:::b/k", SimAnswer{Decision: "allowed"}, ""},
		{"implicit deny, no resource is *", `<member><EvalActionName>s3:GetObject</EvalActionName><EvalDecision>implicitDeny</EvalDecision></member>`,
			"", SimAnswer{Decision: "implicitDeny"}, ""},
		{"missing context", `<member><EvalActionName>s3:GetObject</EvalActionName><EvalDecision>implicitDeny</EvalDecision><MissingContextValues><member>aws:SourceIp</member></MissingContextValues></member>`,
			"*", SimAnswer{Decision: "implicitDeny", Missing: []string{"aws:SourceIp"}}, ""},
		{"no result", ``, "*", SimAnswer{}, "no result"},
		{"two results", `<member><EvalActionName>s3:GetObject</EvalActionName><EvalDecision>allowed</EvalDecision></member><member><EvalActionName>s3:getobject</EvalActionName><EvalDecision>allowed</EvalDecision></member>`,
			"*", SimAnswer{}, "more than one"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := storetest.TwoTenants(t)
			r := simReplay(t, tc.result)
			s := newService(t, r)
			k := createConnector(t, s, f)
			sim, err := s.Simulator(context.Background(), f.DB, f.A.ID, k.ID)
			if err != nil {
				t.Fatal(err)
			}
			got, err := sim.Ask(context.Background(), SimQuery{PrincipalARN: simRole, Action: "s3:GetObject", Resource: tc.resource})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Ask = %v, %v; want an error with %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got.Decision != tc.want.Decision || strings.Join(got.Missing, ",") != strings.Join(tc.want.Missing, ",") {
				t.Fatalf("Ask = %+v, %v; want %+v", got, err, tc.want)
			}
			reqs := r.Requests()
			form := reqs[len(reqs)-1].Form
			wantRes := tc.resource
			if wantRes == "" {
				wantRes = "*"
			}
			if form.Get("PolicySourceArn") != simRole || form.Get("ActionNames.member.1") != "s3:GetObject" || form.Get("ResourceArns.member.1") != wantRes {
				t.Errorf("SimulatePrincipalPolicy form = %v", form)
			}
			// the reader role is assumed in the principal's account
			if reqs[0].Service != "sts" || reqs[0].Form.Get("RoleArn") != "arn:aws:iam::111111111111:role/TesseraReader" {
				t.Errorf("first request = %+v", reqs[0])
			}
		})
	}
}

func TestSimulator_RefusesWhatIsNotAPrincipal(t *testing.T) {
	f := storetest.TwoTenants(t)
	s := newService(t, simReplay(t, ``))
	k := createConnector(t, s, f)
	sim, err := s.Simulator(context.Background(), f.DB, f.A.ID, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"", "alice", "arn:aws:iam:::role/x", "ec2.amazonaws.com"} {
		if _, err := sim.Ask(context.Background(), SimQuery{PrincipalARN: p, Action: "s3:GetObject"}); err == nil {
			t.Errorf("Ask(%q) succeeded", p)
		}
	}
	// another tenant's connector is not found
	if _, err := s.Simulator(context.Background(), f.DB, f.B.ID, k.ID); err == nil {
		t.Error("Simulator on another tenant's connector succeeded")
	}
}
