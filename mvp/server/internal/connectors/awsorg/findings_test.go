package awsorg

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
)

func TestEntityKey(t *testing.T) {
	for arn, want := range map[string]string{
		"arn:aws:iam::222222222222:role/Worker":                           "role:222222222222:Worker",
		"arn:aws:iam::222222222222:role/service-role/Worker":              "role:222222222222:Worker",
		"arn:aws:sts::222222222222:assumed-role/Worker/session-1":         "role:222222222222:Worker",
		"arn:aws:iam::222222222222:user/alice":                            "user:222222222222:alice",
		"arn:aws:iam::222222222222:user/eng/alice":                        "user:222222222222:alice",
		"arn:aws:iam::222222222222:root":                                  "",
		"lambda.amazonaws.com":                                            "",
		"":                                                                "",
		"arn:aws:iam::222222222222:group/eng":                             "",
		"arn:aws:sts::222222222222:federated-user/bob":                    "",
		"arn:aws:sts::222222222222:assumed-role":                          "",
		"arn:aws:iam::111111111111:role/Worker":                           "role:111111111111:Worker", // another account's Worker is another role
		"arn:aws:iam::222222222222:role/aws-reserved/sso.amazonaws.com/A": "role:222222222222:A",
	} {
		if got := entityKey(arn); got != want {
			t.Errorf("entityKey(%q) = %q, want %q", arn, got, want)
		}
	}
}

// TestScopes: which requests a finding can affect, for every scope type.
func TestScopes(t *testing.T) {
	worker := "arn:aws:iam::222222222222:role/Worker"
	req := func(p, pa, r, ra string) Request {
		return Request{PrincipalARN: p, PrincipalAccount: pa, ResourceARN: r, ResourceAccount: ra}
	}
	for _, c := range []struct {
		name  string
		scope Scope
		r     Request
		want  bool
	}{
		{"principal: itself", Scope{ScopePrincipals, []string{worker}}, req(worker, "222222222222", "", ""), true},
		{"principal: a session of the role", Scope{ScopePrincipals, []string{worker}}, req("arn:aws:sts::222222222222:assumed-role/Worker/s", "222222222222", "", ""), true},
		{"principal: same name, another account", Scope{ScopePrincipals, []string{worker}}, req("arn:aws:iam::111111111111:role/Worker", "111111111111", "", ""), false},
		{"principal: a user of the same name", Scope{ScopePrincipals, []string{worker}}, req("arn:aws:iam::222222222222:user/Worker", "222222222222", "", ""), false},
		{"principal: anonymous", Scope{ScopePrincipals, []string{worker}}, req("", "", "", ""), false},
		{"principal: no targets", Scope{Type: ScopePrincipals}, req(worker, "222222222222", "", ""), false},
		{"resource: exact", Scope{ScopeResources, []string{"arn:aws:sqs:us-east-1:1:q"}}, req("", "", "arn:aws:sqs:us-east-1:1:q", ""), true},
		{"resource: a longer name is another resource", Scope{ScopeResources, []string{"arn:aws:sqs:us-east-1:1:q"}}, req("", "", "arn:aws:sqs:us-east-1:1:q2", ""), false},
		{"resource: bucket objects", Scope{ScopeResources, []string{"arn:aws:s3:::b"}}, req("", "", "arn:aws:s3:::b/k/x", ""), true},
		{"resource: bucket with a longer name", Scope{ScopeResources, []string{"arn:aws:s3:::b"}}, req("", "", "arn:aws:s3:::b2/k", ""), false},
		{"resource: an object has no objects below it", Scope{ScopeResources, []string{"arn:aws:s3:::b/k"}}, req("", "", "arn:aws:s3:::b/k/x", ""), false},
		{"resource: a role (trust policy)", Scope{ScopeResources, []string{worker}}, req("", "", worker, ""), true},
		{"resource: none asked", Scope{ScopeResources, []string{worker}}, req(worker, "222222222222", "", ""), false},
		{"prefix: match", Scope{ScopeResourcePrefix, []string{"arn:aws:kms:us-east-1:1:"}}, req("", "", "arn:aws:kms:us-east-1:1:key/a", ""), true},
		{"prefix: other region", Scope{ScopeResourcePrefix, []string{"arn:aws:kms:us-east-1:1:"}}, req("", "", "arn:aws:kms:eu-west-1:1:key/a", ""), false},
		{"prefix: no resource", Scope{ScopeResourcePrefix, []string{"arn:aws:kms:us-east-1:1:"}}, req("", "", "", ""), false},
		{"requester accounts: in", Scope{ScopeRequesterAccounts, []string{"2"}}, req("", "2", "", "9"), true},
		{"requester accounts: out", Scope{ScopeRequesterAccounts, []string{"2"}}, req("", "3", "", "2"), false},
		{"requester accounts: unknown account is conservative", Scope{ScopeRequesterAccounts, []string{"2"}}, req("", "", "", ""), true},
		{"requester accounts: no accounts", Scope{Type: ScopeRequesterAccounts}, req("", "", "", ""), false},
		{"resource accounts: in", Scope{ScopeResourceAccounts, []string{"2"}}, req("", "9", "", "2"), true},
		{"resource accounts: out", Scope{ScopeResourceAccounts, []string{"2"}}, req("", "2", "", "9"), false},
		{"accounts: as requester", Scope{ScopeAccounts, []string{"2"}}, req("", "2", "", "9"), true},
		{"accounts: as resource owner", Scope{ScopeAccounts, []string{"2"}}, req("", "9", "", "2"), true},
		{"accounts: neither", Scope{ScopeAccounts, []string{"2"}}, req("", "8", "", "9"), false},
		{"unknown scope type matches nothing", Scope{"nonsense", []string{"2"}}, req("", "2", "", "2"), false},
	} {
		if got := c.scope.affects(c.r); got != c.want {
			t.Errorf("%s: affects = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestFailClosedContract is the contract of design §3.3 at ingest: a stored
// policy that fails to parse, or has a Dropped anomaly, is recorded and never
// skipped, and every decision it could affect is UNSUPPORTED with
// POLICY_UNPARSEABLE, whose detail names the policy and the error. Decisions it
// cannot affect are untouched.
func TestFailClosedContract(t *testing.T) {
	col, _ := collectFixtures(t)
	worker := "arn:aws:iam::222222222222:role/Worker"
	alice := "arn:aws:iam::111111111111:user/alice"

	for _, c := range []struct {
		name     string
		r        Request
		wantWhy  []string // each must appear in some reason's detail
		wantNone bool
	}{
		{"the role with a policy that does not parse", Request{PrincipalARN: worker, PrincipalAccount: acctMember,
			ResourceARN: "arn:aws:sqs:us-east-1:222222222222:q", ResourceAccount: acctMember},
			[]string{"role/Worker#inline/broken", "duplicate_key", "role/Worker#inline/mixed", "INVALID_ELEMENT_MIX", "policy/Vanished", "ManagedPolicyMissing", "p-broken01"}, false},
		{"a session of that role", Request{PrincipalARN: "arn:aws:sts::222222222222:assumed-role/Worker/s1", PrincipalAccount: acctMember,
			ResourceARN: "arn:aws:sqs:us-east-1:222222222222:q", ResourceAccount: acctMember},
			[]string{"role/Worker#inline/broken", "role/Worker#inline/mixed", "policy/Vanished"}, false},
		{"another principal of the account under the broken SCP", Request{PrincipalARN: "arn:aws:iam::222222222222:user/bob", PrincipalAccount: acctMember,
			ResourceARN: "arn:aws:sqs:us-east-1:222222222222:q", ResourceAccount: acctMember},
			[]string{"p-broken01"}, false},
		{"a principal of the other account", Request{PrincipalARN: alice, PrincipalAccount: acctMgmt,
			ResourceARN: "arn:aws:sqs:us-east-1:111111111111:jobs", ResourceAccount: acctMgmt}, nil, true},
		{"alice reaching into the account with the broken SCP: the SCP binds the requester, not alice", Request{PrincipalARN: alice, PrincipalAccount: acctMgmt,
			ResourceARN: "arn:aws:sqs:us-east-1:222222222222:q", ResourceAccount: acctMember}, nil, true},
		{"the suspended account", Request{PrincipalARN: "arn:aws:iam::333333333333:user/x", PrincipalAccount: acctOld,
			ResourceARN: "arn:aws:sqs:us-east-1:333333333333:q", ResourceAccount: acctOld}, []string{"AccountNotActive"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := col.Findings.Unsupported(c.r)
			if c.wantNone {
				if len(got) != 0 {
					t.Fatalf("reasons = %+v, want none", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatal("no reason: the decision would be returned as exact")
			}
			var all []string
			for _, why := range got {
				if why.Code != authz.ReasonPolicyUnparseable || !why.OutcomeSensitive {
					t.Errorf("reason %+v: want POLICY_UNPARSEABLE, outcome-sensitive", why)
				}
				all = append(all, why.Detail)
			}
			joined := strings.Join(all, "\n")
			for _, w := range c.wantWhy {
				if !strings.Contains(joined, w) {
					t.Errorf("no reason names %q:\n%s", w, joined)
				}
			}
		})
	}

	// the policies are recorded, in full, for the audit trail
	for _, f := range col.Findings {
		if f.SourceARN == "" || f.Code == "" || f.Detail == "" || f.Kind == "" {
			t.Errorf("incomplete finding %+v", f)
		}
	}
}

// TestFailClosed_NoFindingsNoReasons: a clean estate has no reasons.
func TestFailClosed_NoFindingsNoReasons(t *testing.T) {
	var none Findings
	if got := none.Unsupported(Request{PrincipalARN: "arn:aws:iam::1:user/a", PrincipalAccount: "1", ResourceARN: "arn:aws:s3:::b", ResourceAccount: "1"}); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}
