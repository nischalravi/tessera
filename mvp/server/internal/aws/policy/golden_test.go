package policy

import (
	"reflect"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// goldenPolicy is one policy document from the offline golden corpus
// (docs/design/aws-effective-permission-evaluator.md §14.2), copied verbatim.
// The YAML corpus itself lands with the engine (PR-5); until then these are
// the parser's golden inputs and FuzzParse's seed corpus. Policies are parsed
// as written: the corpus default policy_version is applied by the golden
// runner, not here.
type goldenPolicy struct {
	id    string // "GC-NN" plus a suffix when a case has several documents
	kind  model.PolicyKind
	json  string
	check func(t *testing.T, r *Result)
}

const (
	allowStar   = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	allowEC2    = `{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`
	fullAccess  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	rcpFullAWS  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`
	gc06Ident   = `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*/test/*"}]}`
	gc24Ident   = `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-home/${aws:username}/*"}]}`
	gc49RCP     = `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-sbx"},"BoolIfExists":{"aws:PrincipalIsAWSService":"false"}}}]}`
	gc52Bucket  = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:role/Demo"},"Action":["s3:GetObject*","s3:PutObject*"],"Resource":"arn:aws:s3:::tsr-prod/*"}]}`
	gc69NotPrin = `{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111111111111:role/app"},"Action":"s3:*","Resource":["arn:aws:s3:::tsr-bkt","arn:aws:s3:::tsr-bkt/*"]}]}`
)

func stmt(t *testing.T, r *Result, i int) *model.Statement {
	t.Helper()
	if i >= len(r.Doc.Statements) {
		t.Fatalf("want statement %d, have %d", i, len(r.Doc.Statements))
	}
	return &r.Doc.Statements[i]
}

func wantPatterns(t *testing.T, what string, ps *model.PatternSet, want ...string) {
	t.Helper()
	if ps == nil {
		t.Fatalf("%s is absent, want %q", what, want)
	}
	if !reflect.DeepEqual(ps.Patterns, want) {
		t.Errorf("%s = %q, want %q", what, ps.Patterns, want)
	}
}

func wantAtom(t *testing.T, got authz.Atom, op, key string, q authz.Qualifier, ifExists, negated bool, values ...string) {
	t.Helper()
	if got.Op != op || got.Key != key || got.Qualifier != q || got.IfExists != ifExists || got.Negated != negated || !reflect.DeepEqual(got.Values, values) {
		t.Errorf("atom = {%s %s %v ifExists=%v negated=%v %q}, want {%s %s %v ifExists=%v negated=%v %q}",
			got.Op, got.Key, got.Qualifier, got.IfExists, got.Negated, got.Values, op, key, q, ifExists, negated, values)
	}
	if got.Source == nil || got.Source.Span == nil {
		t.Errorf("atom %s has no source statement", key)
	}
}

func wantEntries(t *testing.T, ps *model.PrincipalSet, want ...model.PrincipalEntry) {
	t.Helper()
	if ps == nil {
		t.Fatal("principal set is absent")
	}
	if !reflect.DeepEqual(ps.Entries, want) {
		t.Errorf("entries = %+v, want %+v", ps.Entries, want)
	}
}

func hasFinding(r *Result, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

var goldenPolicies = []goldenPolicy{
	{id: "Allow*", kind: model.PolicyIdentity, json: allowStar},
	{id: "AllowEC2Only", kind: model.PolicySCP, json: allowEC2},
	{id: "FullAWSAccess", kind: model.PolicySCP, json: fullAccess},
	{id: "RCPFullAWSAccess", kind: model.PolicyRCP, json: rcpFullAWS},
	{id: "GC-02", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`,
		check: func(t *testing.T, r *Result) {
			s := stmt(t, r, 0)
			if s.Effect != model.EffectAllow || s.NotActions != nil || s.NotResources != nil {
				t.Errorf("statement = %+v", s)
			}
			wantPatterns(t, "Action", s.Actions, "s3:GetObject") // a string becomes a one-element set
			wantPatterns(t, "Resource", s.Resources, "arn:aws:s3:::tsr-bkt/*")
		}},
	{id: "GC-03", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},
                           {"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::*log*"}]}`,
		check: func(t *testing.T, r *Result) {
			s := stmt(t, r, 1)
			if s.Index != 1 || s.Effect != model.EffectDeny {
				t.Errorf("statement 1 = index %d effect %v", s.Index, s.Effect)
			}
			wantPatterns(t, "Resource", s.Resources, "arn:aws:s3:::*log*")
		}},
	{id: "GC-04", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"S3:getobject","Resource":"*"}]}`,
		check: func(t *testing.T, r *Result) {
			// Action case is kept; matching is case-insensitive (§8.2, PR-3).
			wantPatterns(t, "Action", stmt(t, r, 0).Actions, "S3:getobject")
		}},
	{id: "GC-05", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::TSR-BKT/*"}]}`,
		check: func(t *testing.T, r *Result) {
			wantPatterns(t, "Resource", stmt(t, r, 0).Resources, "arn:aws:s3:::TSR-BKT/*") // ARNs are case-sensitive; never folded
		}},
	{id: "GC-06", kind: model.PolicyIdentity, json: gc06Ident},
	{id: "GC-08", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:111111111111:q?"}]}`},
	{id: "GC-09", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`,
		check: func(t *testing.T, r *Result) {
			s := stmt(t, r, 0)
			if s.Actions != nil {
				t.Error("Actions must be nil with NotAction")
			}
			wantPatterns(t, "NotAction", s.NotActions, "iam:*")
			if !hasFinding(r, "NOTACTION_WITH_ALLOW") {
				t.Error("missing NOTACTION_WITH_ALLOW info")
			}
		}},
	{id: "GC-10", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","NotAction":"s3:DeleteBucket","Resource":"arn:aws:s3:::*"}]}`},
	{id: "GC-11", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},
                           {"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::hr/Payroll","arn:aws:s3:::hr/Payroll/*"]}]}`,
		check: func(t *testing.T, r *Result) {
			s := stmt(t, r, 1)
			if s.Resources != nil {
				t.Error("Resources must be nil with NotResource")
			}
			wantPatterns(t, "NotResource", s.NotResources, "arn:aws:s3:::hr/Payroll", "arn:aws:s3:::hr/Payroll/*")
		}},
	{id: "GC-12", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},
                           {"Effect":"Deny","NotAction":"iam:*","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`,
		check: func(t *testing.T, r *Result) {
			s := stmt(t, r, 1)
			if len(s.Condition) != 1 {
				t.Fatalf("atoms = %d", len(s.Condition))
			}
			wantAtom(t, s.Condition[0], "Bool", "aws:multifactorauthpresent", authz.NoQualifier, true, false, "false")
		}},
	{id: "GC-13", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"data"}}}]}`,
		check: func(t *testing.T, r *Result) {
			wantAtom(t, stmt(t, r, 0).Condition[0], "StringEquals", "aws:principaltag/team", authz.NoQualifier, false, false, "data")
		}},
	{id: "GC-14", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalTag/team":"contractor"}}}]}`,
		check: func(t *testing.T, r *Result) {
			wantAtom(t, stmt(t, r, 0).Condition[0], "StringNotEquals", "aws:principaltag/team", authz.NoQualifier, false, true, "contractor")
		}},
	{id: "GC-15", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalTag/team":"data"}}}]}`},
	{id: "GC-16", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*","Condition":{"StringLikeIfExists":{"ec2:InstanceType":["t3.*"]}}}]}`,
		check: func(t *testing.T, r *Result) {
			// §9.3's own normalization example.
			wantAtom(t, stmt(t, r, 0).Condition[0], "StringLike", "ec2:instancetype", authz.NoQualifier, true, false, "t3.*")
		}},
	{id: "GC-17", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"ec2:CreateTags","Resource":"*","Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["env","cost-center"]}}}]}`,
		check: func(t *testing.T, r *Result) {
			wantAtom(t, stmt(t, r, 0).Condition[0], "StringEquals", "aws:tagkeys", authz.ForAllValues, false, false, "env", "cost-center")
		}},
	{id: "GC-18", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"ec2:CreateTags","Resource":"*","Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["env"]},"Null":{"aws:TagKeys":"false"}}}]}`,
		check: func(t *testing.T, r *Result) {
			c := stmt(t, r, 0).Condition
			if len(c) != 2 {
				t.Fatalf("atoms = %d", len(c))
			}
			wantAtom(t, c[0], "StringEquals", "aws:tagkeys", authz.ForAllValues, false, false, "env")
			wantAtom(t, c[1], "Null", "aws:tagkeys", authz.NoQualifier, false, false, "false")
		}},
	{id: "GC-19", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"ec2:DeleteTags","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":["env"]}}}]}`,
		check: func(t *testing.T, r *Result) {
			wantAtom(t, stmt(t, r, 0).Condition[0], "StringEquals", "aws:tagkeys", authz.ForAnyValue, false, false, "env")
		}},
	{id: "GC-20", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{
              "StringEquals":{"aws:PrincipalTag/team":["data","ml"],"aws:RequestedRegion":"eu-west-1"}}}]}`,
		check: func(t *testing.T, r *Result) {
			c := stmt(t, r, 0).Condition
			if len(c) != 2 {
				t.Fatalf("atoms = %d", len(c))
			}
			// Values OR within one atom; keys become separate (ANDed) atoms.
			wantAtom(t, c[0], "StringEquals", "aws:principaltag/team", authz.NoQualifier, false, false, "data", "ml")
			wantAtom(t, c[1], "StringEquals", "aws:requestedregion", authz.NoQualifier, false, false, "eu-west-1")
		}},
	{id: "GC-21", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"sqs:ListQueues","Resource":"*","Condition":{"Null":{"aws:TokenIssueTime":"true"}}}]}`},
	{id: "GC-22", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}`},
	{id: "GC-23", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}`,
		check: func(t *testing.T, r *Result) {
			wantAtom(t, stmt(t, r, 0).Condition[0], "NotIpAddress", "aws:sourceip", authz.NoQualifier, false, true, "203.0.113.0/24")
		}},
	{id: "GC-24", kind: model.PolicyIdentity, json: gc24Ident,
		check: func(t *testing.T, r *Result) {
			wantPatterns(t, "Resource", stmt(t, r, 0).Resources, "arn:aws:s3:::tsr-home/${aws:username}/*") // substituted per request, not at parse
		}},
	{id: "GC-26", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-team-${aws:PrincipalTag/team, 'company-wide'}/*"}]}`},
	{id: "GC-27", kind: model.PolicyIdentity, json: `{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-home/${aws:username}/*"}]}`,
		check: func(t *testing.T, r *Result) {
			if r.Doc.LanguageVersion != model.LanguageVersion2008 || r.Doc.VariablesEnabled() {
				t.Errorf("version %q, variables enabled %v", r.Doc.LanguageVersion, r.Doc.VariablesEnabled())
			}
			if !hasFinding(r, "VARIABLES_LITERAL") {
				t.Error("missing VARIABLES_LITERAL warning")
			}
		}},
	{id: "GC-28", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"DateLessThan":{"aws:CurrentTime":"2026-10-01T00:00:00Z"}}}]}`},
	{id: "GC-29", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEqualsIgnoreCase":{"aws:PrincipalTag/dept":"finance"}}}]}`},
	{id: "GC-30", kind: model.PolicyResource, json: `{"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage",
      "Resource":"arn:aws:sqs:us-east-1:111111111111:tsr-q","Condition":{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:us-east-1:111111111111:tsr-topic"}}}]}`,
		check: func(t *testing.T, r *Result) {
			s := stmt(t, r, 0)
			wantEntries(t, s.Principals, model.PrincipalEntry{Kind: model.PrincipalService, Value: "sns.amazonaws.com"})
			wantAtom(t, s.Condition[0], "ArnEquals", "aws:sourcearn", authz.NoQualifier, false, false, "arn:aws:sns:us-east-1:111111111111:tsr-topic")
		}},
	{id: "GC-31", kind: model.PolicyBoundary, json: `{"Statement":[{"Effect":"Allow","Action":["ec2:*"],"Resource":"*"}]}`},
	{id: "GC-32", kind: model.PolicyResource, json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/alice"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`,
		check: func(t *testing.T, r *Result) {
			wantEntries(t, stmt(t, r, 0).Principals, model.PrincipalEntry{Kind: model.PrincipalIAMUser, Value: "arn:aws:iam::111111111111:user/alice", AccountID: "111111111111"})
		}},
	{id: "GC-33", kind: model.PolicyBoundary, json: `{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`},
	{id: "GC-34", kind: model.PolicyResource, json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/app"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`,
		check: func(t *testing.T, r *Result) {
			wantEntries(t, stmt(t, r, 0).Principals, model.PrincipalEntry{Kind: model.PrincipalIAMRole, Value: "arn:aws:iam::111111111111:role/app", AccountID: "111111111111"})
		}},
	{id: "GC-36", kind: model.PolicyResource, json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:sts::111111111111:assumed-role/app/s1"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`,
		check: func(t *testing.T, r *Result) {
			wantEntries(t, stmt(t, r, 0).Principals, model.PrincipalEntry{Kind: model.PrincipalAssumedRole, Value: "arn:aws:sts::111111111111:assumed-role/app/s1", AccountID: "111111111111"})
		}},
	{id: "GC-38", kind: model.PolicyResource, json: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*",
                  "Condition":{"ArnEquals":{"aws:PrincipalArn":"arn:aws:iam::111111111111:role/app"}}}]}`,
		check: func(t *testing.T, r *Result) {
			s := stmt(t, r, 0)
			if !s.Principals.Star || !s.Principals.HasWildcard() {
				t.Error(`"*" must be the wildcard principal`)
			}
			wantAtom(t, s.Condition[0], "ArnEquals", "aws:principalarn", authz.NoQualifier, false, false, "arn:aws:iam::111111111111:role/app")
		}},
	{id: "GC-39", kind: model.PolicyResource, json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`,
		check: func(t *testing.T, r *Result) {
			wantEntries(t, stmt(t, r, 0).Principals, model.PrincipalEntry{Kind: model.PrincipalAccount, Value: "arn:aws:iam::111111111111:root", AccountID: "111111111111"})
		}},
	{id: "GC-40", kind: model.PolicySession, json: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`},
	{id: "GC-41", kind: model.PolicyResource, json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:sts::111111111111:federated-user/bob"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`,
		check: func(t *testing.T, r *Result) {
			wantEntries(t, stmt(t, r, 0).Principals, model.PrincipalEntry{Kind: model.PrincipalFederatedUser, Value: "arn:aws:sts::111111111111:federated-user/bob", AccountID: "111111111111"})
		}},
	{id: "GC-43", kind: model.PolicySCP, json: `{"Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}`},
	{id: "GC-48", kind: model.PolicySCP, json: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"eu-west-1"}}}]}`},
	{id: "GC-49", kind: model.PolicyRCP, json: gc49RCP,
		check: func(t *testing.T, r *Result) {
			c := stmt(t, r, 0).Condition
			if len(c) != 2 {
				t.Fatalf("atoms = %d", len(c))
			}
			wantAtom(t, c[0], "StringNotEquals", "aws:principalorgid", authz.NoQualifier, true, true, "o-sbx")
			wantAtom(t, c[1], "Bool", "aws:principalisawsservice", authz.NoQualifier, true, false, "false")
		}},
	{id: "GC-51", kind: model.PolicyRCP, json: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"lambda:InvokeFunction","Resource":"*"}]}`},
	{id: "GC-51-identity", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"*"}]}`},
	{id: "GC-52-identity", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:*Object*","Resource":"arn:aws:s3:::tsr-prod/*"}]}`},
	{id: "GC-52-bucket", kind: model.PolicyResource, json: gc52Bucket,
		check: func(t *testing.T, r *Result) {
			wantPatterns(t, "Action", stmt(t, r, 0).Actions, "s3:GetObject*", "s3:PutObject*")
		}},
	{id: "GC-54", kind: model.PolicyResource, json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":["s3:GetObject*","s3:PutObject*"],"Resource":"arn:aws:s3:::tsr-prod/*"}]}`,
		check: func(t *testing.T, r *Result) {
			wantEntries(t, stmt(t, r, 0).Principals, model.PrincipalEntry{Kind: model.PrincipalAccount, Value: "222222222222", AccountID: "222222222222"})
		}},
	{id: "GC-55", kind: model.PolicyTrust, json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"sts:AssumeRole"}]}`,
		check: func(t *testing.T, r *Result) {
			s := stmt(t, r, 0)
			if s.Resources != nil || s.NotResources != nil {
				t.Error("a trust policy statement without Resource means this role")
			}
			if len(r.Anomalies) != 0 {
				t.Errorf("anomalies = %+v", r.Anomalies)
			}
		}},
	{id: "GC-56", kind: model.PolicyTrust, json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"tsr-42"}}}]}`},
	{id: "GC-56-identity", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`},
	{id: "GC-57", kind: model.PolicyTrust, json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/alice"},"Action":"sts:AssumeRole"}]}`},
	{id: "GC-58", kind: model.PolicyTrust, json: `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`},
	{id: "GC-59", kind: model.PolicyTrust, json: `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
     "Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
     "StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}}]}`,
		check: func(t *testing.T, r *Result) {
			s := stmt(t, r, 0)
			wantEntries(t, s.Principals, model.PrincipalEntry{Kind: model.PrincipalFederated, Value: "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"})
			wantAtom(t, s.Condition[0], "StringEquals", "token.actions.githubusercontent.com:aud", authz.NoQualifier, false, false, "sts.amazonaws.com")
			wantAtom(t, s.Condition[1], "StringLike", "token.actions.githubusercontent.com:sub", authz.NoQualifier, false, false, "repo:acme/*")
		}},
	{id: "GC-60", kind: model.PolicyKMSKey, json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/kadmin"},"Action":"kms:*","Resource":"*"}]}`},
	{id: "GC-60-identity", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}]}`},
	{id: "GC-61", kind: model.PolicyKMSKey, json: `{"Statement":[{"Sid":"Enable IAM User Permissions","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"kms:*","Resource":"*"}]}`,
		check: func(t *testing.T, r *Result) {
			if stmt(t, r, 0).Sid != "Enable IAM User Permissions" {
				t.Error("Sid must be kept verbatim")
			}
			if hasFinding(r, "SID_CHARSET") {
				t.Error("KMS key policies allow spaces in Sid; SID_CHARSET is for IAM policies only")
			}
		}},
	{id: "GC-63-identity", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Deny","Action":"kms:Decrypt","Resource":"*"}]}`},
	{id: "GC-64", kind: model.PolicyKMSKey, json: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"kms:*","Resource":"*"}]}`},
	{id: "GC-66", kind: model.PolicyResource, json: `{"Statement":[
     {"Effect":"Allow","Principal":{"AWS":"222222222222"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"},
     {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`},
	{id: "GC-68", kind: model.PolicyResource, json: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*"}]}`},
	{id: "GC-69", kind: model.PolicyResource, json: gc69NotPrin,
		check: func(t *testing.T, r *Result) {
			s := stmt(t, r, 0)
			if s.Principals != nil || s.Effect != model.EffectDeny {
				t.Error("NotPrincipal statement parsed wrongly")
			}
			wantEntries(t, s.NotPrincipals, model.PrincipalEntry{Kind: model.PrincipalIAMRole, Value: "arn:aws:iam::111111111111:role/app", AccountID: "111111111111"})
			if !hasFinding(r, "NOTPRINCIPAL_DENY") {
				t.Error("missing NOTPRINCIPAL_DENY info")
			}
		}},
	{id: "GC-70", kind: model.PolicyResource, json: `{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":["arn:aws:iam::111111111111:root","arn:aws:iam::111111111111:role/app","arn:aws:sts::111111111111:assumed-role/app/s1"]},"Action":"s3:*","Resource":["arn:aws:s3:::tsr-bkt","arn:aws:s3:::tsr-bkt/*"]}]}`,
		check: func(t *testing.T, r *Result) {
			wantEntries(t, stmt(t, r, 0).NotPrincipals,
				model.PrincipalEntry{Kind: model.PrincipalAccount, Value: "arn:aws:iam::111111111111:root", AccountID: "111111111111"},
				model.PrincipalEntry{Kind: model.PrincipalIAMRole, Value: "arn:aws:iam::111111111111:role/app", AccountID: "111111111111"},
				model.PrincipalEntry{Kind: model.PrincipalAssumedRole, Value: "arn:aws:sts::111111111111:assumed-role/app/s1", AccountID: "111111111111"})
		}},
	{id: "GC-71", kind: model.PolicyResource, json: `{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":["arn:aws:iam::111111111111:root","arn:aws:iam::111111111111:role/app"]},"Action":"s3:*","Resource":["arn:aws:s3:::tsr-bkt","arn:aws:s3:::tsr-bkt/*"]}]}`},
	{id: "GC-72", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`},
	{id: "GC-73", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Deny","NotAction":["iam:*","sts:*"],"Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-west-1"]}}}]}`,
		check: func(t *testing.T, r *Result) {
			s := stmt(t, r, 0)
			wantPatterns(t, "NotAction", s.NotActions, "iam:*", "sts:*")
			wantAtom(t, s.Condition[0], "StringNotEquals", "aws:requestedregion", authz.NoQualifier, false, true, "eu-west-1")
		}},
	{id: "GC-74", kind: model.PolicyIdentity, json: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}},
                           {"Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`},
}

// TestGoldenPolicies parses every policy document of the golden corpus. None
// may produce an anomaly or an error finding, and the parse-relevant cases
// check the normalized model.
func TestGoldenPolicies(t *testing.T) {
	for _, g := range goldenPolicies {
		t.Run(g.id, func(t *testing.T) {
			r, err := Parse([]byte(g.json), Options{Kind: g.kind, AWSManaged: g.id == "RCPFullAWSAccess" || g.id == "FullAWSAccess"})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(r.Anomalies) != 0 {
				t.Errorf("anomalies: %+v", r.Anomalies)
			}
			for _, f := range r.Findings {
				if f.Severity == SeverityError {
					t.Errorf("error finding: %+v", f)
				}
			}
			if g.check != nil {
				g.check(t, r)
			}
		})
	}
}
