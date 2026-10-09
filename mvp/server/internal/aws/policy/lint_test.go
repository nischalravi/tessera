package policy

import (
	"sort"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

func findingCodes(r *Result, sev Severity) map[string]bool {
	out := map[string]bool{}
	for _, f := range r.Findings {
		if sev == "" || f.Severity == sev {
			out[f.Code] = true
		}
	}
	return out
}

func TestLint(t *testing.T) {
	const v = `"Version":"2012-10-17",`
	for _, tc := range []struct {
		name    string
		kind    model.PolicyKind
		managed bool
		in      string
		want    map[string]Severity // code → severity that must be present
		absent  []string            // codes that must not be present
	}{
		{name: "principal in an identity policy", kind: model.PolicyIdentity,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`,
			want: map[string]Severity{"PRINCIPAL_NOT_ALLOWED": SeverityError}},
		{name: "principal in an SCP", kind: model.PolicySCP,
			in:   `{` + v + `"Statement":[{"Effect":"Deny","Principal":{"AWS":"111111111111"},"Action":"*","Resource":"*"}]}`,
			want: map[string]Severity{"PRINCIPAL_NOT_ALLOWED": SeverityError}},
		{name: "resource policy without a principal", kind: model.PolicyResource,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
			want: map[string]Severity{"PRINCIPAL_REQUIRED": SeverityError}},
		{name: "trust policy without a principal", kind: model.PolicyTrust,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`,
			want: map[string]Severity{"PRINCIPAL_REQUIRED": SeverityError}},
		{name: "NotPrincipal in a trust policy", kind: model.PolicyTrust,
			in:   `{` + v + `"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":"111111111111"},"Action":"sts:AssumeRole"}]}`,
			want: map[string]Severity{"NOTPRINCIPAL_NOT_ALLOWED": SeverityError, "NOTPRINCIPAL_DENY": SeverityInfo}},
		{name: "customer RCP rules", kind: model.PolicyRCP,
			in: `{` + v + `"Statement":[{"Effect":"Allow","Principal":{"AWS":"111111111111"},"NotAction":"s3:*","Resource":"*"},
				{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*"},
				{"Effect":"Deny","NotPrincipal":{"AWS":"111111111111"},"Action":"s3:*","Resource":"*"}]}`,
			want: map[string]Severity{"RCP_ALLOW_NOT_ALLOWED": SeverityError, "RCP_PRINCIPAL_NOT_WILDCARD": SeverityError,
				"RCP_NOTACTION_UNSUPPORTED": SeverityError, "RCP_ACTION_STAR": SeverityError, "NOTPRINCIPAL_NOT_ALLOWED": SeverityError}},
		{name: "RCP with {\"AWS\": \"*\"} is a wildcard", kind: model.PolicyRCP,
			in:     `{` + v + `"Statement":[{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"s3:*","Resource":"*"}]}`,
			absent: []string{"RCP_PRINCIPAL_NOT_WILDCARD", "PRINCIPAL_REQUIRED"}},
		{name: "AWS-managed RCPFullAWSAccess", kind: model.PolicyRCP, managed: true, in: rcpFullAWS,
			absent: []string{"RCP_ALLOW_NOT_ALLOWED", "RCP_ACTION_STAR"}},
		{name: "Sid charset in IAM policies", kind: model.PolicyIdentity,
			in:   `{` + v + `"Statement":[{"Sid":"has space","Effect":"Allow","Action":"*","Resource":"*"}]}`,
			want: map[string]Severity{"SID_CHARSET": SeverityWarning}},
		{name: "Sid charset in a trust policy", kind: model.PolicyTrust,
			in:   `{` + v + `"Statement":[{"Sid":"a-b","Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			want: map[string]Severity{"SID_CHARSET": SeverityWarning}},
		{name: "bucket policies allow other Sid characters", kind: model.PolicyResource,
			in:     `{` + v + `"Statement":[{"Sid":"Allow public read","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`,
			absent: []string{"SID_CHARSET"}},
		{name: "duplicate Sid", kind: model.PolicyIdentity,
			in:   `{` + v + `"Statement":[{"Sid":"A","Effect":"Allow","Action":"*","Resource":"*"},{"Sid":"A","Effect":"Deny","Action":"*","Resource":"*"}]}`,
			want: map[string]Severity{"DUPLICATE_SID": SeverityWarning}},
		{name: "empty lists", kind: model.PolicyResource,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Principal":{"AWS":[]},"Action":[],"Resource":"*"}]}`,
			want: map[string]Severity{"EMPTY_LIST": SeverityError}},
		{name: "empty principal map", kind: model.PolicyResource,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Principal":{},"Action":"s3:*","Resource":"*"}]}`,
			want: map[string]Severity{"EMPTY_LIST": SeverityError}},
		{name: "partial wildcard and invalid principals", kind: model.PolicyResource,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::*:root","arn:aws:iam::111111111111:group/eng"],"Service":"*.amazonaws.com"},"Action":"s3:*","Resource":"*"}]}`,
			want: map[string]Severity{"PARTIAL_WILDCARD_PRINCIPAL": SeverityError, "INVALID_PRINCIPAL": SeverityWarning}},
		{name: "incomplete ARN in an identity policy is completed by AWS", kind: model.PolicyIdentity,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs"}]}`,
			want: map[string]Severity{"INCOMPLETE_ARN": SeverityInfo}},
		{name: "incomplete ARN in a session policy is rejected by AWS", kind: model.PolicySession,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs"}]}`,
			want: map[string]Severity{"INCOMPLETE_ARN": SeverityError}},
		{name: "colons inside a variable do not count as ARN segments", kind: model.PolicyIdentity,
			in:     `{` + v + `"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b/${aws:PrincipalTag/a:b}"}]}`,
			absent: []string{"INCOMPLETE_ARN", "VARIABLE_OUTSIDE_RESOURCE_PART"}},
		{name: "variable outside the resource part", kind: model.PolicyIdentity,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam::${aws:PrincipalAccount}:user/x"}]}`,
			want: map[string]Severity{"VARIABLE_OUTSIDE_RESOURCE_PART": SeverityWarning}},
		{name: "variables in actions, principals, keys and numeric values are literal", kind: model.PolicyResource,
			in: `{` + v + `"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/${aws:username}"},"Action":"s3:${aws:username}",
				"Resource":"*","Condition":{"NumericEquals":{"k":"${aws:EpochTime}"},"StringEquals":{"${aws:username}":"x"}}}]}`,
			want: map[string]Severity{"VARIABLE_NOT_ALLOWED": SeverityWarning}},
		{name: "variables without Version 2012 are literal", kind: model.PolicyIdentity,
			in:   `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"s3:prefix":"${aws:username}"}}}]}`,
			want: map[string]Severity{"VARIABLES_LITERAL": SeverityWarning, "MISSING_VERSION": SeverityWarning}},
		{name: "Id in an identity policy", kind: model.PolicyIdentity,
			in:   `{` + v + `"Id":"x","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			want: map[string]Severity{"ID_NOT_ALLOWED": SeverityWarning}},
		{name: "Id in a resource policy is fine", kind: model.PolicyResource,
			in:     `{` + v + `"Id":"x","Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:*"}]}`,
			absent: []string{"ID_NOT_ALLOWED"}},
		{name: "Null rules", kind: model.PolicyIdentity,
			in: `{` + v + `"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NullIfExists":{"a":"true"},
				"ForAllValues:Null":{"b":"true"},"Null":{"c":"maybe"}}}]}`,
			want: map[string]Severity{"NULL_IFEXISTS": SeverityError, "NULL_WITH_QUALIFIER": SeverityWarning, "NULL_VALUE": SeverityWarning}},
		{name: "empty condition values and blocks", kind: model.PolicyIdentity,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"a":[]},"StringLike":{}}}]}`,
			want: map[string]Severity{"EMPTY_CONDITION_VALUES": SeverityWarning, "EMPTY_CONDITION_BLOCK": SeverityWarning}},
		{name: "operator case", kind: model.PolicyIdentity,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"stringEquals":{"a":"b"}}}]}`,
			want: map[string]Severity{"NONCANONICAL_OPERATOR_CASE": SeverityWarning}},
		{name: "action and resource formats", kind: model.PolicyIdentity,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Action":["s3GetObject","s3:","a:b:c",":x"],"Resource":["bucket","arn:aws:s3:::ok"]}]}`,
			want: map[string]Severity{"ACTION_FORMAT": SeverityWarning, "RESOURCE_FORMAT": SeverityWarning}},
		{name: "wildcards anywhere in an action are well-formed", kind: model.PolicySCP,
			in:     `{` + v + `"Statement":[{"Effect":"Allow","Action":["*:Describe*","s3:Get*Object","*"],"Resource":"*"}]}`,
			absent: []string{"ACTION_FORMAT"}},
		{name: "NotResource with Allow", kind: model.PolicyIdentity,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::secret/*"}]}`,
			want: map[string]Severity{"NOTRESOURCE_WITH_ALLOW": SeverityInfo}},
		{name: "every statement dropped", kind: model.PolicyIdentity,
			in:   `{` + v + `"Statement":[{"Effect":"Allow","Action":"*"}]}`,
			want: map[string]Severity{"NO_STATEMENTS": SeverityError, "MISSING_RESOURCE": SeverityError}},
		{name: "empty statement list", kind: model.PolicyIdentity,
			in:   `{` + v + `"Statement":[]}`,
			want: map[string]Severity{"NO_STATEMENTS": SeverityError}},
		{name: "Version 2008", kind: model.PolicyIdentity,
			in:   `{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			want: map[string]Severity{"VERSION_2008": SeverityInfo}, absent: []string{"MISSING_VERSION"}},
		{name: "a clean identity policy", kind: model.PolicyIdentity,
			in:     `{` + v + `"Statement":[{"Sid":"Read","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/${aws:username}/*"}]}`,
			absent: []string{"MISSING_VERSION", "VARIABLES_LITERAL", "VARIABLE_OUTSIDE_RESOURCE_PART", "SID_CHARSET", "INCOMPLETE_ARN"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Parse([]byte(tc.in), Options{Kind: tc.kind, AWSManaged: tc.managed})
			if err != nil {
				t.Fatal(err)
			}
			for code, sev := range tc.want {
				if !findingCodes(r, sev)[code] {
					t.Errorf("missing %s %s; findings: %+v", sev, code, r.Findings)
				}
			}
			all := findingCodes(r, "")
			for _, code := range tc.absent {
				if all[code] {
					t.Errorf("unexpected %s; findings: %+v", code, r.Findings)
				}
			}
			for _, f := range r.Findings {
				if f.StatementIndex >= 0 && f.Span == nil {
					t.Errorf("statement finding without a span: %+v", f)
				}
			}
			if !sort.SliceIsSorted(r.Findings, func(i, j int) bool {
				a, b := r.Findings[i], r.Findings[j]
				if a.StatementIndex != b.StatementIndex {
					return a.StatementIndex < b.StatementIndex
				}
				return a.Code < b.Code || a.Code == b.Code && a.Message < b.Message
			}) {
				t.Error("findings are not sorted")
			}
		})
	}
}

// Lint works on documents built in code, without the raw text.
func TestLintModelOnly(t *testing.T) {
	doc := &model.PolicyDoc{Kind: model.PolicyIdentity, LanguageVersion: model.LanguageVersion2012, Statements: []model.Statement{{
		Index: 0, Effect: model.EffectAllow,
		Actions:    &model.PatternSet{Patterns: []string{"s3:GetObject"}},
		Resources:  &model.PatternSet{Patterns: []string{"*"}},
		Principals: &model.PrincipalSet{Star: true, Entries: []model.PrincipalEntry{{Kind: model.PrincipalWildcard, Value: "*"}}},
	}}}
	fs := Lint(doc)
	if len(fs) != 1 || fs[0].Code != "PRINCIPAL_NOT_ALLOWED" || fs[0].StatementIndex != 0 {
		t.Errorf("findings = %+v", fs)
	}
}

func TestVariableRefs(t *testing.T) {
	for _, tc := range []struct {
		in   string
		keys []string // "" for an escape
	}{
		{"arn:aws:s3:::b/${aws:username}/*", []string{"aws:username"}},
		{"${aws:PrincipalTag/Team, 'none'}", []string{"aws:principaltag/team"}},
		{"${*}${?}${$}", []string{"", "", ""}},
		{"a${b", nil},
		{"${a}${", []string{"a"}},
		{"$${a}}", []string{"a"}},
		{"", nil},
	} {
		var got []string
		for _, r := range variableRefs(tc.in) {
			got = append(got, r.key)
		}
		if len(got) != len(tc.keys) {
			t.Errorf("variableRefs(%q) = %q, want %q", tc.in, got, tc.keys)
			continue
		}
		for i := range got {
			if got[i] != tc.keys[i] {
				t.Errorf("variableRefs(%q) = %q, want %q", tc.in, got, tc.keys)
			}
		}
	}
	for in, want := range map[string]bool{
		"arn:aws:s3:::b/${aws:username}":         false,
		"arn:aws:iam::${aws:PrincipalAccount}:x": true,
		"arn:aws:${a}":                           true,
		"arn:aws:s3:::${*}":                      false,
		"arn:aws:s3:::b/${a:b:c:d:e}/${c}":       false,
	} {
		if got := variableOutsideResourcePart(in); got != want {
			t.Errorf("variableOutsideResourcePart(%q) = %v, want %v", in, got, want)
		}
	}
	if !IsGlobalMultivaluedKey("aws:tagkeys") || IsGlobalMultivaluedKey("aws:TagKeys") || IsGlobalMultivaluedKey("aws:username") {
		t.Error("IsGlobalMultivaluedKey takes lower-cased keys")
	}
}
