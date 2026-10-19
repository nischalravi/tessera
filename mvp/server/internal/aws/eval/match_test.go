package eval

import (
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

func ps(patterns ...string) *model.PatternSet { return &model.PatternSet{Patterns: patterns} }

func TestActionMatch(t *testing.T) {
	tests := []struct {
		name   string
		action *model.PatternSet
		not    *model.PatternSet
		in     string
		want   bool
	}{
		{"exact", ps("s3:GetObject"), nil, "s3:GetObject", true},
		{"case-insensitive (GC-04)", ps("S3:getobject"), nil, "s3:GetObject", true},
		{"case-insensitive request side", ps("s3:GetObject"), nil, "S3:GETOBJECT", true},
		{"prefix wildcard", ps("s3:Get*"), nil, "s3:GetObjectAcl", true},
		{"infix wildcard", ps("s3:Get*Object"), nil, "s3:GetBucketObject", true},
		{"service wildcard (SCP style)", ps("*:Describe*"), nil, "ec2:DescribeInstances", true},
		{"star is everything", ps("*"), nil, "iam:CreateUser", true},
		{"service star", ps("s3:*"), nil, "ec2:RunInstances", false},
		{"question mark is one char", ps("s3:GetObjec?"), nil, "s3:GetObject", true},
		{"question mark not two", ps("s3:GetObjec?"), nil, "s3:GetObjects", false},
		{"any of several", ps("ec2:Run*", "s3:Get*"), nil, "s3:GetObject", true},
		{"none of several", ps("ec2:Run*", "s3:Get*"), nil, "s3:PutObject", false},
		{"future action still matches", ps("s3:*"), nil, "s3:BrandNewApi2031", true},
		{"NotAction excludes listed (GC-09)", nil, ps("iam:*"), "iam:CreateUser", false},
		{"NotAction admits others (GC-09)", nil, ps("iam:*"), "ec2:DescribeInstances", true},
		{"NotAction is case-insensitive", nil, ps("IAM:*"), "iam:createuser", false},
		{"NotAction grants future actions", nil, ps("s3:DeleteBucket"), "s3:BrandNewApi2031", true},
		{"ASCII folding only", ps("s3:é"), nil, "s3:É", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := CompileActions(tc.action, tc.not)
			if err != nil {
				t.Fatal(err)
			}
			if got := m.Match(tc.in); got != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCompileActionsErrors(t *testing.T) {
	if _, err := CompileActions(nil, nil); err == nil {
		t.Error("neither Action nor NotAction must fail")
	}
	if _, err := CompileActions(ps("a"), ps("b")); err == nil {
		t.Error("both Action and NotAction must fail")
	}
	if _, err := CompileActions(ps("s3:\xff"), nil); err == nil {
		t.Error("invalid UTF-8 must fail")
	}
	if _, err := CompileActions(ps(strings.Repeat("a", 9000)), nil); err == nil {
		t.Error("oversized pattern must fail")
	}
}

func TestResourceMatch(t *testing.T) {
	tests := []struct {
		name  string
		res   *model.PatternSet
		not   *model.PatternSet
		rbp   bool // resource-based policy
		arn   string
		want  bool
		isErr bool
	}{
		{name: "exact", res: ps("arn:aws:s3:::b/k"), arn: "arn:aws:s3:::b/k", want: true},
		{name: "any of several", res: ps("arn:aws:s3:::a", "arn:aws:s3:::b/*"), arn: "arn:aws:s3:::b/k", want: true},
		{name: "no resource-level action, star", res: ps("*"), arn: "*", want: true},
		{name: "no resource-level action, empty arn, star", res: ps("*"), arn: "", want: true},
		{name: "no resource-level action, ARN pattern", res: ps("arn:aws:s3:::*"), arn: "*", want: false},
		{name: "no resource-level action, ARN star pattern", res: ps("arn:aws:s3:*"), arn: "", want: false},
		{name: "NotResource matches action without resource support", not: ps("arn:aws:s3:::x"), arn: "*", want: true},
		{name: "NotResource star excludes it", not: ps("*"), arn: "*", want: false},
		{name: "NotResource excludes listed", not: ps("arn:aws:s3:::hr/Payroll", "arn:aws:s3:::hr/Payroll/*"), arn: "arn:aws:s3:::hr/Payroll/p1", want: false},
		{name: "NotResource admits others", not: ps("arn:aws:s3:::hr/Payroll", "arn:aws:s3:::hr/Payroll/*"), arn: "arn:aws:s3:::other/x", want: true},
		{name: "implied resource in a resource policy", rbp: true, arn: "arn:aws:s3:::anything", want: true},
		{name: "no Resource in identity policy is an error", isErr: true},
		{name: "both Resource and NotResource is an error", res: ps("*"), not: ps("*"), isErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := CompileResources(tc.res, tc.not, tc.rbp)
			if tc.isErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := m.Match(tc.arn); got != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.arn, got, tc.want)
			}
		})
	}
}

// TestResourceMatchUsesCompletedPatterns: the parser completes "arn:aws:sqs"
// to "arn:aws:sqs:*:*:*" in identity policies and the matcher uses that form.
func TestResourceMatchUsesCompletedPatterns(t *testing.T) {
	st := parseStatements(t, model.PolicyIdentity, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs"}]}`)[0]
	m, err := CompileResources(st.Resources, st.NotResources, false)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match("arn:aws:sqs:us-east-1:111111111111:q") {
		t.Error("incomplete ARN must match every SQS resource")
	}
	if m.Match("arn:aws:sns:us-east-1:111111111111:t") {
		t.Error("incomplete ARN must not match another service")
	}
	raw, _ := CompileResources(ps("arn:aws:sqs"), nil, true) // resource policies keep the raw pattern
	if raw.Match("arn:aws:sqs:us-east-1:111111111111:q") {
		t.Error("an uncompleted short pattern matches nothing")
	}
}

func parseStatements(t *testing.T, kind model.PolicyKind, doc string) []model.Statement {
	t.Helper()
	res, err := policy.Parse([]byte(doc), policy.Options{Kind: kind})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return res.Doc.Statements
}

// applies is the matcher-level check of one identity statement against a request.
func applies(t *testing.T, st model.Statement, action, resource string) bool {
	t.Helper()
	am, err := CompileActions(st.Actions, st.NotActions)
	if err != nil {
		t.Fatal(err)
	}
	rm, err := CompileResources(st.Resources, st.NotResources, false)
	if err != nil {
		t.Fatal(err)
	}
	return am.Match(action) && rm.Match(resource)
}

// TestGoldenMatcherLevel runs GC-03..GC-11 (design §14.2) at the matcher level:
// which statements apply to which request. The decision (Allow, Deny, implicit)
// is the engine's, from PR-5; here a denied case means no Allow statement applies.
func TestGoldenMatcherLevel(t *testing.T) {
	type req struct {
		action, resource string
		applies          []bool // per statement, in order
	}
	tests := []struct {
		id   string
		doc  string
		reqs []req
	}{
		{"GC-03", `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},
			{"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::*log*"}]}`,
			[]req{{"s3:PutObject", "arn:aws:s3:::tsr-applog/x", []bool{true, true}}}},
		{"GC-04", `{"Statement":[{"Effect":"Allow","Action":"S3:getobject","Resource":"*"}]}`,
			[]req{{"s3:GetObject", "arn:aws:s3:::tsr-bkt/a", []bool{true}}}},
		{"GC-05", `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::TSR-BKT/*"}]}`,
			[]req{{"s3:GetObject", "arn:aws:s3:::tsr-bkt/a", []bool{false}}}},
		{"GC-06", `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*/test/*"}]}`,
			[]req{{"s3:GetObject", "arn:aws:s3:::tsr-bkt/1/2/test/object.jpg", []bool{true}}}},
		{"GC-07", `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::tsr-bkt/*/test/*"}]}`,
			[]req{{"s3:GetObject", "arn:aws:s3:::tsr-bkt/test/object.jpg", []bool{false}}}},
		{"GC-08", `{"Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:111111111111:q?"}]}`,
			[]req{
				{"sqs:SendMessage", "arn:aws:sqs:us-east-1:111111111111:q1", []bool{true}},
				{"sqs:SendMessage", "arn:aws:sqs:us-east-1:111111111111:q10", []bool{false}},
			}},
		{"GC-09", `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`,
			[]req{
				{"ec2:DescribeInstances", "*", []bool{true}},
				{"iam:CreateUser", "arn:aws:iam::111111111111:user/bob", []bool{false}},
			}},
		{"GC-10", `{"Statement":[{"Effect":"Allow","NotAction":"s3:DeleteBucket","Resource":"arn:aws:s3:::*"}]}`,
			[]req{{"ec2:DescribeInstances", "*", []bool{false}}}},
		{"GC-11", `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},
			{"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::hr/Payroll","arn:aws:s3:::hr/Payroll/*"]}]}`,
			[]req{
				{"s3:GetObject", "arn:aws:s3:::other/x", []bool{true, true}},
				{"s3:GetObject", "arn:aws:s3:::hr/Payroll/p1", []bool{true, false}},
			}},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			stmts := parseStatements(t, model.PolicyIdentity, tc.doc)
			for _, r := range tc.reqs {
				if len(stmts) != len(r.applies) {
					t.Fatalf("%d statements, %d expectations", len(stmts), len(r.applies))
				}
				for i, st := range stmts {
					if got := applies(t, st, r.action, r.resource); got != r.applies[i] {
						t.Errorf("%s statement %d applies to %s on %s = %v, want %v", tc.id, i, r.action, r.resource, got, r.applies[i])
					}
				}
			}
		})
	}
}

func BenchmarkMatch(b *testing.B) {
	am, _ := CompileActions(ps("s3:Get*"), nil)
	arn, _ := CompileARN("arn:aws:s3:::bucket/*")
	wide, _ := CompileARN("arn:aws:logs:*:*:log-group:a*")
	b.Run("action_prefix", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			am.Match("s3:GetObject")
		}
	})
	b.Run("arn_bucket_star", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			arn.Match("arn:aws:s3:::bucket/some/deep/key.txt")
		}
	})
	b.Run("arn_segments", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			wide.Match("arn:aws:logs:us-east-1:111111111111:log-group:app/prod")
		}
	})
}
