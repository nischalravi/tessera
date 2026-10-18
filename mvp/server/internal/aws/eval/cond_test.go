package eval

import (
	"reflect"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
)

func atom(op, key string, vals ...string) authz.Atom {
	return authz.Atom{Op: op, Key: asciiLower(key), RawKey: key, Values: vals, Negated: policy.IsNegatedOperator(op)}
}

func ctxOf(mode Mode, kv map[string]ContextValue) *Context {
	return &Context{Mode: mode, Values: kv}
}

// TestOperatorTruthTable covers every operator family for matching,
// non-matching and unparseable request values.
func TestOperatorTruthTable(t *testing.T) {
	tests := []struct {
		name string
		op   string
		vals []string // policy values
		have string   // request value
		want string
	}{
		{"StringEquals match", "StringEquals", []string{"a", "b"}, "b", "T"},
		{"StringEquals case sensitive", "StringEquals", []string{"a"}, "A", "F"},
		{"StringNotEquals", "StringNotEquals", []string{"a"}, "b", "T"},
		{"StringNotEquals same", "StringNotEquals", []string{"a", "b"}, "b", "F"},
		{"IgnoreCase", "StringEqualsIgnoreCase", []string{"finance"}, "Finance", "T"},
		{"NotIgnoreCase", "StringNotEqualsIgnoreCase", []string{"finance"}, "FINANCE", "F"},
		{"Like star", "StringLike", []string{"t3.*"}, "t3.micro", "T"},
		{"Like question", "StringLike", []string{"t?.micro"}, "t3.micro", "T"},
		{"Like miss", "StringLike", []string{"t3.*"}, "m5.large", "F"},
		{"Like case sensitive", "StringLike", []string{"T3.*"}, "t3.micro", "F"},
		{"NotLike", "StringNotLike", []string{"t3.*"}, "m5.large", "T"},
		{"Like escape star is literal", "StringLike", []string{"a${*}b"}, "a*b", "T"},
		{"Like escape star not wildcard", "StringLike", []string{"a${*}b"}, "axxb", "F"},
		{"Like escape dollar", "StringLike", []string{"${$}x"}, "$x", "T"},
		{"Numeric eq decimal", "NumericEquals", []string{"1.50"}, "1.5", "T"},
		{"Numeric lt", "NumericLessThan", []string{"10"}, "9", "T"},
		{"Numeric lt exact no float rounding", "NumericLessThan", []string{"0.30000000000000004"}, "0.3", "T"},
		{"Numeric le equal", "NumericLessThanEquals", []string{"10"}, "10", "T"},
		{"Numeric gt", "NumericGreaterThan", []string{"10"}, "10", "F"},
		{"Numeric ge neg", "NumericGreaterThanEquals", []string{"-5"}, "-4.9", "T"},
		{"Numeric ne", "NumericNotEquals", []string{"1"}, "2", "T"},
		{"Numeric bad request value positive", "NumericEquals", []string{"1"}, "abc", "F"},
		{"Numeric bad request value negated", "NumericNotEquals", []string{"1"}, "abc", "T"},
		{"Numeric bad policy value", "NumericEquals", []string{"1e3"}, "1000", "F"},
		{"Date lt", "DateLessThan", []string{"2026-10-01T00:00:00Z"}, "2026-10-08T12:00:00Z", "F"},
		{"Date lt true", "DateLessThan", []string{"2026-10-01T00:00:00Z"}, "2026-09-30T23:59:59Z", "T"},
		{"Date offset normalised", "DateEquals", []string{"2026-10-01T01:00:00+01:00"}, "2026-10-01T00:00:00Z", "T"},
		{"Date epoch vs iso", "DateEquals", []string{"1790812800"}, "2026-10-01T00:00:00Z", "T"},
		{"Date ne", "DateNotEquals", []string{"2026-10-01"}, "2026-10-02", "T"},
		{"Date bad value positive", "DateGreaterThan", []string{"2026-10-01"}, "yesterday", "F"},
		{"Date bad value negated", "DateNotEquals", []string{"2026-10-01"}, "yesterday", "T"},
		{"Bool true", "Bool", []string{"true"}, "TRUE", "T"},
		{"Bool mismatch", "Bool", []string{"false"}, "true", "F"},
		{"Bool junk", "Bool", []string{"true"}, "yes", "F"},
		{"Binary", "BinaryEquals", []string{"aGVsbG8="}, "aGVsbG8=", "T"},
		{"Binary bad base64", "BinaryEquals", []string{"aGVsbG8="}, "!!!", "F"},
		{"Ip cidr", "IpAddress", []string{"203.0.113.0/24"}, "203.0.113.77", "T"},
		{"Ip outside", "IpAddress", []string{"203.0.113.0/24"}, "203.0.114.1", "F"},
		{"Ip bare address", "IpAddress", []string{"203.0.113.9"}, "203.0.113.9", "T"},
		{"Ip bare address neighbour", "IpAddress", []string{"203.0.113.9"}, "203.0.113.10", "F"},
		{"Ip v6", "IpAddress", []string{"2001:db8::/32"}, "2001:db8:1::5", "T"},
		{"Ip family mismatch", "IpAddress", []string{"2001:db8::/32"}, "10.0.0.1", "F"},
		{"Ip 4in6 mapped", "IpAddress", []string{"10.0.0.0/8"}, "::ffff:10.1.1.1", "T"},
		{"NotIp inside", "NotIpAddress", []string{"10.0.0.0/8"}, "10.1.1.1", "F"},
		{"NotIp outside", "NotIpAddress", []string{"10.0.0.0/8"}, "11.1.1.1", "T"},
		{"NotIp junk is no match so true", "NotIpAddress", []string{"10.0.0.0/8"}, "banana", "T"},
		{"Ip junk positive", "IpAddress", []string{"10.0.0.0/8"}, "banana", "F"},
		{"ArnEquals", "ArnEquals", []string{"arn:aws:sns:us-east-1:111111111111:tsr-topic"}, "arn:aws:sns:us-east-1:111111111111:tsr-topic", "T"},
		{"ArnLike account differs", "ArnLike", []string{"arn:aws:sns:us-east-1:111111111111:tsr-topic"}, "arn:aws:sns:us-east-1:777788889999:tsr-topic", "F"},
		{"ArnLike star per segment", "ArnLike", []string{"arn:aws:sns:*:111111111111:*"}, "arn:aws:sns:eu-west-1:111111111111:t", "T"},
		{"ArnLike sixth segment holds colons", "ArnLike", []string{"arn:aws:s3:::a*"}, "arn:aws:s3:::a:b", "T"},
		{"ArnLike segment star stays in segment", "ArnLike", []string{"arn:aws:*:::x"}, "arn:aws:sns:us-east-1:1:x", "F"},
		{"ArnLike trailing star of segment 5 takes the rest (A1)", "ArnLike", []string{"arn:aws:sqs:us-east-1:*"}, "arn:aws:sqs:us-east-1:111111111111:q", "T"},
		{"ArnLike not an arn", "ArnLike", []string{"arn:aws:s3:::*"}, "bucket", "F"},
		{"ArnNotLike", "ArnNotLike", []string{"arn:aws:s3:::a*"}, "arn:aws:s3:::b", "T"},
		{"ArnNotEquals junk", "ArnNotEquals", []string{"arn:aws:s3:::a"}, "junk", "T"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := ctxOf(Concrete, map[string]ContextValue{"k": PresentValues(tc.have)})
			got := EvalAtom(atom(tc.op, "k", tc.vals...), ctx, true).Result
			if got.String() != tc.want {
				t.Errorf("%s %v on %q = %s, want %s", tc.op, tc.vals, tc.have, got, tc.want)
			}
		})
	}
}

// TestMissingKeyTable is the §9.3 truth table: key state by qualifier.
func TestMissingKeyTable(t *testing.T) {
	with := func(a authz.Atom, q authz.Qualifier, ifExists bool) authz.Atom {
		a.Qualifier, a.IfExists = q, ifExists
		return a
	}
	pos := atom("StringEquals", "aws:principaltag/team", "data")
	neg := atom("StringNotEquals", "aws:principaltag/team", "data")
	tags := atom("StringEquals", "aws:TagKeys", "env")
	negTags := atom("StringNotEquals", "aws:TagKeys", "env")
	empty := PresentValues()
	emptyStr := PresentValues("")
	two := PresentValues("env", "cost")
	rows := []struct {
		name string
		a    authz.Atom
		have *ContextValue // nil: absent
		want string
		amb  []string
	}{
		{"absent positive", pos, nil, "F", nil},
		{"absent negated", neg, nil, "T", nil},
		{"absent IfExists positive", with(pos, 0, true), nil, "T", nil},
		{"absent IfExists negated", with(neg, 0, true), nil, "T", nil},
		{"absent ForAllValues", with(tags, authz.ForAllValues, false), nil, "T", nil},
		{"absent ForAllValues negated", with(negTags, authz.ForAllValues, false), nil, "T", nil},
		{"absent ForAnyValue", with(tags, authz.ForAnyValue, false), nil, "F", nil},
		{"absent ForAnyValue negated is false (A5)", with(negTags, authz.ForAnyValue, false), nil, "F", []string{"A5"}},
		{"absent ForAnyValue IfExists", with(tags, authz.ForAnyValue, true), nil, "T", nil},
		{"present empty set positive", tags, &empty, "F", nil},
		{"present empty set negated", negTags, &empty, "T", nil},
		{"present empty string is the empty set ForAllValues", with(tags, authz.ForAllValues, false), &emptyStr, "T", nil},
		{"present empty string ForAnyValue", with(tags, authz.ForAnyValue, false), &emptyStr, "F", nil},
		{"present empty set ForAllValues", with(tags, authz.ForAllValues, false), &empty, "T", nil},
		{"present empty set ForAnyValue", with(tags, authz.ForAnyValue, false), &empty, "F", nil},
		{"ForAllValues every value allowed", with(atom("StringEquals", "aws:TagKeys", "env", "cost"), authz.ForAllValues, false), &two, "T", nil},
		{"ForAllValues one value outside", with(tags, authz.ForAllValues, false), &two, "F", nil},
		{"ForAnyValue one value in", with(tags, authz.ForAnyValue, false), &two, "T", nil},
		{"ForAnyValue negated one value outside", with(negTags, authz.ForAnyValue, false), &two, "T", nil},
		{"ForAllValues negated all outside", with(atom("StringNotEquals", "aws:TagKeys", "x"), authz.ForAllValues, false), &two, "T", nil},
		{"ForAllValues negated one inside", with(negTags, authz.ForAllValues, false), &two, "F", nil},
		{"single operator on multivalued key, positive any (A7)", tags, &two, "T", []string{"A7"}},
		{"single operator on multivalued key, negated none (A7)", negTags, &two, "F", []string{"A7"}},
		{"Null true absent", atom("Null", "aws:TagKeys", "true"), nil, "T", nil},
		{"Null true present", atom("Null", "aws:TagKeys", "true"), &two, "F", nil},
		{"Null false present", atom("Null", "aws:TagKeys", "false"), &two, "T", nil},
		{"Null false absent", atom("Null", "aws:TagKeys", "false"), nil, "F", nil},
		{"Null false present empty set", atom("Null", "aws:TagKeys", "false"), &empty, "T", nil},
		{"NullIfExists evaluates as Null", with(atom("Null", "aws:TagKeys", "true"), 0, true), nil, "T", nil},
		{"qualifier on single-valued key (A8)", with(pos, authz.ForAllValues, false), nil, "T", []string{"A8"}},
		{"NotIpAddress with absent SourceIp (A17)", atom("NotIpAddress", "aws:SourceIp", "203.0.113.0/24"), nil, "T", []string{"A17"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			kv := map[string]ContextValue{}
			if r.have != nil {
				kv[r.a.Key] = *r.have
			}
			res := EvalAtom(r.a, ctxOf(Concrete, kv), true)
			if res.Result.String() != r.want {
				t.Errorf("got %s, want %s", res.Result, r.want)
			}
			if len(res.Ambiguities) != len(r.amb) || (len(r.amb) > 0 && !reflect.DeepEqual(res.Ambiguities, r.amb)) {
				t.Errorf("ambiguities %v, want %v", res.Ambiguities, r.amb)
			}
		})
	}
}

func TestUnknownKeyIsResidual(t *testing.T) {
	a := atom("IpAddress", "aws:SourceIp", "10.0.0.0/8")
	got := EvalAtom(a, ctxOf(Symbolic, nil), true)
	if !got.Result.IsUnknown() {
		t.Fatalf("want U, got %s", got.Result)
	}
	if at, ok := got.Result.Residual().(authz.Atom); !ok || at.Op != "IpAddress" {
		t.Fatalf("residual should be the atom, got %#v", got.Result.Residual())
	}
	if got.Trace.RequestState != "unknown" || got.Trace.Result != "unknown" {
		t.Errorf("trace %+v", got.Trace)
	}
	// The same key in concrete mode is absent, not unknown.
	if r := EvalAtom(a, ctxOf(Concrete, nil), true).Result; !r.IsFalse() {
		t.Errorf("concrete absent positive: %s", r)
	}
	// An operator this package does not know never gives a confident answer.
	if r := EvalAtom(atom("Frobnicate", "k", "v"), ctxOf(Concrete, nil), true).Result; !r.IsUnknown() {
		t.Errorf("unknown operator: %s", r)
	}
}

func TestEvalConditionsCombining(t *testing.T) {
	ctx := ctxOf(Concrete, map[string]ContextValue{
		"aws:principaltag/team": PresentValues("ml"),
		"aws:requestedregion":   PresentValues("eu-west-1"),
	})
	conds := []authz.Atom{
		atom("StringEquals", "aws:PrincipalTag/team", "data", "ml"),
		atom("StringEquals", "aws:RequestedRegion", "eu-west-1"),
	}
	r, traces, _ := EvalConditions(conds, ctx, true)
	if !r.IsTrue() || len(traces) != 2 {
		t.Fatalf("got %s with %d traces", r, len(traces))
	}
	ctx.Values["aws:requestedregion"] = PresentValues("us-east-1")
	r, traces, _ = EvalConditions(conds, ctx, true)
	if !r.IsFalse() || len(traces) != 2 || traces[0].Result != "true" || traces[1].Result != "false" {
		t.Fatalf("got %s %+v", r, traces)
	}
	if r, _, _ := EvalConditions(nil, ctx, true); !r.IsTrue() {
		t.Fatalf("no blocks must be T, got %s", r)
	}
}

// ---- golden cases at the condition level ------------------------------

var (
	userAlice = model.Principal{
		ARN: "arn:aws:iam::111111111111:user/alice", Kind: model.IAMUser, AccountID: "111111111111",
		UniqueID: "AIDAALICEEXAMPLE0001",
	}
	roleSession = model.Principal{
		ARN: "arn:aws:sts::111111111111:assumed-role/app/s1", Kind: model.RoleSession, AccountID: "111111111111",
		EntityARN: "arn:aws:iam::111111111111:role/app", UniqueID: "AROAAPPEXAMPLE000001",
	}
)

func withTags(p model.Principal, tags map[string]string) model.Principal {
	p.Tags = tags
	return p
}

// goldenCond parses a policy document and evaluates the condition of its
// first statement.
func goldenCond(t *testing.T, doc string, ctx *Context) authz.Tri {
	t.Helper()
	res, err := policy.Parse([]byte(doc), policy.Options{Kind: model.PolicyIdentity})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r, _, _ := EvalConditions(res.Doc.Statements[0].Condition, ctx, res.Doc.VariablesEnabled())
	return r
}

func condDoc(effect, cond string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"` + effect + `","Action":"*","Resource":"*","Condition":` + cond + `}]}`
}

func TestGoldenConditions(t *testing.T) {
	u := func(extra map[string]ContextValue) *Context {
		return DeriveContext(DeriveInput{Mode: Concrete, Principal: &userAlice, LongTermCredentials: true, Supplied: extra})
	}
	uTags := func(tags map[string]string, extra map[string]ContextValue) *Context {
		p := withTags(userAlice, tags)
		return DeriveContext(DeriveInput{Mode: Concrete, Principal: &p, LongTermCredentials: true, Supplied: extra})
	}
	tests := []struct {
		id   string
		doc  string
		ctx  *Context
		want string
	}{
		{"GC-12 deny BoolIfExists MFA with long-term keys", condDoc("Deny", `{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}`), u(nil), "T"},
		{"GC-13 positive on missing key", condDoc("Allow", `{"StringEquals":{"aws:PrincipalTag/team":"data"}}`), u(nil), "F"},
		{"GC-14 negated on missing key", condDoc("Allow", `{"StringNotEquals":{"aws:PrincipalTag/team":"contractor"}}`), u(nil), "T"},
		{"GC-15 negated on missing key in a Deny", condDoc("Deny", `{"StringNotEquals":{"aws:PrincipalTag/team":"data"}}`), u(nil), "T"},
		{"GC-16 StringLikeIfExists missing", condDoc("Allow", `{"StringLikeIfExists":{"ec2:InstanceType":["t3.*"]}}`), u(nil), "T"},
		{"GC-17 ForAllValues missing", condDoc("Allow", `{"ForAllValues:StringEquals":{"aws:TagKeys":["env","cost-center"]}}`), u(nil), "T"},
		{"GC-18 ForAllValues plus Null false", condDoc("Allow", `{"ForAllValues:StringEquals":{"aws:TagKeys":["env"]},"Null":{"aws:TagKeys":"false"}}`), u(nil), "F"},
		{"GC-19 ForAnyValue missing", condDoc("Allow", `{"ForAnyValue:StringEquals":{"aws:TagKeys":["env"]}}`), u(nil), "F"},
		{"GC-20 values OR, keys AND (match)", condDoc("Allow", `{"StringEquals":{"aws:PrincipalTag/team":["data","ml"],"aws:RequestedRegion":"eu-west-1"}}`),
			uTags(map[string]string{"team": "ml"}, map[string]ContextValue{"aws:requestedregion": PresentValues("eu-west-1")}), "T"},
		{"GC-20 values OR, keys AND (other region)", condDoc("Allow", `{"StringEquals":{"aws:PrincipalTag/team":["data","ml"],"aws:RequestedRegion":"eu-west-1"}}`),
			uTags(map[string]string{"team": "ml"}, map[string]ContextValue{"aws:requestedregion": PresentValues("us-east-1")}), "F"},
		{"GC-21 Null true, long-term keys", condDoc("Allow", `{"Null":{"aws:TokenIssueTime":"true"}}`), u(nil), "T"},
		{"GC-22 IpAddress allow through a VPCE", condDoc("Allow", `{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`),
			u(map[string]ContextValue{"aws:sourcevpce": PresentValues("vpce-1")}), "F"},
		{"GC-23 NotIpAddress deny through a VPCE", condDoc("Deny", `{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`),
			u(map[string]ContextValue{"aws:sourcevpce": PresentValues("vpce-1")}), "T"},
		{"GC-28 date on CurrentTime", condDoc("Allow", `{"DateLessThan":{"aws:CurrentTime":"2026-10-01T00:00:00Z"}}`),
			u(map[string]ContextValue{"aws:currenttime": PresentValues("2026-10-08T12:00:00Z")}), "F"},
		{"GC-29 StringEqualsIgnoreCase", condDoc("Allow", `{"StringEqualsIgnoreCase":{"aws:PrincipalTag/dept":"finance"}}`),
			uTags(map[string]string{"dept": "Finance"}, nil), "T"},
		{"GC-30 ArnEquals SourceArn (match)", condDoc("Allow", `{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:us-east-1:111111111111:tsr-topic"}}`),
			ctxOf(Concrete, map[string]ContextValue{"aws:sourcearn": PresentValues("arn:aws:sns:us-east-1:111111111111:tsr-topic")}), "T"},
		{"GC-30 ArnEquals SourceArn (other account)", condDoc("Allow", `{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:us-east-1:111111111111:tsr-topic"}}`),
			ctxOf(Concrete, map[string]ContextValue{"aws:sourcearn": PresentValues("arn:aws:sns:us-east-1:777788889999:tsr-topic")}), "F"},
		// GC-24..27 are about Resource patterns, which PR-5 matches with the
		// same Substitute; these are the condition-value counterparts.
		{"GC-24 variable resolves for a user", condDoc("Allow", `{"StringEquals":{"s3:prefix":"home/${aws:username}/"}}`),
			u(map[string]ContextValue{"s3:prefix": PresentValues("home/alice/")}), "T"},
		{"GC-25 variable is null for a role session (A6)", condDoc("Allow", `{"StringEquals":{"s3:prefix":"home/${aws:username}/"}}`),
			DeriveContext(DeriveInput{Mode: Concrete, Principal: &roleSession, Supplied: map[string]ContextValue{"s3:prefix": PresentValues("home//")}}), "F"},
		{"A6 negated operator with a null variable is true", condDoc("Deny", `{"StringNotEquals":{"s3:ExistingObjectTag/Team":"${aws:PrincipalTag/Team}"}}`),
			u(map[string]ContextValue{"s3:existingobjecttag/team": PresentValues("x")}), "T"},
		{"GC-26 default applies when the tag is absent", condDoc("Allow", `{"StringEquals":{"s3:prefix":"team-${aws:PrincipalTag/team, 'company-wide'}"}}`),
			u(map[string]ContextValue{"s3:prefix": PresentValues("team-company-wide")}), "T"},
		{"GC-27 version 2008-10-17 keeps variables literal",
			`{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"s3:prefix":"home/${aws:username}/"}}}]}`,
			u(map[string]ContextValue{"s3:prefix": PresentValues("home/alice/")}), "F"},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			if got := goldenCond(t, tc.doc, tc.ctx); got.String() != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestSubstitute(t *testing.T) {
	ctx := ctxOf(Symbolic, map[string]ContextValue{
		"aws:username":         PresentValues("alice"),
		"aws:principaltag/ok":  PresentValues("v*?"),
		"aws:principaltag/no":  AbsentValue,
		"aws:principaltag/unk": UnknownValue,
		"aws:tagkeys":          PresentValues("a", "b"),
	})
	tests := []struct {
		name    string
		in      string
		enabled bool
		text    string
		res     Resolution
	}{
		{"plain", "abc", true, "abc", SubstResolved},
		{"present", "x/${aws:username}/y", true, "x/alice/y", SubstResolved},
		{"key case folds", "${AWS:UserName}", true, "alice", SubstResolved},
		{"spaces around key", "${ aws:username }", true, "alice", SubstResolved},
		{"default used when absent", "${aws:principaltag/no, 'dflt'}", true, "dflt", SubstResolved},
		{"default ignored when present", "${aws:username, 'dflt'}", true, "alice", SubstResolved},
		{"absent no default is null", "a${aws:principaltag/no}b", true, "ab", SubstNull},
		{"unknown", "a${aws:principaltag/unk}b", true, "ab", SubstUnknown},
		{"null beats unknown", "${aws:principaltag/unk}${aws:principaltag/no}", true, "", SubstNull},
		{"escapes", "${*}${?}${$}", true, "*?$", SubstResolved},
		{"unterminated is literal", "a${b", true, "a${b", SubstResolved},
		{"disabled version keeps text", "${aws:username}", false, "${aws:username}", SubstResolved},
		{"multivalued key stays literal", "${aws:TagKeys}", true, "${aws:TagKeys}", SubstResolved},
		{"unlisted symbolic key is unknown", "${s3:prefix}", true, "", SubstUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, res := Substitute(tc.in, ctx, tc.enabled)
			if res != tc.res || p.String() != tc.text {
				t.Errorf("got %q %v, want %q %v", p.String(), res, tc.text, tc.res)
			}
		})
	}
	// A substituted value is literal: a tag value of "v*?" is not a wildcard.
	p, _ := Substitute("${aws:principaltag/ok}", ctx, true)
	if likeMatch(p, "vXY") || !likeMatch(p, "v*?") {
		t.Error("substituted value must match literally")
	}
}

func TestUnknownVariableGivesResidual(t *testing.T) {
	a := atom("StringEquals", "aws:ResourceTag/team", "${aws:PrincipalTag/team}")
	ctx := ctxOf(Symbolic, map[string]ContextValue{"aws:resourcetag/team": PresentValues("x")})
	r := EvalAtom(a, ctx, true)
	if !r.Result.IsUnknown() {
		t.Fatalf("got %s", r.Result)
	}
	if at := r.Result.Residual().(authz.Atom); at.Values[0] != "${aws:PrincipalTag/team}" {
		t.Errorf("residual lost the variable: %v", at.Values)
	}
	// An absent key decides the atom without looking at the variable.
	absent := &Context{Mode: Symbolic, Values: map[string]ContextValue{"k": AbsentValue}}
	if got := EvalAtom(atom("StringEquals", "k", "${x}"), absent, true).Result; !got.IsFalse() {
		t.Errorf("absent key: %s", got)
	}
}

func TestDeriveContext(t *testing.T) {
	p := withTags(roleSession, map[string]string{"Team": "a", "Env": "dev"})
	p.SessionTags = map[string]string{"team": "b"}
	p.SourceIdentity = "bob"
	c := DeriveContext(DeriveInput{
		Mode: Symbolic, Principal: &p, PrincipalOrgID: "o-1", PrincipalOrgPaths: []string{"o-1/r-1/ou-b/", "o-1/r-1/"},
		Resource: &ResourceInfo{Account: "222222222222", Tags: map[string]string{"Owner": "z"}, TagsSupported: true},
		Network:  PathInternet, DirectCall: true,
		Profile: DefaultProfile(time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)),
	})
	check := func(key string, st KeyState, vals ...string) {
		t.Helper()
		got := c.Lookup(key)
		if got.State != st || (st == Present && !reflect.DeepEqual(got.Values, vals)) {
			t.Errorf("%s = %+v, want %v %v", key, got, st, vals)
		}
	}
	check("aws:PrincipalArn", Present, "arn:aws:iam::111111111111:role/app") // the role, not the session
	check("aws:PrincipalAccount", Present, "111111111111")
	check("aws:PrincipalOrgID", Present, "o-1")
	check("aws:PrincipalOrgPaths", Present, "o-1/r-1/", "o-1/r-1/ou-b/")
	check("aws:PrincipalTag/Team", Present, "b") // session tag overrides
	check("aws:PrincipalTag/env", Present, "dev")
	check("aws:PrincipalTag/other", Absent) // known namespace
	check("aws:PrincipalType", Present, "AssumedRole")
	check("aws:userid", Present, "AROAAPPEXAMPLE000001:s1")
	check("aws:username", Absent)
	check("aws:PrincipalIsAWSService", Present, "false")
	check("aws:SourceIdentity", Present, "bob")
	check("aws:FederatedProvider", Absent)
	check("aws:ResourceAccount", Present, "222222222222")
	check("aws:ResourceOrgID", Absent)
	check("aws:ResourceTag/owner", Present, "z")
	check("aws:ResourceTag/missing", Absent)
	check("aws:SourceVpce", Absent) // internet path
	check("aws:SourceIp", Unknown)
	check("aws:ViaAWSService", Absent)
	check("aws:CalledVia", Absent)
	check("aws:CurrentTime", Present, "2026-10-08T12:00:00Z")
	check("aws:SecureTransport", Present, "true")
	check("aws:MultiFactorAuthPresent", Unknown) // temporary credentials, symbolic
	check("aws:RequestedRegion", Unknown)

	// Long-term credentials: token and MFA keys are absent.
	u := DeriveContext(DeriveInput{Mode: Symbolic, Principal: &userAlice, LongTermCredentials: true})
	for _, k := range []string{"aws:TokenIssueTime", "aws:MultiFactorAuthPresent", "aws:MultiFactorAuthAge"} {
		if u.Lookup(k).State != Absent {
			t.Errorf("%s should be absent for long-term keys", k)
		}
	}
	if got := u.Lookup("aws:username"); got.State != Present || got.Values[0] != "alice" {
		t.Errorf("username: %+v", got)
	}

	// Resource tags the service does not support are absent.
	nt := DeriveContext(DeriveInput{Mode: Symbolic, Resource: &ResourceInfo{Tags: map[string]string{"a": "b"}}})
	if nt.Lookup("aws:ResourceTag/a").State != Absent {
		t.Error("unsupported resource tags must be absent")
	}

	// Concrete, VPC key supplied: SourceIp is absent; otherwise the VPC keys are.
	v := DeriveContext(DeriveInput{Mode: Concrete, Supplied: map[string]ContextValue{"AWS:SourceVpc": PresentValues("vpc-1")}})
	if v.Lookup("aws:sourceip").State != Absent || v.Lookup("aws:sourcevpc").State != Present {
		t.Error("vpc path")
	}

	// Service and anonymous principals.
	svc := model.Principal{Kind: model.Service}
	s := DeriveContext(DeriveInput{Mode: Symbolic, Principal: &svc, ServiceName: "sns.amazonaws.com"})
	if s.Lookup("aws:PrincipalIsAWSService").Values[0] != "true" || s.Lookup("aws:PrincipalArn").State != Absent {
		t.Error("service principal")
	}
	an := model.Principal{Kind: model.Anonymous}
	a := DeriveContext(DeriveInput{Mode: Symbolic, Principal: &an})
	if a.Lookup("aws:PrincipalAccount").State != Absent || a.Lookup("aws:PrincipalIsAWSService").State != Absent ||
		a.Lookup("aws:userid").Values[0] != "anonymous" || a.Lookup("aws:MultiFactorAuthPresent").State != Absent {
		t.Error("anonymous principal")
	}

	// Supplied beats profile beats derived; keys fold ASCII case only.
	o := DeriveContext(DeriveInput{
		Mode: Concrete, Principal: &userAlice,
		Profile:  map[string]ContextValue{"aws:username": PresentValues("p")},
		Supplied: map[string]ContextValue{"AWS:UserName": PresentValues("s")},
	})
	if o.Lookup("aws:username").Values[0] != "s" {
		t.Error("precedence")
	}
	if asciiLower("AWS:Key") == "aws:key" {
		t.Error("the Kelvin sign must not fold to k (A22)")
	}
}

func TestProfiles(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	for _, n := range []string{"any-network", "mfa-session", "now", "tls"} {
		if _, err := Profile(n, now); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	if _, err := Profile("corp-network", now); err != ErrProfileUnsupported {
		t.Errorf("corp-network: %v", err)
	}
	if _, err := Profile("nope", now); err == nil {
		t.Error("unknown profile must error")
	}
	d := DefaultProfile(now)
	if d["aws:epochtime"].Values[0] != "1791460800" || d["aws:securetransport"].Values[0] != "true" {
		t.Errorf("default profile: %+v", d)
	}
}
