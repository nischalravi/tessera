package harness

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
)

func TestSimCustomPagination(t *testing.T) {
	s := baseSpec("page")
	page1 := evalXML("SimulateCustomPolicy", nil, true, "marker-1") // IAM may return fewer results than exist
	page2 := evalXML("SimulateCustomPolicy", []xmlResult{{Action: s.Action, Resource: s.Resource, Decision: "allowed",
		Matched: []xmlMatch{{"PolicyInputList.1", "IAM Policy", 1}}}}, false, "")
	cas := recordCassette(t, s, OracleSimCustom, okResp(page1), okResp(page2))
	if len(cas.Entries) != 2 {
		t.Fatalf("a Marker must give each page its own key: %d entries", len(cas.Entries))
	}
	a, err := replayOracle(cas, OracleSimCustom, Backoff{Base: 1}).Ask(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != AnswerOK || a.Decision != DecisionAllowed || a.Attempts != 2 || len(a.Matched) != 1 {
		t.Fatalf("answer %+v", a)
	}
}

func TestResourceSpecificResultsAggregationTrap(t *testing.T) {
	s := baseSpec("trap")
	mk := func(per []xmlRes) *Answer {
		body := evalXML("SimulateCustomPolicy", []xmlResult{{Action: s.Action, Resource: "*", Decision: "implicitDeny", PerResource: per}}, false, "")
		cas := recordCassette(t, s, OracleSimCustom, okResp(body))
		a, err := replayOracle(cas, OracleSimCustom, Backoff{Base: 1}).Ask(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	// The top level is the most restrictive of the resources; ours is allowed.
	a := mk([]xmlRes{{Name: "arn:aws:s3:::other/x", Decision: "implicitDeny"}, {Name: testObject, Decision: "allowed",
		Matched: []xmlMatch{{"PolicyInputList.1", "IAM Policy", 1}}}})
	if a.Status != AnswerOK || a.Decision != DecisionAllowed {
		t.Fatalf("read the aggregate instead of the per-resource decision: %+v", a)
	}
	// One entry whose name differs (a canonicalised ARN) is still the only candidate.
	if a := mk([]xmlRes{{Name: "arn:aws:s3:::tsr-bkt/K", Decision: "allowed"}}); a.Status != AnswerOK || a.Decision != DecisionAllowed {
		t.Fatalf("single entry: %+v", a)
	}
	// Several entries and none ours: the check is invalid, not guessed.
	a = mk([]xmlRes{{Name: "arn:aws:s3:::a/1", Decision: "allowed"}, {Name: "arn:aws:s3:::b/1", Decision: "allowed"}})
	if a.Status != AnswerInvalid {
		t.Fatalf("ambiguous resources must be invalid: %+v", a)
	}
}

func TestSourcePolicyTypeEnumMismatch(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"resource", "resource"}, {"Resource Policy", "resource"}, {"RESOURCE POLICY", "resource"},
		{"user", "identity"}, {"group", "identity"}, {"role", "identity"}, {"aws-managed", "identity"}, {"user-managed", "identity"},
		{"IAM Policy", "identity"}, {"Permissions Boundary", "boundary"}, {"none", "none"}, {"", "none"},
		{"Surprise Policy", "unknown:Surprise Policy"},
	} {
		if got := NormalizePolicyType(tc.raw); got != tc.want {
			t.Errorf("NormalizePolicyType(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
	// Both spellings arrive through the SDK unchanged and are accepted.
	for _, typ := range []string{"resource", "Resource Policy"} {
		s := baseSpec("spt")
		body := evalXML("SimulateCustomPolicy", []xmlResult{{Action: s.Action, Resource: s.Resource, Decision: "allowed",
			Matched: []xmlMatch{{"ResourcePolicy", typ, 1}}}}, false, "")
		cas := recordCassette(t, s, OracleSimCustom, okResp(body))
		a, err := replayOracle(cas, OracleSimCustom, Backoff{Base: 1}).Ask(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Matched) != 1 || a.Matched[0].PolicyType != "resource" || a.Matched[0].RawPolicyType != typ {
			t.Errorf("%q: %+v", typ, a.Matched)
		}
	}
}

func TestMissingContextValuesIsInvalid(t *testing.T) {
	for name, res := range map[string]xmlResult{
		"top level": {Missing: []string{"aws:PrincipalTag/team"}},
		"per resource": {PerResource: []xmlRes{{Name: testObject, Decision: "implicitDeny",
			Missing: []string{"aws:PrincipalTag/team"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			s := baseSpec("missing")
			res.Action, res.Resource, res.Decision = s.Action, s.Resource, "implicitDeny"
			cas := recordCassette(t, s, OracleSimCustom, okResp(evalXML("SimulateCustomPolicy", []xmlResult{res}, false, "")))
			a, err := replayOracle(cas, OracleSimCustom, Backoff{Base: 1}).Ask(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			if a.Status != AnswerInvalid || !reflect.DeepEqual(a.Missing, []string{"aws:PrincipalTag/team"}) {
				t.Fatalf("answer %+v", a)
			}
			// Invalid is a harness bug: excluded, never a divergence.
			d, w, err := Decide(context.Background(), OfflineCatalog{}, s)
			if err != nil {
				t.Fatal(err)
			}
			c := Compare(s, d, w, a, true)
			if c.Verdict != Excluded || c.Exclusion != ExcludedInvalid {
				t.Fatalf("check %v", c)
			}
		})
	}
}

func TestThrottlingBackoff(t *testing.T) {
	ok := okResp(evalXML("SimulateCustomPolicy", []xmlResult{{Action: "s3:GetObject", Resource: testObject, Decision: "allowed"}}, false, ""))
	ask := func(t *testing.T, bo Backoff, rs ...awstest.Response) (*Answer, error) {
		t.Helper()
		s := baseSpec("throttle")
		// Recording the throttles through the SDK would retry them, so build the cassette by hand.
		cas := recordCassette(t, s, OracleSimCustom, ok)
		cas.Entries[0].Responses = rs
		return replayOracle(cas, OracleSimCustom, bo).Ask(context.Background(), s)
	}

	t.Run("RetryAfterSeconds floors the delay", func(t *testing.T) {
		var log sleepLog
		a, err := ask(t, Backoff{Base: time.Second, Max: 4 * time.Second, Sleep: log.sleep}, throttleResp("7"), ok)
		if err != nil || a.Decision != DecisionAllowed || a.Attempts != 2 {
			t.Fatalf("%+v %v", a, err)
		}
		if !reflect.DeepEqual(log.d, []time.Duration{7 * time.Second}) {
			t.Fatalf("delays %v", log.d)
		}
	})
	t.Run("exponential and capped without a hint", func(t *testing.T) {
		var log sleepLog
		a, err := ask(t, Backoff{Base: time.Second, Max: 3 * time.Second, MaxAttempts: 4, Sleep: log.sleep}, throttleResp(""), throttleResp(""), throttleResp(""), ok)
		if err != nil || a.Attempts != 4 {
			t.Fatalf("%+v %v", a, err)
		}
		if want := []time.Duration{time.Second, 2 * time.Second, 3 * time.Second}; !reflect.DeepEqual(log.d, want) {
			t.Fatalf("delays %v, want %v", log.d, want)
		}
	})
	t.Run("gives up", func(t *testing.T) {
		_, err := ask(t, Backoff{Base: 1, MaxAttempts: 2}, throttleResp(""), throttleResp(""))
		if !errors.Is(err, ErrRetriesExhausted) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("a cassette running dry is an error, not a repeat", func(t *testing.T) {
		_, err := ask(t, Backoff{Base: 1, MaxAttempts: 5}, throttleResp(""))
		if !errors.Is(err, awstest.ErrCassetteExhausted) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("other errors are not retried", func(t *testing.T) {
		denied := awstest.Response{Status: 403, Body: `<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>no</Message></Error><RequestId>r</RequestId></ErrorResponse>`}
		var log sleepLog
		_, err := ask(t, Backoff{Base: 1, Sleep: log.sleep}, denied, ok)
		if err == nil || errors.Is(err, ErrRetriesExhausted) || len(log.d) != 0 {
			t.Fatalf("err %v, delays %v", err, log.d)
		}
	})
	t.Run("context cancellation stops the loop", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		n, err := Backoff{Base: 1}.Do(ctx, func() error { return nil })
		if n != 0 || !errors.Is(err, context.Canceled) {
			t.Fatalf("%d %v", n, err)
		}
	})
}

// TestRetryAfterHook covers a service whose delay is not an HTTP header (Access
// Analyzer's ThrottlingException.RetryAfterSeconds, wired in PR-9).
type raErr struct{ s int32 }

func (e raErr) Error() string            { return "throttled" }
func (e raErr) RetryAfterSeconds() int32 { return e.s }

func TestRetryAfterSecondsMethod(t *testing.T) {
	var log sleepLog
	calls := 0
	n, err := Backoff{Base: time.Second, Sleep: log.sleep}.Do(context.Background(), func() error {
		calls++
		if calls == 1 {
			return raErr{30}
		}
		return nil
	})
	if err != nil || n != 2 || !reflect.DeepEqual(log.d, []time.Duration{30 * time.Second}) {
		t.Fatalf("%d %v %v", n, err, log.d)
	}
}

func TestNewIAMClientDefaultsToAdaptiveRetry(t *testing.T) {
	c := NewIAMClient(awstest.NewReplay(&awstest.Cassette{FixtureVersion: "x"}), "us-east-1", nil)
	if _, ok := c.Options().Retryer.(*retry.AdaptiveMode); !ok {
		t.Fatalf("retryer %T, want adaptive mode", c.Options().Retryer)
	}
	// The SDK stores anonymous credentials as nil; either way nothing is signed.
	if cr := c.Options().Credentials; cr != nil {
		if _, anon := cr.(aws.AnonymousCredentials); !anon {
			t.Fatalf("credentials %T: the offline client must carry none", cr)
		}
	}
}

func TestSimPrincipalInputUsesExclusions(t *testing.T) {
	s := baseSpec("excl")
	s.PolicySourceArn = s.PrincipalARN
	s.Exclusions = []string{"arn:aws:iam::aws:policy/ReadOnlyAccess", "SCP"}
	in := principalInput(s)
	if len(in.PolicyExclusionList) != 2 || aws.ToString(in.PolicySourceArn) != testUser {
		t.Fatalf("%+v", in)
	}
	// The custom input carries the ordered SCP levels and resource owner.
	s2 := baseSpec("custom")
	s2.SCPLevels = [][]string{{allowGetObject}, {allowGetObject}}
	s2.ResourcePolicy, s2.ResourceOwner = allowGetObject, "222222222222"
	ci := customInput(s2)
	if len(ci.OrderedOrganizationPolicyInputList) != 2 || aws.ToString(ci.ResourceOwner) != "arn:aws:iam::222222222222:root" || aws.ToString(ci.CallerArn) != testUser {
		t.Fatalf("%+v", ci)
	}
	// aws:PrincipalArn is passed even when the spec did not name it (§13.2).
	var found bool
	for _, e := range ci.ContextEntries {
		found = found || aws.ToString(e.ContextKeyName) == "aws:PrincipalArn"
	}
	if !found {
		t.Fatal("aws:PrincipalArn missing from the context entries")
	}
}
