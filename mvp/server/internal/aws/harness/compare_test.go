package harness

import (
	"context"
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
)

func decide(t *testing.T, s *RequestSpec) (*authz.Decision, *World) {
	t.Helper()
	d, w, err := Decide(context.Background(), OfflineCatalog{}, s)
	if err != nil {
		t.Fatal(err)
	}
	return d, w
}

func simAnswer(decision string) *Answer {
	return &Answer{Oracle: OracleSimCustom, Status: AnswerOK, Decision: decision}
}

func specs() (allow, implicit, explicit *RequestSpec) {
	allow = baseSpec("allow")
	implicit = baseSpec("implicit")
	implicit.Action = "s3:PutObject"
	explicit = baseSpec("explicit")
	explicit.Identity = append(explicit.Identity, `{"Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`)
	return
}

func TestEngineDecisionsOfTheFixtures(t *testing.T) {
	allow, implicit, explicit := specs()
	for _, tc := range []struct {
		s    *RequestSpec
		want string
	}{{allow, "allowed"}, {implicit, "implicitDeny"}, {explicit, "explicitDeny"}} {
		d, _ := decide(t, tc.s)
		if got := OursDecision(d); got != tc.want || d.Fidelity != authz.Exact {
			t.Errorf("%s: %s (%s), want %s exact", tc.s.ID, got, d.Fidelity, tc.want)
		}
	}
}

func TestCompareM1(t *testing.T) {
	allow, implicit, explicit := specs()
	for _, tc := range []struct {
		name   string
		s      *RequestSpec
		theirs string
		want   Verdict
	}{
		{"allow/allowed", allow, DecisionAllowed, Agree},
		{"allow/implicit", allow, DecisionImplicitDeny, Disagree},
		{"implicit/implicit", implicit, DecisionImplicitDeny, Agree},
		{"implicit/explicit is still agreement on M1", implicit, DecisionExplicitDeny, Agree},
		{"implicit/allowed", implicit, DecisionAllowed, Disagree},
		{"explicit/allowed", explicit, DecisionAllowed, Disagree},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, w := decide(t, tc.s)
			if c := Compare(tc.s, d, w, simAnswer(tc.theirs), true); c.Verdict != tc.want || !c.Covered {
				t.Fatalf("%v", c)
			}
		})
	}
}

func TestCompareM2DenyKind(t *testing.T) {
	_, implicit, explicit := specs()
	for _, tc := range []struct {
		s      *RequestSpec
		theirs string
		want   *bool // nil: not applicable
	}{
		{implicit, DecisionImplicitDeny, ptr(true)},
		{implicit, DecisionExplicitDeny, ptr(false)},
		{explicit, DecisionExplicitDeny, ptr(true)},
		{explicit, DecisionImplicitDeny, ptr(false)},
		{explicit, DecisionAllowed, nil},
	} {
		d, w := decide(t, tc.s)
		c := Compare(tc.s, d, w, simAnswer(tc.theirs), true)
		if (c.M2 == nil) != (tc.want == nil) || (c.M2 != nil && *c.M2 != *tc.want) {
			t.Errorf("%s vs %s: M2 = %v", tc.s.ID, tc.theirs, c.M2)
		}
	}
}

func ptr(b bool) *bool { return &b }

func TestCompareM3MatchedStatements(t *testing.T) {
	_, _, explicit := specs()
	d, w := decide(t, explicit)
	mk := func(id string, line int) *Answer {
		a := simAnswer(DecisionExplicitDeny)
		a.Matched = []MatchedStatement{{SourcePolicyID: id, PolicyType: "identity", Line: line}}
		return a
	}
	// Policy 2 holds the Deny: its statement is among ours.
	if c := Compare(explicit, d, w, mk("PolicyInputList.2", 1), true); c.M3 == nil || !*c.M3 {
		t.Errorf("M3 = %v", c.M3)
	}
	// Policy 1 holds an Allow that matched nothing in our trace for a Deny? It
	// matched (Allow), so it is among ours as well; line 7 is not.
	if c := Compare(explicit, d, w, mk("PolicyInputList.2", 7), true); c.M3 == nil || *c.M3 {
		t.Errorf("a statement we never matched must fail M3: %v", c.M3)
	}
	// An id outside the spec cannot be mapped: M3 is not computed, not failed.
	if c := Compare(explicit, d, w, mk("PolicyInputList.9", 1), true); c.M3 != nil {
		t.Errorf("unmappable id: M3 = %v", *c.M3)
	}
}

func TestCompareExclusions(t *testing.T) {
	allow, _, _ := specs()
	d, w := decide(t, allow)

	if c := Compare(allow, d, w, &Answer{Oracle: OracleSimCustom, Status: AnswerInconclusive}, true); c.Exclusion != ExcludedInconclusive || c.Covered {
		t.Errorf("inconclusive: %v", c)
	}
	// UNSUPPORTED is excluded and not covered, so it cannot raise M1.
	un := *d
	un.Fidelity = authz.Unsupported
	if c := Compare(allow, &un, w, simAnswer(DecisionAllowed), true); c.Exclusion != ExcludedUnsupported || c.Covered || c.Ours != "unsupported" {
		t.Errorf("unsupported: %v", c)
	}
	// CONDITIONAL in concrete mode is an engine bug: a disagreement.
	cond := *d
	cond.Outcome = authz.Conditional
	if c := Compare(allow, &cond, w, simAnswer(DecisionAllowed), true); c.Verdict != Disagree {
		t.Errorf("conditional: %v", c)
	}
	// A secondary oracle is recorded, never counted.
	if c := Compare(allow, d, w, simAnswer(DecisionAllowed), false); c.Exclusion != ExcludedNotAuthority {
		t.Errorf("secondary: %v", c)
	}
	// Set checks are not gated.
	s6 := allow.Clone()
	s6.Stratum = S6SetChecks
	if c := Compare(s6, d, w, simAnswer(DecisionAllowed), true); c.Exclusion != ExcludedStratumNoCount {
		t.Errorf("S6: %v", c)
	}
}

func TestCompareProbeStageM4(t *testing.T) {
	_, _, explicit := specs()
	d, w := decide(t, explicit)
	probe := func(stage authz.Stage) *Answer {
		return &Answer{Oracle: OracleProbe, Status: AnswerOK, Decision: DecisionDenied, DeniedStage: stage}
	}
	c := Compare(explicit, d, w, probe(authz.StageIdentity), true)
	if c.Verdict != Agree || c.OurStage != authz.StageIdentity || c.M4 == nil || !*c.M4 {
		t.Fatalf("%v M4=%v stage=%s", c, c.M4, c.OurStage)
	}
	if c := Compare(explicit, d, w, probe(authz.StageSCP), true); c.M4 == nil || *c.M4 || c.Verdict != Agree {
		t.Fatalf("a wrong stage fails M4 but not M1: %v", c)
	}
	// A probe cannot tell explicit from implicit, so there is no M2.
	if c.M2 != nil {
		t.Fatalf("M2 = %v", *c.M2)
	}
}

func TestCompareAccessAnalyzer(t *testing.T) {
	allow, implicit, _ := specs()
	dAllow, wAllow := decide(t, allow)
	dDeny, wDeny := decide(t, implicit)
	aa := func(decision string, reasons ...AAReason) *Answer {
		return &Answer{Oracle: OracleAccessCheck, Status: AnswerOK, Decision: decision, Reasons: reasons}
	}
	for _, tc := range []struct {
		name string
		s    *RequestSpec
		d    *authz.Decision
		w    *World
		ans  *Answer
		want Verdict
		why  Exclusion
	}{
		{"PASS and we deny agree", implicit, dDeny, wDeny, aa(DecisionPass), Agree, ""},
		{"PASS but we allow is a disagreement", allow, dAllow, wAllow, aa(DecisionPass), Disagree, ""},
		{"FAIL and we allow: AA may be a false positive", allow, dAllow, wAllow, aa(DecisionFail, AAReason{StatementIndex: 0}), Excluded, ExcludedManualTriage},
		{"FAIL naming a statement we say matches nothing", implicit, dDeny, wDeny, aa(DecisionFail, AAReason{StatementIndex: 0}), Disagree, ""},
		{"FAIL without a reason", implicit, dDeny, wDeny, aa(DecisionFail), Excluded, ExcludedManualTriage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Compare(tc.s, tc.d, tc.w, tc.ans, true)
			if c.Verdict != tc.want || c.Exclusion != tc.why {
				t.Fatalf("%v (%s)", c, c.Note)
			}
		})
	}
	// FAIL naming a statement we do match, yet we deny: manual triage.
	_, _, explicit := specs()
	dx, wx := decide(t, explicit)
	if c := Compare(explicit, dx, wx, aa(DecisionFail, AAReason{StatementIndex: 0}), true); c.Exclusion != ExcludedManualTriage {
		t.Fatalf("%v", c)
	}
}

func TestSpecIngestRefusal(t *testing.T) {
	for name, pol := range map[string]string{
		"both Action and NotAction": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","NotAction":"s3:PutObject","Resource":"*"}]}`,
		"NotPrincipal with Allow":   `{"Statement":[{"Effect":"Allow","NotPrincipal":"*","Action":"s3:GetObject","Resource":"*"}]}`,
	} {
		s := baseSpec("refuse")
		s.Identity = []string{pol}
		var ref *RefusalError
		if err := s.CheckIngest(); !errors.As(err, &ref) || ref.Reason != RefusedDroppedAnomaly {
			t.Errorf("%s: %v", name, err)
		}
		// Both simulator clients refuse it before any call is made.
		for _, o := range []Oracle{&SimCustom{}, &SimPrincipal{}} {
			s2 := s.Clone()
			s2.PolicySourceArn = s2.PrincipalARN
			if _, err := o.Ask(context.Background(), s2); !errors.As(err, &ref) {
				t.Errorf("%s %s: %v", name, o.Kind(), err)
			}
		}
	}
	bad := baseSpec("bad")
	bad.Identity = []string{`{"Statement":[`}
	var ref *RefusalError
	if err := bad.CheckIngest(); !errors.As(err, &ref) || ref.Reason != RefusedUnparseable {
		t.Errorf("unparseable: %v", err)
	}
	if err := baseSpec("ok").CheckIngest(); err != nil {
		t.Errorf("a clean spec: %v", err)
	}
}

func TestSpecValidate(t *testing.T) {
	for name, mut := range map[string]func(*RequestSpec){
		"no id":                func(s *RequestSpec) { s.ID = "" },
		"bad stratum":          func(s *RequestSpec) { s.Stratum = "S9" },
		"no fixture":           func(s *RequestSpec) { s.FixtureVersion = "" },
		"wildcard action":      func(s *RequestSpec) { s.Action = "s3:Get*" },
		"no service":           func(s *RequestSpec) { s.Action = "GetObject" },
		"session principal":    func(s *RequestSpec) { s.PrincipalARN = "arn:aws:sts::111111111111:assumed-role/app/s1" },
		"two boundaries":       func(s *RequestSpec) { s.Boundary = []string{"{}", "{}"} },
		"eight SCP levels":     func(s *RequestSpec) { s.SCPLevels = make([][]string, 8) },
		"policy without owner": func(s *RequestSpec) { s.ResourcePolicy = "{}" },
		"source arn differs":   func(s *RequestSpec) { s.PolicySourceArn = "arn:aws:iam::111111111111:user/bob" },
		"unknown feature":      func(s *RequestSpec) { s.Features = []string{"warp"} },
		"empty context":        func(s *RequestSpec) { s.Context = map[string]ContextEntry{"k": {}} },
	} {
		s := baseSpec("v")
		mut(s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseSpec([]byte(`{"id":"x","bogus":1}`)); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := ParseSpec([]byte(`{} {}`)); err == nil {
		t.Error("trailing data accepted")
	}
}

func TestRoute(t *testing.T) {
	plain := baseSpec("r")
	deployed := baseSpec("r")
	deployed.PolicySourceArn = deployed.PrincipalARN
	withRP := baseSpec("r")
	withRP.ResourcePolicy, withRP.ResourceOwner = "{}", testAcct
	rcp := baseSpec("r")
	rcp.Features = []string{FeatureRCP, FeatureBPA}
	for _, tc := range []struct {
		s    *RequestSpec
		want OracleKind
	}{{plain, OracleSimCustom}, {deployed, OracleSimPrincipal}, {withRP, OracleSimCustom}, {rcp, OracleProbe}} {
		if got := Route(tc.s); got != tc.want {
			t.Errorf("%+v routes to %s, want %s", tc.s.Features, got, tc.want)
		}
	}
	for f := range probeOnlyFeatures {
		s := baseSpec("r")
		s.Features = []string{f}
		if Route(s) != OracleProbe {
			t.Errorf("feature %s is not routed to a probe", f)
		}
	}
}

func TestBuildWorldSCPChain(t *testing.T) {
	for _, n := range []int{1, 2, 3, 7} {
		s := baseSpec("scp")
		for i := 0; i < n; i++ {
			s.SCPLevels = append(s.SCPLevels, []string{`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`})
		}
		d, _ := decide(t, s)
		if got := OursDecision(d); got != "allowed" {
			t.Errorf("%d allow-all SCP levels: %s", n, got)
		}
		s.SCPLevels[n-1] = []string{`{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`}
		d, _ = decide(t, s)
		if got := OursDecision(d); got == "allowed" {
			t.Errorf("%d levels, account level allows only ec2: still allowed", n)
		}
	}
}
