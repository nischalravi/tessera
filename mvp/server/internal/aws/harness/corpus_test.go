package harness

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/awstest"
)

const corpusDir = "../../../testdata/aws/cassettes"

// TestReplayCorpus is the offline replay job: every committed case concludes
// what it expects, with no credentials and no network.
func TestReplayCorpus(t *testing.T) {
	cases, err := LoadDir(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 12 {
		t.Fatalf("%d cases; the corpus shrank", len(cases))
	}
	rep := Replay(context.Background(), OfflineCatalog{}, cases)
	for _, c := range rep.Cases {
		if !c.OK {
			t.Errorf("%s: %s", c.ID, c.Problem)
		}
	}
	by := map[string]*Check{}
	for _, c := range rep.Cases {
		by[c.ID] = c.Check
	}
	// The cassettes exercise what they claim to.
	if c := by["sim-paginated"]; c == nil || c.Attempts != 2 || c.Ours != "allowed" {
		t.Errorf("sim-paginated: %v", c)
	}
	if c := by["sim-throttled-then-allowed"]; c == nil || c.Attempts != 2 {
		t.Errorf("sim-throttled-then-allowed: %v", c)
	}
	if c := by["sim-resource-specific-trap"]; c == nil || c.Theirs != DecisionAllowed || c.Answer.Matched[0].PolicyType != "identity" {
		t.Errorf("sim-resource-specific-trap: %v", c)
	}
	if c := by["sim-resource-policy-spelling"]; c == nil || c.Answer.Matched[0].RawPolicyType != "Resource Policy" || c.M3 == nil || !*c.M3 {
		t.Errorf("sim-resource-policy-spelling: %v", c)
	}
	if c := by["sim-explicit-deny-identity"]; c == nil || c.M2 == nil || !*c.M2 || c.M3 == nil || !*c.M3 {
		t.Errorf("sim-explicit-deny-identity: %v", c)
	}
	if c := by["sim-scp-gate-deny"]; c == nil || c.Answer.DeniedStage != authz.StageSCP || c.M2 == nil || !*c.M2 {
		t.Errorf("sim-scp-gate-deny: %v", c)
	}
	if c := by["probe-allowed-after-inconclusive"]; c == nil || c.Attempts != 2 || c.Verdict != Agree {
		t.Errorf("probe-allowed-after-inconclusive: %v", c)
	}
	if c := by["probe-denied-identity"]; c == nil || c.M4 != nil && !*c.M4 {
		t.Errorf("probe-denied-identity: %v", c)
	}
	if m := rep.Metrics; m.Excluded[ExcludedDropped] != 1 || m.Excluded[ExcludedInvalid] != 1 || m.M1.Agree != m.M1.Total {
		t.Errorf("metrics %+v", m)
	}
	if !rep.OK {
		t.Fatal("replay failed")
	}
}

// Every committed cassette key is what the SDK sends today: replaying with a
// changed request builder would fail with ErrNoRecording, which the corpus test
// above turns into a failed case. This guards the keys against a fixture bump.
func TestCorpusCassettesAreBoundToTheirFixture(t *testing.T) {
	cases, err := LoadDir(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if !c.Synthetic {
			continue
		}
		if c.IAM != nil && c.IAM.FixtureVersion != c.Spec.FixtureVersion {
			t.Errorf("%s: fixture mismatch", c.ID)
		}
	}
}

func caseJSON(t *testing.T, mut func(*Case)) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpusDir, "sim-implicit-deny-other-action.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadCase(b)
	if err != nil {
		t.Fatal(err)
	}
	mut(c)
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestKnownDivergencePins(t *testing.T) {
	good := &Known{Class: ClassSimulatorLimitation, Justification: "the simulator ignores aws:SourceVpce", ProbeEvidence: "probe run 42"}
	// The pin is held out of M1, and the case passes only while it still diverges.
	c, err := LoadCase(caseJSON(t, func(c *Case) {
		c.Known = good
		c.IAM = recordCassette(t, c.Spec, OracleSimCustom, okResp(evalXML("SimulateCustomPolicy",
			[]xmlResult{{Action: c.Spec.Action, Resource: c.Spec.Resource, Decision: "allowed"}}, false, "")))
	}))
	if err != nil {
		t.Fatal(err)
	}
	rep := Replay(context.Background(), OfflineCatalog{}, []*Case{c})
	if !rep.OK || !rep.Cases[0].Known || rep.Metrics.M1.Total != 0 || rep.Metrics.Excluded[ExcludedKnown] != 1 {
		t.Fatalf("%+v", rep)
	}
	// A stale pin (the check now agrees) fails the corpus.
	stale, err := LoadCase(caseJSON(t, func(c *Case) { c.Known = good }))
	if err != nil {
		t.Fatal(err)
	}
	rep = Replay(context.Background(), OfflineCatalog{}, []*Case{stale})
	if rep.OK || !strings.Contains(rep.Cases[0].Problem, "remove the pin") {
		t.Fatalf("%+v", rep.Cases[0])
	}
	// An unexpected divergence fails it too.
	bad, err := LoadCase(caseJSON(t, func(c *Case) {
		c.IAM = recordCassette(t, c.Spec, OracleSimCustom, okResp(evalXML("SimulateCustomPolicy",
			[]xmlResult{{Action: c.Spec.Action, Resource: c.Spec.Resource, Decision: "allowed"}}, false, "")))
	}))
	if err != nil {
		t.Fatal(err)
	}
	if rep = Replay(context.Background(), OfflineCatalog{}, []*Case{bad}); rep.OK || !strings.Contains(rep.Cases[0].Problem, "expected agreement") {
		t.Fatalf("%+v", rep.Cases[0])
	}
}

func TestLoadCaseRejects(t *testing.T) {
	for name, mut := range map[string]func(*Case){
		"pin without evidence":   func(c *Case) { c.Known = &Known{Class: ClassSimulatorLimitation, Justification: "x"} },
		"pin without justif.":    func(c *Case) { c.Known = &Known{Class: ClassSimulatorLimitation, ProbeEvidence: "x"} },
		"pin of another class":   func(c *Case) { c.Known = &Known{Class: ClassEngineBug, Justification: "x", ProbeEvidence: "y"} },
		"excluded without a why": func(c *Case) { c.Expect = Expect{Verdict: Excluded} },
		"unknown verdict":        func(c *Case) { c.Expect = Expect{Verdict: "maybe"} },
		"fixture drift":          func(c *Case) { c.IAM.FixtureVersion = "other" },
		"spec id differs":        func(c *Case) { c.Spec.ID = "other" },
		"pin with excluded expect": func(c *Case) {
			c.Known = &Known{Class: ClassSimulatorLimitation, Justification: "x", ProbeEvidence: "y"}
			c.Expect = Expect{Verdict: Excluded, Exclusion: ExcludedInvalid}
		},
	} {
		if _, err := LoadCase(caseJSON(t, mut)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadCase([]byte(`{"id":"x","spec":null,"bogus":1}`)); err == nil {
		t.Error("unknown field accepted")
	}
	// A duplicate id across files, and an empty directory, are errors.
	dir := t.TempDir()
	b := caseJSON(t, func(*Case) {})
	for _, n := range []string{"a.json", "b.json"} {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Errorf("duplicate id: %v", err)
	}
}

func TestOracleForNeedsItsRecordings(t *testing.T) {
	c, err := LoadCase(caseJSON(t, func(c *Case) { c.IAM = nil }))
	if err != nil {
		t.Fatal(err)
	}
	rep := Replay(context.Background(), OfflineCatalog{}, []*Case{c})
	if rep.OK || !strings.Contains(rep.Cases[0].Problem, "no iam_cassette") {
		t.Fatalf("%+v", rep.Cases[0])
	}
}

func TestClassifyProbe(t *testing.T) {
	for _, tc := range []struct {
		r     ProbeResponse
		want  AnswerStatus
		dec   string
		stage authz.Stage
	}{
		{ProbeResponse{Family: FamilyS3, Success: true}, AnswerOK, DecisionAllowed, ""},
		{ProbeResponse{Family: FamilyS3, ErrorCode: "AccessDenied", Message: "with an explicit deny in a service control policy"}, AnswerOK, DecisionDenied, authz.StageSCP},
		{ProbeResponse{Family: FamilyS3, ErrorCode: "SlowDown"}, AnswerInconclusive, "", ""},
		{ProbeResponse{Family: FamilyS3, ErrorCode: "NoSuchKey"}, AnswerInconclusive, "", ""},
		{ProbeResponse{Family: FamilyEC2DryRun, ErrorCode: "DryRunOperation"}, AnswerOK, DecisionAllowed, ""},
		{ProbeResponse{Family: FamilyEC2DryRun, ErrorCode: "UnauthorizedOperation"}, AnswerOK, DecisionDenied, ""},
		{ProbeResponse{Family: FamilyEC2DryRun, Success: true}, AnswerInconclusive, "", ""},
		{ProbeResponse{Family: FamilySNS, ErrorCode: "AuthorizationError"}, AnswerOK, DecisionDenied, ""},
		{ProbeResponse{Family: FamilyKMS, ErrorCode: "AccessDeniedException", Message: "no resource-based policy allows"}, AnswerOK, DecisionDenied, authz.StageResourcePolicy},
		{ProbeResponse{Family: FamilySecretsManager, ErrorCode: "ResourceNotFoundException"}, AnswerInconclusive, "", ""},
		{ProbeResponse{Family: FamilyNotInCatalog, Success: true}, AnswerInconclusive, "", ""},
		{ProbeResponse{Family: "unknown-family", Success: true}, AnswerInconclusive, "", ""},
	} {
		a := ClassifyProbe(tc.r)
		if a.Status != tc.want || a.Decision != tc.dec || a.DeniedStage != tc.stage {
			t.Errorf("%+v -> %+v", tc.r, a)
		}
	}
	for msg, want := range map[string]authz.Stage{
		"with an explicit deny in a resource control policy":            authz.StageRCP,
		"because no VPC endpoint policy allows the s3:GetObject action": authz.StageVPCE,
		"with an explicit deny in a permissions boundary":               authz.StageBoundary,
		"because no session policy allows the action":                   authz.StageSession,
		"because no identity-based policy allows the action":            authz.StageIdentity,
		"because no resource-based policy allows the action":            authz.StageResourcePolicy,
	} {
		if got, ok := ParseAccessDeniedStage(msg); !ok || got != want {
			t.Errorf("%q -> %s, %v", msg, got, ok)
		}
	}
	if _, ok := ParseAccessDeniedStage("Access Denied"); ok {
		t.Error("a message with no policy type must not name a stage")
	}
}

func TestProbeOracleNeverTurnsInconclusiveIntoDeny(t *testing.T) {
	s := baseSpec("p")
	s.Features = []string{FeatureAmbiguity}
	slow := ProbeResponse{Family: FamilyS3, ErrorCode: "SlowDown"}
	o := &ProbeOracle{Client: &RecordedProbe{Responses: []ProbeResponse{slow, slow, slow}}, Backoff: Backoff{Base: 1, MaxAttempts: 3}}
	a, err := o.Ask(context.Background(), s)
	if err != nil || a.Status != AnswerInconclusive || a.Decision != "" || a.Attempts != 3 {
		t.Fatalf("%+v %v", a, err)
	}
	// Not in the probe catalog: inconclusive at once, no retry.
	o = &ProbeOracle{Client: &RecordedProbe{Responses: []ProbeResponse{{Family: FamilyNotInCatalog}}}, Backoff: Backoff{Base: 1}}
	if a, err = o.Ask(context.Background(), s); err != nil || a.Status != AnswerInconclusive || a.Attempts != 1 {
		t.Fatalf("%+v %v", a, err)
	}
	// A transport error is an error, not an answer.
	o = &ProbeOracle{Client: &RecordedProbe{}, Backoff: Backoff{Base: 1}}
	if _, err = o.Ask(context.Background(), s); err == nil {
		t.Fatal("exhausted recording accepted")
	}
}

func TestAccessAnalyzerOracle(t *testing.T) {
	s := baseSpec("aa")
	s.Stratum = S6SetChecks
	o := &AccessAnalyzer{Client: &RecordedAA{Results: []AAResult{{Result: "PASS"}, {Result: "FAIL", Reasons: []AAReason{{StatementIndex: 0}}}, {Result: "MAYBE"}}}, Backoff: Backoff{Base: 1}}
	for i, want := range []string{DecisionPass, DecisionFail} {
		a, err := o.Ask(context.Background(), s)
		if err != nil || a.Decision != want {
			t.Fatalf("%d: %+v %v", i, a, err)
		}
	}
	if a, _ := o.Ask(context.Background(), s); a.Status != AnswerInvalid {
		t.Fatalf("unknown result: %+v", a)
	}
	multi := s.Clone()
	multi.Boundary = []string{"{}"}
	if _, err := o.Ask(context.Background(), multi); err == nil {
		t.Fatal("a spec with an environment accepted")
	}
}

func TestRunnerSettleReprobe(t *testing.T) {
	s := baseSpec("settle")
	s.Features = []string{FeatureAmbiguity}
	s.Stratum = S4Probes
	// Our engine allows. The first probe says denied (IAM had not propagated),
	// the re-probe after the settle window says allowed.
	rp := &RecordedProbe{Responses: []ProbeResponse{{Family: FamilyS3, ErrorCode: "AccessDenied"}, {Family: FamilyS3, Success: true}}}
	settled := 0
	r := NewRunner(OfflineCatalog{}, &ProbeOracle{Client: rp, Backoff: Backoff{Base: 1}})
	r.Settle = func(context.Context) error { settled++; return nil }
	tick := time.Unix(0, 0)
	r.Now = func() time.Time { tick = tick.Add(5 * time.Millisecond); return tick }
	c, err := r.Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if settled != 1 || c.Verdict != Agree || !c.Settled || !c.Propagation || c.LatencyMS != 5 {
		t.Fatalf("%+v settled=%d", c, settled)
	}
	// A disagreement that persists stays one.
	rp = &RecordedProbe{Responses: []ProbeResponse{{Family: FamilyS3, ErrorCode: "AccessDenied"}, {Family: FamilyS3, ErrorCode: "AccessDenied"}}}
	r = NewRunner(OfflineCatalog{}, &ProbeOracle{Client: rp, Backoff: Backoff{Base: 1}})
	r.Settle = func(context.Context) error { return nil }
	if c, err = r.Run(context.Background(), s); err != nil || c.Verdict != Disagree || !c.Settled || c.Propagation {
		t.Fatalf("%+v %v", c, err)
	}
	// Without a Settle (offline replay) there is no re-probe.
	rp = &RecordedProbe{Responses: []ProbeResponse{{Family: FamilyS3, ErrorCode: "AccessDenied"}}}
	r = NewRunner(OfflineCatalog{}, &ProbeOracle{Client: rp, Backoff: Backoff{Base: 1}})
	if c, err = r.Run(context.Background(), s); err != nil || c.Verdict != Disagree || c.Settled {
		t.Fatalf("%+v %v", c, err)
	}
	// An oracle that is not configured is a run error.
	if _, err = NewRunner(OfflineCatalog{}).Run(context.Background(), s); err == nil {
		t.Fatal("missing oracle accepted")
	}
	// An action outside the catalog is UNSUPPORTED: excluded and not covered.
	nocat := baseSpec("nocat")
	nocat.Action, nocat.Features = "nosuch:Thing", []string{FeatureAmbiguity}
	rp = &RecordedProbe{Responses: []ProbeResponse{{Family: FamilyS3, Success: true}}}
	r = NewRunner(OfflineCatalog{}, &ProbeOracle{Client: rp, Backoff: Backoff{Base: 1}})
	if c, err = r.Run(context.Background(), nocat); err != nil || c.Exclusion != ExcludedUnsupported || c.Covered {
		t.Fatalf("%+v %v", c, err)
	}
	// An engine that cannot answer at all (here: the evaluation's context is
	// already cancelled) is an excluded check, not a failed run.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c, err = NewRunner(OfflineCatalog{}).Run(ctx, baseSpec("cancelled")); err != nil || c.Exclusion != ExcludedEngineError {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestClassify(t *testing.T) {
	allowed, denied := &authz.Decision{Outcome: authz.Allow, Fidelity: authz.Exact}, &authz.Decision{Outcome: authz.Deny, Fidelity: authz.Exact}
	ans := func(k OracleKind, d string) *Answer { return &Answer{Oracle: k, Status: AnswerOK, Decision: d} }
	withReason := func(d *authz.Decision, code authz.ReasonCode) *authz.Decision {
		c := *d
		c.FidelityReasons = []authz.FidelityReason{{Code: code}}
		return &c
	}
	for _, tc := range []struct {
		name string
		e    Evidence
		want DivergenceClass
	}{
		{"engine bug: probe and simulator agree against us", Evidence{Ours: allowed, Primary: ans(OracleSimCustom, DecisionImplicitDeny), Probe: ans(OracleProbe, DecisionDenied)}, ClassEngineBug},
		{"simulator limitation: the probe sides with us", Evidence{Ours: allowed, Primary: ans(OracleSimCustom, DecisionImplicitDeny), Probe: ans(OracleProbe, DecisionAllowed)}, ClassSimulatorLimitation},
		{"engine bug: probe primary, simulator agrees with it", Evidence{Ours: denied, Primary: ans(OracleProbe, DecisionAllowed), Alternate: ans(OracleSimCustom, DecisionAllowed)}, ClassEngineBug},
		{"propagation: agrees after the settle", Evidence{Ours: allowed, Primary: ans(OracleProbe, DecisionDenied), Settle: ans(OracleProbe, DecisionAllowed)}, ClassPropagation},
		{"context mismatch", Evidence{Ours: allowed, Primary: &Answer{Oracle: OracleSimCustom, Status: AnswerInvalid, Missing: []string{"aws:x"}}}, ClassContextMismatch},
		{"context mismatch flag", Evidence{Ours: allowed, Primary: ans(OracleSimCustom, DecisionImplicitDeny), ContextMismatch: true}, ClassContextMismatch},
		{"catalog stale", Evidence{Ours: withReason(denied, authz.ReasonCatalogMiss), Primary: ans(OracleSimCustom, DecisionAllowed)}, ClassCatalogStale},
		{"fixture drift", Evidence{Ours: allowed, Primary: ans(OracleProbe, DecisionDenied), FixtureDrift: true}, ClassFixtureDrift},
		{"doc ambiguity", Evidence{Ours: withReason(allowed, authz.AmbiguityReason("A3")), Primary: ans(OracleProbe, DecisionDenied)}, ClassDocAmbiguity},
		{"unclassified", Evidence{Ours: allowed, Primary: ans(OracleSimCustom, DecisionImplicitDeny)}, ClassUnclassified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, why := Classify(tc.e); got != tc.want || why == "" {
				t.Fatalf("%s (%s), want %s", got, why, tc.want)
			}
		})
	}
}

func TestTriageStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "triage.jsonl")
	st, err := OpenTriage(path)
	if err != nil {
		t.Fatal(err)
	}
	pass := true
	m := NewMetrics()
	m.Add(Check{Stratum: S2GrammarFuzz, Verdict: Agree, Covered: true})
	steps := []error{
		st.AddRun(Run{ID: "r1", Mode: "replay", Seed: 7, Metrics: m}),
		st.AddCheck("r1", Check{SpecID: "a", Verdict: Agree}),
		st.AddCheck("r1", Check{SpecID: "b", Verdict: Disagree}),
		st.AddDivergence(Divergence{ID: "d1", RunID: "r1", SpecID: "b", Class: ClassUnclassified, Minimized: baseSpec("b")}),
		st.AddDivergence(Divergence{ID: "d2", RunID: "r1", SpecID: "c", Class: ClassEngineBug}),
		// A later record replaces an earlier one: the status and issue link update.
		st.AddDivergence(Divergence{ID: "d2", RunID: "r1", SpecID: "c", Class: ClassEngineBug, Status: StatusClosed, IssueURL: "https://example.invalid/1"}),
		st.AddRun(Run{ID: "r1", Mode: "replay", Seed: 7, Metrics: m, GatePass: &pass}),
	}
	for i, err := range steps {
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	if err := st.AddDivergence(Divergence{}); err == nil {
		t.Fatal("a divergence without ids accepted")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	snap, err := LoadTriage(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Runs) != 1 || snap.Runs[0].GatePass == nil || len(snap.Checks["r1"]) != 2 || len(snap.Divergences) != 2 {
		t.Fatalf("%+v", snap)
	}
	open := snap.Open()
	if len(open) != 1 || open[0].ID != "d1" || open[0].Minimized == nil || open[0].Minimized.ID != "b" {
		t.Fatalf("open %+v", open)
	}
	if snap.Divergences[1].Status != StatusClosed || snap.Divergences[1].IssueURL == "" {
		t.Fatalf("%+v", snap.Divergences[1])
	}
	// A corrupt line is an error naming the line.
	if err := os.WriteFile(path, []byte("{\"kind\":\"run\",\"run\":{\"id\":\"x\"}}\nnot json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTriage(path); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("err %v", err)
	}
}

func TestAwstestErrorsSurfaceThroughTheOracle(t *testing.T) {
	s := baseSpec("noreq")
	empty := &awstest.Cassette{FixtureVersion: fixtureV}
	_, err := replayOracle(empty, OracleSimCustom, Backoff{Base: 1}).Ask(context.Background(), s)
	if !errors.Is(err, awstest.ErrNoRecording) {
		t.Fatalf("err %v", err)
	}
}
