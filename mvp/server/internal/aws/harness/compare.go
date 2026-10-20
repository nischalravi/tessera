package harness

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
)

// Verdict is the comparator's result for one check.
type Verdict string

// Verdicts.
const (
	Agree    Verdict = "agree"
	Disagree Verdict = "disagree"
	Excluded Verdict = "excluded"
)

// Exclusion says why a check left the gate metric (§13.6). Every excluded check
// is still counted, so excluding cannot hide behind a high agreement rate.
type Exclusion string

// Exclusions.
const (
	ExcludedUnsupported    Exclusion = "unsupported"     // our fidelity is UNSUPPORTED
	ExcludedDropped        Exclusion = "dropped_anomaly" // a policy has a Dropped ingest anomaly (§8.4.3)
	ExcludedUnparseable    Exclusion = "unparseable"
	ExcludedInvalid        Exclusion = "invalid"      // MissingContextValues or a bad response shape: a harness bug
	ExcludedInconclusive   Exclusion = "inconclusive" // a probe that could not tell
	ExcludedManualTriage   Exclusion = "manual_triage"
	ExcludedNotAuthority   Exclusion = "not_authoritative" // a secondary oracle: recorded, not counted
	ExcludedStratumNoCount Exclusion = "stratum_not_counted"
)

// Check is one compared check, the row of harness_checks (§13.1).
type Check struct {
	SpecID      string      `json:"spec_id"`
	SpecHash    string      `json:"spec_hash"`
	Stratum     Stratum     `json:"stratum"`
	Service     string      `json:"service"`
	Oracle      OracleKind  `json:"oracle"`
	Ours        string      `json:"ours"`   // normalized: allowed, explicitDeny, implicitDeny, conditional, unsupported
	Theirs      string      `json:"theirs"` // the oracle's decision
	Verdict     Verdict     `json:"verdict"`
	Exclusion   Exclusion   `json:"exclusion,omitempty"`
	Fidelity    string      `json:"fidelity"`
	Covered     bool        `json:"covered"` // fidelity EXACT or APPROXIMATE and the oracle answered: counts toward C
	M2          *bool       `json:"m2,omitempty"`
	M3          *bool       `json:"m3,omitempty"`
	M4          *bool       `json:"m4,omitempty"`
	Settled     bool        `json:"settled,omitempty"`     // re-asked after the settle window
	Propagation bool        `json:"propagation,omitempty"` // agreed after the settle window
	Note        string      `json:"note,omitempty"`
	Attempts    int         `json:"attempts"`
	LatencyMS   int64       `json:"latency_ms"`
	OurStage    authz.Stage `json:"our_stage,omitempty"`
	Reasons     []string    `json:"fidelity_reasons,omitempty"`
	Answer      *Answer     `json:"answer,omitempty"`
}

// Counted reports whether the check is in the M1 denominator.
func (c *Check) Counted() bool { return c.Verdict != Excluded }

// OursDecision normalizes our decision for comparison (§13.6): Allow is
// "allowed"; an explicit Deny is "explicitDeny"; every other Deny, guardrails
// included, is "implicitDeny" (guardrails map to "denied" for probes, which the
// comparator handles by not distinguishing deny kinds there).
func OursDecision(d *authz.Decision) string {
	switch d.Outcome {
	case authz.Conditional:
		return "conditional"
	}
	if d.Fidelity == authz.Unsupported {
		return "unsupported"
	}
	return d.AWSEvalDecision()
}

// Compare compares our decision with an oracle answer. counted is false for a
// secondary oracle, whose checks are recorded but never enter M1.
func Compare(s *RequestSpec, ours *authz.Decision, w *World, ans *Answer, counted bool) Check {
	svc, _, _ := strings.Cut(strings.ToLower(s.Action), ":")
	c := Check{SpecID: s.ID, SpecHash: s.Hash(), Stratum: s.Stratum, Service: svc, Oracle: ans.Oracle, Ours: OursDecision(ours),
		Theirs: ans.Decision, Fidelity: ours.Fidelity.String(), Attempts: ans.Attempts, Answer: ans, OurStage: decisiveStage(ours)}
	for _, r := range ours.FidelityReasons {
		c.Reasons = append(c.Reasons, string(r.Code))
	}
	exclude := func(why Exclusion, note string) Check {
		c.Verdict, c.Exclusion, c.Note = Excluded, why, note
		return c
	}
	switch {
	case ours.Fidelity == authz.Unsupported:
		return exclude(ExcludedUnsupported, "")
	case ans.Status == AnswerInvalid:
		return exclude(ExcludedInvalid, ans.Detail)
	case ans.Status == AnswerInconclusive:
		return exclude(ExcludedInconclusive, ans.Detail)
	}
	c.Covered = true
	switch {
	case !counted:
		return exclude(ExcludedNotAuthority, "secondary oracle")
	case !s.Stratum.GateEligible():
		return exclude(ExcludedStratumNoCount, "")
	}
	if ans.Oracle == OracleAccessCheck {
		return compareAccessCheck(c, ours, ans)
	}

	// M1: allow versus deny. CONDITIONAL in concrete mode is an engine bug and
	// counts as a disagreement.
	oursAllowed := ours.Outcome == authz.Allow
	theirsAllowed := ans.Decision == DecisionAllowed
	switch {
	case ours.Outcome == authz.Conditional:
		c.Verdict, c.Note = Disagree, "CONDITIONAL in concrete mode"
	case oursAllowed == theirsAllowed:
		c.Verdict = Agree
	default:
		c.Verdict = Disagree
	}

	// M2: explicit versus implicit, only where the oracle states it and both
	// sides deny.
	if (ans.Decision == DecisionExplicitDeny || ans.Decision == DecisionImplicitDeny) && ours.Outcome == authz.Deny {
		b := (ours.DenyKind == authz.Explicit) == (ans.Decision == DecisionExplicitDeny)
		c.M2 = &b
	}
	// M3: the simulator's matched identity and resource statements must be
	// among our matching statements.
	if ans.Oracle == OracleSimCustom {
		c.M3 = matchedSubset(ours, w, ans)
	}
	// M4: the policy type an AccessDenied message names equals our decisive stage.
	if ans.DeniedStage != "" && ours.Outcome == authz.Deny && c.OurStage != "" {
		b := ans.DeniedStage == c.OurStage
		c.M4 = &b
	}
	return c
}

// compareAccessCheck applies the universal-claim rule of §13.3: PASS is
// trustworthy and FAIL may be a false positive. Counted outcomes are PASS
// against our ALLOW (we grant what AA proves is not granted), PASS against our
// deny (agreement), and FAIL naming a statement that we say matches nothing.
// Anything else goes to manual triage.
func compareAccessCheck(c Check, ours *authz.Decision, ans *Answer) Check {
	triage := func(note string) Check {
		c.Verdict, c.Exclusion, c.Note = Excluded, ExcludedManualTriage, note
		return c
	}
	if ours.Outcome == authz.Conditional {
		c.Verdict, c.Note = Disagree, "CONDITIONAL in concrete mode"
		return c
	}
	allowed := ours.Outcome == authz.Allow
	switch ans.Decision {
	case DecisionPass:
		c.Verdict = Agree
		if allowed {
			c.Verdict = Disagree
		}
	case DecisionFail:
		if allowed {
			return triage("AA FAIL and we allow: consistent, but AA may be a false positive")
		}
		if len(ans.Reasons) == 0 {
			return triage("AA FAIL without a reason statement")
		}
		for _, r := range ans.Reasons {
			if matchesIndex(ours, r.StatementIndex) {
				return triage("AA FAIL names a statement we match, yet we deny")
			}
		}
		c.Verdict, c.Note = Disagree, "AA names a granting statement we say matches nothing"
	default:
		return triage("unknown AA result " + ans.Decision)
	}
	return c
}

// decisiveStage is the stage of our first decisive step, mapped through the
// statement's policy kind where there is one (an explicit Deny is recorded in
// the explicit_deny stage, but the AccessDenied message names the policy type).
func decisiveStage(d *authz.Decision) authz.Stage {
	// The engine names the decisive stage on its final step. An explicit Deny is
	// recorded as the stage "explicit_deny"; its policy type comes from the
	// decisive statement below.
	for _, st := range d.Steps {
		if st.Stage == authz.StageFinal && st.MatchedOn["decisive_stage"] != "" && st.MatchedOn["decisive_stage"] != string(authz.StageExplicitDeny) {
			return authz.Stage(st.MatchedOn["decisive_stage"])
		}
	}
	for _, st := range d.Steps {
		if !st.Decisive {
			continue
		}
		if st.Statement != nil {
			switch st.Statement.PolicyKind {
			case "identity":
				return authz.StageIdentity
			case "boundary":
				return authz.StageBoundary
			case "scp":
				return authz.StageSCP
			case "rcp":
				return authz.StageRCP
			case "session":
				return authz.StageSession
			case "resource", "trust", "kms_key_policy", "s3_access_point":
				return authz.StageResourcePolicy
			case "vpc_endpoint":
				return authz.StageVPCE
			}
		}
		switch st.Stage {
		case authz.StageFinal, authz.StageParse, authz.StageContext, authz.StageExplicitDeny:
			continue
		}
		return st.Stage
	}
	return ""
}

// matchesIndex reports whether a matching statement of the decision has the
// given index (used for the single-policy Access Analyzer comparison).
func matchesIndex(d *authz.Decision, idx int) bool {
	for _, st := range d.Steps {
		if st.Statement != nil && st.Statement.StatementIndex == idx && (st.Result == authz.ResultAllow || st.Result == authz.ResultDeny) {
			return true
		}
	}
	return false
}

// matchedSubset computes M3. It is nil when the simulator's statements cannot
// be mapped to ours (no matched statements, or an id outside the spec's lists).
func matchedSubset(d *authz.Decision, w *World, ans *Answer) *bool {
	if w == nil {
		return nil
	}
	type key struct {
		doc  string
		line int
	}
	have := map[key]bool{}
	for _, st := range d.Steps {
		if st.Statement == nil || st.Statement.Span == nil {
			continue
		}
		if st.Result == authz.ResultAllow || st.Result == authz.ResultDeny {
			have[key{st.Statement.PolicyID, st.Statement.Span.StartLine}] = true
		}
	}
	checked := false
	ok := true
	for _, m := range ans.Matched {
		if m.PolicyType != "identity" && m.PolicyType != "resource" {
			continue
		}
		doc := docForSourceID(w, m.SourcePolicyID)
		if doc == "" {
			return nil
		}
		checked = true
		if !have[key{doc, m.Line}] {
			ok = false
		}
	}
	if !checked {
		return nil
	}
	return &ok
}

// docForSourceID maps the simulator's source id to one of our document ids:
// "PolicyInputList.N" (1-based) or "ResourcePolicy".
func docForSourceID(w *World, id string) string {
	if id == "ResourcePolicy" {
		return w.ResourceDocID
	}
	if n, ok := strings.CutPrefix(id, "PolicyInputList."); ok {
		i, err := strconv.Atoi(n)
		if err == nil && i >= 1 && i <= len(w.IdentityDocIDs) {
			return w.IdentityDocIDs[i-1]
		}
	}
	return ""
}

// String renders a check on one line.
func (c Check) String() string {
	return fmt.Sprintf("%s [%s/%s] ours=%s theirs=%s %s %s", c.SpecID, c.Stratum, c.Oracle, c.Ours, c.Theirs, c.Verdict, c.Exclusion)
}
