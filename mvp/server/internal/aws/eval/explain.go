package eval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// explainer builds the "why" trace (§7.11) for the base run.
type explainer struct {
	e     *evaluator
	v     *verdict
	steps []authz.ExplanationStep
	at    map[*stmtEval]int // statement → index of its step
	dec   []authz.StmtRef
	seen  map[int]bool
}

func (x *explainer) stmtStep(stage authz.Stage, se *stmtEval) {
	st := authz.ExplanationStep{Stage: stage, Statement: &se.ref, ConditionTrace: se.traces}
	if len(se.matched) > 0 {
		st.MatchedOn = map[string]string{}
		for k, v := range se.matched {
			st.MatchedOn[k] = v
		}
	}
	switch {
	case se.doc.notApplicable != "":
		st.Result, st.Note = authz.ResultNotApplicable, se.doc.notApplicable
	case se.match.IsTrue():
		st.Result = authz.ResultAllow
		if se.effect == model.EffectDeny {
			st.Result = authz.ResultDeny
		}
	case se.match.IsFalse():
		st.Result, st.Note = authz.ResultNoMatch, "no match: "+se.why
		if st.MatchedOn == nil {
			st.MatchedOn = map[string]string{}
		}
		st.MatchedOn["failed"] = se.why
	default:
		st.Result, st.Residual = authz.ResultConditional, se.match.Residual()
	}
	x.at[se] = len(x.steps)
	x.steps = append(x.steps, st)
}

func (x *explainer) gateStep(stage authz.Stage, ok authz.Tri, matched map[string]string, pass, fail string) int {
	st := authz.ExplanationStep{Stage: stage, MatchedOn: matched}
	switch {
	case ok.IsTrue():
		st.Result, st.Note = authz.ResultPass, pass
	case ok.IsFalse():
		st.Result, st.Note = authz.ResultFail, fail
	default:
		st.Result, st.Residual, st.Note = authz.ResultConditional, ok.Residual(), pass
	}
	x.steps = append(x.steps, st)
	return len(x.steps) - 1
}

func (x *explainer) notApplicable(stage authz.Stage, why string) {
	x.steps = append(x.steps, authz.ExplanationStep{Stage: stage, Result: authz.ResultNotApplicable, Note: why})
}

func (x *explainer) mark(i int) {
	x.steps[i].Decisive = true
}

func (x *explainer) markStmt(se *stmtEval) {
	if se == nil {
		return
	}
	if i, ok := x.at[se]; ok && !x.seen[i] {
		x.seen[i] = true
		x.steps[i].Decisive = true
		x.dec = append(x.dec, se.ref)
	}
}

func allows(ds []*docEntry) []*stmtEval {
	var out []*stmtEval
	for _, d := range ds {
		for _, se := range d.stmts {
			if se.effect == model.EffectAllow {
				out = append(out, se)
			}
		}
	}
	return out
}

func firstTrue(ss []*stmtEval, kinds ...MatchKind) *stmtEval {
	if len(kinds) == 0 {
		for _, se := range ss {
			if se.match.IsTrue() {
				return se
			}
		}
		return nil
	}
	for _, k := range kinds {
		for _, se := range ss {
			if se.match.IsTrue() && se.kinds.Has(k) {
				return se
			}
		}
	}
	return nil
}

// build lists the steps in pipeline order and marks the decisive ones.
// It returns the final step's facts.
func (x *explainer) build() map[string]string {
	e, v := x.e, x.v
	for _, se := range e.denies {
		x.stmtStep(authz.StageExplicitDeny, se)
	}
	x.orgSection(authz.StageRCP, e.rcp, e.rcpNA, v.rcpOK, "resource control policy", e.shadowRCP)
	x.orgSection(authz.StageSCP, e.scp, e.scpNA, v.scpOK, "service control policy", nil)

	rbpAllows := allows(e.rbp)
	for _, se := range rbpAllows {
		x.stmtStep(authz.StageResourcePolicy, se)
	}
	for _, se := range allows(e.id) {
		x.stmtStep(authz.StageIdentity, se)
	}
	gatePB, gateSP := -1, -1
	if e.hasBoundary {
		for _, se := range allows(e.pb) {
			x.stmtStep(authz.StageBoundary, se)
		}
		gatePB = x.gateStep(authz.StageBoundary, v.pbOK, nil, "a permissions boundary allows", "no permissions boundary allows")
	}
	if len(e.sp) > 0 || e.p.Kind == model.FederatedUserSession {
		for _, se := range allows(e.sp) {
			x.stmtStep(authz.StageSession, se)
		}
		gateSP = x.gateStep(authz.StageSession, v.spOK, nil, "a session policy allows", "no session policy allows")
	}
	gateVPCE := -1
	if len(e.vpce) > 0 {
		for _, se := range allows(e.vpce) {
			x.stmtStep(authz.StageVPCE, se)
		}
		gateVPCE = x.gateStep(authz.StageVPCE, v.g, nil, "the VPC endpoint policy allows", "no VPC endpoint policy allows")
	}
	gateGrant := x.gateStep(authz.StageResourcePolicy, v.grant, nil, "a grant path allows", "no grant path allows")

	facts := map[string]string{}
	switch v.outcome {
	case authz.Deny:
		x.decideDeny(facts, gatePB, gateSP, gateVPCE, gateGrant)
	case authz.Allow:
		x.decideAllow(facts, rbpAllows)
	}
	return facts
}

func (x *explainer) orgSection(stage authz.Stage, ls []*level, na string, ok authz.Tri, what string, shadow []*level) {
	if x.e.snap.Org == nil {
		return
	}
	if ls == nil {
		x.notApplicable(stage, na)
		for _, l := range shadow {
			for _, d := range l.docs {
				for _, se := range d.stmts {
					x.stmtStep(stage, se)
				}
			}
		}
		return
	}
	for _, l := range ls {
		var lvlOK authz.Tri = authz.F
		for _, d := range l.docs {
			for _, se := range d.stmts {
				if se.effect == model.EffectAllow {
					x.stmtStep(stage, se)
					lvlOK = lvlOK.Or(se.match)
				}
			}
		}
		x.gateStep(stage, lvlOK, map[string]string{"level": l.node.ID},
			what+"s at "+l.label()+" allow "+x.e.action, "no "+what+" allows "+x.e.action+" (level "+l.node.ID+")")
	}
}

func (x *explainer) decideDeny(facts map[string]string, gatePB, gateSP, gateVPCE, gateGrant int) {
	e, v := x.e, x.v
	facts["deny_kind"] = v.denyKind.String()
	if v.denyKind == authz.Explicit {
		se := firstTrue(e.denies)
		x.markStmt(se)
		facts["decisive_stage"] = string(authz.StageExplicitDeny)
		if se != nil && se.ref.OrgLevel != "" {
			facts["decisive_level"] = se.ref.OrgLevel
		}
		return
	}
	stage, lvl, note := x.failure()
	facts["decisive_stage"] = string(stage)
	facts["reason"] = note
	if lvl != nil {
		facts["blocking_level"] = lvl.node.ID
	}
	// The decisive item is the failing gate: the first failing gate step of the stage.
	for i := range x.steps {
		s := x.steps[i]
		if s.Statement != nil || s.Stage != stage || s.Result != authz.ResultFail {
			continue
		}
		if lvl != nil && s.MatchedOn["level"] != lvl.node.ID {
			continue
		}
		x.mark(i)
		return
	}
	// A stage with no gate step of its own (identity, a missing resource-policy
	// allow): the grant summary carries it.
	x.mark(gateGrantIndex(x.steps, gateGrant))
	_, _, _ = gatePB, gateSP, gateVPCE
}

func gateGrantIndex(steps []authz.ExplanationStep, i int) int {
	if i < 0 || i >= len(steps) {
		return len(steps) - 1
	}
	return i
}

// failure names the stage that made an implicit or guardrail deny and says
// so in AWS's AccessDenied wording (§7.10).
func (x *explainer) failure() (authz.Stage, *level, string) {
	e, v := x.e, x.v
	if v.denyKind == authz.Guardrail {
		return authz.StageVPCE, nil, "no VPC endpoint policy allows " + e.action
	}
	switch {
	case v.blockRCP != nil && !v.rcpOK.IsTrue():
		return authz.StageRCP, v.blockRCP, "no resource control policy allows " + e.action + " (level " + v.blockRCP.node.ID + ")"
	case v.blockSCP != nil && !v.scpOK.IsTrue():
		return authz.StageSCP, v.blockSCP, "no service control policy allows " + e.action + " (level " + v.blockSCP.node.ID + ")"
	}
	rbNotFalse := func(k MatchKind) bool { return !v.rb[k].IsFalse() }
	switch e.class {
	case classService, classAnonymous, classProvider:
		return authz.StageResourcePolicy, nil, "no resource-based policy allows " + e.action
	}
	capped := v.idAllow.IsTrue() || (!v.cross && rbNotFalse(MatchParent))
	switch {
	case capped && !v.pbOK.IsTrue():
		return authz.StageBoundary, nil, "no permissions boundary allows " + e.action
	case capped && !v.spOK.IsTrue():
		return authz.StageSession, nil, "no session policy allows " + e.action
	case v.cross && v.idAllow.IsTrue():
		return authz.StageResourcePolicy, nil, "no resource-based policy allows " + e.action
	case v.idAllow.IsTrue() && v.explicit:
		return authz.StageResourcePolicy, nil, "no resource-based policy allows " + e.action
	}
	return authz.StageIdentity, nil, "no identity-based policy allows " + e.action
}

// decideAllow marks a minimal justification: one matching Allow per required
// layer (§7.10), choosing the first statement in stable order.
func (x *explainer) decideAllow(facts map[string]string, rbpAllows []*stmtEval) {
	e, v := x.e, x.v
	for _, l := range e.rcp {
		x.markStmt(firstTrue(allows(l.docs)))
	}
	for _, l := range e.scp {
		x.markStmt(firstTrue(allows(l.docs)))
	}
	if len(e.vpce) > 0 {
		x.markStmt(firstTrue(allows(e.vpce)))
	}
	idPick := firstTrue(allows(e.id))
	pbPick, spPick := firstTrue(allows(e.pb)), firstTrue(allows(e.sp))
	layers := func() { // the limits that apply to the identity path
		if e.hasBoundary {
			x.markStmt(pbPick)
		}
		if len(e.sp) > 0 {
			x.markStmt(spPick)
		}
	}
	setStage := func(s authz.Stage, se *stmtEval) {
		facts["decisive_stage"] = string(s)
		if se != nil {
			x.markStmt(se)
			facts["match_kind"] = kindOf(se)
		}
	}
	switch {
	case e.class != classIAM:
		setStage(authz.StageResourcePolicy, firstTrue(rbpAllows, MatchSelf, MatchService, MatchWildcard))
	case v.cross:
		setStage(authz.StageCrossAccount, firstTrue(rbpAllows, MatchSelf, MatchWildcardPrincipalARN, MatchWildcard, MatchParent, MatchAccount))
		x.markStmt(idPick)
		layers()
	default:
		if se := firstTrue(rbpAllows, MatchSelf, MatchWildcardPrincipalARN, MatchWildcard); se != nil && v.rb[MatchSelf].Or(v.rb[MatchWildcardPrincipalARN]).Or(v.rb[MatchWildcard]).IsTrue() {
			setStage(authz.StageResourcePolicy, se)
		} else if se := firstTrue(rbpAllows, MatchParent); se != nil && v.rb[MatchParent].And(v.pbOK).And(v.spOK).IsTrue() {
			setStage(authz.StageResourcePolicy, se)
			layers()
		} else if idPick != nil {
			setStage(authz.StageIdentity, idPick)
			layers()
			if v.explicit {
				x.markStmt(firstTrue(rbpAllows, MatchAccount))
			}
			delete(facts, "match_kind")
		} else if e.rootDefault {
			facts["decisive_stage"] = string(authz.StageSpecialRule)
			facts["reason"] = "the account's root user is allowed by default"
		}
	}
}

func kindOf(se *stmtEval) string {
	for _, k := range []MatchKind{MatchSelf, MatchWildcardPrincipalARN, MatchWildcard, MatchParent, MatchAccount, MatchService} {
		if se.kinds.Has(k) {
			return k.String()
		}
	}
	return ""
}

// finish assembles the Decision from the base verdict.
func (e *evaluator) finish(v *verdict) *authz.Decision {
	x := &explainer{e: e, v: v, at: map[*stmtEval]int{}, seen: map[int]bool{}}
	facts := x.build()
	fid, reasons := e.fidelity()
	d := &authz.Decision{
		Outcome:         v.outcome,
		DenyKind:        v.denyKind,
		Residual:        v.residual,
		Fidelity:        fid,
		FidelityReasons: reasons,
		Decisive:        x.dec,
		Request:         e.req,
		EngineVersion:   EngineVersion,
		CatalogVersion:  e.cat.Version(),
		SnapshotID:      e.snap.ID,
	}
	final := authz.ExplanationStep{Stage: authz.StageFinal, MatchedOn: facts}
	switch v.outcome {
	case authz.Allow:
		final.Result = authz.ResultAllow
	case authz.Deny:
		final.Result = authz.ResultDeny
	default:
		final.Result, final.Residual = authz.ResultConditional, v.residual
	}
	d.Steps = append(x.steps, final)
	d.Steps[len(d.Steps)-1].Note = Summary(d)
	return d
}

// Summary is the one-line rendering in the AWS AccessDenied style (§7.11):
//
//	DENY (implicit): no service control policy allows s3:PutObject (level ou-ab12)
func Summary(d *authz.Decision) string {
	req, _ := d.Request.(*EvaluationRequest)
	what := ""
	if req != nil {
		what = " " + req.Action
		if req.ResourceARN != "" && req.ResourceARN != "*" {
			what += " on " + req.ResourceARN
		}
	}
	facts := map[string]string{}
	if n := len(d.Steps); n > 0 && d.Steps[n-1].Stage == authz.StageFinal {
		facts = d.Steps[n-1].MatchedOn
	}
	switch d.Outcome {
	case authz.Allow:
		s := "ALLOW" + what
		if st := facts["decisive_stage"]; st != "" {
			s += " via " + st
		}
		return s + fidelitySuffix(d)
	case authz.Conditional:
		return "CONDITIONAL" + what + ": " + authz.Render(d.Residual, authz.RenderOptions{}) + fidelitySuffix(d)
	}
	kind := d.DenyKind.String()
	if kind == "" {
		kind = "depends on context"
	}
	reason := facts["reason"]
	if d.DenyKind == authz.Explicit {
		reason = "an explicit deny matches"
		if len(d.Decisive) > 0 {
			ref := d.Decisive[0]
			reason += fmt.Sprintf(" [%s %s#%d]", ref.PolicyKind, lastElem(ref.SourceARN), ref.StatementIndex)
		}
	}
	return "DENY (" + kind + "):" + what + " - " + reason + fidelitySuffix(d)
}

func fidelitySuffix(d *authz.Decision) string {
	if d.Fidelity == authz.Exact {
		return ""
	}
	var codes []string
	for _, r := range d.FidelityReasons {
		if r.OutcomeSensitive {
			codes = append(codes, string(r.Code))
		}
	}
	return " [" + d.Fidelity.String() + ": " + strings.Join(codes, ", ") + "]"
}

func lastElem(s string) string {
	if i := strings.LastIndexAny(s, "/:"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// Narrative is the ordered rendering for the UI and PR comments: one line per
// step, decisive statements marked with "*".
func Narrative(d *authz.Decision) string {
	var b strings.Builder
	for _, s := range d.Steps {
		mark := " "
		if s.Decisive {
			mark = "*"
		}
		line := fmt.Sprintf("%s %-15s %-14s", mark, s.Stage, s.Result)
		if s.Statement != nil {
			line += fmt.Sprintf(" %s %s#%d", s.Statement.PolicyKind, lastElem(s.Statement.SourceARN), s.Statement.StatementIndex)
			if s.Statement.OrgLevel != "" {
				line += " @" + s.Statement.OrgLevel
			}
		}
		if s.Note != "" {
			line += " - " + s.Note
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// ExplanationID is the content address of a decision's trace: the SHA-256 of
// its canonical JSON (encoding/json writes map keys sorted and struct fields in
// declaration order), so the same snapshot, catalog and engine give the same id.
func ExplanationID(d *authz.Decision) (string, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
