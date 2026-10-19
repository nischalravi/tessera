package eval

import (
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// level is one org level (root, OU or account) of an SCP or RCP chain.
type level struct {
	node *model.OrgNode
	docs []*docEntry
}

func (l *level) label() string {
	if l.node.Name != "" {
		return l.node.ID + " (" + l.node.Name + ")"
	}
	return l.node.ID
}

// docEntry is one policy document taking part in the evaluation, with its
// statements already evaluated against the request.
type docEntry struct {
	doc   *model.PolicyDoc
	path  []string // attachment path for explanations
	level *level   // SCP/RCP only
	stmts []*stmtEval
	// notApplicable is set for shadow RCPs (A14): evaluated, not counted.
	notApplicable string
}

// stmtEval is the result of stmt_match for one statement (§7.1).
type stmtEval struct {
	key    string
	doc    *docEntry
	st     *model.Statement
	ref    authz.StmtRef
	effect model.Effect
	match  authz.Tri
	// why is the first failing element of a no-match: "action", "resource",
	// "principal" or "condition:<key>".
	why     string
	kinds   MatchKinds
	traces  []authz.CondTrace
	amb     []string  // ambiguity ids that decided part of match
	alt     authz.Tri // match under the other reading of amb (valid when len(amb) > 0)
	matched map[string]string
}

func stmtKey(d *docEntry, st *model.Statement) string {
	k := fmt.Sprintf("%s#%d", d.doc.ID, st.Index)
	if d.level != nil {
		k += "@" + d.level.node.ID
	}
	return k
}

// evalDoc evaluates every statement of d.
func (e *evaluator) evalDoc(d *docEntry) error {
	if d.doc.Unparseable != "" {
		e.addReason(string(authz.ReasonPolicyUnparseable),
			fmt.Sprintf("policy %s (%s): %s", d.doc.ID, d.doc.SourceARN, d.doc.Unparseable), true)
	}
	for i := range d.doc.Statements {
		if err := e.rctx.Err(); err != nil {
			return err
		}
		d.stmts = append(d.stmts, e.evalStmt(d, &d.doc.Statements[i]))
	}
	return nil
}

func (e *evaluator) stmtRef(d *docEntry, st *model.Statement) authz.StmtRef {
	ref := authz.StmtRef{
		PolicyID:       d.doc.ID,
		PolicyKind:     d.doc.Kind.String(),
		SourceARN:      d.doc.SourceARN,
		VersionID:      d.doc.VersionID,
		StatementIndex: st.Index,
		Sid:            st.Sid,
		Span:           st.Span,
		AttachmentPath: d.path,
	}
	if d.level != nil {
		ref.OrgLevel = d.level.node.ID
	}
	return ref
}

// evalStmt is stmt_match (§7.1): action, resource, principal, then conditions,
// stopping at the first element that fails. Conditions of a statement that
// does not apply are not evaluated, so they raise no ambiguity flags.
func (e *evaluator) evalStmt(d *docEntry, st *model.Statement) *stmtEval {
	se := &stmtEval{key: stmtKey(d, st), doc: d, st: st, effect: st.Effect, match: authz.F,
		ref: e.stmtRef(d, st), matched: map[string]string{}}
	fail := func(why string) *stmtEval { se.match, se.why = authz.F, why; return se }

	am, err := CompileActions(st.Actions, st.NotActions)
	if err != nil {
		e.addReason(string(authz.ReasonPolicyUnparseable), fmt.Sprintf("policy %s statement %d: %v", d.doc.ID, st.Index, err), true)
		return fail("action")
	}
	if !am.Match(e.action) {
		return fail("action")
	}
	se.matched["action"] = e.action

	rm, resAlt, err := e.matchResource(d, st)
	if err != nil {
		e.addReason(string(authz.ReasonPolicyUnparseable), fmt.Sprintf("policy %s statement %d: %v", d.doc.ID, st.Index, err), true)
		return fail("resource")
	}
	if rm.IsFalse() && !resAlt.hasAlt {
		return fail("resource")
	}
	if !rm.IsFalse() {
		se.matched["resource"] = e.res.arn
	}

	pm, altPM := authz.T, authz.T
	switch {
	case st.NotPrincipals != nil:
		if st.Effect != model.EffectDeny {
			return fail("principal") // NotPrincipal with Allow is dropped at ingest
		}
		applies, a4 := NotPrincipalDenyApplies(st.NotPrincipals, e.p)
		pm, altPM = authz.Bool(applies), authz.Bool(applies)
		if a4 {
			se.amb = append(se.amb, "A4")
			altPM = authz.Bool(!applies)
		}
	case st.Principals != nil:
		se.kinds = MatchStatementPrincipal(st, e.p, e.snap.CanonicalIDs)
		pm = authz.Bool(!se.kinds.Empty())
		if !se.kinds.Empty() {
			se.matched["principal"] = se.kinds.String()
		}
	case d.doc.Kind.IsResourceBased():
		pm = authz.F // a resource policy statement needs a principal element
	}

	cond, traces, camb := EvalConditions(st.Condition, e.ctx, d.doc.VariablesEnabled())
	se.traces = traces
	base := rm.And(pm).And(cond)
	se.match = base
	switch {
	case rm.IsFalse():
		se.why = "resource"
	case pm.IsFalse():
		se.why = "principal"
	case cond.IsFalse():
		se.why = condFailure(traces)
	}

	// Alternative readings of the register entries that decided part of this
	// statement (§7.9): alt is the match value under the other reading.
	altRM, altCond := rm, cond
	if resAlt.hasAlt {
		se.amb = append(se.amb, "A21")
		altRM = resAlt.value
	}
	if len(camb) > 0 {
		se.amb = append(se.amb, camb...)
		altCond = e.altCondition(st, d.doc.VariablesEnabled())
	}
	se.alt = altRM.And(altPM).And(altCond)
	// A2: an SCP Allow that uses Condition or a Resource other than "*" is
	// valid only under the September 2025 reading. The other reading rejects
	// the statement, so it would not count.
	if d.doc.Kind == model.PolicySCP && st.Effect == model.EffectAllow && se.match.IsTrue() && scpAllowUsesFullLanguage(st) {
		se.amb = append(se.amb, "A2")
		se.alt = authz.F
	}
	se.amb = uniqueSorted(se.amb)
	return se
}

func condFailure(traces []authz.CondTrace) string {
	for _, t := range traces {
		if t.Result == "false" {
			key := t.Atom.RawKey
			if key == "" {
				key = t.Atom.Key
			}
			return "condition:" + key
		}
	}
	return "condition"
}

// altCondition re-evaluates a statement's condition with every atom that
// raised an ambiguity flag flipped. An unknown atom stays unknown.
func (e *evaluator) altCondition(st *model.Statement, vars bool) authz.Tri {
	res := authz.T
	for _, a := range st.Condition {
		r := EvalAtom(a, e.ctx, vars)
		t := r.Result
		if len(r.Ambiguities) > 0 && !t.IsUnknown() {
			t = t.Not()
		}
		res = res.And(t)
	}
	return res
}

func scpAllowUsesFullLanguage(st *model.Statement) bool {
	if len(st.Condition) > 0 || st.NotResources != nil {
		return true
	}
	if st.Resources == nil {
		return false
	}
	for _, p := range st.Resources.Patterns {
		if p != "*" {
			return true
		}
	}
	return false
}

// resAltResult reports whether completing an incomplete ARN decided the
// resource match of an SCP statement (A21), and the match without completion.
type resAltResult struct {
	hasAlt bool
	value  authz.Tri
}

// matchResource is resource_match (§8.3) with policy variables substituted.
// A pattern whose variable names an absent key with no default matches nothing;
// one whose variable is unknown (symbolic mode) leaves the match unknown unless
// another pattern already matched.
func (e *evaluator) matchResource(d *docEntry, st *model.Statement) (authz.Tri, resAltResult, error) {
	if st.Resources == nil && st.NotResources == nil {
		if d.doc.Kind.IsResourceBased() {
			return authz.T, resAltResult{}, nil // "this resource" (§8.3)
		}
		return authz.F, resAltResult{}, nil
	}
	ps, negate := st.Resources, false
	if ps == nil {
		ps, negate = st.NotResources, true
	}
	res, err := e.matchResourceSet(d, st, ps.MatchPatterns(), negate)
	if err != nil {
		return authz.F, resAltResult{}, err
	}
	if d.doc.Kind == model.PolicySCP && ps.Completed != nil {
		raw, err := e.matchResourceSet(d, st, ps.Patterns, negate)
		if err == nil && raw.String() != res.String() {
			return res, resAltResult{hasAlt: true, value: raw}, nil
		}
	}
	return res, resAltResult{}, nil
}

func (e *evaluator) matchResourceSet(d *docEntry, st *model.Statement, patterns []string, negate bool) (authz.Tri, error) {
	vars := d.doc.VariablesEnabled()
	resolved := make([]string, 0, len(patterns))
	unknown := false
	for _, p := range patterns {
		if !vars || !strings.Contains(p, "${") {
			resolved = append(resolved, p)
			continue
		}
		pat, res := Substitute(p, e.ctx, true)
		switch res {
		case SubstNull:
			continue
		case SubstUnknown:
			unknown = true
			continue
		}
		resolved = append(resolved, escapeLiterals(pat))
	}
	set := &model.PatternSet{Patterns: resolved}
	var m *ResourceMatcher
	var err error
	if vars {
		m, err = CompileResourcesEscaped(set, nil, d.doc.Kind.IsResourceBased())
	} else {
		m, err = CompileResources(set, nil, d.doc.Kind.IsResourceBased())
	}
	if err != nil {
		return authz.F, err
	}
	hit := m.Match(e.res.arn)
	switch {
	case hit:
		return authz.Bool(!negate), nil
	case unknown:
		// A variable that is unknown in symbolic mode: the pattern might or
		// might not match. The atom's key is never in a context, so it stays
		// symbolic.
		ref := e.stmtRef(d, st)
		t := authz.U(authz.Atom{Op: "ArnLike", Key: "tessera:resource", RawKey: "resource", Values: patterns, Source: &ref})
		if negate {
			return t.Not(), nil
		}
		return t, nil
	}
	return authz.Bool(negate), nil
}

func (d *docEntry) stmtRefs(st *model.Statement) []authz.StmtRef {
	ref := authz.StmtRef{PolicyID: d.doc.ID, PolicyKind: d.doc.Kind.String(), SourceARN: d.doc.SourceARN,
		VersionID: d.doc.VersionID, StatementIndex: st.Index, Sid: st.Sid, Span: st.Span, AttachmentPath: d.path}
	if d.level != nil {
		ref.OrgLevel = d.level.node.ID
	}
	return []authz.StmtRef{ref}
}

// escapeLiterals turns the literal segments of a substituted pattern back into
// ${*}, ${?} and ${$} escapes so that CompileARNEscaped reads them as
// characters, not wildcards.
func escapeLiterals(p Pattern) string {
	var b strings.Builder
	for _, s := range p.Segs {
		if !s.Lit {
			b.WriteString(s.Text)
			continue
		}
		for i := 0; i < len(s.Text); i++ {
			switch c := s.Text[i]; c {
			case '*', '?', '$':
				b.WriteString("${" + string(c) + "}")
			default:
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func uniqueSorted(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	out := append([]string(nil), ss...)
	sortStrings(out)
	w := 0
	for i, s := range out {
		if i == 0 || s != out[w-1] {
			out[w] = s
			w++
		}
	}
	return out[:w]
}
