package admin

import (
	"errors"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/agentscopeascode"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeAgentScopesBundleApply applies agent scopes (what an AI agent may hold) from a policy repository (issue #653,
// AC-7; design docs/design/access-as-code-repo.md sections 3.5, 6, 7 and 10), the same way sod.bundle.apply does for
// SoD rules. Every apply takes two people, tightening or not (decision 1): a scope is a ceiling an agent is held to,
// and retiring or widening one changes what counts as a violation, so the requester files the bundle with the digest
// of the plan they reviewed, a different admin approves what the payload hash says, and the applier plans again in
// its own transaction and refuses a plan that is not the approved one (409 stale_plan). A plan over the step
// ceiling or past the deletion guard is refused at both steps, with no override (decision 4). The payload holds the
// files, so the approver and the audit ledger see exactly what is applied; the commit, bundle_sha256 and path go to
// each scope version written as its policy_ref.
const TypeAgentScopesBundleApply = "agent_scopes.bundle.apply"

func init() {
	changeTypes[TypeAgentScopesBundleApply] = typed(TypeAgentScopesBundleApply, nil, planAgentScopesBundle, applyAgentScopesBundle,
		func(_ *env, v *rolesBundlePayload) string {
			return fmt.Sprintf("Apply the agent scopes of policy repository commit %s (%d files, plan %.12s)",
				v.Commit, len(v.Files), v.PlanSHA256)
		})
}

// agentScopesBundleErr turns what the scope writers return into an API error (the roles errors are the same types).
func agentScopesBundleErr(err error) error {
	var re *roles.Error
	var inv *agentscopeascode.InvalidError
	switch {
	case errors.As(err, &re):
		return newErr(re.Status, re.Code, "%s", re.Msg)
	case errors.As(err, &inv):
		return newErr(422, "invalid_bundle", "%s", inv.Error())
	}
	return err
}

func (e *env) agentScopesOptions() (agentscopeascode.Options, error) {
	t, err := e.tenantRecord()
	if err != nil {
		return agentscopeascode.Options{}, err
	}
	return agentscopeascode.Options{Tenant: t.Slug, MaxSteps: e.svc.PolicyMaxSteps}, nil
}

// planAgentScopesBundle files a request only for a bundle that is valid and whose plan is the one named now: what
// the requester reviewed. Two people always.
func planAgentScopesBundle(e *env, v *rolesBundlePayload) (plan, error) {
	if blankCommit(v.Commit) || len(v.Commit) > agentscopeascode.MaxCommit {
		return plan{}, invalid("commit is 1 to %d characters", agentscopeascode.MaxCommit)
	}
	if len(v.Files) == 0 {
		return plan{}, invalid("files is required")
	}
	files := v.bundle()
	if d := agentscopeascode.Digest(files); d != v.BundleSHA256 {
		return plan{}, invalid("bundle_sha256 is %q; the files hash to %s", v.BundleSHA256, d)
	}
	opt, err := e.agentScopesOptions()
	if err != nil {
		return plan{}, err
	}
	p, err := agentscopeascode.Build(e.tx, files, opt)
	if err != nil {
		return plan{}, agentScopesBundleErr(err)
	}
	if p.PlanSHA256 != v.PlanSHA256 {
		return plan{}, conflict("stale_plan", "the plan is %s, not %s; plan the bundle again", p.PlanSHA256, v.PlanSHA256)
	}
	return plan{twoPerson: true, target: "agent_scopes"}, nil
}

func applyAgentScopesBundle(e *env, ch *store.AdminChange, v *rolesBundlePayload) error {
	opt, err := e.agentScopesOptions()
	if err != nil {
		return err
	}
	by := ch.RequestedBy
	if ch.ApprovedBy != nil {
		by = *ch.ApprovedBy
	}
	actor := roles.Actor{UserID: by, Display: e.name(by)}
	if _, err := agentscopeascode.Apply(e.tx, v.bundle(), opt, agentscopeascode.Ref{Commit: v.Commit}, v.PlanSHA256, actor, e.now); err != nil {
		return agentScopesBundleErr(err)
	}
	return nil
}
