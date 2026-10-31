package admin

import (
	"errors"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/jitascode"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeJitBundleApply applies JIT eligibility rules from a policy repository (issue #651, AC-5; design
// docs/design/access-as-code-repo.md sections 6, 7 and 10), the same way roles.bundle.apply does for roles. Every
// apply takes two people, tightening or not (decision 1): the requester files the bundle with the digest of the plan
// they reviewed, a different admin approves what the payload hash says, and the applier plans again in its own
// transaction and refuses a plan that is not the approved one (409 stale_plan). A plan over the step ceiling or past
// the deletion guard is refused at both steps, with no override (decision 4). The payload holds the files, so the
// approver and the audit ledger see exactly what is applied; the commit, bundle_sha256 and path go to each rule
// version as its policy_ref. Turning enforcement on or off is part of the bundle (jit_enforce in tessera.yaml), so it
// takes the same two people.
const TypeJitBundleApply = "jit.bundle.apply"

func init() {
	changeTypes[TypeJitBundleApply] = typed(TypeJitBundleApply, nil, planJitBundle, applyJitBundle,
		func(_ *env, v *rolesBundlePayload) string {
			return fmt.Sprintf("Apply the JIT eligibility rules of policy repository commit %s (%d files, plan %.12s)",
				v.Commit, len(v.Files), v.PlanSHA256)
		})
}

// jitBundleErr turns what the JIT writers return into an API error (the roles errors are the same types).
func jitBundleErr(err error) error {
	var re *roles.Error
	var inv *jitascode.InvalidError
	switch {
	case errors.As(err, &re):
		return newErr(re.Status, re.Code, "%s", re.Msg)
	case errors.As(err, &inv):
		return newErr(422, "invalid_bundle", "%s", inv.Error())
	}
	return err
}

func (e *env) jitOptions() (jitascode.Options, error) {
	t, err := e.tenantRecord()
	if err != nil {
		return jitascode.Options{}, err
	}
	return jitascode.Options{Tenant: t.Slug, MaxSteps: e.svc.PolicyMaxSteps}, nil
}

// planJitBundle files a request only for a bundle that is valid and whose plan is the one named now: what the
// requester reviewed. Two people always.
func planJitBundle(e *env, v *rolesBundlePayload) (plan, error) {
	if blankCommit(v.Commit) || len(v.Commit) > jitascode.MaxCommit {
		return plan{}, invalid("commit is 1 to %d characters", jitascode.MaxCommit)
	}
	if len(v.Files) == 0 {
		return plan{}, invalid("files is required")
	}
	files := v.bundle()
	if d := jitascode.Digest(files); d != v.BundleSHA256 {
		return plan{}, invalid("bundle_sha256 is %q; the files hash to %s", v.BundleSHA256, d)
	}
	opt, err := e.jitOptions()
	if err != nil {
		return plan{}, err
	}
	p, err := jitascode.Build(e.tx, files, opt)
	if err != nil {
		return plan{}, jitBundleErr(err)
	}
	if p.PlanSHA256 != v.PlanSHA256 {
		return plan{}, conflict("stale_plan", "the plan is %s, not %s; plan the bundle again", p.PlanSHA256, v.PlanSHA256)
	}
	return plan{twoPerson: true, target: "jit"}, nil
}

func applyJitBundle(e *env, ch *store.AdminChange, v *rolesBundlePayload) error {
	opt, err := e.jitOptions()
	if err != nil {
		return err
	}
	by := ch.RequestedBy
	if ch.ApprovedBy != nil {
		by = *ch.ApprovedBy
	}
	actor := roles.Actor{UserID: by, Display: e.name(by)}
	if _, err := jitascode.Apply(e.tx, v.bundle(), opt, jitascode.Ref{Commit: v.Commit}, v.PlanSHA256, actor, e.now); err != nil {
		return jitBundleErr(err)
	}
	return nil
}
