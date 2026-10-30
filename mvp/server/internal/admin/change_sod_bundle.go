package admin

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/sodascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeSodBundleApply applies SoD rulesets, functions and risks from a policy repository (issue #652, AC-6; design
// docs/design/access-as-code-repo.md sections 6, 7 and 10), the same way jit.bundle.apply does for JIT eligibility.
// Every apply takes two people, tightening or not (decision 1): the requester files the bundle with the digest of the
// plan they reviewed, a different admin approves what the payload hash says, and the applier plans again in its own
// transaction and refuses a plan that is not the approved one (409 stale_plan). A plan over the step ceiling or past
// the deletion guard is refused at both steps, with no override (decision 4). The payload holds the files, so the
// approver and the audit ledger see exactly what is applied; the commit, bundle_sha256 and path go to each ruleset
// written as its policy_ref.
const TypeSodBundleApply = "sod.bundle.apply"

func init() {
	changeTypes[TypeSodBundleApply] = typed(TypeSodBundleApply, nil, planSodBundle, applySodBundle,
		func(_ *env, v *rolesBundlePayload) string {
			return fmt.Sprintf("Apply the SoD rulesets of policy repository commit %s (%d files, plan %.12s)",
				v.Commit, len(v.Files), v.PlanSHA256)
		})
}

// sodBundleErr turns what the SoD writers return into an API error (the roles errors are the same types).
func sodBundleErr(err error) error {
	var re *roles.Error
	var inv *sodascode.InvalidError
	switch {
	case errors.As(err, &re):
		return newErr(re.Status, re.Code, "%s", re.Msg)
	case errors.As(err, &inv):
		return newErr(422, "invalid_bundle", "%s", inv.Error())
	}
	return err
}

func (e *env) sodOptions() (sodascode.Options, error) {
	t, err := e.tenantRecord()
	if err != nil {
		return sodascode.Options{}, err
	}
	return sodascode.Options{Tenant: t.Slug, MaxSteps: e.svc.PolicyMaxSteps}, nil
}

// planSodBundle files a request only for a bundle that is valid and whose plan is the one named now: what the
// requester reviewed. Two people always.
func planSodBundle(e *env, v *rolesBundlePayload) (plan, error) {
	if strings.TrimSpace(v.Commit) == "" || len(v.Commit) > sodascode.MaxCommit {
		return plan{}, invalid("commit is 1 to %d characters", sodascode.MaxCommit)
	}
	if len(v.Files) == 0 {
		return plan{}, invalid("files is required")
	}
	files := v.bundle()
	if d := sodascode.Digest(files); d != v.BundleSHA256 {
		return plan{}, invalid("bundle_sha256 is %q; the files hash to %s", v.BundleSHA256, d)
	}
	opt, err := e.sodOptions()
	if err != nil {
		return plan{}, err
	}
	p, err := sodascode.Build(e.tx, files, opt)
	if err != nil {
		return plan{}, sodBundleErr(err)
	}
	if p.PlanSHA256 != v.PlanSHA256 {
		return plan{}, conflict("stale_plan", "the plan is %s, not %s; plan the bundle again", p.PlanSHA256, v.PlanSHA256)
	}
	return plan{twoPerson: true, target: "sod"}, nil
}

func applySodBundle(e *env, ch *store.AdminChange, v *rolesBundlePayload) error {
	opt, err := e.sodOptions()
	if err != nil {
		return err
	}
	by := ch.RequestedBy
	if ch.ApprovedBy != nil {
		by = *ch.ApprovedBy
	}
	actor := roles.Actor{UserID: by, Display: e.name(by)}
	if _, err := sodascode.Apply(e.tx, v.bundle(), opt, sodascode.Ref{Commit: v.Commit}, v.PlanSHA256, actor, e.now); err != nil {
		return sodBundleErr(err)
	}
	return nil
}
