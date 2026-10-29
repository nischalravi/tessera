package admin

import (
	"errors"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/rolesascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeRolesBundleApply applies roles and birthright rules from a policy repository (issue #650, AC-4; design
// docs/design/access-as-code-repo.md sections 6, 7 and 10). Every apply takes two people, tightening or not
// (decision 1): the requester files the bundle with the digest of the plan they reviewed, a different admin
// approves what the payload hash says, and the applier plans again in its own transaction and refuses a plan that is
// not the approved one (409 stale_plan). A plan over the step ceiling or past the deletion guard is refused at
// both steps, with no override (decision 4). The payload holds the files, so the approver and the audit
// ledger see exactly what is applied; commit, bundle_sha256 and plan_sha256 go to each role version as its policy_ref.
const TypeRolesBundleApply = "roles.bundle.apply"

type rolesBundlePayload struct {
	Commit       string            `json:"commit"`
	Files        map[string]string `json:"files"`
	BundleSHA256 string            `json:"bundle_sha256"`
	PlanSHA256   string            `json:"plan_sha256"`
}

func (v *rolesBundlePayload) bundle() policybundle.Files {
	f := make(policybundle.Files, len(v.Files))
	for p, s := range v.Files {
		f[p] = []byte(s)
	}
	return f
}

func init() {
	changeTypes[TypeRolesBundleApply] = typed(TypeRolesBundleApply, nil, planRolesBundle, applyRolesBundle,
		func(_ *env, v *rolesBundlePayload) string {
			return fmt.Sprintf("Apply the roles and birthright rules of policy repository commit %s (%d files, plan %.12s)",
				v.Commit, len(v.Files), v.PlanSHA256)
		})
}

// rolesBundleErr turns what the roles writers return into an API error.
func rolesBundleErr(err error) error {
	var re *roles.Error
	var inv *rolesascode.InvalidError
	switch {
	case errors.As(err, &re):
		return newErr(re.Status, re.Code, "%s", re.Msg)
	case errors.As(err, &inv):
		return newErr(422, "invalid_bundle", "%s", inv.Error())
	}
	return err
}

func (e *env) rolesOptions() (rolesascode.Options, error) {
	t, err := e.tenantRecord()
	if err != nil {
		return rolesascode.Options{}, err
	}
	return rolesascode.Options{Tenant: t.Slug, MaxSteps: e.svc.PolicyMaxSteps}, nil
}

// planRolesBundle files a request only for a bundle that is valid and whose plan is the one named now: what the
// requester reviewed. Two people always.
func planRolesBundle(e *env, v *rolesBundlePayload) (plan, error) {
	if v.Commit == "" || len(v.Commit) > rolesascode.MaxCommit {
		return plan{}, invalid("commit is 1 to %d characters", rolesascode.MaxCommit)
	}
	if len(v.Files) == 0 {
		return plan{}, invalid("files is required")
	}
	files := v.bundle()
	if d := rolesascode.Digest(files); d != v.BundleSHA256 {
		return plan{}, invalid("bundle_sha256 is %q; the files hash to %s", v.BundleSHA256, d)
	}
	opt, err := e.rolesOptions()
	if err != nil {
		return plan{}, err
	}
	p, err := rolesascode.Build(e.tx, files, opt, e.now)
	if err != nil {
		return plan{}, rolesBundleErr(err)
	}
	if p.PlanSHA256 != v.PlanSHA256 {
		return plan{}, conflict("stale_plan", "the plan is %s, not %s; plan the bundle again", p.PlanSHA256, v.PlanSHA256)
	}
	return plan{twoPerson: true, target: "roles"}, nil
}

func applyRolesBundle(e *env, ch *store.AdminChange, v *rolesBundlePayload) error {
	opt, err := e.rolesOptions()
	if err != nil {
		return err
	}
	// the person who approved is the one who applies; with no approver (never, for this type) the requester
	by := ch.RequestedBy
	if ch.ApprovedBy != nil {
		by = *ch.ApprovedBy
	}
	actor := roles.Actor{UserID: by, Display: e.name(by)}
	if _, err := rolesascode.Apply(e.tx, v.bundle(), opt, rolesascode.Ref{Commit: v.Commit}, v.PlanSHA256, actor, e.now); err != nil {
		return rolesBundleErr(err)
	}
	return nil
}
