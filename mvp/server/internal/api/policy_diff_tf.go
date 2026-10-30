package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tfplan"
)

// Terraform plan input of the blast-radius preview (issue #655, AC-9; internal/tfplan):
//
//	POST /api/policy/diff  {terraform_plan: <the JSON of terraform show -json plan.tfplan>, base_snapshot, profile, ...}
//
// The plan is untrusted. It rides in the body of the diff route, so it has that route's permission (graph.read with
// STEP_UP_POLICY), audit event, tenant scoping and body cap (413 when the body is too large), and its operations count
// toward TESSERA_POLICY_MAX_STEPS with the others (413 plan_too_large). tfplan.Parse bounds its nesting and number of
// resource changes and refuses anything that is not a Terraform plan (422 invalid_terraform_plan); nothing in it is
// executed or fetched. tfplan.Map turns its IAM policies, attachments, roles, S3 bucket policies, SCPs and RCPs into
// operations against the base snapshot (labelled "terraform:<address>", replayed after the explicit operations) and
// lists everything else as a finding. A value unknown until apply is CONDITIONAL: the change is not applied and the
// answer says so. No plan value is returned: findings carry an address, a type, the actions and a fixed reason.

// maxListedFindings bounds the findings the answer lists by name; the counts are exact.
const maxListedFindings = 500

// policyDiffTerraform describes what the plan did to the answer.
type policyDiffTerraform struct {
	FormatVersion    string `json:"format_version"`
	TerraformVersion string `json:"terraform_version,omitempty"`
	PlanSHA256       string `json:"plan_sha256"`
	// Resources are the managed resource changes of the plan; Operations how many operations they became (listed in
	// aws.operations with their source); Ignored the data sources, reads and no-ops.
	Resources  int `json:"resources"`
	Operations int `json:"operations"`
	Ignored    int `json:"ignored"`
	// Conditional: some change is unknown until apply or is not in the snapshot, so the answer holds only if it has no
	// effect on access.
	Conditional        bool `json:"conditional"`
	Unsupported        int  `json:"unsupported"`
	ConditionalChanges int  `json:"conditional_changes"`
	Unresolved         int  `json:"unresolved"`
	NoEffect           int  `json:"no_effect"`
	// Findings are sorted by address; the ones past maxListedFindings are counted in FindingsOmitted.
	Findings        []tfplan.Finding `json:"findings"`
	FindingsOmitted int              `json:"findings_omitted"`
}

var planVersionRE = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,40}$`)

// hasPlan reports whether the request carries a plan (an absent field and null are none).
func hasPlan(raw []byte) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && string(t) != "null"
}

// planErr maps an unreadable plan to the API's errors: too many changes is 413 like the other ceilings, the rest 422.
func planErr(err error) error {
	var pe *tfplan.Error
	if !errors.As(err, &pe) {
		return err
	}
	if pe.Code == "plan_too_large" {
		return &readiness.Error{Status: http.StatusRequestEntityTooLarge, Code: "plan_too_large", Msg: pe.Msg}
	}
	return &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_terraform_plan", Msg: pe.Msg, Extra: map[string]any{"reason": pe.Code}}
}

// applyTerraformPlan reads the request's plan, maps it against the base snapshot and appends its operations to the
// request's. It returns the answer's description of the plan, and the snapshot it loaded so the AWS half need not
// load it again.
func (s *Server) applyTerraformPlan(tx *store.TenantTx, in *policyDiffIn, maxOps int) (*policyDiffTerraform, *awsCtx, error) {
	plan, err := tfplan.Parse(in.TerraformPlan)
	if err != nil {
		return nil, nil, planErr(err)
	}
	ac, err := s.awsContext(tx, in.BaseSnapshot)
	if err != nil {
		return nil, nil, err
	}
	res := tfplan.Map(plan, tfplan.NewEstate(ac.eng.snap), max(1, maxOps-len(in.Operations)))
	if res.Exceeded {
		return nil, nil, &readiness.Error{Status: http.StatusRequestEntityTooLarge, Code: "plan_too_large",
			Msg: "the plan makes more operations than a preview takes (TESSERA_POLICY_MAX_STEPS). Split it into smaller changes"}
	}
	in.Operations = append(in.Operations[:len(in.Operations):len(in.Operations)], res.Operations...)
	sum := sha256.Sum256(in.TerraformPlan)
	v := &policyDiffTerraform{FormatVersion: plan.FormatVersion, PlanSHA256: hex.EncodeToString(sum[:]), Resources: res.Resources,
		Operations: len(res.Operations), Ignored: res.Ignored, Conditional: res.Conditional(), Unsupported: res.Count(tfplan.StatusUnsupported),
		ConditionalChanges: res.Count(tfplan.StatusConditional), Unresolved: res.Count(tfplan.StatusUnresolved), NoEffect: res.Count(tfplan.StatusNoEffect),
		Findings: res.Findings}
	if planVersionRE.MatchString(plan.TerraformVersion) {
		v.TerraformVersion = plan.TerraformVersion
	}
	if len(v.Findings) > maxListedFindings {
		v.FindingsOmitted = len(v.Findings) - maxListedFindings
		v.Findings = v.Findings[:maxListedFindings]
	}
	if v.Findings == nil {
		v.Findings = []tfplan.Finding{}
	}
	return v, ac, nil
}

func markTerraform(r *http.Request, v *policyDiffTerraform) {
	ctx := r.Context()
	audit.Mark(ctx, "policy_diff_tf_resources", v.Resources)
	audit.Mark(ctx, "policy_diff_tf_operations", v.Operations)
	audit.Mark(ctx, "policy_diff_tf_unsupported", v.Unsupported)
	audit.Mark(ctx, "policy_diff_tf_conditional", v.ConditionalChanges+v.Unresolved)
	audit.Mark(ctx, "policy_diff_tf_plan_sha256", v.PlanSHA256)
}
