package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/snapshot"
	"github.com/nischalravi/tessera/mvp/server/internal/blast"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/simulate"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Unified blast-radius preview (issue #654, AC-8; design docs/design/access-as-code-repo.md section 8):
//
//	POST /api/policy/diff  {files, operations, base_snapshot, profile}
//
// files is a policy bundle as the as-code routes take it ({"<path>": "<text>"}: tessera.yaml, roles/, jit/, sod/,
// agents/); operations are AWS changes (the ops of /api/aws/simulate-policy-change, each with an optional "source"
// label such as a Terraform address); either may be empty, not both. The bundle's role grants become graph edits and
// its agent scopes and SoD rules become the policies evaluated after; internal/simulate gives the identity diff and the
// violations before and after. The operations go through snapshot.Apply and query.Diff against the base snapshot.
// AWS principals are joined to identities through the aws accounts the collector materialized, and the answer
// summarizes who gains and loses access by identity type and by resource ("N identities gain a path to bucket X; k are
// agents"), sorted, with diff_sha256 over the whole so a pull request comment can be compared byte for byte.
//
// terraform_plan is a Terraform plan (AC-9, #655; policy_diff_tf.go): its IAM, S3 bucket policy, SCP and RCP changes are
// added to the operations, and what it cannot map or leaves unknown is listed under "terraform".
//
// It changes nothing: it needs graph.read with STEP_UP_POLICY like the plan routes, runs in one read transaction,
// reads only the session's tenant, and is refused 413 plan_too_large when the bundle's writes and the operations pass
// TESSERA_POLICY_MAX_STEPS. The request's audit event carries the totals.

func (s *Server) registerPolicyDiffRoutes() {
	s.handle(http.MethodPost, "/api/policy/diff", read, needStepUp(auth.PermGraphRead, auth.StepUpPolicy), s.policyDiff).answersRead = true
}

const maxOperationSource = 200

type policyDiffIn struct {
	Files        map[string]string `json:"files"`
	Operations   []blast.Operation `json:"operations"`
	BaseSnapshot string            `json:"base_snapshot"`
	Profile      string            `json:"profile"`
	// TerraformPlan is the JSON of a Terraform plan (policy_diff_tf.go).
	TerraformPlan json.RawMessage `json:"terraform_plan"`
}

type policyDiffOp struct {
	Index     int     `json:"index"`
	Op        string  `json:"op"`
	TargetARN string  `json:"target_arn"`
	PolicyARN *string `json:"policy_arn,omitempty"`
	Source    string  `json:"source,omitempty"`
}

// policyDiffAWS describes the AWS half of the answer.
type policyDiffAWS struct {
	BaseSnapshot string         `json:"base_snapshot"`
	HeadSnapshot string         `json:"head_snapshot"`
	Profile      string         `json:"profile"`
	Catalog      string         `json:"catalog_version"`
	Engine       string         `json:"engine_version"`
	Operations   []policyDiffOp `json:"operations"`
	Changes      int            `json:"changes"`
	Groups       int            `json:"groups"`
	Recomputed   int            `json:"recomputed"`
	// Global: something every decision depends on changed, so everything was recomputed.
	Global bool `json:"global"`
	// ListedResourcesCut counts changes that name more resources than the answer lists by name.
	ListedResourcesCut int `json:"changes_with_resources_cut"`
}

type policyDiffView struct {
	Tenant           string              `json:"tenant"`
	BundleSHA256     string              `json:"bundle_sha256"`
	OperationsSHA256 string              `json:"operations_sha256"`
	Kinds            []blast.KindSummary `json:"kinds"`
	AWS              *policyDiffAWS      `json:"aws"`
	// Terraform is what the request's Terraform plan did (AC-9); absent when it had none.
	Terraform *policyDiffTerraform `json:"terraform,omitempty"`
	*blast.Report
	// DiffSHA256 is the digest of this answer with this field empty.
	DiffSHA256 string `json:"diff_sha256"`
}

func (s *Server) policyDiff(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var in policyDiffIn
	if err := decodeBody(r, &in, false); err != nil {
		return nil, err
	}
	planGiven := hasPlan(in.TerraformPlan)
	if len(in.Files) == 0 && len(in.Operations) == 0 && !planGiven {
		return nil, badRequest("empty_change", "a change needs files, operations, a terraform_plan or a combination")
	}
	for i, o := range in.Operations {
		if len(o.Source) > maxOperationSource || !utf8.ValidString(o.Source) {
			return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_change", Msg: "an operation's source must be text of at most 200 bytes",
				Extra: map[string]any{"change_index": i}}
		}
	}
	ctx, tx := r.Context(), store.TxFrom(r.Context())
	now := s.clock()
	t, err := tx.TenantRecord()
	if err != nil {
		return nil, err
	}
	opt := blast.Options{Tenant: t.Slug, MaxSteps: s.admin.PolicyMaxSteps, Now: now}
	// a Terraform plan adds its operations to the request's (AC-9)
	var tf *policyDiffTerraform
	var ac *awsCtx
	if planGiven {
		if tf, ac, err = s.applyTerraformPlan(tx, &in, opt.Limit()); err != nil {
			return nil, err
		}
	}
	if err := blast.CheckCeiling(opt, 0, len(in.Operations)); err != nil {
		return nil, bundleErr(err)
	}

	// the bundle
	files := make(policybundle.Files, len(in.Files))
	for p, text := range in.Files {
		files[p] = []byte(text)
	}
	before, err := s.effectivePolicies(tx)
	if err != nil {
		return nil, err
	}
	if opt.Risks, err = s.currentRisks(tx); err != nil {
		return nil, err
	}
	c, err := blast.Compile(tx, files, opt)
	if err != nil {
		return nil, bundleErr(err)
	}
	if err := blast.CheckCeiling(opt, c.Steps, len(in.Operations)); err != nil {
		return nil, bundleErr(err)
	}
	var graphRes *simulate.Result
	if !c.Empty() {
		var risks []*sod.Risk
		if c.RisksChanged {
			risks = c.Risks
		}
		afterPolicies := before
		if c.RisksChanged || c.ScopesChanged {
			scopes := &c.Scopes
			if !c.ScopesChanged {
				scopes = nil
			}
			if afterPolicies, err = s.effectivePoliciesWith(tx, risks, scopes); err != nil {
				return nil, err
			}
		}
		if graphRes, err = simulate.Run(tx, c.Request, simulate.Inputs{Now: now, Policies: before, AfterPolicies: afterPolicies}); err != nil {
			return nil, err
		}
	}

	// the AWS operations
	var aws *blast.AWSDiff
	var awsView *policyDiffAWS
	if len(in.Operations) > 0 {
		if aws, awsView, err = s.policyDiffAWS(ctx, tx, &in, ac, now); err != nil {
			return nil, err
		}
	}

	people, err := tenantPeople(tx)
	if err != nil {
		return nil, err
	}
	if aws != nil {
		if aws.Principals, err = awsPrincipalOwners(tx); err != nil {
			return nil, err
		}
	}
	ops, err := json.Marshal(in.Operations)
	if err != nil {
		return nil, err
	}
	opsSum := sha256.Sum256(ops)
	view := &policyDiffView{Tenant: t.Slug, BundleSHA256: c.BundleSHA256, OperationsSHA256: hex.EncodeToString(opsSum[:]), Kinds: c.Kinds,
		AWS: awsView, Terraform: tf, Report: blast.Summarize(blast.Inputs{People: people, Graph: graphRes, AWS: aws})}
	raw, err := json.Marshal(view)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	view.DiffSHA256 = hex.EncodeToString(sum[:])

	sm := &view.Summary
	audit.Mark(ctx, "policy_diff_identities_gaining", sm.IdentitiesGaining)
	audit.Mark(ctx, "policy_diff_agents_gaining", sm.AgentsGaining)
	audit.Mark(ctx, "policy_diff_identities_losing", sm.IdentitiesLosing)
	audit.Mark(ctx, "policy_diff_violations_introduced", view.Violations.IntroducedTotal)
	audit.Mark(ctx, "policy_diff_operations", len(in.Operations))
	audit.Mark(ctx, "policy_diff_bundle_sha256", c.BundleSHA256)
	audit.Mark(ctx, "policy_diff_diff_sha256", view.DiffSHA256)
	if tf != nil {
		markTerraform(r, tf)
	}
	return view, nil
}

// currentRisks are the SoD risks the tenant is checked against now: the base a bundle's SoD rules are applied to.
func (s *Server) currentRisks(tx *store.TenantTx) ([]*sod.Risk, error) {
	files, err := s.policies()
	if err != nil {
		return nil, err
	}
	legacy, err := policy.LegacyBundle(files, false)
	if err != nil {
		return nil, err
	}
	return sod.Load(tx, legacy)
}

// policyDiffAWS applies the operations to the base snapshot and diffs the two, as /api/aws/simulate-policy-change
// does, without rendering a comment.
func (s *Server) policyDiffAWS(ctx context.Context, tx *store.TenantTx, in *policyDiffIn, ac *awsCtx, now time.Time) (*blast.AWSDiff, *policyDiffAWS, error) {
	if ac == nil {
		var err error
		if ac, err = s.awsContext(tx, in.BaseSnapshot); err != nil {
			return nil, nil, err
		}
	}
	opts, label, err := awsOptions(in.Profile, now)
	if err != nil {
		return nil, nil, err
	}
	run, err := blast.ApplyAndDiff(ctx, blast.AWSBase{Snap: ac.eng.snap, Index: ac.eng.ix, Memo: ac.eng.memo}, in.Operations,
		snapshot.ApplyOptions{FetchedAt: now, MultivaluedKey: ac.cat.MultivaluedKey}, ac.cat.indexConfig, opts, policyDiffMaxExpand)
	if err != nil {
		var ce *snapshot.ChangeError
		if errors.As(err, &ce) {
			extra := map[string]any{"change_index": ce.Index}
			if ce.Index >= 0 && ce.Index < len(in.Operations) && in.Operations[ce.Index].Source != "" {
				extra["source"] = in.Operations[ce.Index].Source
			}
			return nil, nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_change", Msg: ce.Error(), Extra: extra}
		}
		return nil, nil, awsEvalErr(err)
	}
	head, res := run.Head, run.Diff
	v := &policyDiffAWS{BaseSnapshot: ac.hdr.ID, HeadSnapshot: head.ID, Profile: label, Catalog: ac.cat.Cat.Version(), Engine: eval.EngineVersion,
		Operations: make([]policyDiffOp, len(in.Operations)), Changes: len(res.Changes), Groups: res.Groups, Recomputed: res.Recomputed, Global: res.Global}
	for i, o := range in.Operations {
		v.Operations[i] = policyDiffOp{Index: i, Op: string(o.Op), TargetARN: o.TargetARN, PolicyARN: o.PolicyARN, Source: o.Source}
	}
	for i := range res.Changes {
		if c := &res.Changes[i]; c.ResourceCount > len(c.Resources) {
			v.ListedResourcesCut++
		}
	}
	return &blast.AWSDiff{Changes: res.Changes}, v, nil
}

// policyDiffMaxExpand is how many action and resource names of a change the diff names; the counts are exact.
const policyDiffMaxExpand = 200

// tenantPeople lists the tenant's identities for the report.
func tenantPeople(tx *store.TenantTx) (map[int64]blast.Person, error) {
	ids, err := tx.Identities()
	if err != nil {
		return nil, err
	}
	out := make(map[int64]blast.Person, len(ids))
	for _, i := range ids {
		out[i.ID] = blast.Person{ID: i.ID, Name: i.Name, Type: i.Type}
	}
	return out, nil
}

// awsPrincipalOwners maps each AWS principal ARN the collector materialized as an account to the identity that owns
// it. The accounts are the tenant's own, so another tenant's principals never join.
func awsPrincipalOwners(tx *store.TenantTx) (map[string]int64, error) {
	accts, err := tx.Accounts()
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, a := range accts {
		if a.System == "aws" && a.IdentityID != nil {
			out[a.ExternalID] = *a.IdentityID
		}
	}
	return out, nil
}
