package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/agentscopeascode"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/jitascode"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/rolesascode"
	"github.com/nischalravi/tessera/mvp/server/internal/sodascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/syncverify"
)

// TypePolicySyncApply applies the policy bundle read from a commit of the repository's default branch (issue #657, AC-11;
// design docs/design/access-as-code-repo.md sections 6 and 7): roles and birthright rules, JIT eligibility, SoD rules and
// agent scopes in ONE transaction, with every kind's own audit event and one policy.sync.applied event. Always two
// people (the requester, or the machine client's owner, can never approve): the requester files the bundle with the plan
// digest of each kind and the blast-radius prediction they reviewed, a different admin approves what the payload hash says
// (approval plans again and refuses a stale plan), and the applier plans again and applies each kind against its digest.
//
// Kind "rollback" is the same bundle read from an earlier commit Tessera applied before: planning it against the current
// state is a plan that returns to that state. The commit is recorded as the tenant's last synced commit in policy_syncs
// in the apply's transaction, and the prediction check (internal/syncverify) runs there too: state before and after the
// writes, compared with the prediction; a difference raises findings and marks the sync "mismatch", agreement marks it
// "verified". A mismatch does not undo the apply (the approver reviewed that bundle); it is raised for a human.
const TypePolicySyncApply = "policy.sync.apply"

// Kinds of a sync request.
const (
	SyncKindSync     = store.PolicySyncKindSync
	SyncKindRollback = store.PolicySyncKindRollback
)

// PolicySyncKind is one kind of object (roles, agents, sod, jit) the bundle holds, with its plan.
type PolicySyncKind struct {
	Kind       string `json:"kind"`
	Mode       string `json:"mode,omitempty"`
	Created    int    `json:"created"`
	Updated    int    `json:"updated"`
	Retired    int    `json:"retired"`
	Steps      int    `json:"steps"`
	PlanSHA256 string `json:"plan_sha256"`
}

// PolicySyncPlan is the plan of every kind of a bundle and the digest of them all.
type PolicySyncPlan struct {
	BundleSHA256 string           `json:"bundle_sha256"`
	PlanSHA256   string           `json:"plan_sha256"`
	Kinds        []PolicySyncKind `json:"kinds"`
	// Changes counts what the plans would create, update or retire.
	Changes int `json:"changes"`
	Steps   int `json:"steps"`
}

type policySyncPayload struct {
	Repo string `json:"repo"`
	// SHA is the commit the bundle was read at (for a rollback, the earlier commit returned to).
	SHA  string `json:"sha"`
	Kind string `json:"kind"`
	// RollbackFrom is the commit last synced when a rollback was filed.
	RollbackFrom string `json:"rollback_from,omitempty"`
	// LastSyncID is the id of the last applied sync when this request was filed ("" for none): the request is refused (409
	// stale_base) at approval and apply when another sync was applied since, so an older commit never replaces a newer one.
	LastSyncID    string                 `json:"last_sync_id"`
	DefaultBranch string                 `json:"default_branch"`
	Files         map[string]string      `json:"files"`
	BundleSHA256  string                 `json:"bundle_sha256"`
	PlanSHA256    string                 `json:"plan_sha256"`
	Kinds         []PolicySyncKind       `json:"kinds"`
	Prediction    *syncverify.Prediction `json:"prediction"`
}

func (v *policySyncPayload) bundle() policybundle.Files {
	f := make(policybundle.Files, len(v.Files))
	for p, s := range v.Files {
		f[p] = []byte(s)
	}
	return f
}

var (
	syncSHARE  = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	syncRepoRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$`)
)

func init() {
	t := typed(TypePolicySyncApply, nil, planPolicySync, applyPolicySync,
		func(e *env, v *policySyncPayload) string {
			verb := "Apply"
			if v.Kind == SyncKindRollback {
				verb = "Roll back to"
			}
			out := fmt.Sprintf("%s the policy bundle of %s commit %.12s from default branch %q (%d files, plan %.12s)", verb, v.Repo, v.SHA, v.DefaultBranch, len(v.Files), v.PlanSHA256)
			if n, err := e.tx.CountSodRulesets(); err == nil && n == 0 {
				for _, k := range v.Kinds {
					if k.Kind == "sod" && k.Created > 0 {
						out += ". WARNING: this creates the tenant's first SoD ruleset, which replaces (retires) its legacy YAML SoD policies"
						break
					}
				}
			}
			return out
		})
	t.afterSubmit = func(e *env, ch *store.AdminChange, v any) error {
		p := v.(*policySyncPayload)
		pred, err := json.Marshal(p.Prediction)
		if err != nil {
			return err
		}
		err = e.tx.InsertPolicySync(&store.PolicySync{Repo: p.Repo, SHA: p.SHA, Kind: p.Kind, RollbackFrom: p.RollbackFrom,
			ChangeID: ch.ID.String(), BundleSHA256: p.BundleSHA256, PlanSHA256: p.PlanSHA256, Prediction: string(pred),
			RequestedBy: e.name(ch.RequestedBy)}, e.now)
		if errors.Is(err, store.ErrDuplicate) {
			return conflict("sync_exists", "commit %.12s of %s is already filed for a sync (open or applied)", p.SHA, p.Repo)
		}
		return err
	}
	t.afterEnd = func(e *env, ch *store.AdminChange, _ any) error { return e.tx.ClosePolicySync(ch.ID.String()) }
	changeTypes[TypePolicySyncApply] = t
}

func syncErr(err error) error {
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

// BuildPolicySync plans every kind the bundle holds or manages against the tenant, as each kind's own plan route does,
// writing nothing (run it in a read transaction). tenant is the session's tenant slug (tessera.yaml must name it).
func BuildPolicySync(tx *store.TenantTx, files policybundle.Files, tenant string, maxSteps int, now time.Time) (*PolicySyncPlan, error) {
	out := &PolicySyncPlan{BundleSHA256: rolesascode.Digest(files), Kinds: []PolicySyncKind{}}
	b, diags := policybundle.Load(files, nil)
	if len(diags) > 0 {
		ds := make([]rolesascode.Diag, len(diags))
		for i, d := range diags {
			ds[i] = rolesascode.Diag{Path: d.Path, Line: d.Line, Code: d.Code, Msg: d.Msg}
		}
		return nil, &rolesascode.InvalidError{Diags: ds}
	}
	if b.Config.Tenant != tenant {
		return nil, &rolesascode.InvalidError{Diags: []rolesascode.Diag{{Path: policybundle.ConfigFile, Code: "tenant_mismatch",
			Msg: fmt.Sprintf("tessera.yaml names tenant %q; this is %q", b.Config.Tenant, tenant)}}}
	}
	has := func(kind string, n int) bool { return b.Config.Manage[kind] != "" || n > 0 }
	ropt := rolesascode.Options{Tenant: tenant, MaxSteps: maxSteps}
	if has("roles", len(b.Roles)) {
		p, err := rolesascode.Build(tx, files, ropt, now)
		if err != nil {
			return nil, err
		}
		out.Kinds = append(out.Kinds, PolicySyncKind{Kind: "roles", Mode: b.Config.Manage["roles"], Created: p.Created, Updated: p.Updated,
			Steps: p.Steps, PlanSHA256: p.PlanSHA256})
	}
	if has("agents", len(b.AgentScopes)) {
		p, err := agentscopeascode.Build(tx, files, ropt)
		if err != nil {
			return nil, err
		}
		out.Kinds = append(out.Kinds, PolicySyncKind{Kind: "agents", Mode: p.Mode, Created: p.Created, Updated: p.Updated, Retired: p.Retired,
			Steps: p.Steps, PlanSHA256: p.PlanSHA256})
	}
	if has("sod", len(b.Sod)) {
		p, err := sodascode.Build(tx, files, ropt)
		if err != nil {
			return nil, err
		}
		out.Kinds = append(out.Kinds, PolicySyncKind{Kind: "sod", Mode: p.Mode, Created: p.Created, Updated: p.Updated, Retired: p.Retired,
			Steps: p.Steps, PlanSHA256: p.PlanSHA256})
	}
	if has("jit", len(b.Jit)) {
		p, err := jitascode.Build(tx, files, ropt)
		if err != nil {
			return nil, err
		}
		out.Kinds = append(out.Kinds, PolicySyncKind{Kind: "jit", Mode: p.Mode, Created: p.Created, Updated: p.Updated, Retired: p.Retired,
			Steps: p.Steps, PlanSHA256: p.PlanSHA256})
	}
	sort.Slice(out.Kinds, func(i, j int) bool { return out.Kinds[i].Kind < out.Kinds[j].Kind })
	h := sha256.New()
	fmt.Fprintf(h, "bundle %s\n", out.BundleSHA256)
	for _, k := range out.Kinds {
		fmt.Fprintf(h, "%s %s\n", k.Kind, k.PlanSHA256)
		out.Changes += k.Created + k.Updated + k.Retired
		out.Steps += k.Steps
	}
	out.PlanSHA256 = hex.EncodeToString(h.Sum(nil))
	return out, nil
}

func (e *env) syncPlan(v *policySyncPayload) (*PolicySyncPlan, error) {
	t, err := e.tenantRecord()
	if err != nil {
		return nil, err
	}
	p, err := BuildPolicySync(e.tx, v.bundle(), t.Slug, e.svc.PolicyMaxSteps, e.now)
	if err != nil {
		return nil, syncErr(err)
	}
	return p, nil
}

// planPolicySync files a request only for a bundle that is valid and whose plan is the one named now. Two people always.
func planPolicySync(e *env, v *policySyncPayload) (plan, error) {
	switch {
	case !syncRepoRE.MatchString(v.Repo):
		return plan{}, invalid("repo must be owner/name")
	case !syncSHARE.MatchString(v.SHA):
		return plan{}, invalid("sha must be a full commit id in lower-case hex")
	case v.Kind != SyncKindSync && v.Kind != SyncKindRollback:
		return plan{}, invalid("kind is %q; want %s or %s", v.Kind, SyncKindSync, SyncKindRollback)
	case v.Kind == SyncKindRollback && !syncSHARE.MatchString(v.RollbackFrom):
		return plan{}, invalid("a rollback names the commit it leaves (rollback_from)")
	case len(v.Files) == 0:
		return plan{}, invalid("files is required")
	case v.Prediction == nil:
		return plan{}, invalid("prediction is required")
	case v.DefaultBranch == "" || len(v.DefaultBranch) > 200:
		return plan{}, invalid("default_branch is required")
	}
	if err := v.Prediction.Valid(); err != nil {
		return plan{}, invalid("%v", err)
	}
	st, err := e.tx.GitHubAppSettings()
	if err != nil {
		return plan{}, err
	}
	if !st.Enabled || !strings.EqualFold(st.Repo, v.Repo) {
		return plan{}, conflict("repo_not_configured", "repo is not the repository the GitHub App is configured for")
	}
	if err := e.syncBase(v); err != nil {
		return plan{}, err
	}
	files := v.bundle()
	if d := rolesascode.Digest(files); d != v.BundleSHA256 {
		return plan{}, invalid("bundle_sha256 is %q; the files hash to %s", v.BundleSHA256, d)
	}
	p, err := e.syncPlan(v)
	if err != nil {
		return plan{}, err
	}
	if p.PlanSHA256 != v.PlanSHA256 {
		return plan{}, conflict("stale_plan", "the plan is %s, not %s; sync the commit again", p.PlanSHA256, v.PlanSHA256)
	}
	return plan{twoPerson: true, target: "policy"}, nil
}

// syncBase refuses a request filed against a last synced commit that is not the last one now.
func (e *env) syncBase(v *policySyncPayload) error {
	last, err := e.tx.LastPolicySync(v.Repo)
	if err != nil {
		return err
	}
	now := ""
	if last != nil {
		now = last.ID
	}
	if now != v.LastSyncID {
		return conflict("stale_base", "another sync was applied since this one was filed; sync the commit again")
	}
	return nil
}

func syncDigestOf(v *policySyncPayload, kind string) string {
	for _, k := range v.Kinds {
		if k.Kind == kind {
			return k.PlanSHA256
		}
	}
	return ""
}

func applyPolicySync(e *env, ch *store.AdminChange, v *policySyncPayload) error {
	t, err := e.tenantRecord()
	if err != nil {
		return err
	}
	files := v.bundle()
	// the plan of every kind is checked as a whole before anything is written
	if err := e.syncBase(v); err != nil {
		return err
	}
	cur, err := e.syncPlan(v)
	if err != nil {
		return err
	}
	if cur.PlanSHA256 != v.PlanSHA256 {
		return conflict("stale_plan", "the plan is %s, not %s; sync the commit again", cur.PlanSHA256, v.PlanSHA256)
	}
	by := ch.RequestedBy
	if ch.ApprovedBy != nil {
		by = *ch.ApprovedBy
	}
	actor := roles.Actor{UserID: by, Display: e.name(by)}
	ropt := rolesascode.Options{Tenant: t.Slug, MaxSteps: e.svc.PolicyMaxSteps}

	var pols []*policy.Policy
	if e.svc.EffectivePolicies != nil {
		if pols, err = e.svc.EffectivePolicies(e.tx); err != nil {
			return err
		}
	}
	before, err := syncverify.Capture(e.tx, pols, e.now)
	if err != nil {
		return err
	}

	for _, k := range cur.Kinds {
		want := syncDigestOf(v, k.Kind)
		switch k.Kind {
		case "roles":
			_, err = rolesascode.Apply(e.tx, files, ropt, rolesascode.Ref{Commit: v.SHA}, want, actor, e.now)
		case "agents":
			_, err = agentscopeascode.Apply(e.tx, files, ropt, agentscopeascode.Ref{Commit: v.SHA}, want, actor, e.now)
		case "sod":
			_, err = sodascode.Apply(e.tx, files, ropt, sodascode.Ref{Commit: v.SHA}, want, actor, e.now)
		case "jit":
			_, err = jitascode.Apply(e.tx, files, ropt, jitascode.Ref{Commit: v.SHA}, want, actor, e.now)
		}
		if err != nil {
			return syncErr(err)
		}
	}

	// the prediction check: the state after the writes, as the store shows it (and as a connector re-collect shows it,
	// through the hook), against what the preview predicted
	if e.svc.EffectivePolicies != nil {
		if pols, err = e.svc.EffectivePolicies(e.tx); err != nil {
			return err
		}
	}
	after, err := syncverify.Capture(e.tx, pols, e.now)
	if err != nil {
		return err
	}
	if e.svc.SyncObserve != nil {
		e.svc.SyncObserve(after)
	}
	ms, total := syncverify.Compare(v.Prediction, before, after)
	// verified only when the whole comparison ran: a cut prediction or no policies to read violations with is partial
	var partial []string
	if v.Prediction.Truncated() {
		partial = append(partial, "prediction_truncated")
	}
	if !before.Checked || !after.Checked {
		partial = append(partial, "violations_not_checked")
	}
	status := store.PolicySyncVerified
	switch {
	case total > 0:
		status = store.PolicySyncMismatch
	case len(partial) > 0:
		status = store.PolicySyncPartial
	}
	detail, err := json.Marshal(map[string]any{"predicted_permission_changes": v.Prediction.PermsTotal,
		"identities_affected": v.Prediction.IdentitiesAffected, "violations_checked": before.Checked && after.Checked,
		"mismatches": total, "partial_reasons": partial, "diff_sha256": v.Prediction.DiffSHA256})
	if err != nil {
		return err
	}
	sync, err := e.tx.PolicySyncByChange(ch.ID.String())
	if err != nil {
		return err
	}
	if sync == nil {
		return errors.New("admin: a policy sync request has no policy_syncs row")
	}
	if err := e.tx.MarkPolicySyncApplied(v.Repo, ch.ID.String(), e.now, status, string(detail)); err != nil {
		return err
	}
	for _, m := range ms {
		if err := e.tx.InsertPolicySyncFinding(&store.PolicySyncFinding{SyncID: sync.ID, Kind: m.Kind, Subject: m.Subject,
			Predicted: m.Predicted, Observed: m.Observed}, e.now); err != nil {
			return err
		}
	}
	d := ojson.Object{{Key: "repo", Value: v.Repo}, {Key: "sha", Value: v.SHA}, {Key: "kind", Value: v.Kind},
		{Key: "bundle_sha256", Value: v.BundleSHA256}, {Key: "plan_sha256", Value: v.PlanSHA256}, {Key: "change_id", Value: ch.ID.String()}}
	if v.Kind == SyncKindRollback {
		d = append(d, ojson.KV{Key: "rollback_from", Value: v.RollbackFrom})
	}
	if _, err := audit.Record(e.tx.Context(), e.tx, "policy.sync.applied", d, audit.At(e.now), audit.Target("policy_sync", sync.ID)); err != nil {
		return err
	}
	action := "policy.sync.verified"
	outcome := store.OutcomeSuccess
	switch status {
	case store.PolicySyncMismatch:
		action, outcome = "policy.sync.mismatch", store.OutcomeFailure
	case store.PolicySyncPartial:
		action = "policy.sync.partial"
	}
	d = append(d, ojson.KV{Key: "mismatches", Value: total}, ojson.KV{Key: "predicted_permission_changes", Value: v.Prediction.PermsTotal})
	_, err = audit.Record(e.tx.Context(), e.tx, action, d, audit.At(e.now), audit.Target("policy_sync", sync.ID), audit.Outcome(outcome))
	return err
}
