// Package sodascode is AC-6 of the access-as-code plan (issue #652, design docs/design/access-as-code-repo.md
// sections 3.4, 6, 7 and 10): separation-of-duties rulesets, functions and risks as files (sod/<ruleset-key>.yaml,
// the tessera.sod/v1 document of internal/sod, unchanged) in a policy repository.
//
// Export writes the tenant's active rulesets. Plan loads a bundle (internal/policybundle), checks every file with
// internal/sod's own strict parser and validator, and says which rulesets, functions and risks it would create,
// update or retire, by running the existing sod.Writer.Import in dry-run. Apply re-plans in its own transaction,
// refuses a plan that is not the approved one (409 stale_plan), runs the same import for real (each change versioned
// and audited by internal/sod) and records the repository change (commit, path, bundle digest) as the policy_ref of
// every ruleset it writes (store.SodPolicyRef).
//
// Rules are data (YAML), never Cedar: the loader refuses anything but .yaml under sod/, a file that does not match
// tessera.sod/v1 exactly (unknown fields, a second document, a selector or subject condition outside the grammar of
// internal/sod) is refused with a diagnostic, and detection stays in internal/sod. Both manage modes are supported:
// partial creates and updates what the bundle lists; full also retires (never deletes) the risks a listed ruleset no
// longer lists and the rulesets an earlier apply wrote that the bundle no longer lists. An apply whose writes pass
// MaxSteps is refused with 413 plan_too_large, and one whose retirements pass the deletion guard with 409
// deletion_guard; both outright, with no override (design section 10, decision 4).
package sodascode

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/rolesascode"
	"github.com/nischalravi/tessera/mvp/server/internal/sod"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Diag, InvalidError, Options, Digest and the limits are the ones of roles as code, so the API and the change
// handler treat every kind alike.
type (
	Diag         = rolesascode.Diag
	InvalidError = rolesascode.InvalidError
	Options      = rolesascode.Options
)

// MaxCommit is the longest commit reference.
const MaxCommit = rolesascode.MaxCommit

// Digest is the SHA-256 of a bundle (see rolesascode.Digest).
func Digest(files policybundle.Files) string { return rolesascode.Digest(files) }

func refuse(status int, code, format string, args ...any) error {
	return &roles.Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

func sortDiags(ds []Diag) {
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].Path != ds[j].Path {
			return ds[i].Path < ds[j].Path
		}
		return ds[i].Line < ds[j].Line
	})
}

// ---------------------------------------------------------------- export

// Export writes the tenant's active rulesets as a bundle: tessera.yaml and sod/<ruleset-key>.yaml, each file the
// document sod.BundleOf makes. Loading the result and planning it against the same state is a plan of no changes.
func Export(tx *store.TenantTx, tenant string) (policybundle.Files, error) {
	cfg, err := yaml.Marshal(policybundle.Config{Schema: policybundle.TagRepo, Tenant: tenant,
		Manage: map[string]string{"sod": "partial"}})
	if err != nil {
		return nil, err
	}
	files := policybundle.Files{policybundle.ConfigFile: cfg}
	rs, err := tx.SodRulesets()
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		if r.Status != store.SodActive {
			continue
		}
		b, err := sod.BundleOf(tx, r)
		if err != nil {
			return nil, err
		}
		doc, err := b.MarshalYAML()
		if err != nil {
			return nil, err
		}
		files[policybundle.DirSod+"/"+r.Key+".yaml"] = doc
	}
	return files, nil
}

// ---------------------------------------------------------------- plan

// RulesetPlan is what the bundle does to one ruleset: the changes sod.Writer.Import reports, each "kind key".
type RulesetPlan struct {
	Key       string   `json:"key"`
	Action    string   `json:"action"` // create, update, retire or unchanged
	Adopt     bool     `json:"adopt,omitempty"`
	Created   []string `json:"created"`
	Updated   []string `json:"updated"`
	Unchanged []string `json:"unchanged"`
	Retired   []string `json:"retired"`
}

// Plan is what applying a bundle would do.
type Plan struct {
	Tenant       string        `json:"tenant"`
	BundleSHA256 string        `json:"bundle_sha256"`
	Mode         string        `json:"mode"` // partial or full
	Rulesets     []RulesetPlan `json:"rulesets"`
	Created      int           `json:"created"`
	Updated      int           `json:"updated"`
	Retired      int           `json:"retired"`
	Unchanged    int           `json:"unchanged"`
	// Steps are the writes: one per ruleset, function or risk created, updated or retired.
	Steps int `json:"steps"`
	// Removes are the rulesets and risks retired: what the deletion guard counts.
	Removes  int      `json:"removals"`
	Warnings []string `json:"warnings"`
	// PlanSHA256 is the digest of the plan; the approver approves it and the apply refuses any other.
	PlanSHA256 string `json:"plan_sha256"`
}

type item struct {
	path   string
	key    string
	doc    *sod.Bundle // nil: retire the ruleset (full mode)
	rs     *store.SodRuleset
	adopt  bool
	retire []*store.SodRisk // active risks to retire with the ruleset
}

type prepared struct {
	digest string
	mode   string
	items  []item
}

func refusalDiag(path string, err error) Diag {
	var rf *sod.Refusal
	if errors.As(err, &rf) {
		return Diag{Path: path, Code: rf.Code, Msg: rf.Msg}
	}
	return Diag{Path: path, Code: "invalid_document", Msg: err.Error()}
}

// prepare loads and resolves the bundle against the tenant; no writes.
func prepare(tx *store.TenantTx, files policybundle.Files, opt Options) (*prepared, error) {
	b, diags := policybundle.Load(files, nil)
	var ds []Diag
	for _, d := range diags {
		ds = append(ds, Diag{Path: d.Path, Line: d.Line, Code: d.Code, Msg: d.Msg})
	}
	if len(ds) > 0 {
		return nil, &InvalidError{Diags: ds}
	}
	add := func(path, code, format string, args ...any) {
		ds = append(ds, Diag{Path: path, Code: code, Msg: fmt.Sprintf(format, args...)})
	}
	if b.Config.Tenant != opt.Tenant {
		add(policybundle.ConfigFile, "tenant_mismatch", "tessera.yaml names tenant %q; this is %q", b.Config.Tenant, opt.Tenant)
	}
	out := &prepared{digest: Digest(files), mode: b.Config.Manage["sod"]}
	if out.mode != "partial" && out.mode != "full" {
		add(policybundle.ConfigFile, "not_managed", "manage.sod must be partial or full for a repository that holds SoD rules")
	}

	refs, err := tx.SodPolicyRefs()
	if err != nil {
		return nil, err
	}
	managed := map[string]bool{}
	for _, r := range refs {
		managed[r.RulesetID] = true
	}
	allRisks, err := tx.SodRisks()
	if err != nil {
		return nil, err
	}

	fnDoc := map[string]string{}    // function key -> its canonical document and the file that defined it
	fnFile := map[string]string{}   // function key -> file
	riskFile := map[string]string{} // risk key -> file
	listed := map[string]bool{}     // risk keys in the bundle
	seen := map[string]bool{}
	list := slices.Clone(b.Sod)
	sort.Slice(list, func(i, j int) bool { return list[i].Ruleset.Key < list[j].Ruleset.Key })
	for _, f := range list {
		path := f.Path
		if want := policybundle.DirSod + "/" + f.Ruleset.Key + ".yaml"; path != want && path != strings.TrimSuffix(want, ".yaml")+".yml" {
			add(path, "path_key_mismatch", "the file for ruleset %q is %s", f.Ruleset.Key, want)
		}
		doc, err := sod.ParseYAML(files[path])
		if err != nil {
			ds = append(ds, refusalDiag(path, err))
			continue
		}
		it := item{path: path, key: doc.Ruleset.Key, doc: doc}
		seen[it.key] = true
		for _, fn := range doc.Functions {
			j, _ := json.Marshal(fn)
			if prev, ok := fnDoc[fn.Key]; ok && prev != string(j) {
				add(path, "conflicting_function", "function %q is defined differently in %s", fn.Key, fnFile[fn.Key])
			}
			fnDoc[fn.Key], fnFile[fn.Key] = string(j), path
			if e, err := tx.SodFunctionByKey(fn.Key); err == nil && e.Status != store.SodActive {
				add(path, "function_retired", "function %q is retired; use another key", fn.Key)
			} else if err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
		}
		for _, r := range doc.Risks {
			if q := riskFile[r.Key]; q != "" {
				add(path, "duplicate_key", "risk %q is also defined in %s", r.Key, q)
			}
			riskFile[r.Key] = path
			listed[r.Key] = true
			if e, err := tx.SodRiskByKey(r.Key); err == nil && e.Status != store.SodActive {
				add(path, "risk_retired", "risk %q is retired; use another key", r.Key)
			} else if err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
		}
		switch rs, err := tx.SodRulesetByKey(it.key); {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return nil, err
		case rs.Status != store.SodActive:
			add(path, "ruleset_retired", "ruleset %q is retired; use another key", it.key)
		default:
			it.rs, it.adopt = rs, !managed[rs.ID]
		}
		out.items = append(out.items, it)
	}
	if out.mode == "full" {
		all, err := tx.SodRulesets()
		if err != nil {
			return nil, err
		}
		for _, rs := range all {
			if rs.Status != store.SodActive || seen[rs.Key] || !managed[rs.ID] {
				continue
			}
			it := item{key: rs.Key, rs: rs}
			for _, r := range allRisks {
				if r.RulesetID == rs.ID && r.Status == store.SodActive && !listed[r.Key] {
					it.retire = append(it.retire, r)
				}
			}
			out.items = append(out.items, it)
		}
		sort.Slice(out.items, func(i, j int) bool { return out.items[i].key < out.items[j].key })
	}
	if len(ds) > 0 {
		sortDiags(ds)
		return nil, &InvalidError{Diags: ds}
	}
	return out, nil
}

// compute plans the prepared bundle.
func compute(tx *store.TenantTx, p *prepared, opt Options) (*Plan, error) {
	plan := &Plan{Tenant: opt.Tenant, BundleSHA256: p.digest, Mode: p.mode, Rulesets: []RulesetPlan{}, Warnings: []string{}}
	w := &sod.Writer{Tx: tx, Quiet: true}
	var ds []Diag
	counted := map[string]bool{} // "function k" written by an earlier file: a shared function counts once
	for i := range p.items {
		it := &p.items[i]
		rp := RulesetPlan{Key: it.key, Adopt: it.adopt, Created: []string{}, Updated: []string{}, Unchanged: []string{}, Retired: []string{}}
		if it.doc == nil {
			for _, r := range it.retire {
				rp.Retired = append(rp.Retired, "risk "+r.Key)
			}
			rp.Retired = append(rp.Retired, "ruleset "+it.key)
			rp.Action = "retire"
		} else {
			res, err := w.Import(it.doc, sod.ImportOptions{Prune: p.mode == "full", DryRun: true})
			if err != nil {
				ds = append(ds, refusalDiag(it.path, err))
				continue
			}
			keep := func(l []string) []string {
				out := []string{}
				for _, s := range l {
					if strings.HasPrefix(s, "function ") {
						if counted[s] {
							continue
						}
						counted[s] = true
					}
					out = append(out, s)
				}
				return out
			}
			rp.Created, rp.Updated, rp.Retired = keep(res.Created), keep(res.Updated), res.Retired
			rp.Unchanged = res.Same
			switch {
			case slices.Contains(res.Created, "ruleset "+it.key):
				rp.Action = "create"
			case len(rp.Created)+len(rp.Updated)+len(rp.Retired) > 0:
				rp.Action = "update"
			default:
				rp.Action = "unchanged"
			}
		}
		plan.Created += len(rp.Created)
		plan.Updated += len(rp.Updated)
		plan.Retired += len(rp.Retired)
		plan.Unchanged += len(rp.Unchanged)
		plan.Removes += len(rp.Retired)
		plan.Rulesets = append(plan.Rulesets, rp)
		if rp.Adopt {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("ruleset %s was made outside the repository; applying adopts it", it.key))
		}
	}
	if len(ds) > 0 {
		sortDiags(ds)
		return nil, &InvalidError{Diags: ds}
	}
	plan.Steps = plan.Created + plan.Updated + plan.Retired
	if limit := opt.MaxSteps; limit <= 0 && plan.Steps > rolesascode.DefaultMaxSteps || limit > 0 && plan.Steps > limit {
		if limit <= 0 {
			limit = rolesascode.DefaultMaxSteps
		}
		return nil, refuse(413, "plan_too_large", "the bundle makes %d writes; one apply makes at most %d. Split it into smaller changes", plan.Steps, limit)
	}
	if plan.Removes > 0 {
		if err := rolesascode.Guard(tx, plan.Removes); err != nil {
			return nil, err
		}
	}
	b, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	plan.PlanSHA256 = hex.EncodeToString(sum[:])
	return plan, nil
}

// Validate loads and resolves the bundle without planning it.
func Validate(tx *store.TenantTx, files policybundle.Files, opt Options) error {
	_, err := prepare(tx, files, opt)
	return err
}

// Build plans a bundle against the tenant. It writes nothing; run it in a read transaction.
func Build(tx *store.TenantTx, files policybundle.Files, opt Options) (*Plan, error) {
	p, err := prepare(tx, files, opt)
	if err != nil {
		return nil, err
	}
	return compute(tx, p, opt)
}

// ---------------------------------------------------------------- apply

// Ref says which repository change an apply is.
type Ref struct {
	Commit string
}

type policyRef struct {
	Commit       string `json:"commit"`
	Path         string `json:"path"`
	BundleSHA256 string `json:"bundle_sha256"`
}

// Apply re-plans the bundle in the caller's write transaction, refuses it with 409 stale_plan unless the plan's
// digest is wantPlan (what was approved), then imports each ruleset (sod.Writer.Import, which versions and audits
// each change), retires the rulesets of full mode, records the repository change as the policy_ref of each ruleset
// written, and appends one policy.sod.applied audit event. Any error leaves nothing to commit: run it inside
// DB.InTenant and return the error.
func Apply(tx *store.TenantTx, files policybundle.Files, opt Options, ref Ref, wantPlan string, by roles.Actor, now time.Time) (*Plan, error) {
	ref.Commit = strings.TrimSpace(ref.Commit)
	if ref.Commit == "" || len(ref.Commit) > MaxCommit {
		return nil, refuse(422, "invalid_commit", "a commit of 1 to %d characters is required", MaxCommit)
	}
	p, err := prepare(tx, files, opt)
	if err != nil {
		return nil, err
	}
	plan, err := compute(tx, p, opt)
	if err != nil {
		return nil, err
	}
	if plan.PlanSHA256 != wantPlan {
		return nil, refuse(409, "stale_plan", "the plan changed since it was made (now %s); plan the bundle again", plan.PlanSHA256[:12])
	}
	w := &sod.Writer{Tx: tx, By: sod.Actor{UserID: by.UserID, Display: by.Display}, Now: now}
	record := func(key, path string) error {
		rs, err := tx.SodRulesetByKey(key)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(policyRef{Commit: ref.Commit, Path: path, BundleSHA256: p.digest})
		if err != nil {
			return err
		}
		return tx.AddSodPolicyRef(&store.SodPolicyRef{RulesetID: rs.ID, RulesetVersion: rs.Version, PolicyRef: string(raw),
			Actor: by.Display, AppliedAt: store.RT(now)})
	}
	for i := range p.items { // the rulesets the bundle lists first, so a risk that moves out of a retired one has moved
		it := &p.items[i]
		if it.doc == nil {
			continue
		}
		if _, err := w.Import(it.doc, sod.ImportOptions{Prune: p.mode == "full"}); err != nil {
			return nil, fmt.Errorf("%s: %w", it.path, wrapRefusal(err))
		}
		if plan.Rulesets[i].Action != "unchanged" || it.adopt {
			if err := record(it.key, it.path); err != nil {
				return nil, err
			}
		}
	}
	for i := range p.items {
		it := &p.items[i]
		if it.doc != nil {
			continue
		}
		for _, r := range it.retire {
			if _, err := w.RetireRisk(r.ID, "not in the policy repository at commit "+ref.Commit); err != nil {
				return nil, fmt.Errorf("sod/%s.yaml: %w", it.key, wrapRefusal(err))
			}
		}
		if _, err := w.RetireRuleset(it.rs.ID, "not in the policy repository at commit "+ref.Commit); err != nil {
			return nil, fmt.Errorf("sod/%s.yaml: %w", it.key, wrapRefusal(err))
		}
	}
	err = tx.Audit(now, by.Display, "policy.sod.applied", ojson.Object{{Key: "commit", Value: ref.Commit},
		{Key: "bundle_sha256", Value: p.digest}, {Key: "plan_sha256", Value: plan.PlanSHA256},
		{Key: "rulesets", Value: len(plan.Rulesets)}, {Key: "created", Value: plan.Created},
		{Key: "updated", Value: plan.Updated}, {Key: "retired", Value: plan.Retired}, {Key: "unchanged", Value: plan.Unchanged}})
	return plan, err
}

// wrapRefusal turns a sod refusal into the roles error the API already renders.
func wrapRefusal(err error) error {
	var rf *sod.Refusal
	if errors.As(err, &rf) {
		return &roles.Error{Status: rf.Status, Code: rf.Code, Msg: rf.Msg}
	}
	return err
}
