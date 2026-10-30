// Package jitascode is AC-5 of the access-as-code plan (issue #651, design docs/design/access-as-code-repo.md
// sections 3.3, 6, 7 and 10): JIT eligibility rules as files (jit/<key>.yaml) in a policy repository.
//
// Export writes the tenant's active rules. Plan loads a bundle (internal/policybundle), resolves every group
// reference inside the tenant by system:name (a name may hold spaces) and says which rules it would create, update
// or retire, how the groups each names change, and whether it turns enforcement on or off. Apply re-plans in its own
// transaction, refuses a plan that is not the approved one (409 stale_plan), writes the rules and records the
// repository change (commit, path, bundle digest) as the policy_ref of every version it writes.
//
// Rules are data (YAML), never Cedar: the loader refuses anything but .yaml under jit/ (so there is no fragment
// to parse, and no forbid, narrowed scope or lone has can enter through this kind), and the fixed jit_request
// policy of the design is evaluated by internal/jit, not authored. Both manage modes are supported: partial creates
// and updates the rules in the bundle; full also retires (never deletes) the active rules absent from it. An apply
// whose writes pass MaxSteps is refused with 413 plan_too_large, and one whose removals (rules retired, groups
// dropped from a rule) pass the deletion guard's group_members threshold with 409 deletion_guard; both are refused
// outright, with no override (design section 10, decision 4).
//
// Enforcement itself is in internal/jit: once tessera.yaml says jit_enforce: true, a request needs a matching rule
// (deny by default); until then groups.requestable keeps working.
package jitascode

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
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Diag, InvalidError, Options, Digest and the limits are the ones of roles as code, so the API and the change
// handler treat both kinds alike.
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

// Export writes the tenant's active rules as a bundle: tessera.yaml (with the enforcement switch as it is) and
// jit/<key>.yaml. Loading the result and planning it against the same state is a plan of no changes.
func Export(tx *store.TenantTx, tenant string) (policybundle.Files, error) {
	names, count, err := groupNames(tx)
	if err != nil {
		return nil, err
	}
	set, err := tx.JITSettings()
	if err != nil {
		return nil, err
	}
	cfg, err := yaml.Marshal(policybundle.Config{Schema: policybundle.TagRepo, Tenant: tenant,
		Manage: map[string]string{"jit": "partial"}, JitEnforce: &set.Enabled})
	if err != nil {
		return nil, err
	}
	files := policybundle.Files{policybundle.ConfigFile: cfg}
	es, err := tx.JITEligibilities()
	if err != nil {
		return nil, err
	}
	var problems []Diag
	for _, e := range es {
		if e.Status != store.JITEligibilityActive {
			continue
		}
		path := policybundle.DirJit + "/" + e.Key + ".yaml"
		list := func(ids []int64) []string {
			out := []string{}
			for _, id := range ids {
				n := names[id]
				if count[n] > 1 {
					problems = append(problems, Diag{Path: path, Code: "ambiguous_group", Msg: fmt.Sprintf("%q names more than one group", n)})
				}
				out = append(out, n)
			}
			sort.Strings(out)
			return out
		}
		doc := policybundle.Jit{Schema: policybundle.TagJit, Key: e.Key, Principals: list(e.Principals),
			Entitlements: list(e.Entitlements), MaxHours: e.MaxHours, Approvers: list(e.Approvers),
			MinApprovals: e.MinApprovals, StepUp: e.StepUp}
		b, err := yaml.Marshal(doc)
		if err != nil {
			return nil, err
		}
		files[path] = b
	}
	if len(problems) > 0 {
		sortDiags(problems)
		return nil, &InvalidError{Diags: problems}
	}
	return files, nil
}

func groupNames(tx *store.TenantTx) (names map[int64]string, count map[string]int, err error) {
	gs, err := tx.Groups()
	if err != nil {
		return nil, nil, err
	}
	names, count = map[int64]string{}, map[string]int{}
	for _, g := range gs {
		names[g.ID] = g.System + ":" + g.Name
		count[names[g.ID]]++
	}
	return names, count, nil
}

// ---------------------------------------------------------------- plan

// RulePlan is what the bundle does to one rule.
type RulePlan struct {
	Key          string   `json:"key"`
	Action       string   `json:"action"` // create, update, retire or unchanged
	Version      int      `json:"version,omitempty"`
	MaxHours     int      `json:"max_hours"`
	MinApprovals int      `json:"min_approvals"`
	StepUp       bool     `json:"step_up"`
	Principals   []string `json:"principals"`
	Entitlements []string `json:"entitlements"`
	Approvers    []string `json:"approvers"`
	// GroupsAdded and GroupsRemoved count the group references the rule gains and loses.
	GroupsAdded   int `json:"groups_added"`
	GroupsRemoved int `json:"groups_removed"`
}

// Enforcement is the tenant's deny-by-default switch before and after the apply.
type Enforcement struct {
	Current bool `json:"current"`
	Wanted  bool `json:"wanted"`
}

// Plan is what applying a bundle would do.
type Plan struct {
	Tenant       string      `json:"tenant"`
	BundleSHA256 string      `json:"bundle_sha256"`
	Mode         string      `json:"mode"` // partial or full
	Enforcement  Enforcement `json:"enforcement"`
	Rules        []RulePlan  `json:"rules"`
	Created      int         `json:"rules_created"`
	Updated      int         `json:"rules_updated"`
	Retired      int         `json:"rules_retired"`
	Unchanged    int         `json:"rules_unchanged"`
	// Steps are the writes: one per rule created, updated or retired, one per group reference added or removed.
	Steps int `json:"steps"`
	// Removes are the rules retired and the group references removed: what the deletion guard counts.
	Removes int `json:"removals"`
	// ActiveAfter is how many rules are active once applied.
	ActiveAfter int      `json:"active_after"`
	Warnings    []string `json:"warnings"`
	// PlanSHA256 is the digest of the plan; the approver approves it and the apply refuses any other.
	PlanSHA256 string `json:"plan_sha256"`
}

type item struct {
	path                                string
	key                                 string
	want                                store.JITEligibility // the rule as the bundle says it; Principals etc. are group ids
	existing                            *store.JITEligibility
	retire                              bool
	principals, entitlements, approvers []string // names, sorted
}

type prepared struct {
	digest string
	mode   string
	wanted *bool
	items  []item
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
	out := &prepared{digest: Digest(files), mode: b.Config.Manage["jit"], wanted: b.Config.JitEnforce}
	if out.mode != "partial" && out.mode != "full" {
		add(policybundle.ConfigFile, "not_managed", "manage.jit must be partial or full for a repository that holds JIT eligibility")
	}

	gs, err := tx.Groups()
	if err != nil {
		return nil, err
	}
	groups := map[string][]int64{}
	for _, g := range gs {
		n := g.System + ":" + g.Name
		groups[n] = append(groups[n], g.ID)
	}
	resolve := func(path, what string, refs []string) []int64 {
		var ids []int64
		for _, r := range refs {
			switch g := groups[r]; len(g) {
			case 0:
				add(path, "unknown_group", "%s: %q is not a group of this tenant", what, r)
			case 1:
				ids = append(ids, g[0])
			default:
				add(path, "ambiguous_group", "%s: %q names %d groups", what, r, len(g))
			}
		}
		slices.Sort(ids)
		return slices.Compact(ids)
	}
	sorted := func(l []string) []string {
		l = slices.Clone(l)
		slices.Sort(l)
		return l
	}

	seen := map[string]bool{}
	list := slices.Clone(b.Jit)
	sort.Slice(list, func(i, j int) bool { return list[i].Key < list[j].Key })
	for _, j := range list {
		seen[j.Key] = true
		if j.MinApprovals > 1 {
			add(j.Path, "unsupported_min_approvals", "min_approvals is 0 or 1; an approval by more than one person is not supported yet")
		}
		it := item{path: j.Path, key: j.Key, principals: sorted(j.Principals), entitlements: sorted(j.Entitlements), approvers: sorted(j.Approvers)}
		it.want = store.JITEligibility{Key: j.Key, Status: store.JITEligibilityActive, MaxHours: j.MaxHours,
			MinApprovals: j.MinApprovals, StepUp: j.StepUp,
			Principals: resolve(j.Path, "principals", j.Principals), Entitlements: resolve(j.Path, "entitlements", j.Entitlements),
			Approvers: resolve(j.Path, "approvers", j.Approvers)}
		if it.existing, err = tx.JITEligibilityByKey(j.Key); errors.Is(err, store.ErrNotFound) {
			it.existing = nil
		} else if err != nil {
			return nil, err
		}
		out.items = append(out.items, it)
	}
	if out.mode == "full" {
		all, err := tx.JITEligibilities()
		if err != nil {
			return nil, err
		}
		for _, e := range all {
			if e.Status == store.JITEligibilityActive && !seen[e.Key] {
				out.items = append(out.items, item{key: e.Key, existing: e, retire: true})
			}
		}
		sort.Slice(out.items, func(i, j int) bool { return out.items[i].key < out.items[j].key })
	}
	if len(ds) > 0 {
		sortDiags(ds)
		return nil, &InvalidError{Diags: ds}
	}
	return out, nil
}

func diffIDs(have, want []int64) (added, removed int) {
	for _, id := range want {
		if !slices.Contains(have, id) {
			added++
		}
	}
	for _, id := range have {
		if !slices.Contains(want, id) {
			removed++
		}
	}
	return added, removed
}

// same says whether the active rule already is what the bundle says.
func (it *item) same() bool {
	e := it.existing
	if e == nil || e.Status != store.JITEligibilityActive {
		return false
	}
	w := &it.want
	return e.MaxHours == w.MaxHours && e.MinApprovals == w.MinApprovals && e.StepUp == w.StepUp &&
		slices.Equal(e.Principals, w.Principals) && slices.Equal(e.Entitlements, w.Entitlements) && slices.Equal(e.Approvers, w.Approvers)
}

func (it *item) plan(names map[int64]string) RulePlan {
	rp := RulePlan{Key: it.key, Principals: it.principals, Entitlements: it.entitlements, Approvers: it.approvers,
		MaxHours: it.want.MaxHours, MinApprovals: it.want.MinApprovals, StepUp: it.want.StepUp}
	nameList := func(ids []int64) []string {
		out := []string{}
		for _, id := range ids {
			out = append(out, names[id])
		}
		sort.Strings(out)
		return out
	}
	if rp.Principals == nil {
		rp.Principals = []string{}
	}
	if rp.Entitlements == nil {
		rp.Entitlements = []string{}
	}
	if rp.Approvers == nil {
		rp.Approvers = []string{}
	}
	e := it.existing
	switch {
	case it.retire:
		rp.Action, rp.Version = "retire", e.Version+1
		rp.MaxHours, rp.MinApprovals, rp.StepUp = e.MaxHours, e.MinApprovals, e.StepUp
		rp.Principals, rp.Entitlements, rp.Approvers = nameList(e.Principals), nameList(e.Entitlements), nameList(e.Approvers)
		rp.GroupsRemoved = len(e.Principals) + len(e.Entitlements) + len(e.Approvers)
		return rp
	case it.same():
		rp.Action, rp.Version = "unchanged", e.Version
		return rp
	case e == nil:
		rp.Action, rp.Version = "create", 1
		rp.GroupsAdded = len(it.want.Principals) + len(it.want.Entitlements) + len(it.want.Approvers)
		return rp
	}
	rp.Action, rp.Version = "update", e.Version+1
	for _, p := range [][2][]int64{{e.Principals, it.want.Principals}, {e.Entitlements, it.want.Entitlements}, {e.Approvers, it.want.Approvers}} {
		a, r := diffIDs(p[0], p[1])
		rp.GroupsAdded, rp.GroupsRemoved = rp.GroupsAdded+a, rp.GroupsRemoved+r
	}
	return rp
}

// compute plans the prepared bundle.
func compute(tx *store.TenantTx, p *prepared, opt Options) (*Plan, error) {
	names, _, err := groupNames(tx)
	if err != nil {
		return nil, err
	}
	cur, err := tx.JITSettings()
	if err != nil {
		return nil, err
	}
	plan := &Plan{Tenant: opt.Tenant, BundleSHA256: p.digest, Mode: p.mode, Rules: []RulePlan{}, Warnings: []string{},
		Enforcement: Enforcement{Current: cur.Enabled, Wanted: cur.Enabled}}
	if p.wanted != nil {
		plan.Enforcement.Wanted = *p.wanted
	}
	all, err := tx.JITEligibilities()
	if err != nil {
		return nil, err
	}
	active := map[string]bool{}
	for _, e := range all {
		active[e.Key] = e.Status == store.JITEligibilityActive
	}
	for i := range p.items {
		it := &p.items[i]
		rp := it.plan(names)
		writes := 0
		switch rp.Action {
		case "create":
			plan.Created++
			active[rp.Key] = true
			writes = 1
		case "update":
			plan.Updated++
			active[rp.Key] = true
			writes = 1
		case "retire":
			plan.Retired++
			active[rp.Key] = false
			writes = 1
			plan.Removes++
		default:
			plan.Unchanged++
		}
		plan.Steps += writes + rp.GroupsAdded + rp.GroupsRemoved
		plan.Removes += rp.GroupsRemoved
		plan.Rules = append(plan.Rules, rp)
	}
	for _, a := range active {
		if a {
			plan.ActiveAfter++
		}
	}
	if plan.Enforcement.Wanted && plan.ActiveAfter == 0 {
		plan.Warnings = append(plan.Warnings, "enforcement is on and no rule is active: every JIT request will be denied")
	}
	if plan.Enforcement.Wanted != plan.Enforcement.Current {
		if plan.Enforcement.Wanted {
			plan.Warnings = append(plan.Warnings, "enforcement turns on: groups.requestable stops deciding and only a matching rule allows a request")
		} else {
			plan.Warnings = append(plan.Warnings, "enforcement turns off: groups.requestable decides again and rules no longer limit requests")
		}
	}
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

type snapshot struct {
	Key          string   `json:"key"`
	Status       string   `json:"status"`
	MaxHours     int      `json:"max_hours"`
	MinApprovals int      `json:"min_approvals"`
	StepUp       bool     `json:"step_up"`
	Principals   []string `json:"principals"`
	Entitlements []string `json:"entitlements"`
	Approvers    []string `json:"approvers"`
}

// Apply re-plans the bundle in the caller's write transaction, refuses it with 409 stale_plan unless the plan's
// digest is wantPlan (what was approved), then writes the rules and the enforcement switch, recording the
// repository change as the policy_ref of each version, and appends one policy.jit.applied audit event. Any error
// leaves nothing to commit: run it inside DB.InTenant and return the error.
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
	for i := range p.items {
		it := &p.items[i]
		rp := plan.Rules[i]
		if rp.Action == "unchanged" {
			continue
		}
		raw, err := json.Marshal(policyRef{Commit: ref.Commit, Path: it.path, BundleSHA256: p.digest})
		if err != nil {
			return nil, err
		}
		pref := string(raw)
		if it.retire {
			pref = ""
		}
		e := it.want
		e.Key, e.UpdatedAt = it.key, now
		switch {
		case it.retire:
			e = *it.existing
			e.Status, e.Version, e.UpdatedAt = store.JITEligibilityRetired, it.existing.Version+1, now
			err = tx.SaveJITEligibility(&e, it.existing.Version)
			if err == nil {
				for _, role := range []string{store.JITPrincipal, store.JITEntitlement, store.JITApprover} {
					if err = tx.SetJITEligibilityGroups(e.ID, role, nil); err != nil {
						break
					}
				}
			}
		case it.existing == nil:
			e.Version, e.CreatedAt = 1, now
			if err = tx.InsertJITEligibility(&e); err == nil {
				err = setGroups(tx, &e)
			}
		default:
			e.ID, e.Version = it.existing.ID, it.existing.Version+1
			if err = tx.SaveJITEligibility(&e, it.existing.Version); err == nil {
				err = setGroups(tx, &e)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", it.path, err)
		}
		snap, err := json.Marshal(snapshot{Key: rp.Key, Status: e.Status, MaxHours: rp.MaxHours, MinApprovals: rp.MinApprovals,
			StepUp: rp.StepUp, Principals: rp.Principals, Entitlements: rp.Entitlements, Approvers: rp.Approvers})
		if err != nil {
			return nil, err
		}
		v := &store.JITEligibilityVersion{EligibilityID: e.ID, Version: e.Version, Snapshot: string(snap),
			Actor: by.Display, ChangedAt: now}
		if pref != "" {
			v.PolicyRef = &pref
		}
		if err := tx.AddJITEligibilityVersion(v); err != nil {
			return nil, err
		}
		if err := tx.Audit(now, by.Display, "policy.jit."+rp.Action, ojson.Object{{Key: "key", Value: rp.Key},
			{Key: "version", Value: e.Version}, {Key: "commit", Value: ref.Commit}}); err != nil {
			return nil, err
		}
	}
	if plan.Enforcement.Wanted != plan.Enforcement.Current {
		if err := tx.PutJITSettings(plan.Enforcement.Wanted, by.Display, now); err != nil {
			return nil, err
		}
		if err := tx.Audit(now, by.Display, "policy.jit.enforcement", ojson.Object{{Key: "enabled", Value: plan.Enforcement.Wanted},
			{Key: "commit", Value: ref.Commit}}); err != nil {
			return nil, err
		}
	}
	err = tx.Audit(now, by.Display, "policy.jit.applied", ojson.Object{{Key: "commit", Value: ref.Commit},
		{Key: "bundle_sha256", Value: p.digest}, {Key: "plan_sha256", Value: plan.PlanSHA256},
		{Key: "rules_created", Value: plan.Created}, {Key: "rules_updated", Value: plan.Updated},
		{Key: "rules_retired", Value: plan.Retired}, {Key: "rules_unchanged", Value: plan.Unchanged},
		{Key: "enforcement", Value: plan.Enforcement.Wanted}})
	return plan, err
}

func setGroups(tx *store.TenantTx, e *store.JITEligibility) error {
	for role, ids := range map[string][]int64{store.JITPrincipal: e.Principals, store.JITEntitlement: e.Entitlements,
		store.JITApprover: e.Approvers} {
		if err := tx.SetJITEligibilityGroups(e.ID, role, ids); err != nil {
			return err
		}
	}
	return nil
}
