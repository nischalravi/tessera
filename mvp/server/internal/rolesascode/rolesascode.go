// Package rolesascode is AC-4 of the access-as-code plan (issue #650, design
// docs/design/access-as-code-repo.md): business roles and their birthright
// rules as files in a policy repository.
//
// Export writes the tenant's active roles as roles/<key>.yaml and
// birthright/<key>.cedar. Plan loads a bundle (internal/policybundle),
// resolves its references inside the tenant (owner by external id, entitlements
// by system:name, the attribute policy by name) and runs each role through
// roles.Create or roles.Update as a dry run, so the plan is the same diff the UI
// shows for the same change. Apply re-plans in its own transaction, refuses a plan
// that is not the approved one (409 stale_plan), runs the same writers for real
// and records the repository change (commit, path, bundle digest) as the
// policy_ref of every version it writes.
//
// v1 is partial mode: roles in the bundle are created or updated, roles
// absent from it are left alone (retiring them is a later change, with the
// managed_by lock of design section 6.3). A plan over MaxSteps grant steps, or
// whose grant removals pass the deletion guard's group_members threshold, is
// refused outright (design section 10, decision 4); there is no override.
package rolesascode

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Limits.
const (
	// DefaultMaxSteps is the most grant steps (adds, removals, members) one apply may make
	// (TESSERA_POLICY_MAX_STEPS).
	DefaultMaxSteps = 20000
	// stepsShown is how many steps of a role the plan lists; the digest covers all of them.
	stepsShown = 200
	// MaxCommit is the longest commit reference.
	MaxCommit = 128
)

// Diag is one finding of a bundle, at a file and, when known, a line.
type Diag struct {
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
	Code string `json:"code"`
	Msg  string `json:"message"`
}

func (d Diag) String() string {
	if d.Line > 0 {
		return fmt.Sprintf("%s:%d: %s: %s", d.Path, d.Line, d.Code, d.Msg)
	}
	return fmt.Sprintf("%s: %s: %s", d.Path, d.Code, d.Msg)
}

// InvalidError is a bundle that cannot be applied: every finding, in path order (422 invalid_bundle).
type InvalidError struct{ Diags []Diag }

func (e *InvalidError) Error() string {
	n := len(e.Diags)
	if n == 0 {
		return "invalid bundle"
	}
	shown := e.Diags
	if n > 5 {
		shown = shown[:5]
	}
	parts := make([]string, len(shown))
	for i, d := range shown {
		parts[i] = d.String()
	}
	more := ""
	if n > len(shown) {
		more = fmt.Sprintf(" (and %d more)", n-len(shown))
	}
	return fmt.Sprintf("the bundle has %d findings: %s%s", n, strings.Join(parts, "; "), more)
}

func sortDiags(ds []Diag) {
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].Path != ds[j].Path {
			return ds[i].Path < ds[j].Path
		}
		return ds[i].Line < ds[j].Line
	})
}

func refuse(status int, code, format string, args ...any) error {
	return &roles.Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Options say whose bundle it is and how large an apply may be.
type Options struct {
	Tenant   string // the session's tenant slug; tessera.yaml must name it
	MaxSteps int    // 0: DefaultMaxSteps
}

func (o Options) maxSteps() int {
	if o.MaxSteps > 0 {
		return o.MaxSteps
	}
	return DefaultMaxSteps
}

// Digest is the SHA-256 of a bundle: each path and content, in path order, length-prefixed.
func Digest(files policybundle.Files) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	h := sha256.New()
	var n [8]byte
	for _, p := range paths {
		for _, b := range [][]byte{[]byte(p), files[p]} {
			binary.BigEndian.PutUint64(n[:], uint64(len(b)))
			h.Write(n[:])
			h.Write(b)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------- export

// Export writes the tenant's active roles as a bundle: tessera.yaml, roles/<key>.yaml and, for a role with a
// birthright rule, birthright/<key>.cedar. Loading the result and planning it against the same state is a plan of
// no changes (the round trip).
func Export(tx *store.TenantTx, tenant string) (policybundle.Files, error) {
	rs, err := tx.BusinessRoles()
	if err != nil {
		return nil, err
	}
	gs, err := tx.Groups()
	if err != nil {
		return nil, err
	}
	names := map[int64]string{}
	count := map[string]int{}
	for _, g := range gs {
		names[g.ID] = g.System + ":" + g.Name
		count[names[g.ID]]++
	}
	people, err := tx.Identities()
	if err != nil {
		return nil, err
	}
	xid := map[int64]string{}
	for _, p := range people {
		xid[p.ID] = p.ExternalID
	}
	cfg, err := yaml.Marshal(policybundle.Config{Schema: policybundle.TagRepo, Tenant: tenant, Manage: map[string]string{"roles": "partial"}})
	if err != nil {
		return nil, err
	}
	files := policybundle.Files{policybundle.ConfigFile: cfg}
	var problems []Diag
	for _, r := range rs {
		if r.Status != store.RoleActive {
			continue
		}
		path := policybundle.DirRoles + "/" + r.Key + ".yaml"
		if r.Key == "" {
			problems = append(problems, Diag{Path: r.Name, Code: "no_key", Msg: "the role has no key"})
			continue
		}
		ids, err := tx.RoleEntitlements(r.ID)
		if err != nil {
			return nil, err
		}
		doc := policybundle.Role{Schema: policybundle.TagRole, Key: r.Key, Name: r.Name, Description: r.Description,
			Risk: r.Risk, Requestable: r.Requestable, Entitlements: []string{}}
		for _, id := range ids {
			n := names[id]
			if count[n] > 1 {
				problems = append(problems, Diag{Path: path, Code: "ambiguous_entitlement", Msg: fmt.Sprintf("%q names more than one group", n)})
			}
			doc.Entitlements = append(doc.Entitlements, n)
		}
		sort.Strings(doc.Entitlements)
		if r.OwnerIdentityID != nil {
			doc.Owner = xid[*r.OwnerIdentityID]
		}
		b, err := yaml.Marshal(doc)
		if err != nil {
			return nil, err
		}
		files[path] = b
		rule, err := roles.ParseRule(r.Birthright)
		if err != nil {
			return nil, err
		}
		if rule == nil {
			continue
		}
		abac := ""
		if rule.Policy != "" {
			p, err := tx.AbacPolicy(rule.Policy)
			if err != nil {
				return nil, err
			}
			abac = p.Name
		}
		files[policybundle.DirBirthright+"/"+r.Key+".cedar"] = []byte(birthrightCedar(r.Key, rule, abac))
	}
	if len(problems) > 0 {
		sortDiags(problems)
		return nil, &InvalidError{Diags: problems}
	}
	return files, nil
}

// ---------------------------------------------------------------- plan

// RolePlan is what the bundle does to one role.
type RolePlan struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Action string `json:"action"` // create, update or unchanged
	// RoleID is the role's id; empty for a role that does not exist yet.
	RoleID  string `json:"role_id,omitempty"`
	Version int    `json:"version,omitempty"` // the version the role is at after the change
	Adds    int    `json:"grants_added"`
	Removes int    `json:"grants_removed"`
	Members int    `json:"members_added"`
	Leaves  int    `json:"members_removed"`
	Missing int    `json:"no_account"`
	// Steps are the member and grant changes, as roles.Plan lists them (a create names no role id); at most the
	// first stepsShown are listed, StepsOmitted is how many more there are.
	Steps        []roles.Step `json:"steps"`
	StepsOmitted int          `json:"steps_omitted,omitempty"`
}

// Plan is what applying a bundle would do.
type Plan struct {
	Tenant       string     `json:"tenant"`
	BundleSHA256 string     `json:"bundle_sha256"`
	Roles        []RolePlan `json:"roles"`
	Created      int        `json:"roles_created"`
	Updated      int        `json:"roles_updated"`
	Unchanged    int        `json:"roles_unchanged"`
	Steps        int        `json:"steps"`
	Adds         int        `json:"grants_added"`
	Removes      int        `json:"grants_removed"`
	Members      int        `json:"members_added"`
	Leaves       int        `json:"members_removed"`
	// PlanSHA256 is the digest of the plan with every step; the approver approves it and the apply refuses any other.
	PlanSHA256 string `json:"plan_sha256"`
}

type item struct {
	path     string
	spec     roles.Spec
	existing *store.BusinessRole
}

type prepared struct {
	files  policybundle.Files
	digest string
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
	add := func(path string, line int, code, format string, args ...any) {
		ds = append(ds, Diag{Path: path, Line: line, Code: code, Msg: fmt.Sprintf(format, args...)})
	}
	if b.Config.Tenant != opt.Tenant {
		add(policybundle.ConfigFile, 0, "tenant_mismatch", "tessera.yaml names tenant %q; this is %q", b.Config.Tenant, opt.Tenant)
	}
	switch b.Config.Manage["roles"] {
	case "partial":
	case "full":
		add(policybundle.ConfigFile, 0, "unsupported_mode", "manage.roles is full; roles apply in partial mode only (roles absent from the bundle are left alone)")
	default:
		add(policybundle.ConfigFile, 0, "not_managed", "manage.roles must be partial for a repository that holds roles")
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

	rules := map[string]*roles.Rule{}
	rulePath := map[string]string{}
	for _, f := range b.Birthright {
		for _, id := range f.Policies.IDs() {
			line := f.Policies.Line(id)
			role, _ := f.Policies.Annotation(id, "role")
			c, err := compileRule(f.Policies, id, role)
			if err != nil {
				var re *ruleError
				if errors.As(err, &re) {
					add(f.Path, line, "unsupported_birthright", "%s", re.msg)
					continue
				}
				return nil, err
			}
			rule := c.Rule
			if name, ok := f.Policies.Annotation(id, "abac"); ok {
				p, err := tx.AbacPolicyByName(name)
				switch {
				case errors.Is(err, store.ErrNotFound):
					add(f.Path, line, "unknown_abac_policy", "the attribute policy %q does not exist", name)
					continue
				case err != nil:
					return nil, err
				}
				rule.Policy = p.ID
			}
			if rule.Normalized() == nil {
				add(f.Path, line, "empty_birthright", "a birthright rule tests department, type or title, or names an attribute policy with @abac")
				continue
			}
			rules[role], rulePath[role] = rule.Normalized(), f.Path
		}
	}

	out := &prepared{files: files, digest: Digest(files)}
	people := map[string]*store.Identity{}
	names := map[string]string{}
	roleList := slices.Clone(b.Roles)
	sort.Slice(roleList, func(i, j int) bool { return roleList[i].Key < roleList[j].Key })
	for _, r := range roleList {
		if other := names[strings.TrimSpace(r.Name)]; other != "" {
			add(r.Path, 0, "duplicate_name", "role name %q is also used by %s", r.Name, other)
		}
		names[strings.TrimSpace(r.Name)] = r.Path
		spec := roles.Spec{Key: r.Key, Name: r.Name, Description: r.Description, Risk: r.Risk, Requestable: r.Requestable,
			Birthright: rules[r.Key]}
		if r.Owner != "" {
			p, ok := people[r.Owner]
			if !ok {
				if p, err = tx.IdentityByExternalID(r.Owner); errors.Is(err, store.ErrNotFound) {
					p = nil
				} else if err != nil {
					return nil, err
				}
				people[r.Owner] = p
			}
			if p == nil {
				add(r.Path, 0, "unknown_owner", "owner %q is not an identity of this tenant", r.Owner)
			} else {
				spec.OwnerIdentityID = &p.ID
			}
		}
		for _, e := range r.Entitlements {
			switch ids := groups[e]; len(ids) {
			case 0:
				add(r.Path, 0, "unknown_entitlement", "%q is not a group of this tenant", e)
			case 1:
				spec.Entitlements = append(spec.Entitlements, ids[0])
			default:
				add(r.Path, 0, "ambiguous_entitlement", "%q names %d groups", e, len(ids))
			}
		}
		it := item{path: r.Path, spec: spec}
		if it.existing, err = tx.BusinessRoleByKey(r.Key); errors.Is(err, store.ErrNotFound) {
			it.existing = nil
		} else if err != nil {
			return nil, err
		}
		out.items = append(out.items, it)
	}
	if len(ds) > 0 {
		sortDiags(ds)
		return nil, &InvalidError{Diags: ds}
	}
	return out, nil
}

// unchanged says whether the role already is what the spec says.
func (it *item) unchanged(tx *store.TenantTx) (bool, error) {
	r := it.existing
	if r == nil || r.Status != store.RoleActive {
		return false, nil
	}
	s := &it.spec
	if r.Name != strings.TrimSpace(s.Name) || r.Description != strings.TrimSpace(s.Description) || r.Risk != s.Risk ||
		r.Requestable != s.Requestable || (r.OwnerIdentityID == nil) != (s.OwnerIdentityID == nil) ||
		(r.OwnerIdentityID != nil && *r.OwnerIdentityID != *s.OwnerIdentityID) {
		return false, nil
	}
	have, err := roles.ParseRule(r.Birthright)
	if err != nil {
		return false, err
	}
	if !sameRule(have, s.Birthright.Normalized()) {
		return false, nil
	}
	ents, err := tx.RoleEntitlements(r.ID)
	if err != nil {
		return false, err
	}
	want := slices.Clone(s.Entitlements)
	slices.Sort(want)
	return slices.Equal(ents, slices.Compact(want)), nil
}

// dry runs one role as a dry run (or says it is unchanged).
func (it *item) dry(tx *store.TenantTx, now time.Time) (RolePlan, *roles.Plan, error) {
	rp := RolePlan{Key: it.spec.Key, Name: strings.TrimSpace(it.spec.Name), Steps: []roles.Step{}}
	same, err := it.unchanged(tx)
	if err != nil {
		return rp, nil, err
	}
	if same {
		rp.Action, rp.RoleID, rp.Version = "unchanged", it.existing.ID, it.existing.Version
		return rp, nil, nil
	}
	var res *roles.Result
	if it.existing == nil {
		rp.Action = "create"
		res, err = roles.Create(tx, it.spec, roles.Actor{}, true, now)
	} else {
		rp.Action, rp.RoleID = "update", it.existing.ID
		res, err = roles.Update(tx, it.existing.ID, it.existing.Version, it.spec, roles.Actor{}, true, now)
	}
	if err != nil {
		return rp, nil, err
	}
	if rp.Action == "create" {
		rp.Version = 1
	} else {
		rp.Version = res.Role.Version
	}
	return rp, res.Plan, nil
}

// compute plans the prepared bundle.
func compute(tx *store.TenantTx, p *prepared, opt Options, now time.Time) (*Plan, error) {
	plan := &Plan{Tenant: opt.Tenant, BundleSHA256: p.digest, Roles: []RolePlan{}}
	var ds []Diag
	for i := range p.items {
		it := &p.items[i]
		rp, rpl, err := it.dry(tx, now)
		var re *roles.Error
		if errors.As(err, &re) {
			ds = append(ds, Diag{Path: it.path, Code: re.Code, Msg: re.Msg})
			continue
		} else if err != nil {
			return nil, err
		}
		if rpl != nil {
			rp.Adds, rp.Removes, rp.Members, rp.Leaves, rp.Missing = rpl.Adds, rpl.Removes, rpl.Members, rpl.Leaves, rpl.Missing
			rp.Steps = rpl.Steps
			if rp.Action == "create" {
				rp.Steps = slices.Clone(rp.Steps)
				for j := range rp.Steps {
					rp.Steps[j].RoleID = "" // a new role's id is made at apply time; the plan must not depend on it
				}
			}
		}
		switch rp.Action {
		case "create":
			plan.Created++
		case "update":
			plan.Updated++
		default:
			plan.Unchanged++
		}
		plan.Steps += len(rp.Steps)
		plan.Adds, plan.Removes, plan.Members, plan.Leaves = plan.Adds+rp.Adds, plan.Removes+rp.Removes, plan.Members+rp.Members, plan.Leaves+rp.Leaves
		plan.Roles = append(plan.Roles, rp)
	}
	if len(ds) > 0 {
		sortDiags(ds)
		return nil, &InvalidError{Diags: ds}
	}
	if limit := opt.maxSteps(); plan.Steps > limit {
		return nil, refuse(413, "plan_too_large", "the bundle makes %d grant steps; one apply makes at most %d. Split it into smaller changes", plan.Steps, limit)
	}
	if plan.Removes > 0 {
		if err := guard(tx, plan.Removes); err != nil {
			return nil, err
		}
	}
	b, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	plan.PlanSHA256 = hex.EncodeToString(sum[:])
	for i := range plan.Roles {
		r := &plan.Roles[i]
		if len(r.Steps) > stepsShown {
			r.StepsOmitted, r.Steps = len(r.Steps)-stepsShown, r.Steps[:stepsShown]
		}
	}
	return plan, nil
}

// guard refuses a plan whose grant removals pass what the deletion guard allows the group_members category in its
// window. Unlike the guard's own hold, an apply is atomic, so it is refused rather than half applied (design
// section 6.2); the author splits the change.
func guard(tx *store.TenantTx, removes int) error {
	pol, err := deleteguard.PolicyOf(tx, deleteguard.CatMembers)
	if err != nil {
		return err
	}
	pop := 0
	if pol.MaxPercent != nil {
		if pop, err = tx.DeletionPopulation(deleteguard.CatMembers); err != nil {
			return err
		}
	}
	if lim := pol.Limit(pop); lim != nil && removes > *lim {
		return refuse(409, "deletion_guard", "the bundle removes %d grants; the deletion guard allows %d membership removals in %d minutes. Split it into smaller changes",
			removes, *lim, pol.WindowMinutes)
	}
	return nil
}

// Validate loads and resolves the bundle without planning it.
func Validate(tx *store.TenantTx, files policybundle.Files, opt Options) error {
	_, err := prepare(tx, files, opt)
	return err
}

// Build plans a bundle against the tenant: the roles it creates, updates or leaves, with each one's member and
// grant steps. It writes nothing; run it in a read transaction.
func Build(tx *store.TenantTx, files policybundle.Files, opt Options, now time.Time) (*Plan, error) {
	p, err := prepare(tx, files, opt)
	if err != nil {
		return nil, err
	}
	return compute(tx, p, opt, now)
}

// ---------------------------------------------------------------- apply

// Ref says which repository change an apply is: the commit, and the bundle digest Tessera checked.
type Ref struct {
	Commit string
}

type policyRef struct {
	Commit       string `json:"commit"`
	Path         string `json:"path"`
	BundleSHA256 string `json:"bundle_sha256"`
}

// Apply re-plans the bundle in the caller's write transaction, refuses it with 409 stale_plan unless the plan's
// digest is wantPlan (what was approved), then creates and updates the roles, recording the repository change as the
// policy_ref of each version, and appends one policy.roles.applied audit event. Any error leaves nothing to
// commit: run it inside DB.InTenant and return the error.
func Apply(tx *store.TenantTx, files policybundle.Files, opt Options, ref Ref, wantPlan string, by roles.Actor, now time.Time) (*Plan, error) {
	ref.Commit = strings.TrimSpace(ref.Commit)
	if ref.Commit == "" || len(ref.Commit) > MaxCommit {
		return nil, refuse(422, "invalid_commit", "a commit of 1 to %d characters is required", MaxCommit)
	}
	p, err := prepare(tx, files, opt)
	if err != nil {
		return nil, err
	}
	plan, err := compute(tx, p, opt, now)
	if err != nil {
		return nil, err
	}
	if plan.PlanSHA256 != wantPlan {
		return nil, refuse(409, "stale_plan", "the plan changed since it was made (now %s); plan the bundle again", plan.PlanSHA256[:12])
	}
	for i := range p.items {
		it := &p.items[i]
		if plan.Roles[i].Action == "unchanged" {
			continue
		}
		b, err := json.Marshal(policyRef{Commit: ref.Commit, Path: it.path, BundleSHA256: p.digest})
		if err != nil {
			return nil, err
		}
		it.spec.PolicyRef = string(b)
		it.spec.Note = "applied from policy repository commit " + ref.Commit
		if it.existing == nil {
			_, err = roles.Create(tx, it.spec, by, false, now)
		} else {
			_, err = roles.Update(tx, it.existing.ID, it.existing.Version, it.spec, by, false, now)
		}
		if err != nil {
			var re *roles.Error
			if errors.As(err, &re) {
				return nil, fmt.Errorf("%s: %w", it.path, err)
			}
			return nil, err
		}
	}
	err = tx.Audit(now, by.Display, "policy.roles.applied", ojson.Object{{Key: "commit", Value: ref.Commit},
		{Key: "bundle_sha256", Value: p.digest}, {Key: "plan_sha256", Value: plan.PlanSHA256},
		{Key: "roles_created", Value: plan.Created}, {Key: "roles_updated", Value: plan.Updated},
		{Key: "roles_unchanged", Value: plan.Unchanged}, {Key: "grants_added", Value: plan.Adds},
		{Key: "grants_removed", Value: plan.Removes}})
	return plan, err
}
