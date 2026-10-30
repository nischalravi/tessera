// Package agentscopeascode is AC-7 of the access-as-code plan (issue #653, design docs/design/access-as-code-repo.md
// sections 3.5, 6, 7 and 10): agent scopes, what an AI agent may hold, as files (agents/<key>.yaml, the
// tessera.agentscope/v1 document of internal/agentscope) in a policy repository.
//
// Export writes the tenant's active scopes. Plan loads a bundle (internal/policybundle, which reads each file with
// internal/agentscope's strict parser), resolves every selector against the tenant (the agent or blueprint must be
// one the tenant has discovered, so a selector naming another tenant's agent is refused as unknown) and says which
// scopes it would create, update or retire. Apply re-plans in its own transaction, refuses a plan that is not the
// approved one (409 stale_plan), writes each change as a versioned row of agent_scopes with the repository change
// (commit, path, bundle digest) as its policy_ref, and audits it. internal/policy turns the active scopes into the
// agent-out-of-scope and agent-exceeds-owner invariants, so a scope takes effect when its apply commits.
//
// Both manage modes are supported: partial creates and updates what the bundle lists; full also retires (never
// deletes) the scopes it no longer lists, every scope having been written by an apply. A plan whose writes pass
// MaxSteps is refused with 413 plan_too_large, and one whose retirements pass the deletion guard with 409
// deletion_guard; both outright, with no override (design section 10, decision 4). Agents/ also holds Cedar files in
// the offline CLI; the server applies YAML scopes only and refuses a Cedar file rather than ignore it.
package agentscopeascode

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/agentscope"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/roles"
	"github.com/nischalravi/tessera/mvp/server/internal/rolesascode"
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

func pathOf(key string) string { return policybundle.DirAgents + "/" + key + ".yaml" }

// ---------------------------------------------------------------- export

// Export writes the tenant's active scopes as a bundle: tessera.yaml and agents/<key>.yaml, each file the canonical
// document. Loading the result and planning it against the same state is a plan of no changes.
func Export(tx *store.TenantTx, tenant string) (policybundle.Files, error) {
	cfg, err := yaml.Marshal(policybundle.Config{Schema: policybundle.TagRepo, Tenant: tenant,
		Manage: map[string]string{"agents": "partial"}})
	if err != nil {
		return nil, err
	}
	files := policybundle.Files{policybundle.ConfigFile: cfg}
	rows, err := tx.AgentScopes()
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.Status != store.AgentScopeActive {
			continue
		}
		d, err := agentscope.FromJSON(r.Doc)
		if err != nil {
			return nil, err
		}
		doc, err := d.YAML()
		if err != nil {
			return nil, err
		}
		files[pathOf(r.Key)] = doc
	}
	return files, nil
}

// ---------------------------------------------------------------- plan

// ScopePlan is what the bundle does to one scope.
type ScopePlan struct {
	Key    string `json:"key"`
	Action string `json:"action"` // create, update, retire or unchanged
	// Agent says whom the scope applies to: "<source>:<external id>" or "blueprint:<app id>".
	Agent        string   `json:"agent"`
	Actions      []string `json:"actions"`
	Resources    int      `json:"resource_classes"`
	OwnerCeiling bool     `json:"owner_ceiling"`
}

// Plan is what applying a bundle would do.
type Plan struct {
	Tenant       string      `json:"tenant"`
	BundleSHA256 string      `json:"bundle_sha256"`
	Mode         string      `json:"mode"` // partial or full
	Scopes       []ScopePlan `json:"scopes"`
	Created      int         `json:"created"`
	Updated      int         `json:"updated"`
	Retired      int         `json:"retired"`
	Unchanged    int         `json:"unchanged"`
	// Steps are the writes: one per scope created, updated or retired.
	Steps int `json:"steps"`
	// Removes are the scopes retired: what the deletion guard counts.
	Removes  int      `json:"removals"`
	Warnings []string `json:"warnings"`
	// PlanSHA256 is the digest of the plan; the approver approves it and the apply refuses any other.
	PlanSHA256 string `json:"plan_sha256"`
}

type item struct {
	path     string
	key      string
	doc      *agentscope.Doc   // nil: retire the scope (full mode)
	existing *store.AgentScope // nil: a new scope
	json     string            // canonical JSON of doc
}

type prepared struct {
	digest string
	mode   string
	items  []item
}

func selector(d *agentscope.Doc) string {
	if d.ByBlueprint() {
		return "blueprint:" + d.Agent.Blueprint
	}
	return d.Agent.Source + ":" + d.Agent.ExternalID
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
	out := &prepared{digest: Digest(files), mode: b.Config.Manage["agents"]}
	if out.mode != "partial" && out.mode != "full" {
		add(policybundle.ConfigFile, "not_managed", "manage.agents must be partial or full for a repository that holds agent scopes")
	}
	for _, f := range b.Agents {
		add(f.Path, "cedar_scope_unsupported", "agent scopes are applied from .yaml files (tessera.agentscope/v1); a Cedar file in agents/ is checked offline only")
	}

	profiles, err := tx.AgentProfiles()
	if err != nil {
		return nil, err
	}
	links, err := tx.AgentLinks()
	if err != nil {
		return nil, err
	}
	blueprints, err := tx.AgentBlueprints()
	if err != nil {
		return nil, err
	}
	agents, apps := map[string]bool{}, map[string]bool{}
	for _, p := range profiles {
		agents[p.Source+"\x00"+p.ExternalID] = true
	}
	for _, l := range links {
		if l.BlueprintAppID != "" {
			apps[l.BlueprintAppID] = true
		}
	}
	for _, bp := range blueprints {
		if bp.AppID != "" {
			apps[bp.AppID] = true
		}
	}
	rows, err := tx.AgentScopes()
	if err != nil {
		return nil, err
	}
	byKey := map[string]*store.AgentScope{}
	for _, r := range rows {
		byKey[r.Key] = r
	}

	list := append([]policybundle.AgentScopeFile(nil), b.AgentScopes...)
	sort.Slice(list, func(i, j int) bool { return list[i].Doc.Key < list[j].Doc.Key })
	seen := map[string]bool{}
	for _, f := range list {
		d := f.Doc
		if want := pathOf(d.Key); f.Path != want && f.Path != strings.TrimSuffix(want, ".yaml")+".yml" {
			add(f.Path, "path_key_mismatch", "the file for agent scope %q is %s", d.Key, want)
		}
		switch {
		case d.ByBlueprint() && !apps[d.Agent.Blueprint]:
			add(f.Path, "unknown_blueprint", "no agent blueprint %q is known to this tenant", d.Agent.Blueprint)
		case !d.ByBlueprint() && !agents[d.Agent.Source+"\x00"+d.Agent.ExternalID]:
			add(f.Path, "unknown_agent", "no agent %s is known to this tenant", selector(d))
		}
		js, err := d.JSON()
		if err != nil {
			return nil, err
		}
		it := item{path: f.Path, key: d.Key, doc: d, json: js}
		seen[d.Key] = true
		if e := byKey[d.Key]; e != nil {
			if e.Status != store.AgentScopeActive {
				add(f.Path, "scope_retired", "agent scope %q is retired; use another key", d.Key)
			}
			it.existing = e
		}
		out.items = append(out.items, it)
	}
	if out.mode == "full" {
		for _, r := range rows {
			if r.Status == store.AgentScopeActive && !seen[r.Key] {
				out.items = append(out.items, item{key: r.Key, existing: r})
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

// compute plans the prepared bundle.
func compute(tx *store.TenantTx, p *prepared, opt Options) (*Plan, error) {
	plan := &Plan{Tenant: opt.Tenant, BundleSHA256: p.digest, Mode: p.mode, Scopes: []ScopePlan{}, Warnings: []string{}}
	for i := range p.items {
		it := &p.items[i]
		sp := ScopePlan{Key: it.key, Actions: []string{}}
		cur := it.existing
		switch {
		case it.doc == nil: // full mode: not in the repository any more
			d, err := agentscope.FromJSON(cur.Doc)
			if err != nil {
				return nil, err
			}
			sp.Action, sp.Agent, sp.Actions, sp.Resources, sp.OwnerCeiling = "retire", selector(d), d.Allow.Actions, len(d.Allow.Resources), d.Ceiling()
			plan.Retired++
			plan.Removes++
		default:
			d := it.doc
			sp.Agent, sp.Actions, sp.Resources, sp.OwnerCeiling = selector(d), d.Allow.Actions, len(d.Allow.Resources), d.Ceiling()
			switch {
			case cur == nil:
				sp.Action = "create"
				plan.Created++
			case cur.Doc != it.json:
				sp.Action = "update"
				plan.Updated++
			default:
				sp.Action = "unchanged"
				plan.Unchanged++
			}
			if !d.Ceiling() {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("agent scope %s does not hold the agent to its owner (owner_ceiling: false)", it.key))
			}
		}
		plan.Scopes = append(plan.Scopes, sp)
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

type snapshot struct {
	Key    string `json:"key"`
	Status string `json:"status"`
	Doc    string `json:"doc"` // the canonical document JSON
}

// Apply re-plans the bundle in the caller's write transaction, refuses it with 409 stale_plan unless the plan's
// digest is wantPlan (what was approved), then writes each scope the plan creates, updates or retires as a new
// version with the repository change as its policy_ref, audits each, and appends one policy.agent_scopes.applied
// audit event. Any error leaves nothing to commit: run it inside DB.InTenant and return the error.
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
		action := plan.Scopes[i].Action
		if action == "unchanged" {
			continue
		}
		var row store.AgentScope
		var pref *string
		switch action {
		case "retire":
			row = *it.existing
			row.Status, row.Version, row.UpdatedAt = store.AgentScopeRetired, it.existing.Version+1, now
			if err := tx.SaveAgentScope(&row, it.existing.Version); err != nil {
				return nil, fmt.Errorf("%s: %w", pathOf(it.key), err)
			}
		default:
			sum := sha256.Sum256([]byte(it.json))
			row = store.AgentScope{Key: it.key, Status: store.AgentScopeActive, Name: it.doc.Name, Doc: it.json,
				DocSHA256: hex.EncodeToString(sum[:]), Version: 1, CreatedAt: now, UpdatedAt: now}
			if it.existing == nil {
				err = tx.InsertAgentScope(&row)
			} else {
				row.ID, row.Version, row.CreatedAt = it.existing.ID, it.existing.Version+1, it.existing.CreatedAt
				err = tx.SaveAgentScope(&row, it.existing.Version)
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", it.path, err)
			}
			raw, err := json.Marshal(policyRef{Commit: ref.Commit, Path: it.path, BundleSHA256: p.digest})
			if err != nil {
				return nil, err
			}
			s := string(raw)
			pref = &s
		}
		snap, err := json.Marshal(snapshot{Key: row.Key, Status: row.Status, Doc: row.Doc})
		if err != nil {
			return nil, err
		}
		if err := tx.AddAgentScopeVersion(&store.AgentScopeVersion{ScopeID: row.ID, Version: row.Version, Snapshot: string(snap),
			Actor: by.Display, ChangedAt: now, PolicyRef: pref}); err != nil {
			return nil, err
		}
		if err := tx.Audit(now, by.Display, "policy.agent_scope."+action, ojson.Object{{Key: "key", Value: row.Key},
			{Key: "version", Value: row.Version}, {Key: "commit", Value: ref.Commit}}); err != nil {
			return nil, err
		}
	}
	err = tx.Audit(now, by.Display, "policy.agent_scopes.applied", ojson.Object{{Key: "commit", Value: ref.Commit},
		{Key: "bundle_sha256", Value: p.digest}, {Key: "plan_sha256", Value: plan.PlanSHA256},
		{Key: "created", Value: plan.Created}, {Key: "updated", Value: plan.Updated},
		{Key: "retired", Value: plan.Retired}, {Key: "unchanged", Value: plan.Unchanged}})
	return plan, err
}
