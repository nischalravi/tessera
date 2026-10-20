package policygroups

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Applying a change (design §8.5 step 3): validate every file, compile, and
// bring the native groups in line, in the caller's transaction, as one change.
// A refusal anywhere leaves nothing behind. Every change the sync makes carries
// the cause policy_repo and the commit (the engine's effective-membership events
// through Engine.WithCause, the group and membership events through Env.Cause),
// and each policy group records the commit in policy_ref.

// Applier applies policy changes in a tenant transaction.
type Applier struct {
	Env    model.Env
	Schema Schema
	Attrs  AttrSource // nil: IdentityAttrs
}

// ApplyInput is one change: the files of a commit of the policy repository
// (Origin repo), or the text the policy builder saved (Origin ui, commit empty).
// Full makes the files the whole repository: the repository's policy groups that
// are not among them are retired.
type ApplyInput struct {
	Origin string
	Commit string
	Files  []SourceFile
	Full   bool
}

// Actions of a GroupResult.
const (
	ActionCreated   = "created"
	ActionUpdated   = "updated"
	ActionUnchanged = "unchanged"
	ActionRemoved   = "removed"
)

// GroupResult is what a change did to one policy group.
type GroupResult struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	Path   string `json:"path"`
	Action string `json:"action"`
}

// ApplyResult is what a change did.
type ApplyResult struct {
	Groups       []GroupResult `json:"groups"`
	NodesCreated int           `json:"nodes_created"`
	NodesRetired int           `json:"nodes_retired"`
	AttrAdded    int           `json:"attribute_members_added"`
	AttrRemoved  int           `json:"attribute_members_removed"`
	// Queued says some recompute did not fit the synchronous budget; the groups
	// are pending until the engine's queue drains.
	Queued bool `json:"queued"`
}

// policyRef is the JSON in grp_groups.policy_ref (design §5.3).
type policyRef struct {
	Path           string `json:"path"`
	Commit         string `json:"commit"`
	CompiledSHA256 string `json:"compiled_sha256"`
}

func (r policyRef) json() string {
	b, _ := json.Marshal(r) // strings only
	return string(b)
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// planned is a file with its plan and the group that holds it.
type planned struct {
	file    *File
	plan    *Plan
	group   *store.NativeGroup
	created bool
	factors []*Node // allow, deny (distinct)
	src     string  // the cedar text
}

func managedFor(origin string) store.ManagedBy {
	if origin == store.PolicyOriginRepo {
		return store.ManagedByPolicyRepo
	}
	return store.ManagedByUI
}

// Apply validates and applies a change. It returns a *ValidationError for any
// finding in the files, and the model's errors (a cycle, a name taken) as they
// are.
func (a *Applier) Apply(in ApplyInput) (*ApplyResult, error) {
	if in.Origin != store.PolicyOriginRepo && in.Origin != store.PolicyOriginUI {
		return nil, &ValidationError{Diags: []Diagnostic{{Code: CodeInvalidPolicy, Msg: "origin is repo or ui"}}}
	}
	if in.Origin == store.PolicyOriginRepo && !ValidCommit(in.Commit) {
		return nil, &ValidationError{Diags: []Diagnostic{{Code: CodeInvalidCommit, Msg: "a repository change names its commit (1 to 64 letters, digits, '.', '_' or '-')"}}}
	}
	if in.Origin == store.PolicyOriginUI && (in.Commit != "" || in.Full) {
		return nil, &ValidationError{Diags: []Diagnostic{{Code: CodeInvalidPolicy, Msg: "a change from the UI has no commit and is not a full sync"}}}
	}
	if err := a.Schema.Validate(); err != nil {
		return nil, &ValidationError{Diags: []Diagnostic{{Code: CodeInvalidSchema, Msg: err.Error()}}}
	}
	files, diags := ParseAll(a.Schema, in.Files)
	if len(diags) > 0 {
		return nil, &ValidationError{Diags: diags}
	}
	texts := map[string]string{}
	for _, f := range in.Files {
		texts[f.Path] = f.Cedar
	}

	// the sync's own operation: it may change policy-managed groups and stamps its
	// events with the commit; the policy groups themselves belong to the caller
	env := a.Env
	env.System = true
	if in.Origin == store.PolicyOriginRepo {
		env.Cause, env.CauseRef = store.CausePolicyRepo, in.Commit
		base := env.Engine
		if base == nil {
			base = engine.New(0)
		}
		env.Engine = base.WithCause(store.CausePolicyRepo, in.Commit)
	}
	sys := env
	sys.ByIdentity = nil // the system owns what it creates: no creator privileges
	tx := env.Tx
	res := &ApplyResult{}
	managed := managedFor(in.Origin)

	// the groups the files define
	batch := map[string]bool{}
	for _, f := range files {
		batch[strings.ToLower(f.Group)] = true
	}
	ps := make([]*planned, 0, len(files))
	for _, f := range files {
		p := &planned{file: f, src: texts[f.Path]}
		g, err := tx.GrpGroupByName(f.Group)
		switch {
		case err == nil:
			if g.Definition != store.DefinitionPolicy {
				return nil, &ValidationError{Diags: []Diagnostic{{Path: f.Path, Line: 1, Col: 1, Code: CodeNotPolicyGroup,
					Msg: fmt.Sprintf("group %q exists and is not a policy group", g.Name)}}}
			}
			if g.ManagedBy == store.ManagedByPolicyRepo && in.Origin == store.PolicyOriginUI {
				return nil, &ValidationError{Diags: []Diagnostic{{Path: f.Path, Line: 1, Col: 1, Code: CodePolicyManaged,
					Msg: fmt.Sprintf("group %q is managed by the policy repository: change its policy file", g.Name)}}}
			}
			p.group = g
		case errors.Is(err, store.ErrNotFound):
		default:
			return nil, err
		}
		ps = append(ps, p)
	}

	// the system folders and the two empty groups
	comp := NewCompiler()
	if _, err := sys.EnsureFolderPath(FolderPolicy); err != nil {
		return nil, err
	}
	if _, err := sys.EnsureFolderPath(FolderAttr); err != nil {
		return nil, err
	}
	if err := a.ensureObjectTypes(env); err != nil {
		return nil, err
	}

	// shells of the new policy groups, so that groups of the same change can refer to each other
	empty, empty2 := comp.Empty(), comp.Empty2()
	emptyID, err := a.ensureLeaf(sys, empty, res)
	if err != nil {
		return nil, err
	}
	empty2ID, err := a.ensureLeaf(sys, empty2, res)
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		if p.group == nil {
			parent, ext := naming.Split(p.file.Group)
			folder, err := env.EnsureFolderPath(parent)
			if err != nil {
				return nil, err
			}
			ref := policyRef{Path: p.file.Path, Commit: in.Commit}.json()
			g, err := env.CreateGroup(model.CreateGroupInput{Folder: folder.ID, Extension: ext, Description: p.file.Display,
				DataOwner: p.file.Owner, Definition: store.DefinitionPolicy, PolicyRef: &ref, ManagedBy: managed,
				Factors: []store.GroupID{emptyID, empty2ID}})
			if err != nil {
				return nil, err
			}
			p.group, p.created = g, true
			if err := a.tagPolicy(env, g); err != nil {
				return nil, err
			}
		} else if p.group.Status == store.GroupDeleted {
			g, err := env.RestoreGroup(p.group.ID)
			if err != nil {
				return nil, err
			}
			p.group = g
		}
	}

	// compile, now that every group exists
	resolve := resolver(tx, batch)
	var cdiags []Diagnostic
	for _, p := range ps {
		plan, ds := comp.Compile(p.file, resolve)
		cdiags = append(cdiags, ds...)
		p.plan = plan
	}
	if len(cdiags) > 0 {
		return nil, &ValidationError{Diags: cdiags}
	}
	var need []*Node
	seen := map[string]bool{}
	addNodes := func(ns []*Node) {
		for _, n := range ns {
			if !seen[n.Hash] {
				seen[n.Hash] = true
				need = append(need, n)
			}
		}
	}
	for _, p := range ps {
		p.factors = factorsOf(comp, p.plan)
		addNodes(p.plan.Reach())
		addNodes(p.factors)
	}

	// attribute groups first, filled from the identities, so a composite made
	// next starts from the right members; then the composites, operands first
	groupOf := map[string]store.GroupID{}
	for _, n := range need {
		switch n.Kind {
		case store.NodeAttr, store.NodeHas, store.NodeEmpty:
			id, err := a.ensureLeaf(sys, n, res)
			if err != nil {
				return nil, err
			}
			groupOf[n.Hash] = id
		}
	}
	ix := Indexer{Schema: a.Schema, Source: a.Attrs}
	var attrNodes []*store.GrpPolicyNode
	for _, n := range need {
		if n.Kind == store.NodeAttr || n.Kind == store.NodeHas {
			sn, err := tx.GrpPolicyNode(n.Hash)
			if err != nil {
				return nil, err
			}
			attrNodes = append(attrNodes, sn)
		}
	}
	if len(attrNodes) > 0 {
		rep, err := ix.Reindex(sys, attrNodes)
		if err != nil {
			return nil, err
		}
		res.AttrAdded, res.AttrRemoved, res.Queued = rep.Added, rep.Removed, res.Queued || rep.Queued
	}
	nodeGroup := func(n *Node) (store.GroupID, error) {
		if n.Kind == KindGroup {
			return store.GroupID(n.Group), nil
		}
		if id, ok := groupOf[n.Hash]; ok {
			return id, nil
		}
		return "", fmt.Errorf("policygroups: node %s has no group", n.Hash)
	}
	for _, n := range need {
		switch n.Kind {
		case store.NodeUnion, store.NodeIntersection, store.NodeComplement:
			kids := make([]store.GroupID, len(n.Kids))
			for i, k := range n.Kids {
				if kids[i], err = nodeGroup(k); err != nil {
					return nil, err
				}
			}
			id, err := a.ensureComposite(sys, n, kids, res)
			if err != nil {
				return nil, err
			}
			groupOf[n.Hash] = id
		}
	}

	// the policy groups: which changed, then their definitions
	existing := map[store.GroupID]*store.GrpPolicySource{}
	for _, p := range ps {
		if s, err := tx.GrpPolicySource(p.group.ID); err == nil {
			existing[p.group.ID] = s
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	type change struct {
		p       *planned
		digest  string
		cedarH  string
		factors []store.GroupID
	}
	var changes []change
	for _, p := range ps {
		fs := make([]store.GroupID, len(p.factors))
		for i, n := range p.factors {
			if fs[i], err = nodeGroup(n); err != nil {
				return nil, err
			}
		}
		c := change{p: p, digest: p.plan.Digest(), cedarH: sha(p.src), factors: fs}
		s := existing[p.group.ID]
		unchanged := !p.created && s != nil && s.CompiledSHA256 == c.digest && s.CedarSHA256 == c.cedarH && s.CommitSHA == in.Commit &&
			s.Path == p.file.Path && s.Origin == in.Origin && p.group.ManagedBy == managed && p.group.Status == store.GroupActive &&
			p.group.Description == p.file.Display && deref(p.group.DataOwner) == p.file.Owner
		if unchanged {
			res.Groups = append(res.Groups, GroupResult{Name: p.group.Name, ID: string(p.group.ID), Path: p.file.Path, Action: ActionUnchanged})
			continue
		}
		changes = append(changes, c)
	}
	// free the paths first: two files may swap paths in one change
	for _, c := range changes {
		if existing[c.p.group.ID] != nil {
			if err := tx.DeleteGrpPolicySource(c.p.group.ID); err != nil {
				return nil, err
			}
		}
	}
	for _, c := range changes {
		p := c.p
		ref := policyRef{Path: p.file.Path, Commit: in.Commit, CompiledSHA256: c.digest}
		g, out, err := env.SetPolicy(p.group.ID, model.PolicyInput{Ref: ref.json(), ManagedBy: managed, Factors: c.factors})
		if err != nil {
			return nil, err
		}
		res.Queued = res.Queued || out.Queued
		if g.Description != p.file.Display || deref(g.DataOwner) != p.file.Owner {
			desc, owner := p.file.Display, p.file.Owner
			if g, err = env.UpdateGroup(g.ID, model.UpdateGroupInput{Description: &desc, DataOwner: &owner}); err != nil {
				return nil, err
			}
		}
		if err := tx.SetGrpPolicySource(&store.GrpPolicySource{GroupID: g.ID, Origin: in.Origin, Path: p.file.Path, CommitSHA: in.Commit,
			Cedar: p.src, CedarSHA256: c.cedarH, AllowNode: hashOrEmpty(p.plan.Allow), DenyNode: hashOrEmpty(p.plan.Deny),
			CompiledSHA256: c.digest, AppliedAt: env.Now, AppliedBy: env.By}); err != nil {
			return nil, err
		}
		reach := p.plan.Reach()
		hs := make([]string, 0, len(reach)+2)
		for _, n := range reach {
			hs = append(hs, n.Hash)
		}
		for _, n := range p.factors {
			if n.Kind != KindGroup && !slices.Contains(hs, n.Hash) {
				hs = append(hs, n.Hash)
			}
		}
		if err := tx.ReplaceGrpPolicyUses(g.ID, hs); err != nil {
			return nil, err
		}
		action := ActionUpdated
		if p.created {
			action = ActionCreated
		}
		res.Groups = append(res.Groups, GroupResult{Name: g.Name, ID: string(g.ID), Path: p.file.Path, Action: action})
		res.Queued = res.Queued || g.RecomputeState != "clean"
	}

	// a full sync retires the repository's groups whose files are gone
	if in.Full {
		sources, err := tx.GrpPolicySources(store.PolicyOriginRepo)
		if err != nil {
			return nil, err
		}
		for _, s := range sources {
			if slices.ContainsFunc(ps, func(p *planned) bool { return p.group.ID == s.GroupID }) {
				continue
			}
			g, err := tx.GrpGroup(s.GroupID)
			if err != nil {
				return nil, err
			}
			if err := env.DeleteGroup(g.ID); err != nil {
				return nil, err
			}
			if err := tx.ReplaceGrpPolicyUses(g.ID, nil); err != nil {
				return nil, err
			}
			if err := tx.DeleteGrpPolicySource(g.ID); err != nil {
				return nil, err
			}
			res.Groups = append(res.Groups, GroupResult{Name: g.Name, ID: string(g.ID), Path: s.Path, Action: ActionRemoved})
		}
	}

	// nodes no policy reaches any more are retired
	unused, err := tx.GrpPolicyNodesUnused()
	if err != nil {
		return nil, err
	}
	for _, n := range unused {
		g, err := tx.GrpGroup(n.GroupID)
		if err != nil {
			return nil, err
		}
		if err := sys.DeleteGroup(g.ID); err != nil {
			return nil, err
		}
		if err := tx.DeleteGrpPolicyNode(n.Hash); err != nil {
			return nil, err
		}
		res.NodesRetired++
	}

	slices.SortFunc(res.Groups, func(x, y GroupResult) int { return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name)) })
	names := make([]string, 0, len(res.Groups))
	counts := map[string]int{}
	for _, g := range res.Groups {
		names = append(names, g.Name)
		counts[g.Action]++
	}
	detail := ojson.Object{{Key: "origin", Value: in.Origin}, {Key: "commit", Value: in.Commit}, {Key: "full", Value: in.Full},
		{Key: "groups", Value: names}, {Key: "created", Value: counts[ActionCreated]}, {Key: "updated", Value: counts[ActionUpdated]},
		{Key: "unchanged", Value: counts[ActionUnchanged]}, {Key: "removed", Value: counts[ActionRemoved]},
		{Key: "nodes_created", Value: res.NodesCreated}, {Key: "nodes_retired", Value: res.NodesRetired},
		{Key: "attribute_members_added", Value: res.AttrAdded}, {Key: "attribute_members_removed", Value: res.AttrRemoved},
		{Key: "queued", Value: res.Queued}}
	return res, env.Audit("groups.policy.applied", "tenant", env.Tx.Tenant().String(), detail)
}

func hashOrEmpty(n *Node) string {
	if n.Kind == store.NodeEmpty {
		return ""
	}
	return n.Hash
}

// factorsOf returns the policy group's two factors, allow and deny, which must be
// two different groups: an empty side is one of the two empty groups, and a
// policy whose allow and deny are the same set is the empty set.
func factorsOf(c *Compiler, p *Plan) []*Node {
	allow, deny := p.Allow, p.Deny
	switch {
	case allow.Hash == deny.Hash:
		return []*Node{c.Empty(), c.Empty2()}
	case allow.Kind == store.NodeEmpty:
		return []*Node{c.Empty(), deny}
	case deny.Kind == store.NodeEmpty:
		return []*Node{allow, c.Empty()}
	}
	return []*Node{allow, deny}
}

// ensureObjectTypes makes sure the object types definition exists, so a policy
// group can be badged "policy".
func (a *Applier) ensureObjectTypes(env model.Env) error { return env.EnsureObjectTypes() }

// tagPolicy gives a new policy group the "policy" object type (design §10.9).
func (a *Applier) tagPolicy(env model.Env, g *store.NativeGroup) error {
	return env.SetGroupObjectTypes(g.ID, []string{"policy"})
}

// nodeName is the name of the internal group of a node.
func nodeName(n *Node) (folder, ext string) {
	switch n.Kind {
	case store.NodeAttr:
		d := strings.TrimPrefix(AttrGroupName(n.Attr, n.Value), FolderAttr+naming.Sep)
		parts := strings.SplitN(d, naming.Sep, 2)
		return FolderAttr + naming.Sep + parts[0], parts[1]
	case store.NodeHas:
		return FolderAttr + naming.Sep + n.Attr, HasGroup
	case store.NodeEmpty:
		return FolderPolicy, "_" + n.Hash
	}
	return FolderPolicy, "_n" + n.Hash
}

func describe(n *Node) string {
	switch n.Kind {
	case store.NodeAttr:
		return fmt.Sprintf("Identities whose %s is %q (kept current by the attribute indexer)", n.Attr, n.Value)
	case store.NodeHas:
		return fmt.Sprintf("Identities that have a %s (kept current by the attribute indexer)", n.Attr)
	case store.NodeEmpty:
		return "No members (an empty side of a policy group)"
	}
	return "Compiled policy: " + n.Kind + " (internal)"
}

// ensureLeaf returns the group of an attribute, has or empty node, creating it
// (or bringing a retired one back) and recording the node.
func (a *Applier) ensureLeaf(sys model.Env, n *Node, res *ApplyResult) (store.GroupID, error) {
	return a.ensureNode(sys, n, nil, res)
}

func (a *Applier) ensureComposite(sys model.Env, n *Node, kids []store.GroupID, res *ApplyResult) (store.GroupID, error) {
	return a.ensureNode(sys, n, kids, res)
}

func (a *Applier) ensureNode(sys model.Env, n *Node, kids []store.GroupID, res *ApplyResult) (store.GroupID, error) {
	tx := sys.Tx
	op := map[string]store.CompositeOp{store.NodeUnion: store.CompUnion, store.NodeIntersection: store.CompIntersection,
		store.NodeComplement: store.CompComplement}[n.Kind]
	composite := op != ""
	// a node we already hold
	if row, err := tx.GrpPolicyNode(n.Hash); err == nil {
		g, err := tx.GrpGroup(row.GroupID)
		if err != nil {
			return "", err
		}
		if g.Status == store.GroupDeleted {
			if _, err := sys.RestoreGroup(g.ID); err != nil {
				return "", err
			}
		}
		if composite {
			if err := a.checkFactors(sys, g.ID, op, kids); err != nil {
				return "", err
			}
		}
		return g.ID, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	folderName, ext := nodeName(n)
	folder, err := sys.EnsureFolderPath(folderName)
	if err != nil {
		return "", err
	}
	name := folderName + naming.Sep + ext
	var gid store.GroupID
	g, err := tx.GrpGroupByName(name)
	switch {
	case err == nil:
		// a retired node of the same name: it is the same group, brought back
		if other, oerr := tx.GrpPolicyNodeOfGroup(g.ID); oerr == nil && other.Hash != n.Hash {
			return "", &ValidationError{Diags: []Diagnostic{{Code: CodeHashCollision, Msg: fmt.Sprintf("group %q belongs to another node", name)}}}
		}
		if g.Status == store.GroupDeleted {
			if g, err = sys.RestoreGroup(g.ID); err != nil {
				return "", err
			}
		}
		gid = g.ID
		if composite {
			if err := a.checkFactors(sys, g.ID, op, kids); err != nil {
				return "", err
			}
		}
	case errors.Is(err, store.ErrNotFound):
		in := model.CreateGroupInput{Folder: folder.ID, Extension: ext, Description: describe(n), ManagedBy: store.ManagedByPolicyRepo}
		if composite {
			in.Definition, in.Op, in.Factors = store.DefinitionComposite, op, kids
		}
		if g, err = sys.CreateGroup(in); err != nil {
			return "", err
		}
		gid = g.ID
	default:
		return "", err
	}
	if err := tx.InsertGrpPolicyNode(&store.GrpPolicyNode{Hash: n.Hash, Kind: n.Kind, Attr: n.Attr, Value: n.Value, GroupID: gid,
		CreatedAt: sys.Now}); err != nil {
		return "", err
	}
	res.NodesCreated++
	return gid, nil
}

// checkFactors makes a node's group hold the operands the node says, which only
// a retired and reused group could be missing.
func (a *Applier) checkFactors(sys model.Env, id store.GroupID, op store.CompositeOp, kids []store.GroupID) error {
	have, err := sys.Tx.GrpFactors(id)
	if err != nil {
		return err
	}
	g, err := sys.Tx.GrpGroup(id)
	if err != nil {
		return err
	}
	if slices.Equal(have, kids) && g.CompositeOp != nil && *g.CompositeOp == op {
		return nil
	}
	_, _, err = sys.SetComposite(id, model.CompositeInput{Op: op, Factors: kids})
	return err
}
