package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
)

// Chunk sizes: a simulation takes at most 100 changes and a batch at most 1,000
// operations (internal/groups/model).
const (
	simChunk   = 100
	batchChunk = 1000
)

// ImpactGroup is a group whose effective members would change.
type ImpactGroup struct {
	ID       string
	Name     string
	Targeted bool // a group the plan changes directly, rather than one that contains it
	Before   int
	After    int
	Added    int
	Removed  int
}

// Impact is what the plan's membership changes would do to effective membership.
type Impact struct {
	Groups  []ImpactGroup
	Added   int // identities that would gain a membership
	Removed int
	// Simulated and Skipped count the plan's membership changes that were and
	// were not simulated (a change on a group the plan creates cannot be: the
	// group does not exist yet).
	Simulated, Skipped int
	// Chunks is the number of simulations made; with more than one, the totals add
	// the chunks (each starts from the live state), so an identity added by two
	// chunks counts twice.
	Chunks    int
	Truncated bool
}

type simChange struct {
	Kind        string `json:"kind"`
	Group       string `json:"group"`
	Identity    *int64 `json:"identity,omitempty"`
	MemberGroup string `json:"member_group,omitempty"`
	Member      string `json:"member,omitempty"`
}

// memberKey is how the API names a member in a remove: an identity id or a group id.
func (l *Live) removeKey(m MemberRef) (string, bool) {
	if m.Group == "" {
		return strconv.FormatInt(m.Identity, 10), true
	}
	if g := l.FindGroup(m.Group); g != nil {
		return g.ID, true
	}
	return "", false
}

// Simulate asks the server what the plan's membership changes would do
// (POST /api/groups:simulate, which runs the real operations and the real engine
// and rolls everything back). The server checks the same privileges as the
// changes themselves.
func Simulate(ctx context.Context, c Client, p *Plan, live *Live) (*Impact, error) {
	var changes []simChange
	imp := &Impact{}
	for _, a := range p.Actions {
		if a.Kind != MemberAdd && a.Kind != MemberRemove {
			continue
		}
		g := live.FindGroup(a.Name)
		if g == nil {
			imp.Skipped++
			continue
		}
		ch := simChange{Group: g.ID}
		if a.Kind == MemberAdd {
			ch.Kind = "add_member"
			switch {
			case a.member.Group == "":
				id := a.member.Identity
				ch.Identity = &id
			case live.FindGroup(a.member.Group) != nil:
				ch.MemberGroup = live.FindGroup(a.member.Group).ID
			default:
				imp.Skipped++
				continue
			}
		} else {
			key, ok := live.removeKey(a.member)
			if !ok {
				imp.Skipped++
				continue
			}
			ch.Kind, ch.Member = "remove_member", key
		}
		changes = append(changes, ch)
	}
	imp.Simulated = len(changes)
	byID := map[string]*ImpactGroup{}
	for start := 0; start < len(changes); start += simChunk {
		end := min(start+simChunk, len(changes))
		var out struct {
			Groups []struct {
				GroupID  string `json:"group_id"`
				Name     string `json:"name"`
				Targeted bool   `json:"targeted"`
				Before   int    `json:"before"`
				After    int    `json:"after"`
				Added    int    `json:"added"`
				Removed  int    `json:"removed"`
			} `json:"groups"`
			Added     int  `json:"added"`
			Removed   int  `json:"removed"`
			Truncated bool `json:"truncated"`
		}
		if _, err := call(ctx, c, http.MethodPost, "/api/groups:simulate", map[string]any{"changes": changes[start:end]}, &out, nil); err != nil {
			return nil, fmt.Errorf("simulating the membership changes: %w", err)
		}
		imp.Chunks++
		imp.Added += out.Added
		imp.Removed += out.Removed
		imp.Truncated = imp.Truncated || out.Truncated
		for _, g := range out.Groups {
			ig := byID[g.GroupID]
			if ig == nil {
				ig = &ImpactGroup{ID: g.GroupID, Name: g.Name, Before: g.Before}
				byID[g.GroupID] = ig
			}
			ig.Targeted = ig.Targeted || g.Targeted
			ig.Added += g.Added
			ig.Removed += g.Removed
			ig.After = ig.Before + ig.Added - ig.Removed
		}
	}
	for _, g := range byID {
		imp.Groups = append(imp.Groups, *g)
	}
	sort.Slice(imp.Groups, func(i, j int) bool { return naming.Fold(imp.Groups[i].Name) < naming.Fold(imp.Groups[j].Name) })
	return imp, nil
}

// Result is what an apply did.
type Result struct {
	Folders, Groups, Grants, Added, Removed int
	// Ops are the engine operations of recomputes that were queued (large
	// changes are applied in the background: 202 and an op id).
	Ops []int64
}

// Options of an apply.
type Options struct {
	// Progress, if set, is called before each step.
	Progress func(a Action)
	// RunID is mixed into the idempotency keys. The same plan and the same live
	// difference with the same RunID replay the first answer (for 24 hours)
	// instead of repeating a batch.
	RunID string
	// Reason is kept with the memberships the plan adds; empty means "tessera-cli
	// groups apply" and the plan's digest.
	Reason string
}

// Apply executes the plan against the server: folders, groups and privileges
// one request each, then each group's membership changes as batches (atomic, up
// to 1,000 operations, with an Idempotency-Key derived from the batch itself so
// that sending it again, after a lost answer, writes nothing twice). live is
// updated with what is created. It stops at the first refusal and says which
// action failed; running the plan again continues, because it only does what
// is still missing.
func Apply(ctx context.Context, c Client, p *Plan, live *Live, o Options) (*Result, error) {
	res := &Result{}
	progress := func(a Action) {
		if o.Progress != nil {
			o.Progress(a)
		}
	}
	for i := 0; i < len(p.Actions); i++ {
		a := p.Actions[i]
		switch a.Kind {
		case FolderCreate:
			progress(a)
			if err := createFolder(ctx, c, live, a); err != nil {
				return res, fmt.Errorf("%s %s: %w", a.Kind, a.Name, err)
			}
			res.Folders++
		case GroupCreate:
			progress(a)
			if err := createGroup(ctx, c, live, a); err != nil {
				return res, fmt.Errorf("%s %s: %w", a.Kind, a.Name, err)
			}
			res.Groups++
		case PrivGrant:
			progress(a)
			if err := grant(ctx, c, live, a); err != nil {
				return res, fmt.Errorf("%s %s: %w", a.Kind, a.Name, err)
			}
			res.Grants++
		case MemberAdd, MemberRemove:
			// the member actions of one group are consecutive
			j := i
			for j < len(p.Actions) && (p.Actions[j].Kind == MemberAdd || p.Actions[j].Kind == MemberRemove) && p.Actions[j].Name == a.Name {
				j++
			}
			for _, x := range p.Actions[i:j] {
				progress(x)
			}
			reason := o.Reason
			if reason == "" {
				reason = "tessera-cli groups apply " + p.Digest()
			}
			if len(reason) > 255 {
				reason = reason[:255]
			}
			if err := batch(ctx, c, live, a.Name, p.Actions[i:j], reason, o.RunID, res); err != nil {
				return res, fmt.Errorf("members of %s: %w", a.Name, err)
			}
			i = j - 1
		}
	}
	return res, nil
}

func folderParentID(live *Live, name string) (string, error) {
	parent, _ := naming.Split(name)
	if parent == "" {
		return "", nil // the root: the server finds it (or creates the first folder)
	}
	f := live.FindFolder(parent)
	if f == nil {
		return "", fmt.Errorf("folder %q was not found", parent)
	}
	return f.ID, nil
}

func createFolder(ctx context.Context, c Client, live *Live, a Action) error {
	parent, err := folderParentID(live, a.Name)
	if err != nil {
		return err
	}
	_, ext := naming.Split(a.Name)
	var out folderRow
	body := map[string]any{"parent": parent, "extension": ext, "display_extension": a.folder.DisplayName,
		"description": a.folder.Description, "data_owner": a.folder.DataOwner}
	if _, err := call(ctx, c, http.MethodPost, "/api/groups/folders", body, &out, nil); err != nil {
		return err
	}
	live.AddFolder(LiveFolder{ID: out.ID, Name: a.Name, DisplayName: a.folder.DisplayName, Description: a.folder.Description})
	return nil
}

func createGroup(ctx context.Context, c Client, live *Live, a Action) error {
	parent, ext := naming.Split(a.Name)
	f := live.FindFolder(parent)
	if f == nil {
		return fmt.Errorf("folder %q was not found", parent)
	}
	g := a.group
	body := map[string]any{"folder": f.ID, "extension": ext, "display_extension": g.DisplayName, "description": g.Description,
		"type": g.Type, "data_owner": g.DataOwner, "member_description": g.MemberDescription}
	if g.Type == "" {
		body["type"] = "group"
	}
	if g.Composite != nil {
		ids := make([]string, len(g.Composite.Factors))
		for i, name := range g.Composite.Factors {
			fg := live.FindGroup(name)
			if fg == nil {
				return fmt.Errorf("factor %q was not found", name)
			}
			ids[i] = fg.ID
		}
		body["definition"], body["composite_op"], body["factors"] = "composite", g.Composite.Op, ids
	}
	var out groupRow
	if _, err := call(ctx, c, http.MethodPost, "/api/groups", body, &out, nil); err != nil {
		return err
	}
	live.AddGroup(LiveGroup{ID: out.ID, Name: a.Name, Type: out.Type, Definition: out.Definition})
	return nil
}

func grant(ctx context.Context, c Client, live *Live, a Action) error {
	id := live.objectID(a.object)
	if id == "" {
		return fmt.Errorf("%s was not found", a.object)
	}
	path := "/api/groups/" + url.PathEscape(id) + "/privileges"
	if a.object.Type == "folder" {
		path = "/api/groups/folders/" + url.PathEscape(id) + "/privileges"
	}
	body := map[string]any{"privilege": a.priv, "holder_type": a.holder.Type, "applies_to": a.row.AppliesTo, "scope": a.row.Scope}
	switch a.holder.Type {
	case "identity":
		body["identity"] = a.holder.Identity
	case "group":
		g := live.FindGroup(a.holder.Group)
		if g == nil {
			return fmt.Errorf("holder group %q was not found", a.holder.Group)
		}
		body["group"] = g.ID
	}
	_, err := call(ctx, c, http.MethodPost, path, body, nil, nil)
	return err
}

type batchAdd struct {
	Identity *int64 `json:"identity,omitempty"`
	Group    string `json:"group,omitempty"`
}

func batch(ctx context.Context, c Client, live *Live, name string, actions []Action, reason, runID string, res *Result) error {
	g := live.FindGroup(name)
	if g == nil {
		return fmt.Errorf("group %q was not found", name)
	}
	var adds []batchAdd
	var removes []string
	for _, a := range actions {
		if a.Kind == MemberAdd {
			switch {
			case a.member.Group == "":
				id := a.member.Identity
				adds = append(adds, batchAdd{Identity: &id})
			default:
				mg := live.FindGroup(a.member.Group)
				if mg == nil {
					return fmt.Errorf("member group %q was not found", a.member.Group)
				}
				adds = append(adds, batchAdd{Group: mg.ID})
			}
			continue
		}
		key, ok := live.removeKey(a.member)
		if !ok {
			return fmt.Errorf("member group %q was not found", a.member.Group)
		}
		removes = append(removes, key)
	}
	// chunks of at most batchChunk operations: adds first, then removes
	type chunk struct {
		Add    []batchAdd
		Remove []string
	}
	var chunks []chunk
	for len(adds) > 0 || len(removes) > 0 {
		var ch chunk
		room := batchChunk
		n := min(room, len(adds))
		ch.Add, adds, room = adds[:n], adds[n:], room-n
		n = min(room, len(removes))
		ch.Remove, removes = removes[:n], removes[n:]
		chunks = append(chunks, ch)
	}
	for i, ch := range chunks {
		body := map[string]any{"atomic": true, "reason": reason}
		if len(ch.Add) > 0 {
			body["add"] = ch.Add
		}
		if len(ch.Remove) > 0 {
			body["remove"] = ch.Remove
		}
		h := http.Header{}
		h.Set("Idempotency-Key", idempotencyKey(g.ID, ch.Add, ch.Remove, runID))
		var out struct {
			Created int     `json:"created"`
			Updated int     `json:"updated"`
			Removed int     `json:"removed"`
			Ops     []int64 `json:"ops"`
		}
		if _, err := call(ctx, c, http.MethodPost, "/api/groups/"+url.PathEscape(g.ID)+"/members:batch", body, &out, h); err != nil {
			var ae *APIError
			if errors.As(err, &ae) && ae.Index >= 0 {
				return fmt.Errorf("batch %d of %d, operation %d refused: %w", i+1, len(chunks), ae.Index, err)
			}
			return err
		}
		res.Added += out.Created + out.Updated
		res.Removed += out.Removed
		res.Ops = append(res.Ops, out.Ops...)
	}
	return nil
}

// idempotencyKey is derived from the group and the operations of the batch (and
// the run id), so the same batch sent twice has the same key and a different
// batch never shares one. It uses only the characters the API allows.
func idempotencyKey(group string, adds []batchAdd, removes []string, runID string) string {
	ops := make([]string, 0, len(adds)+len(removes))
	for _, a := range adds {
		if a.Identity != nil {
			ops = append(ops, "+identity:"+strconv.FormatInt(*a.Identity, 10))
		} else {
			ops = append(ops, "+group:"+a.Group)
		}
	}
	for _, r := range removes {
		ops = append(ops, "-"+r)
	}
	slices.Sort(ops)
	h := sha256.New()
	_, _ = h.Write([]byte(group + "\x00" + runID + "\x00" + strings.Join(ops, "\x00")))
	return "plan-" + hex.EncodeToString(h.Sum(nil))[:40]
}
