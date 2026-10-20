package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
)

// Action kinds.
const (
	FolderCreate = "folder.create"
	GroupCreate  = "group.create"
	MemberAdd    = "member.add"
	MemberRemove = "member.remove"
	PrivGrant    = "privilege.grant"
)

// Action is one change a plan makes, in the order it is applied.
type Action struct {
	Kind   string
	Name   string // the folder, group or object the change is on
	Detail string // a one-line description for the diff

	folder FolderSpec
	group  GroupSpec
	member MemberRef
	object ObjectRef
	priv   string
	holder Holder
	row    privRow
}

// Plan is the difference between a spec and the live state.
type Plan struct {
	Actions []Action
	// Unchanged counts the items the live state already has.
	Unchanged int
}

// Empty says there is nothing to do.
func (p *Plan) Empty() bool { return len(p.Actions) == 0 }

// Counts returns the number of actions of each kind.
func (p *Plan) Counts() map[string]int {
	m := map[string]int{}
	for _, a := range p.Actions {
		m[a.Kind]++
	}
	return m
}

// Digest identifies the plan's actions (not the live state), for logs.
func (p *Plan) Digest() string {
	h := sha256.New()
	for _, a := range p.Actions {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\n", a.Kind, a.Name, a.Detail)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Compute diffs an expanded and validated spec against the live state. It
// refuses a plan that names a parent folder, factor, member group, holder or
// object that neither exists nor is created by the plan.
func Compute(spec *Spec, live *Live) (*Plan, error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	plan := &Plan{}

	// what exists after the plan: live plus what it creates
	willFolder := map[string]bool{"": true}
	willGroup := map[string]bool{}
	for k := range live.Folders {
		willFolder[k] = true
	}
	for k := range live.Groups {
		willGroup[k] = true
	}
	var newFolders []FolderSpec
	for _, f := range spec.Folders {
		if live.FindFolder(f.Name) != nil {
			plan.Unchanged++
			continue
		}
		newFolders = append(newFolders, f)
		willFolder[naming.Fold(f.Name)] = true
	}
	sort.SliceStable(newFolders, func(i, j int) bool { return depth(newFolders[i].Name) < depth(newFolders[j].Name) })
	var newGroups []GroupSpec
	for _, g := range spec.Groups {
		if live.FindGroup(g.Name) != nil {
			plan.Unchanged++
			continue
		}
		newGroups = append(newGroups, g)
		willGroup[naming.Fold(g.Name)] = true
	}
	for _, f := range newFolders {
		parent, _ := naming.Split(f.Name)
		if !willFolder[naming.Fold(parent)] {
			fail("folder %s: its parent folder %q does not exist and the plan does not create it", f.Name, parent)
		}
		plan.Actions = append(plan.Actions, Action{Kind: FolderCreate, Name: f.Name, Detail: describeFolder(f), folder: f})
	}
	for _, g := range newGroups {
		parent, _ := naming.Split(g.Name)
		if !willFolder[naming.Fold(parent)] {
			fail("group %s: its folder %q does not exist and the plan does not create it", g.Name, parent)
		}
		if g.Composite != nil {
			for _, f := range g.Composite.Factors {
				if !willGroup[naming.Fold(f)] {
					fail("group %s: factor %s does not exist and the plan does not create it", g.Name, f)
				}
			}
		}
	}
	ordered, err := orderGroups(newGroups)
	if err != nil {
		fail("%v", err)
	}
	for _, g := range ordered {
		plan.Actions = append(plan.Actions, Action{Kind: GroupCreate, Name: g.Name, Detail: describeGroup(g), group: g})
	}

	// privileges
	for _, p := range spec.Privileges {
		o, _ := ParseObject(p.Object)
		known := willGroup[naming.Fold(o.Name)]
		if o.Type == "folder" {
			known = willFolder[naming.Fold(o.Name)]
		}
		if !known {
			fail("privilege on %s: it does not exist and the plan does not create it", o)
			continue
		}
		id := live.objectID(o)
		names := make([]string, 0, len(p.Grant.Privileges))
		for n := range p.Grant.Privileges {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, name := range names {
			for _, hs := range p.Grant.Privileges[name] {
				h, _ := ParseHolder(hs)
				if h.Type == "group" && !willGroup[naming.Fold(h.Group)] {
					fail("privilege on %s: holder group %s does not exist and the plan does not create it", o, h.Group)
					continue
				}
				for _, row := range rowsFor(o.Type, name, p.Grant.Scope) {
					if id != "" && live.hasPriv(id, name, h, row) {
						plan.Unchanged++
						continue
					}
					if slices.ContainsFunc(plan.Actions, func(a Action) bool {
						return a.Kind == PrivGrant && a.object == o && a.priv == name && a.holder.Key() == h.Key() && a.row == row
					}) {
						continue
					}
					plan.Actions = append(plan.Actions, Action{Kind: PrivGrant, Name: o.String(),
						Detail: describeGrant(name, h, row), object: o, priv: name, holder: h, row: row})
				}
			}
		}
	}

	// members
	for _, g := range spec.Groups {
		if len(g.Members.Add) == 0 && len(g.Members.Remove) == 0 {
			continue
		}
		lg := live.FindGroup(g.Name)
		have := map[string]bool{}
		if lg != nil {
			have = live.Members[lg.ID]
		}
		adds := map[string]bool{}
		for _, s := range g.Members.Add {
			m, _ := ParseMember(s)
			if m.Group != "" && !willGroup[naming.Fold(m.Group)] {
				fail("group %s: member group %s does not exist and the plan does not create it", g.Name, m.Group)
				continue
			}
			if m.Group != "" && naming.Equal(m.Group, g.Name) {
				fail("group %s: a group cannot be its own member", g.Name)
				continue
			}
			if adds[m.Key()] {
				continue
			}
			adds[m.Key()] = true
			if have[m.Key()] {
				plan.Unchanged++
				continue
			}
			plan.Actions = append(plan.Actions, Action{Kind: MemberAdd, Name: g.Name, Detail: m.String(), member: m})
		}
		removes := map[string]bool{}
		for _, s := range g.Members.Remove {
			m, _ := ParseMember(s)
			if adds[m.Key()] {
				fail("group %s: %s is both added and removed", g.Name, m)
				continue
			}
			if removes[m.Key()] {
				continue
			}
			removes[m.Key()] = true
			if !have[m.Key()] {
				plan.Unchanged++
				continue
			}
			plan.Actions = append(plan.Actions, Action{Kind: MemberRemove, Name: g.Name, Detail: m.String(), member: m})
		}
	}
	if len(errs) > 20 {
		errs = append(errs[:20], fmt.Errorf("and %d more", len(errs)-20))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return plan, nil
}

func depth(name string) int { return strings.Count(name, naming.Sep) }

// orderGroups puts composites after their factors (those among the new groups).
func orderGroups(gs []GroupSpec) ([]GroupSpec, error) {
	pending := map[string]bool{}
	for _, g := range gs {
		pending[naming.Fold(g.Name)] = true
	}
	out := make([]GroupSpec, 0, len(gs))
	left := slices.Clone(gs)
	for len(left) > 0 {
		var next []GroupSpec
		progressed := false
		for _, g := range left {
			ready := true
			if g.Composite != nil {
				for _, f := range g.Composite.Factors {
					if pending[naming.Fold(f)] && !naming.Equal(f, g.Name) {
						ready = false
					} else if naming.Equal(f, g.Name) {
						return nil, fmt.Errorf("group %s: a composite cannot be its own factor", g.Name)
					}
				}
			}
			if !ready {
				next = append(next, g)
				continue
			}
			out = append(out, g)
			delete(pending, naming.Fold(g.Name))
			progressed = true
		}
		if !progressed {
			return nil, fmt.Errorf("the composites %s depend on each other", names(next))
		}
		left = next
	}
	return out, nil
}

func names(gs []GroupSpec) string {
	n := make([]string, len(gs))
	for i, g := range gs {
		n[i] = g.Name
	}
	return strings.Join(n, ", ")
}

func (l *Live) hasPriv(objectID, priv string, h Holder, row privRow) bool {
	for _, r := range l.Privs[objectID] {
		if r.Privilege != priv || r.HolderType != h.Type || r.AppliesTo != row.AppliesTo || r.Scope != row.Scope {
			continue
		}
		switch h.Type {
		case "everyone":
			return true
		case "identity":
			if r.HolderID == fmt.Sprint(h.Identity) {
				return true
			}
		case "group":
			if g := l.FindGroup(h.Group); g != nil && g.ID == r.HolderID {
				return true
			}
		}
	}
	return false
}

func describeFolder(f FolderSpec) string {
	if f.DisplayName != "" {
		return fmt.Sprintf("display name %q", f.DisplayName)
	}
	return ""
}

func describeGroup(g GroupSpec) string {
	switch {
	case g.Composite != nil:
		return fmt.Sprintf("composite %s of %s", g.Composite.Op, strings.Join(g.Composite.Factors, ", "))
	case g.Type == "role":
		return "role"
	}
	return ""
}

func describeGrant(priv string, h Holder, row privRow) string {
	s := fmt.Sprintf("%s to %s", priv, h)
	if row.AppliesTo != "self" {
		s += fmt.Sprintf(" (inherited by %s, scope %s)", row.AppliesTo, row.Scope)
	}
	return s
}
