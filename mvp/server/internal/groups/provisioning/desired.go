package provisioning

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Marks and desired state (design §9.2 "Desired state").

// Resolver decides which groups a provisioner provisions. A mark on a group
// covers it (include=0 opts it out); a mark on a folder covers the folder's own
// groups (scope one) or every group below it (scope sub). The nearest mark
// wins, so a sub mark can be cut out by an include=0 mark on a deeper folder or
// on the group. Marks are applied at evaluation time and never copied onto the
// groups below (dynamic inheritance).
type Resolver struct {
	groupMarks  map[string]*store.ProvMark
	folderMarks map[string]*store.ProvMark
	folders     map[string]*store.Folder
}

// NewResolver loads a provisioner's marks and the folder tree.
func NewResolver(tx *store.TenantTx, provisioner string) (*Resolver, error) {
	marks, err := tx.ProvMarks(provisioner)
	if err != nil {
		return nil, err
	}
	r := &Resolver{groupMarks: map[string]*store.ProvMark{}, folderMarks: map[string]*store.ProvMark{}, folders: map[string]*store.Folder{}}
	for _, m := range marks {
		if m.ObjectType == "group" {
			r.groupMarks[m.ObjectID] = m
		} else {
			r.folderMarks[m.ObjectID] = m
		}
	}
	for off := 0; ; off += 500 {
		page, err := tx.GrpFolders(store.GrpFolderFilter{Limit: 500, Offset: off})
		if err != nil {
			return nil, err
		}
		for _, f := range page {
			r.folders[string(f.ID)] = f
		}
		if len(page) < 500 {
			break
		}
	}
	return r, nil
}

// Coverage says whether a group is provisioned and why.
type Coverage struct {
	Include bool
	// Why names the deciding mark: "group mark", "folder mark on A:B (sub)" or "no mark".
	Why  string
	Meta map[string]string
}

// Resolve decides one group.
func (r *Resolver) Resolve(g *store.NativeGroup) Coverage {
	if m, ok := r.groupMarks[string(g.ID)]; ok {
		return Coverage{Include: m.Include, Why: "group mark", Meta: metaOf(m)}
	}
	f := r.folders[string(g.FolderID)]
	for depth := 0; f != nil; depth++ {
		if m, ok := r.folderMarks[string(f.ID)]; ok && (m.Scope == "sub" || (m.Scope == "one" && depth == 0)) {
			return Coverage{Include: m.Include, Why: fmt.Sprintf("folder mark on %s (%s)", f.Name, m.Scope), Meta: metaOf(m)}
		}
		if f.ParentID == nil {
			break
		}
		f = r.folders[string(*f.ParentID)]
	}
	return Coverage{Why: "no mark"}
}

// FolderName returns the name of a folder, "" if unknown.
func (r *Resolver) FolderName(id store.FolderID) string {
	if f := r.folders[string(id)]; f != nil {
		return f.Name
	}
	return ""
}

func metaOf(m *store.ProvMark) map[string]string {
	out := map[string]string{}
	var raw map[string]any
	if json.Unmarshal(m.Metadata, &raw) != nil {
		return out
	}
	for k, v := range raw {
		switch x := v.(type) {
		case string:
			out[k] = x
		case float64, bool:
			out[k] = fmt.Sprint(x)
		}
	}
	return out
}

// ValidateMetadata checks a mark's metadata: a JSON object of strings, numbers
// and booleans, at most 20 keys.
func ValidateMetadata(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return cfgErr("metadata must be a JSON object")
	}
	if len(m) > 20 {
		return cfgErr("metadata has more than 20 keys")
	}
	for k, v := range m {
		if !attrKeyRE.MatchString(k) {
			return cfgErr("metadata key %q is not a name", k)
		}
		switch x := v.(type) {
		case string:
			if len(x) > 256 {
				return cfgErr("metadata %q is longer than 256 bytes", k)
			}
		case float64, bool:
		default:
			return cfgErr("metadata %q must be a string, number or boolean", k)
		}
	}
	return nil
}

// DesiredGroup is what one native group should look like on the target.
type DesiredGroup struct {
	GroupID string
	// NativeName is the group's ':' path, for messages.
	NativeName string
	Name       string
	Attrs      map[string][]string
	// Members are target member references, sorted and without duplicates.
	Members []string
	// Unmapped are identities that are members but have no active account in
	// the target system. They are reported, never silently dropped.
	Unmapped []int64
	Why      string
}

// Conflict is two groups that translate to one target name. Neither is provisioned.
type Conflict struct {
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
}

// Desired is the desired state of a provisioner (or of the groups asked for).
type Desired struct {
	ByKey   map[string]*DesiredGroup
	ByGroup map[string]*DesiredGroup
	// Deferred are groups whose membership is still being recomputed by the
	// engine: they are left alone this run, and their effective events bring
	// them back when the recompute finishes.
	Deferred  []string
	Conflicts []Conflict
	// Errors are groups whose templates failed, by group id.
	Errors map[string]string
}

func newDesired() *Desired {
	return &Desired{ByKey: map[string]*DesiredGroup{}, ByGroup: map[string]*DesiredGroup{}, Errors: map[string]string{}}
}

// Compute builds the desired state. only limits it to those group ids (nil: every
// group). Groups that are deleted or not covered by a mark are absent.
func Compute(tx *store.TenantTx, prov *store.Provisioner, c *Compiled, only map[string]bool) (*Desired, error) {
	res, err := NewResolver(tx, prov.ID)
	if err != nil {
		return nil, err
	}
	accounts, err := accountsBySystem(tx, c.AccountSystem)
	if err != nil {
		return nil, err
	}
	var groups []*store.NativeGroup
	if only == nil {
		for off := 0; ; off += 500 {
			page, err := tx.GrpGroups(store.GrpGroupFilter{Limit: 500, Offset: off})
			if err != nil {
				return nil, err
			}
			groups = append(groups, page...)
			if len(page) < 500 {
				break
			}
		}
	} else {
		ids := make([]string, 0, len(only))
		for id := range only {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			g, err := tx.GrpGroup(store.GroupID(id))
			if err != nil {
				if err == store.ErrNotFound {
					continue
				}
				return nil, err
			}
			if g.Status != store.GroupDeleted {
				groups = append(groups, g)
			}
		}
	}
	d := newDesired()
	idents := map[int64]*store.Identity{}
	list := store.MembersListID(tx.Tenant())
	byKey := map[string][]string{}
	for _, g := range groups {
		cov := res.Resolve(g)
		if !cov.Include {
			continue
		}
		if g.RecomputeState != "clean" {
			d.Deferred = append(d.Deferred, string(g.ID))
			continue
		}
		name, attrs, err := c.Group(GroupData{ID: string(g.ID), Name: g.Name, Extension: g.Extension, DisplayName: g.DisplayName,
			DisplayExtension: g.DisplayExtension, Description: g.Description, Folder: res.FolderName(g.FolderID), Meta: cov.Meta})
		if err != nil {
			d.Errors[string(g.ID)] = err.Error()
			continue
		}
		dg := &DesiredGroup{GroupID: string(g.ID), NativeName: g.Name, Name: name, Attrs: attrs, Why: cov.Why, Members: []string{}}
		// a disabled group is the empty set
		if g.Status == store.GroupActive {
			if err := fillMembers(tx, c, dg, g, list, accounts, idents); err != nil {
				if _, ok := err.(memberErr); ok {
					d.Errors[string(g.ID)] = err.Error()
					continue
				}
				return nil, err
			}
		}
		d.ByGroup[dg.GroupID] = dg
		k := Key(name)
		byKey[k] = append(byKey[k], dg.GroupID)
	}
	for k, ids := range byKey {
		if len(ids) == 1 {
			d.ByKey[k] = d.ByGroup[ids[0]]
			continue
		}
		slices.Sort(ids)
		d.Conflicts = append(d.Conflicts, Conflict{Name: d.ByGroup[ids[0]].Name, Groups: ids})
		for _, id := range ids {
			delete(d.ByGroup, id)
		}
	}
	slices.SortFunc(d.Conflicts, func(a, b Conflict) int { return strings.Compare(a.Name, b.Name) })
	slices.Sort(d.Deferred)
	return d, nil
}

type memberErr struct{ msg string }

func (e memberErr) Error() string { return e.msg }

func fillMembers(tx *store.TenantTx, c *Compiled, dg *DesiredGroup, g *store.NativeGroup, list store.ListID,
	accounts map[int64]*store.Account, idents map[int64]*store.Identity) error {
	needIdentity := strings.Contains(c.MemberRef, ".Name") || strings.Contains(c.MemberRef, ".Email")
	seen := map[string]bool{}
	for after := int64(0); ; {
		ids, err := tx.GrpEffectiveIdentitiesAfter(g.ID, list, after, 1000)
		if err != nil {
			return err
		}
		for _, id := range ids {
			after = id
			acct := accounts[id]
			if acct == nil {
				dg.Unmapped = append(dg.Unmapped, id)
				continue
			}
			md := MemberData{IdentityID: id, Username: acct.Username, ExternalID: acct.ExternalID}
			if needIdentity {
				ident := idents[id]
				if ident == nil {
					if ident, err = tx.Identity(id); err != nil {
						return err
					}
					idents[id] = ident
				}
				md.Name = ident.Name
				if ident.Email != nil {
					md.Email = *ident.Email
				}
			}
			ref, err := c.Member(md)
			if err != nil {
				return memberErr{err.Error()}
			}
			if k := NormMember(ref); !seen[k] {
				seen[k] = true
				dg.Members = append(dg.Members, ref)
			}
		}
		if len(ids) < 1000 {
			break
		}
	}
	slices.Sort(dg.Members)
	return nil
}

// accountsBySystem maps an identity to its active account in a system (the
// lowest account id when it has several).
func accountsBySystem(tx *store.TenantTx, system string) (map[int64]*store.Account, error) {
	accts, err := tx.AccountsBySystemUsername(&system)
	if err != nil {
		return nil, err
	}
	out := map[int64]*store.Account{}
	for _, a := range accts {
		if a.IdentityID == nil || a.Status == "disabled" {
			continue
		}
		if cur := out[*a.IdentityID]; cur == nil || a.ID < cur.ID {
			out[*a.IdentityID] = a
		}
	}
	return out, nil
}

// NormMember is the form in which member references are compared: case-folded,
// with the spaces after the commas and around the equals signs of a DN removed.
func NormMember(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.ContainsAny(s, ",=") {
		parts := strings.Split(s, ",")
		for i, p := range parts {
			k, v, ok := strings.Cut(p, "=")
			if ok {
				p = strings.TrimSpace(k) + "=" + strings.TrimSpace(v)
			}
			parts[i] = strings.TrimSpace(p)
		}
		s = strings.Join(parts, ",")
	}
	return s
}
