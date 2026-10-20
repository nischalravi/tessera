// Package privs is the privilege model of native groups (issue #47, GR-4;
// design docs/design/groups-grouper-parity.md §7):
//
//   - implies.go: Grouper's privilege names and the implication table.
//   - check.go: who holds which privilege on an object, with dynamic
//     inheritance from folders (K5): rows are applied at check time, never
//     copied.
//   - explain.go: every path by which an identity holds a privilege.
//   - grant.go: granting and revoking rows, creator and default privileges.
//   - settings.go: the tenant's "everyone" policy and default privileges.
//
// The package reads and writes only through *store.TenantTx, so every query is
// scoped to the request's tenant.
package privs

import "slices"

// Privilege is one of Grouper's privileges, lower-cased (G-36..G-38).
type Privilege string

// Group privileges.
const (
	Admin           Privilege = "admin"
	Update          Privilege = "update"
	Read            Privilege = "read"
	View            Privilege = "view"
	Optin           Privilege = "optin"
	Optout          Privilege = "optout"
	GroupAttrRead   Privilege = "group_attr_read"
	GroupAttrUpdate Privilege = "group_attr_update"
)

// Folder privileges (Grouper's naming privileges; STEM is stem_admin).
const (
	StemAdmin      Privilege = "stem_admin"
	Create         Privilege = "create"
	StemAttrRead   Privilege = "stem_attr_read"
	StemAttrUpdate Privilege = "stem_attr_update"
	StemView       Privilege = "stem_view"
)

// Attribute definition privileges.
const (
	AttrAdmin         Privilege = "attr_admin"
	AttrUpdate        Privilege = "attr_update"
	AttrRead          Privilege = "attr_read"
	AttrView          Privilege = "attr_view"
	AttrOptin         Privilege = "attr_optin"
	AttrOptout        Privilege = "attr_optout"
	AttrDefAttrRead   Privilege = "attr_def_attr_read"
	AttrDefAttrUpdate Privilege = "attr_def_attr_update"
)

// ObjectType is the kind of object a privilege is held on.
type ObjectType string

// Object types (the values of grp_privileges.object_type).
const (
	Folder  ObjectType = "folder"
	Group   ObjectType = "group"
	AttrDef ObjectType = "attr_def"
)

// forObject lists the privileges of each object type, strongest first.
var forObject = map[ObjectType][]Privilege{
	Group:   {Admin, Update, Read, View, Optin, Optout, GroupAttrRead, GroupAttrUpdate},
	Folder:  {StemAdmin, Create, StemAttrRead, StemAttrUpdate, StemView},
	AttrDef: {AttrAdmin, AttrUpdate, AttrRead, AttrView, AttrOptin, AttrOptout, AttrDefAttrRead, AttrDefAttrUpdate},
}

// direct is the implication table of design §7.1, one step: a holder of the key
// also holds each value. Implies and ImpliedBy close it transitively.
//
// The design's table gives the attribute-definition rows only as "as Grouper":
// attr_admin implies all, attr_update and attr_read imply attr_view. Two further
// steps are taken by analogy with the group privileges: attr_optin and
// attr_optout imply attr_view (as optin and optout imply view), and
// attr_def_attr_update implies attr_def_attr_read (as group_attr_update implies
// group_attr_read). GR-15 compares them with Grouper's own on import.
var direct = map[Privilege][]Privilege{
	Admin:             {Update, Read, View, Optin, Optout, GroupAttrRead, GroupAttrUpdate},
	Update:            {View},
	Read:              {View},
	Optin:             {View},
	Optout:            {View},
	GroupAttrUpdate:   {GroupAttrRead},
	StemAdmin:         {Create, StemAttrRead, StemAttrUpdate, StemView},
	Create:            {StemView},
	StemAttrUpdate:    {StemAttrRead},
	AttrAdmin:         {AttrUpdate, AttrRead, AttrView, AttrOptin, AttrOptout, AttrDefAttrRead, AttrDefAttrUpdate},
	AttrUpdate:        {AttrView},
	AttrRead:          {AttrView},
	AttrOptin:         {AttrView},
	AttrOptout:        {AttrView},
	AttrDefAttrUpdate: {AttrDefAttrRead},
}

var (
	all     []Privilege
	objOf   = map[Privilege]ObjectType{}
	grants  = map[Privilege][]Privilege{} // p -> every privilege p implies, p included
	grantee = map[Privilege][]Privilege{} // p -> every privilege that implies p, p included
)

func init() {
	for _, t := range []ObjectType{Group, Folder, AttrDef} {
		for _, p := range forObject[t] {
			all = append(all, p)
			objOf[p] = t
		}
	}
	for _, p := range all {
		seen := map[Privilege]bool{p: true}
		queue := []Privilege{p}
		for len(queue) > 0 {
			q := queue[0]
			queue = queue[1:]
			for _, n := range direct[q] {
				if !seen[n] {
					seen[n] = true
					queue = append(queue, n)
				}
			}
		}
		for _, q := range all { // table order keeps the lists deterministic
			if seen[q] {
				grants[p] = append(grants[p], q)
				grantee[q] = append(grantee[q], p)
			}
		}
	}
}

// All lists every privilege: group, then folder, then attribute definition.
func All() []Privilege { return slices.Clone(all) }

// For lists the privileges that can be held on an object type, strongest first.
func For(t ObjectType) []Privilege { return slices.Clone(forObject[t]) }

// Valid reports whether p is one of the privileges.
func Valid(p Privilege) bool { _, ok := objOf[p]; return ok }

// ObjectOf returns the object type p is held on ("" for an unknown privilege).
func ObjectOf(p Privilege) ObjectType { return objOf[p] }

// Implies reports whether holding held also gives want. Every privilege implies
// itself; an unknown privilege implies nothing.
func Implies(held, want Privilege) bool {
	return slices.Contains(grants[held], want)
}

// Implied lists every privilege that holding p gives, p included.
func Implied(p Privilege) []Privilege { return slices.Clone(grants[p]) }

// ImpliedBy lists every privilege whose holder also holds p, p included: the
// rows that can answer a check for p.
func ImpliedBy(p Privilege) []Privilege { return slices.Clone(grantee[p]) }

// AppliesTo is the object kind an inherited row covers.
func (t ObjectType) AppliesTo() string {
	switch t {
	case Group:
		return "groups"
	case Folder:
		return "folders"
	case AttrDef:
		return "attr_defs"
	}
	return ""
}
