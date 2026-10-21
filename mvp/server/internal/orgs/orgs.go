// Package orgs derives the organization tree from the identity data Tessera
// already ingests: an organization is a department, under one root for the
// tenant. Nothing is stored. A department's owners are derived too: the
// active people in it who do not report to anyone in it (the top of its
// reporting lines), the one with the most direct reports in it first.
// The tree has no write path: an organization cannot be created or renamed here,
// and names and members follow the HR source on the next sync. What
// administrators add (assigned owners, policies, the hierarchy source) is in
// settings.go and applies through Options.
package orgs

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// RootID is the id of the tenant's root organization.
const RootID = "root"

// NoDepartmentID is the id of the group of people with no department.
const NoDepartmentID = "dept-none"

// MaxOwners is how many owners an organization lists.
const MaxOwners = 5

// Kinds of organization.
const (
	KindRoot       = "tenant"
	KindDepartment = "department"
)

// Person is a person as the organization views show them.
type Person struct {
	ID     int64   `json:"id"`
	Name   string  `json:"name"`
	Title  *string `json:"title"`
	Status string  `json:"status"`
}

// Org is one row of the tree.
type Org struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	ParentID *string `json:"parent_id"`
	// Members counts the people in the organization (the root counts everyone); Active only those who are active.
	Members  int     `json:"members"`
	Active   int     `json:"active"`
	Children int     `json:"children"`
	Owner    *Person `json:"owner"`
}

// Owner sources: who the listed owners are.
const (
	OwnersAssigned = "assigned" // administrators named them (organization settings)
	OwnersDerived  = "derived"  // the top of the department's reporting lines
)

// Detail is one organization with its owners, child organizations and members.
type Detail struct {
	Org
	Parent *Org     `json:"parent"`
	Owners []Person `json:"owners"`
	// OwnersSource says whether Owners are assigned or derived.
	OwnersSource string `json:"owners_source"`
	Children     []Org  `json:"child_orgs"`
	// People are the members of this organization itself (the root has none: its members are its children's).
	People []Member `json:"people"`
}

// Member is a person in an organization with their manager.
type Member struct {
	Person
	Manager *Person `json:"manager"`
	Email   *string `json:"email"`
}

// DeptID is the stable, URL-safe id of a department name.
func DeptID(name string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name))))
	return "dept-" + hex.EncodeToString(sum[:5])
}

type dept struct {
	id, name string
	people   []*store.Identity
}

// group puts the people (humans) of the tenant in their departments.
func group(idents []*store.Identity) (byID map[int64]*store.Identity, depts []*dept) {
	byID = make(map[int64]*store.Identity, len(idents))
	index := map[string]*dept{}
	for _, i := range idents {
		byID[i.ID] = i
		if i.Type != "human" {
			continue
		}
		name, id := "", NoDepartmentID
		if i.Department != nil && strings.TrimSpace(*i.Department) != "" {
			name = strings.TrimSpace(*i.Department)
			id = DeptID(name)
		} else {
			name = "No department"
		}
		d := index[id]
		if d == nil {
			d = &dept{id: id, name: name}
			index[id] = d
			depts = append(depts, d)
		}
		d.people = append(d.people, i)
	}
	sort.Slice(depts, func(a, b int) bool {
		// the group of people with no department goes last
		if (depts[a].id == NoDepartmentID) != (depts[b].id == NoDepartmentID) {
			return depts[b].id == NoDepartmentID
		}
		return strings.ToLower(depts[a].name) < strings.ToLower(depts[b].name)
	})
	return byID, depts
}

func person(i *store.Identity) Person {
	return Person{ID: i.ID, Name: i.Name, Title: i.Title, Status: i.Status}
}

func (d *dept) active() int {
	n := 0
	for _, p := range d.people {
		if p.Status == "active" {
			n++
		}
	}
	return n
}

// owners lists the active people of d who do not report to anyone in d and
// who lead someone in d, those with the most direct reports in d first (then
// by name, then id). A department with a single active person is owned by
// that person. A department whose people all work for someone outside it has
// no owner.
func (d *dept) owners() []Person {
	in := map[int64]bool{}
	for _, p := range d.people {
		in[p.ID] = true
	}
	reports := map[int64]int{}
	active := 0
	for _, p := range d.people {
		if p.Status != "active" {
			continue
		}
		active++
		if p.ManagerID != nil && in[*p.ManagerID] {
			reports[*p.ManagerID]++
		}
	}
	var tops []*store.Identity
	for _, p := range d.people {
		if p.Status != "active" || (p.ManagerID != nil && in[*p.ManagerID]) {
			continue
		}
		if reports[p.ID] > 0 || active == 1 {
			tops = append(tops, p)
		}
	}
	sort.Slice(tops, func(a, b int) bool {
		x, y := tops[a], tops[b]
		if reports[x.ID] != reports[y.ID] {
			return reports[x.ID] > reports[y.ID]
		}
		if x.Name != y.Name {
			return x.Name < y.Name
		}
		return x.ID < y.ID
	})
	if len(tops) > MaxOwners {
		tops = tops[:MaxOwners]
	}
	out := make([]Person, len(tops))
	for i, p := range tops {
		out[i] = person(p)
	}
	return out
}

// Options are what administrators add to the derived tree (issue #298).
type Options struct {
	// Owners are the assigned owners by organization id, in order. An
	// organization with an active assigned owner lists those instead of the
	// derived ones (an assigned owner need not work in the organization).
	Owners map[string][]int64
	// System, when set, limits the hierarchy to the people ingested from that
	// source (the hierarchy source setting); "" takes everyone.
	System string
}

// filter returns the people the hierarchy is built from.
func (o Options) filter(idents []*store.Identity) []*store.Identity {
	if o.System == "" {
		return idents
	}
	out := make([]*store.Identity, 0, len(idents))
	for _, i := range idents {
		if i.Source != nil && *i.Source == o.System {
			out = append(out, i)
		}
	}
	return out
}

// resolver picks an organization's owners: assigned and active first, else derived.
type resolver struct {
	opts Options
	all  map[int64]*store.Identity
}

func newResolver(opts Options, idents []*store.Identity) resolver {
	all := make(map[int64]*store.Identity, len(idents))
	for _, i := range idents {
		all[i.ID] = i
	}
	return resolver{opts, all}
}

func (r resolver) owners(id string, derived []Person) ([]Person, string) {
	var out []Person
	for _, pid := range r.opts.Owners[id] {
		if p := r.all[pid]; p != nil && p.Status == "active" && len(out) < MaxOwners {
			out = append(out, person(p))
		}
	}
	if len(out) > 0 {
		return out, OwnersAssigned
	}
	return derived, OwnersDerived
}

func (d *dept) org(root string, r resolver) Org {
	o := Org{ID: d.id, Name: d.name, Kind: KindDepartment, ParentID: &root, Members: len(d.people), Active: d.active()}
	if ow, _ := r.owners(d.id, d.owners()); len(ow) > 0 {
		o.Owner = &ow[0]
	}
	return o
}

func rootOrg(name string, depts []*dept, r resolver) Org {
	o := Org{ID: RootID, Name: name, Kind: KindRoot, Children: len(depts)}
	for _, d := range depts {
		o.Members += len(d.people)
		o.Active += d.active()
	}
	if ow, src := r.owners(RootID, nil); src == OwnersAssigned {
		o.Owner = &ow[0]
	}
	return o
}

// OwnerIDs returns, for every organization, the ids of its effective owners in
// order: assigned and active, else derived. The reviews of the
// organization_owner type read it.
func OwnerIDs(opts Options, idents []*store.Identity) map[string][]int64 {
	r := newResolver(opts, idents)
	_, depts := group(opts.filter(idents))
	out := map[string][]int64{}
	add := func(id string, derived []Person) {
		ow, _ := r.owners(id, derived)
		for _, p := range ow {
			out[id] = append(out[id], p.ID)
		}
	}
	add(RootID, nil)
	for _, d := range depts {
		add(d.id, d.owners())
	}
	return out
}

// Tree returns the root and its departments, the root first then the
// departments by name. rootName is the tenant's display name.
func Tree(rootName string, idents []*store.Identity) []Org {
	return TreeWith(rootName, idents, Options{})
}

// TreeWith is Tree with the administrators' additions.
func TreeWith(rootName string, idents []*store.Identity, opts Options) []Org {
	r := newResolver(opts, idents)
	_, depts := group(opts.filter(idents))
	out := []Org{rootOrg(rootName, depts, r)}
	for _, d := range depts {
		out = append(out, d.org(RootID, r))
	}
	return out
}

// Get returns one organization by id; ok is false when there is none.
func Get(rootName string, idents []*store.Identity, id string) (*Detail, bool) {
	return GetWith(rootName, idents, id, Options{})
}

// GetWith is Get with the administrators' additions.
func GetWith(rootName string, idents []*store.Identity, id string, opts Options) (*Detail, bool) {
	rs := newResolver(opts, idents)
	byID, depts := group(opts.filter(idents))
	root := rootOrg(rootName, depts, rs)
	if id == RootID {
		owners, src := rs.owners(RootID, []Person{})
		det := &Detail{Org: root, Owners: owners, OwnersSource: src, Children: []Org{}, People: []Member{}}
		for _, d := range depts {
			det.Children = append(det.Children, d.org(RootID, rs))
		}
		return det, true
	}
	for _, d := range depts {
		if d.id != id {
			continue
		}
		owners, src := rs.owners(d.id, d.owners())
		det := &Detail{Org: d.org(RootID, rs), Parent: &root, Owners: owners, OwnersSource: src, Children: []Org{}, People: []Member{}}
		people := append([]*store.Identity(nil), d.people...)
		sort.Slice(people, func(a, b int) bool {
			if people[a].Name != people[b].Name {
				return people[a].Name < people[b].Name
			}
			return people[a].ID < people[b].ID
		})
		for _, p := range people {
			m := Member{Person: person(p), Email: p.Email}
			if p.ManagerID != nil {
				if mg := byID[*p.ManagerID]; mg != nil {
					pm := person(mg)
					m.Manager = &pm
				}
			}
			det.People = append(det.People, m)
		}
		return det, true
	}
	return nil, false
}
