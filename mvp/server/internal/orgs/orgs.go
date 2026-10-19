// Package orgs derives the organization tree from the identity data Tessera
// already ingests: an organization is a department, under one root for the
// tenant. Nothing is stored. A department's owners are derived too: the
// active people in it who do not report to anyone in it (the top of its
// reporting lines), the one with the most direct reports in it first.
// Read-only: there is no write path, and an organization cannot be created or
// renamed here. Names and members follow the HR source on the next sync.
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

// Detail is one organization with its owners, child organizations and members.
type Detail struct {
	Org
	Parent   *Org     `json:"parent"`
	Owners   []Person `json:"owners"`
	Children []Org    `json:"child_orgs"`
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

func (d *dept) org(root string) Org {
	o := Org{ID: d.id, Name: d.name, Kind: KindDepartment, ParentID: &root, Members: len(d.people), Active: d.active()}
	if ow := d.owners(); len(ow) > 0 {
		o.Owner = &ow[0]
	}
	return o
}

func rootOrg(name string, depts []*dept) Org {
	r := Org{ID: RootID, Name: name, Kind: KindRoot, Children: len(depts)}
	for _, d := range depts {
		r.Members += len(d.people)
		r.Active += d.active()
	}
	return r
}

// Tree returns the root and its departments, the root first then the
// departments by name. rootName is the tenant's display name.
func Tree(rootName string, idents []*store.Identity) []Org {
	_, depts := group(idents)
	out := []Org{rootOrg(rootName, depts)}
	for _, d := range depts {
		out = append(out, d.org(RootID))
	}
	return out
}

// Get returns one organization by id; ok is false when there is none.
func Get(rootName string, idents []*store.Identity, id string) (*Detail, bool) {
	byID, depts := group(idents)
	root := rootOrg(rootName, depts)
	if id == RootID {
		det := &Detail{Org: root, Owners: []Person{}, Children: []Org{}, People: []Member{}}
		for _, d := range depts {
			det.Children = append(det.Children, d.org(RootID))
		}
		return det, true
	}
	for _, d := range depts {
		if d.id != id {
			continue
		}
		det := &Detail{Org: d.org(RootID), Parent: &root, Owners: d.owners(), Children: []Org{}, People: []Member{}}
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
