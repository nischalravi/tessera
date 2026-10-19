package orgs_test

import (
	"reflect"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/orgs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func sp(s string) *string { return &s }
func ip(i int64) *int64   { return &i }

func person(id int64, name, dept, typ, status string, mgr *int64) *store.Identity {
	i := &store.Identity{ID: id, Name: name, Type: typ, Status: status, ManagerID: mgr}
	if dept != "" {
		i.Department = sp(dept)
	}
	return i
}

func names(ps []orgs.Person) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

func TestTree(t *testing.T) {
	idents := []*store.Identity{
		person(1, "Rosa", "Executive", "human", "active", nil),
		person(2, "Caspian", "Engineering", "human", "active", ip(1)), // reports to the exec: top of Engineering
		person(3, "Ada", "Engineering", "human", "active", ip(2)),
		person(4, "Bo", "Engineering", "human", "active", ip(2)),
		person(5, "Cy", "Engineering", "human", "terminated", ip(2)),
		person(6, "Dee", "engineering ", "human", "active", ip(3)), // same department, another spelling
		person(7, "Fin", "Finance", "human", "active", ip(1)),      // alone, no one reports to them
		person(8, "Gus", "Finance", "human", "active", ip(7)),
		person(9, "Hal", "", "human", "active", nil),                     // no department
		person(10, "svc-etl", "Engineering", "service", "active", ip(2)), // machines are not members
		person(11, "Ivy", "Sales", "human", "active", ip(1)),             // nobody leads anyone in Sales
		person(12, "Jo", "Sales", "human", "active", ip(1)),
	}
	tree := orgs.Tree("Larkspur Labs", idents)
	var got []string
	for _, o := range tree {
		got = append(got, o.Name)
	}
	if want := []string{"Larkspur Labs", "Engineering", "Executive", "Finance", "Sales", "No department"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("orgs = %v, want %v", got, want)
	}
	root := tree[0]
	if root.Kind != orgs.KindRoot || root.ParentID != nil || root.Children != 5 || root.Members != 11 || root.Active != 10 {
		t.Errorf("root = %+v", root)
	}
	byName := map[string]orgs.Org{}
	for _, o := range tree {
		byName[o.Name] = o
	}
	eng := byName["Engineering"]
	if eng.Members != 5 || eng.Active != 4 || eng.ParentID == nil || *eng.ParentID != orgs.RootID || eng.ID != orgs.DeptID("ENGINEERING") {
		t.Errorf("Engineering = %+v", eng)
	}
	for name, want := range map[string]string{"Engineering": "Caspian", "Executive": "Rosa", "Finance": "Fin", "Sales": "", "No department": "Hal"} {
		o := byName[name]
		switch {
		case want == "" && o.Owner != nil:
			t.Errorf("%s owner = %v, want none", name, o.Owner.Name)
		case want != "" && (o.Owner == nil || o.Owner.Name != want):
			t.Errorf("%s owner = %v, want %s", name, o.Owner, want)
		}
	}
	if byName["No department"].ID != orgs.NoDepartmentID {
		t.Errorf("no-department id = %s", byName["No department"].ID)
	}
}

func TestGet(t *testing.T) {
	idents := []*store.Identity{
		person(1, "Rosa", "Executive", "human", "active", nil),
		person(2, "Caspian", "Engineering", "human", "active", ip(1)),
		person(3, "Ada", "Engineering", "human", "active", ip(2)),
		person(4, "Bo", "Engineering", "human", "active", ip(2)),
	}
	eng, ok := orgs.Get("Larkspur Labs", idents, orgs.DeptID("Engineering"))
	if !ok || eng.Parent == nil || eng.Parent.ID != orgs.RootID || len(eng.Children) != 0 {
		t.Fatalf("Engineering = %+v, %v", eng, ok)
	}
	if got := names(eng.Owners); !reflect.DeepEqual(got, []string{"Caspian"}) {
		t.Errorf("owners = %v", got)
	}
	var members []string
	for _, m := range eng.People {
		members = append(members, m.Name)
	}
	if !reflect.DeepEqual(members, []string{"Ada", "Bo", "Caspian"}) {
		t.Errorf("members = %v (sorted by name)", members)
	}
	if m := eng.People[0]; m.Manager == nil || m.Manager.Name != "Caspian" {
		t.Errorf("Ada's manager = %+v", m.Manager)
	}
	if m := eng.People[2]; m.Manager == nil || m.Manager.Name != "Rosa" {
		t.Errorf("Caspian's manager = %+v (outside the department, still shown)", m.Manager)
	}
	root, ok := orgs.Get("Larkspur Labs", idents, orgs.RootID)
	if !ok || len(root.Children) != 2 || root.Children[0].Name != "Engineering" || len(root.People) != 0 || root.Parent != nil {
		t.Errorf("root = %+v, %v", root, ok)
	}
	if _, ok := orgs.Get("Larkspur Labs", idents, orgs.DeptID("Nope")); ok {
		t.Error("an unknown id was found")
	}
	if _, ok := orgs.Get("Larkspur Labs", nil, orgs.RootID); !ok {
		t.Error("the root exists for a tenant with no people")
	}
}

func TestDeptIDStable(t *testing.T) {
	if a, b := orgs.DeptID("Engineering"), orgs.DeptID("  engineering"); a != b || len(a) != len("dept-")+10 {
		t.Errorf("ids %q %q", a, b)
	}
	if orgs.DeptID("R&D") == orgs.DeptID("R D") {
		t.Error("distinct names share an id")
	}
}
