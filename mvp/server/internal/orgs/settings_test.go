package orgs

import (
	"errors"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func f64(v float64) *float64 { return &v }
func iptr(v int) *int        { return &v }
func bptr(v bool) *bool      { return &v }

func TestPolicies_Check(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    Policies
		code string
	}{
		{"empty", Policies{}, ""},
		{"workflow", Policies{DefaultStages: []string{"manager", "owner", "decider"}, DefaultEscalateHours: f64(24)}, ""},
		{"overrides", Policies{JustificationRequired: bptr(true), JustificationMinLength: iptr(40), DefaultHours: f64(4), MaxHours: f64(8)}, ""},
		{"no stages", Policies{DefaultStages: []string{}}, "invalid_stages"},
		{"too many stages", Policies{DefaultStages: []string{"manager", "owner", "decider", "manager", "owner"}}, "invalid_stages"},
		{"unknown stage", Policies{DefaultStages: []string{"boss"}}, "invalid_stages"},
		{"repeated stage", Policies{DefaultStages: []string{"manager", "manager"}}, "invalid_stages"},
		{"escalation without workflow", Policies{DefaultEscalateHours: f64(24)}, "escalation_without_workflow"},
		{"escalation out of range", Policies{DefaultStages: []string{"manager"}, DefaultEscalateHours: f64(100000)}, "invalid_escalation"},
		{"waiving a justification", Policies{JustificationRequired: bptr(false)}, "override_cannot_loosen"},
		{"min length 0", Policies{JustificationMinLength: iptr(0)}, "invalid_justification_min"},
		{"min length huge", Policies{JustificationMinLength: iptr(5000)}, "invalid_justification_min"},
		{"zero max", Policies{MaxHours: f64(0)}, "invalid_max_hours"},
		{"zero default", Policies{DefaultHours: f64(0)}, "invalid_default_hours"},
		{"default above max", Policies{DefaultHours: f64(10), MaxHours: f64(5)}, "default_above_max"},
	} {
		err := tc.p.Check()
		var ce *cfgerr.Error
		switch {
		case tc.code == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.code != "" && (!errors.As(err, &ce) || ce.Code != tc.code):
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		}
	}
	if !(Policies{}).IsZero() || (Policies{MaxHours: f64(1)}).IsZero() {
		t.Error("IsZero")
	}
}

func mkp(id int64, name, dept, status string, mgr *int64, source string) *store.Identity {
	i := &store.Identity{ID: id, Name: name, Type: "human", Status: status, ManagerID: mgr}
	if dept != "" {
		i.Department = &dept
	}
	if source != "" {
		i.Source = &source
	}
	return i
}

func TestAssignedOwnersAndSource(t *testing.T) {
	boss := int64(1)
	idents := []*store.Identity{
		mkp(1, "Boss", "Sales", "active", nil, "workday"),
		mkp(2, "Rep", "Sales", "active", &boss, "workday"),
		mkp(3, "Outsider", "Legal", "active", nil, "csv"),
		mkp(4, "Gone", "Legal", "terminated", nil, "csv"),
	}
	sales := DeptID("Sales")
	root := TreeWith("Acme", idents, Options{})
	if root[0].Members != 4 {
		t.Fatalf("members = %d", root[0].Members)
	}
	// derived owner: the head of the reporting line
	d, ok := Get("Acme", idents, sales)
	if !ok || d.OwnersSource != OwnersDerived || len(d.Owners) != 1 || d.Owners[0].ID != 1 {
		t.Fatalf("derived: %+v", d)
	}
	// assigned owners replace them, in order, even from another department; an inactive one is skipped
	opts := Options{Owners: map[string][]int64{sales: {4, 3, 2}}}
	d, _ = GetWith("Acme", idents, sales, opts)
	if d.OwnersSource != OwnersAssigned || len(d.Owners) != 2 || d.Owners[0].ID != 3 || d.Owners[1].ID != 2 {
		t.Errorf("assigned: %+v", d.Owners)
	}
	if got := OwnerIDs(opts, idents)[sales]; len(got) != 2 || got[0] != 3 {
		t.Errorf("OwnerIDs = %v", got)
	}
	// only inactive assigned owners: back to derived
	d, _ = GetWith("Acme", idents, sales, Options{Owners: map[string][]int64{sales: {4}}})
	if d.OwnersSource != OwnersDerived {
		t.Errorf("all assigned owners inactive: %s", d.OwnersSource)
	}
	// the root can have owners too
	r, _ := GetWith("Acme", idents, RootID, Options{Owners: map[string][]int64{RootID: {1}}})
	if r.OwnersSource != OwnersAssigned || r.Org.Owner == nil || r.Org.Owner.ID != 1 {
		t.Errorf("root: %+v", r)
	}
	// the hierarchy source limits who forms the tree
	only := TreeWith("Acme", idents, Options{System: "workday"})
	if len(only) != 2 || only[0].Members != 2 || only[1].ID != sales {
		t.Errorf("limited to workday: %+v", only)
	}
	if _, ok := GetWith("Acme", idents, DeptID("Legal"), Options{System: "workday"}); ok {
		t.Error("a department of another source is in the tree")
	}
}

func TestOrgOfAndIDs(t *testing.T) {
	if OrgOf(mkp(1, "a", "Sales", "active", nil, "")) != DeptID("Sales") || OrgOf(mkp(1, "a", " ", "active", nil, "")) != NoDepartmentID {
		t.Error("OrgOf")
	}
	m := mkp(9, "bot", "Sales", "active", nil, "")
	m.Type = "service"
	if OrgOf(m) != NoDepartmentID {
		t.Error("a machine identity is in no organization")
	}
	for _, id := range []string{"root", "dept-none", DeptID("x")} {
		if !ValidID(id) {
			t.Errorf("%s invalid", id)
		}
	}
	if ValidID("dept-xyz") || ValidID("../root") {
		t.Error("bad ids accepted")
	}
}
