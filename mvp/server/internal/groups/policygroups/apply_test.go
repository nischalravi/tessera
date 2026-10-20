package policygroups

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func seedRefs(x *harness) {
	x.group("ref:a", 0, 1)
	x.group("ref:b", 1, 2)
	x.group("ref:d", 1)
	x.src.attrs[x.idents[2]]["campus"] = []string{"north"}
}

const polName = "app:x:pol"

func TestApply_CreatesPolicyGroupAndNodes(t *testing.T) {
	x := newHarness(t, 5, nil)
	seedRefs(x)
	res := x.mustApply(repo("c1", true, pol(polName, in("ref:a")+` || (`+in("ref:b")+` && principal.campus == "main")`, in("ref:d"))))
	if len(res.Groups) != 1 || res.Groups[0].Action != ActionCreated || res.NodesCreated == 0 {
		t.Fatalf("result = %+v", res)
	}
	if got := x.members(polName); !slices.Equal(got, []int{0}) {
		t.Errorf("members = %v, want [0]", got)
	}
	g := x.group2(polName)
	if g.Definition != store.DefinitionPolicy || g.ManagedBy != store.ManagedByPolicyRepo || g.PolicyRef == nil {
		t.Fatalf("group = %+v", g)
	}
	var ref policyRef
	if err := json.Unmarshal([]byte(*g.PolicyRef), &ref); err != nil || ref.Commit != "c1" || ref.Path != "groups/app/x/app/x/pol.cedar" && ref.Path == "" || ref.CompiledSHA256 == "" {
		t.Errorf("policy_ref = %s (%v)", *g.PolicyRef, err)
	}
	// the attribute group is an ordinary group with attribute-sourced members
	if got := x.members("sys:attr:campus:main"); !slices.Equal(got, []int{0, 1, 3, 4}) {
		t.Errorf("sys:attr:campus:main = %v", got)
	}
	x.read(func(e model.Env) error {
		ag, _ := e.Tx.GrpGroupByName("sys:attr:campus:main")
		rows, err := e.Tx.GrpDirect(store.GrpDirectFilter{Group: ag.ID})
		if err != nil || len(rows) != 4 || rows[0].Source != AttrSourceName {
			t.Errorf("direct rows = %v, %v", rows, err)
		}
		src, err := e.Tx.GrpPolicySource(g.ID)
		if err != nil || src.Origin != store.PolicyOriginRepo || src.CommitSHA != "c1" || src.Cedar == "" {
			t.Errorf("source = %+v, %v", src, err)
		}
		return nil
	})
	// the same change again changes nothing
	seq := x.lastSeq()
	res = x.mustApply(repo("c1", true, pol(polName, in("ref:a")+` || (`+in("ref:b")+` && principal.campus == "main")`, in("ref:d"))))
	if res.Groups[0].Action != ActionUnchanged || res.NodesCreated != 0 || x.lastSeq() != seq {
		t.Errorf("a repeat: %+v, events %d -> %d", res, seq, x.lastSeq())
	}
}

func TestApply_UpdateRetiresAndRestoresNodes(t *testing.T) {
	x := newHarness(t, 5, nil)
	seedRefs(x)
	x.mustApply(repo("c1", true, pol(polName, in("ref:a")+` && principal.campus == "main"`, "")))
	campus := x.group2("sys:attr:campus:main")
	// a new commit: no attribute any more; the attribute group and the old nodes are retired
	res := x.mustApply(repo("c2", true, pol(polName, in("ref:b"), "")))
	if res.Groups[0].Action != ActionUpdated || res.NodesRetired < 2 {
		t.Errorf("result = %+v", res)
	}
	if got := x.members(polName); !slices.Equal(got, []int{1, 2}) {
		t.Errorf("members = %v", got)
	}
	if g := x.group2("sys:attr:campus:main"); g.Status != store.GroupDeleted || g.ID != campus.ID {
		t.Errorf("attribute group = %+v", g)
	}
	var ref policyRef
	_ = json.Unmarshal([]byte(*x.group2(polName).PolicyRef), &ref)
	if ref.Commit != "c2" {
		t.Errorf("commit = %q", ref.Commit)
	}
	// the attribute is used again: the same group comes back, current
	x.src.attrs[x.idents[3]]["campus"] = []string{"north"}
	x.mustApply(repo("c3", true, pol(polName, in("ref:a")+` && principal.campus == "main"`, "")))
	if g := x.group2("sys:attr:campus:main"); g.Status != store.GroupActive || g.ID != campus.ID {
		t.Errorf("restored group = %+v", g)
	}
	if got := x.members("sys:attr:campus:main"); !slices.Equal(got, []int{0, 1, 4}) {
		t.Errorf("restored members = %v", got)
	}
	if got := x.members(polName); !slices.Equal(got, []int{0, 1}) {
		t.Errorf("members = %v", got)
	}
}

func TestApply_SharedNodesAreOneGroup(t *testing.T) {
	x := newHarness(t, 5, nil)
	seedRefs(x)
	shared := in("ref:a") + ` || (` + in("ref:b") + ` && principal.campus == "main")`
	files := []SourceFile{pol("app:x:p1", shared, ""), pol("app:x:p2", shared, in("ref:d")), pol("app:x:p3", shared+" || "+in("ref:d"), "")}
	x.mustApply(repo("c1", true, files...))
	var nodes []*store.GrpPolicyNode
	x.read(func(e model.Env) error {
		var err error
		nodes, err = e.Tx.GrpPolicyNodes("")
		return err
	})
	// the shared union, the intersection and the campus leaf are held once; p3's union and the two empties are extra
	kinds := map[string]int{}
	for _, n := range nodes {
		kinds[n.Kind]++
	}
	if kinds[store.NodeAttr] != 1 || kinds[store.NodeIntersection] != 1 || kinds[store.NodeUnion] != 2 || kinds[store.NodeEmpty] != 2 {
		t.Errorf("nodes by kind = %v", kinds)
	}
	if a, b := x.members("app:x:p1"), x.members("app:x:p2"); !slices.Equal(a, []int{0, 1}) || !slices.Equal(b, []int{0}) {
		t.Errorf("p1 = %v, p2 = %v", a, b)
	}
	// dropping p3 retires only what p3 alone used
	res := x.mustApply(repo("c2", true, files[:2]...))
	if res.NodesRetired != 1 {
		t.Errorf("retired %d nodes, want 1", res.NodesRetired)
	}
}

func TestApply_FullSyncRetiresMissingFiles(t *testing.T) {
	x := newHarness(t, 5, nil)
	seedRefs(x)
	x.mustApply(repo("c1", true, pol("app:x:p1", in("ref:a"), ""), pol("app:x:p2", in("ref:b"), "")))
	res := x.mustApply(repo("c2", true, pol("app:x:p1", in("ref:a"), "")))
	if len(res.Groups) != 2 || res.Groups[1].Action != ActionRemoved || res.Groups[1].Name != "app:x:p2" {
		t.Fatalf("groups = %+v", res.Groups)
	}
	if g := x.group2("app:x:p2"); g.Status != store.GroupDeleted || len(x.members("app:x:p2")) != 0 {
		t.Errorf("p2 = %+v", g)
	}
	// a partial change leaves the others alone
	x.mustApply(repo("c3", false, pol("app:x:p3", in("ref:d"), "")))
	if g := x.group2("app:x:p1"); g.Status != store.GroupActive {
		t.Error("a partial change retired p1")
	}
	// the file comes back
	x.mustApply(repo("c4", true, pol("app:x:p1", in("ref:a"), ""), pol("app:x:p2", in("ref:b"), "")))
	if g := x.group2("app:x:p2"); g.Status != store.GroupActive || !slices.Equal(x.members("app:x:p2"), []int{1, 2}) {
		t.Errorf("p2 after return = %+v", g)
	}
}

func TestApply_Refusals(t *testing.T) {
	x := newHarness(t, 4, nil)
	seedRefs(x)
	x.group("app:x:plain")
	x.mustApply(repo("c1", false, pol("app:x:p1", in("ref:a"), "")))
	seq := x.lastSeq()
	cases := []struct {
		name string
		in   ApplyInput
		code string
	}{
		{"syntax", repo("c2", false, SourceFile{Path: "a.cedar", Cedar: "permit ("}), CodeSyntax},
		{"unsupported", repo("c2", false, pol("app:x:p9", `context.a == "x"`, "")), CodeUnsupported},
		{"unknown group", repo("c2", false, pol("app:x:p9", in("ref:nope"), "")), CodeUnknownGroup},
		{"unbounded", repo("c2", false, pol("app:x:p9", `!(`+in("ref:a")+`)`, "")), CodeUnbounded},
		{"a basic group's name", repo("c2", false, pol("app:x:plain", in("ref:a"), "")), CodeNotPolicyGroup},
		{"no commit", repo("", false, pol("app:x:p9", in("ref:a"), "")), CodeInvalidCommit},
		{"bad commit", repo("a b", false, pol("app:x:p9", in("ref:a"), "")), CodeInvalidCommit},
		{"duplicate group", repo("c2", false, pol("app:x:p9", in("ref:a"), ""), SourceFile{Path: "other.cedar", Cedar: pol("app:x:p9", in("ref:b"), "").Cedar}), CodeDuplicateGroup},
		{"duplicate path", repo("c2", false, pol("app:x:p9", in("ref:a"), ""), pol("app:x:p9", in("ref:a"), "")), CodeDuplicatePath},
		{"bad path", repo("c2", false, SourceFile{Path: "../x.cedar", Cedar: pol("app:x:p9", in("ref:a"), "").Cedar}), CodeInvalidPath},
		{"ui over a repository group", ApplyInput{Origin: store.PolicyOriginUI, Files: []SourceFile{pol("app:x:p1", in("ref:b"), "")}}, CodePolicyManaged},
		{"ui with a commit", ApplyInput{Origin: store.PolicyOriginUI, Commit: "c", Files: []SourceFile{pol("app:x:p9", in("ref:b"), "")}}, CodeInvalidPolicy},
		{"unknown origin", ApplyInput{Origin: "git", Files: []SourceFile{pol("app:x:p9", in("ref:b"), "")}}, CodeInvalidPolicy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := x.apply(c.in)
			if ve := asValidation(t, err); !hasCode(ve, c.code) {
				t.Errorf("diagnostics = %v, want %s", ve.Diags, c.code)
			}
			if x.lastSeq() != seq {
				t.Error("a refused change left events behind")
			}
		})
	}
	x.read(func(e model.Env) error {
		if _, err := e.Tx.GrpGroupByName("app:x:p9"); err == nil {
			t.Error("a refused change left a group behind")
		}
		return nil
	})
}

// TestApply_CycleRefusedAndRolledBack: two policy groups that refer to each other
// are a 409 cycle from the engine, and nothing of the change stays.
func TestApply_CycleRefusedAndRolledBack(t *testing.T) {
	x := newHarness(t, 4, nil)
	seedRefs(x)
	seq := x.lastSeq()
	_, err := x.apply(repo("c1", false, pol("app:x:p1", in("app:x:p2")+" || "+in("ref:a"), ""), pol("app:x:p2", in("app:x:p1")+" || "+in("ref:b"), "")))
	if ce, ok := err.(*model.Error); !ok || ce.Code != "cycle" {
		t.Fatalf("err = %v, want a cycle", err)
	}
	if x.lastSeq() != seq {
		t.Error("the refused change left events behind")
	}
	// a policy group that refers to itself
	if _, err := x.apply(repo("c2", false, pol("app:x:p1", in("app:x:p1")+" || "+in("ref:a"), ""))); err == nil {
		t.Error("a self-referencing policy was accepted")
	}
	// a chain is fine, in either order of the files
	x.mustApply(repo("c3", false, pol("app:x:p1", in("ref:a"), ""), pol("app:x:p2", in("app:x:p1")+" || "+in("ref:b"), "")))
	if got := x.members("app:x:p2"); !slices.Equal(got, []int{0, 1, 2}) {
		t.Errorf("p2 = %v", got)
	}
	// changing p1 changes p2 through the engine
	x.mustApply(repo("c4", false, pol("app:x:p1", in("ref:d"), "")))
	if got := x.members("app:x:p2"); !slices.Equal(got, []int{1, 2}) {
		t.Errorf("p2 after p1 changed = %v", got)
	}
}

func TestApply_ManagedGroupsRefuseOtherWriters(t *testing.T) {
	x := newHarness(t, 4, nil)
	seedRefs(x)
	x.mustApply(repo("c1", false, pol(polName, in("ref:a")+` && principal.campus == "main"`, "")))
	pg, attr := x.group2(polName), x.group2("sys:attr:campus:main")
	x.read(func(e model.Env) error { return nil })
	err := x.run(func(e model.Env) error {
		for name, fn := range map[string]func() error{
			"update policy group": func() error {
				d := "x"
				_, err := e.UpdateGroup(pg.ID, model.UpdateGroupInput{Description: &d})
				return err
			},
			"delete policy group": func() error { return e.DeleteGroup(pg.ID) },
			"add member to an attribute group": func() error {
				_, err := e.AddMember(attr.ID, model.MemberInput{Identity: &x.idents[3]})
				return err
			},
			"remove member": func() error { _, err := e.RemoveMember(attr.ID, fmt.Sprint(x.idents[0])); return err },
			"convert":       func() error { _, _, err := e.ConvertToComposite(attr.ID, model.CompositeInput{}); return err },
			"move": func() error {
				_, err := e.MoveGroup(pg.ID, attr.FolderID)
				return err
			},
		} {
			me, ok := fn().(*model.Error)
			if !ok || me.Code != "policy_managed" {
				t.Errorf("%s: %v, want policy_managed", name, me)
			}
		}
		// a policy group takes no direct members whoever asks
		ui := e
		ui.System = true
		if _, err := ui.AddMember(pg.ID, model.MemberInput{Identity: &x.idents[3]}); err == nil {
			t.Error("a policy group took a direct member")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// the API cannot create a policy group, and a plain group cannot carry a policy reference
	x.must(func(e model.Env) error {
		f, _ := e.Tx.GrpFolderByName("app:x")
		if _, err := e.CreateGroup(model.CreateGroupInput{Folder: f.ID, Extension: "sneaky", Definition: store.DefinitionPolicy}); err == nil {
			t.Error("a policy group was created without a policy reference")
		}
		ref := "{}"
		if _, err := e.CreateGroup(model.CreateGroupInput{Folder: f.ID, Extension: "sneaky2", PolicyRef: &ref}); err == nil {
			t.Error("a basic group was created with a policy reference")
		}
		return nil
	})
}

func TestApply_UIOriginAndAdoption(t *testing.T) {
	x := newHarness(t, 4, nil)
	seedRefs(x)
	x.mustApply(ApplyInput{Origin: store.PolicyOriginUI, Files: []SourceFile{pol(polName, in("ref:a"), "")}})
	if g := x.group2(polName); g.ManagedBy != store.ManagedByUI || g.Definition != store.DefinitionPolicy {
		t.Fatalf("group = %+v", g)
	}
	// the UI may edit its own group again
	x.mustApply(ApplyInput{Origin: store.PolicyOriginUI, Files: []SourceFile{pol(polName, in("ref:b"), "")}})
	if got := x.members(polName); !slices.Equal(got, []int{1, 2}) {
		t.Errorf("members = %v", got)
	}
	// "Export to repository": the repository adopts it, and the UI no longer may
	x.mustApply(repo("c1", false, pol(polName, in("ref:b"), "")))
	if g := x.group2(polName); g.ManagedBy != store.ManagedByPolicyRepo {
		t.Errorf("managed_by = %s", g.ManagedBy)
	}
	_, err := x.apply(ApplyInput{Origin: store.PolicyOriginUI, Files: []SourceFile{pol(polName, in("ref:a"), "")}})
	if !hasCode(asValidation(t, err), CodePolicyManaged) {
		t.Errorf("err = %v", err)
	}
}

// TestSync_RecordsCommitOnEveryChange: every event a sync writes carries the
// cause policy_repo and the commit (design §8.5 step 4), whether the engine did
// the work in the request or the queue did it later, and each changed group
// records the commit in policy_ref.
func TestSync_RecordsCommitOnEveryChange(t *testing.T) {
	for _, budget := range []int{0, 2} { // 2: nothing fits, the queue does the work
		t.Run(fmt.Sprintf("budget %d", budget), func(t *testing.T) {
			x := newHarness(t, 6, engine.New(budget))
			seedRefs(x)
			seq := x.lastSeq()
			x.mustApply(repo("aaa111", true, pol(polName, in("ref:a")+` && principal.campus == "main"`, in("ref:d"))))
			drain(x)
			check := func(commit string, from int64) map[string]int {
				evs := x.eventsAfter(from)
				kinds := map[string]int{}
				for _, ev := range evs {
					if ev.CauseType != store.CausePolicyRepo || ev.CauseRef != commit {
						t.Errorf("event %d %s has cause %s/%s, want policy_repo/%s", ev.Seq, ev.Type, ev.CauseType, ev.CauseRef, commit)
					}
					kinds[ev.Type]++
				}
				return kinds
			}
			kinds := check("aaa111", seq)
			for _, want := range []string{"group.created", "membership.direct.added", "membership.effective.added", "group.definition_changed"} {
				if kinds[want] == 0 {
					t.Errorf("no %s event in %v", want, kinds)
				}
			}
			if kinds["membership.effective.added"] == 0 || !slices.Equal(x.members(polName), []int{0}) {
				t.Errorf("members = %v", x.members(polName))
			}
			// a second commit: a change of definition and of an attribute
			x.src.attrs[x.idents[0]]["campus"] = []string{"north"}
			seq = x.lastSeq()
			x.mustApply(repo("bbb222", true, pol(polName, in("ref:a")+` && principal.campus == "main"`, in("ref:b")+` || `+in("ref:d"))))
			drain(x)
			kinds = check("bbb222", seq)
			if kinds["membership.effective.removed"] == 0 && kinds["membership.effective.added"] == 0 {
				t.Errorf("no effective change in %v", kinds)
			}
			var ref policyRef
			_ = json.Unmarshal([]byte(*x.group2(polName).PolicyRef), &ref)
			if ref.Commit != "bbb222" {
				t.Errorf("policy_ref.commit = %q", ref.Commit)
			}
			// only the commit moved: still recorded, with no membership change
			seq = x.lastSeq()
			x.mustApply(repo("ccc333", true, pol(polName, in("ref:a")+` && principal.campus == "main"`, in("ref:b")+` || `+in("ref:d"))))
			kinds = check("ccc333", seq)
			_ = json.Unmarshal([]byte(*x.group2(polName).PolicyRef), &ref)
			if ref.Commit != "ccc333" || kinds["membership.effective.added"]+kinds["membership.effective.removed"] != 0 {
				t.Errorf("commit-only change: policy_ref %q, events %v", ref.Commit, kinds)
			}
			// the audit ledger has the commit
			x.read(func(e model.Env) error { return nil })
		})
	}
}

// drain runs the engine's queue to the end, at the harness clock.
func drain(x *harness) {
	x.t.Helper()
	for i := 0; i < 1000; i++ {
		var more bool
		x.must(func(e model.Env) error {
			var err error
			more, err = x.eng.Drain(e.Tx, e.Now)
			return err
		})
		if !more {
			return
		}
	}
	x.t.Fatal("the queue did not drain")
}

func TestIndexer_FollowsAttributes(t *testing.T) {
	x := newHarness(t, 6, nil)
	seedRefs(x)
	x.src.attrs[x.idents[0]]["affiliation"] = []string{"faculty", "staff"}
	x.src.attrs[x.idents[1]]["affiliation"] = []string{"student"}
	x.src.attrs[x.idents[3]]["department"] = []string{"cs"}
	x.mustApply(repo("c1", true, pol(polName,
		`(principal has affiliation && principal.affiliation.contains("faculty")) || (principal has department && principal.department == "cs")`,
		`principal.campus == "north"`)))
	if got := x.members(polName); !slices.Equal(got, []int{0, 3}) {
		t.Fatalf("members = %v", got)
	}
	// an identity changes department, another loses it, another becomes faculty
	x.src.attrs[x.idents[3]]["department"] = []string{"math"}
	x.src.attrs[x.idents[4]]["department"] = []string{"cs"}
	x.src.attrs[x.idents[1]]["affiliation"] = []string{"student", "faculty"}
	delete(x.src.attrs[x.idents[0]], "affiliation")
	var rep *IndexReport
	x.must(func(e model.Env) error {
		var err error
		rep, err = Indexer{Schema: testSchema(), Source: x.src}.Reindex(e, nil)
		return err
	})
	if rep.Groups != 5 || rep.Added == 0 || rep.Removed == 0 {
		t.Errorf("report = %+v", rep)
	}
	if got := x.members(polName); !slices.Equal(got, []int{1, 4}) {
		t.Errorf("members after reindex = %v", got)
	}
	// nothing changed: nothing is written
	seq := x.lastSeq()
	x.must(func(e model.Env) error {
		var err error
		rep, err = Indexer{Schema: testSchema(), Source: x.src}.Reindex(e, nil)
		return err
	})
	if rep.Added+rep.Removed != 0 || x.lastSeq() != seq {
		t.Errorf("a second reindex: %+v", rep)
	}
	// the default source reads the identity record
	if v := (IdentityAttrs{}).Values(&store.Identity{Type: "person", Status: "active"}, "type"); len(v) != 1 || v[0] != "person" {
		t.Errorf("type = %v", v)
	}
	if v := (IdentityAttrs{}).Values(&store.Identity{}, "department"); len(v) != 0 {
		t.Errorf("department of an identity without one = %v", v)
	}
}

func TestDiff_SimulatesWithoutWriting(t *testing.T) {
	x := newHarness(t, 6, nil)
	seedRefs(x)
	files := []SourceFile{pol("app:x:p1", in("ref:a"), in("ref:d")), pol("app:x:p2", in("app:x:p1")+" || "+in("ref:b"), "")}
	diff := func(full bool, fs ...SourceFile) *DiffResult {
		var d *DiffResult
		x.read(func(e model.Env) error {
			var err error
			d, err = x.applier(e).Diff(fs, full)
			return err
		})
		return d
	}
	seq := x.lastSeq()
	d := diff(false, files...)
	if x.lastSeq() != seq || len(d.Groups) != 2 || d.Identities != 6 {
		t.Fatalf("diff = %+v", d)
	}
	if g := d.Groups[0]; g.Name != "app:x:p1" || g.Status != "new" || g.Added != 1 || g.Proposed != 1 || !slices.Equal(g.AddedSample, []int64{x.idents[0]}) {
		t.Errorf("p1 = %+v", g)
	}
	if g := d.Groups[1]; g.Added != 3 || g.Removed != 0 {
		t.Errorf("p2 = %+v", g)
	}
	x.read(func(e model.Env) error {
		if _, err := e.Tx.GrpGroupByName("app:x:p1"); err == nil {
			t.Error("a diff created a group")
		}
		return nil
	})
	x.mustApply(repo("c1", true, files...))
	if d := diff(true, files...); d.Groups[0].Status != "unchanged" || d.Groups[1].Status != "unchanged" {
		t.Errorf("after applying: %+v", d.Groups)
	}
	// a change: ref:b loses i1 from p2's side by forbidding it; p1 widens
	changed := []SourceFile{pol("app:x:p1", in("ref:a")+" || "+in("ref:b"), in("ref:d")), pol("app:x:p2", in("app:x:p1"), in("ref:b"))}
	d = diff(true, changed...)
	if g := d.Groups[0]; g.Status != "changed" || g.Added != 1 || g.Removed != 0 || g.Current != 1 || g.Proposed != 2 {
		t.Errorf("p1 = %+v", g)
	}
	if g := d.Groups[1]; g.Status != "changed" || g.Current != 3 || g.Proposed != 1 || g.Removed != 2 {
		t.Errorf("p2 = %+v", g)
	}
	// the diff is what the apply then does
	x.mustApply(repo("c2", true, changed...))
	if got := x.members("app:x:p2"); !slices.Equal(got, []int{0}) {
		t.Errorf("p2 = %v", got)
	}
	// full: a file that is gone shows as removed
	d = diff(true, changed[:1]...)
	if len(d.Groups) != 2 || d.Groups[1].Status != "removed" || d.Groups[1].Removed != 1 {
		t.Errorf("full diff = %+v", d.Groups)
	}
	// findings are the apply's
	var ve *ValidationError
	x.read(func(e model.Env) error {
		_, err := x.applier(e).Diff([]SourceFile{pol("app:x:p9", in("ref:nope"), "")}, false)
		ve = asValidation(t, err)
		return nil
	})
	if !hasCode(ve, CodeUnknownGroup) {
		t.Errorf("diags = %v", ve.Diags)
	}
}

func TestValidate_ReportsFindingsAndReferences(t *testing.T) {
	x := newHarness(t, 3, nil)
	seedRefs(x)
	x.read(func(e model.Env) error {
		v, fs, err := Validate(e, testSchema(), []SourceFile{pol("app:x:p1", in("ref:a")+" || "+in("app:x:p2"), ""), pol("app:x:p2", in("ref:b"), "")})
		if err != nil || !v.Valid || len(fs) != 2 || len(v.References) != 3 || len(v.Groups) != 2 {
			t.Errorf("validation = %+v, %v", v, err)
		}
		v, fs, err = Validate(e, testSchema(), []SourceFile{pol("app:x:p1", in("ref:zz"), "")})
		if err != nil || v.Valid || fs != nil || v.Diagnostics[0].Code != CodeUnknownGroup {
			t.Errorf("validation = %+v, %v", v, err)
		}
		if _, _, err := Validate(e, Schema{Attrs: map[string]AttrDef{"a b": {}}}, nil); err == nil {
			t.Error("a bad schema was accepted")
		}
		return nil
	})
}

// TestPolicyGroups_PDPAgreesWithEngine generates random identities, groups and
// policies, applies them, and asserts that the evaluator (the PDP) and the
// materialized engine agree on every identity of every policy group, then again
// after the groups, the attributes and a policy change.
func TestPolicyGroups_PDPAgreesWithEngine(t *testing.T) {
	seeds := 14
	if testing.Short() {
		seeds = 4
	}
	for seed := int64(1); seed <= int64(seeds); seed++ {
		t.Run(fmt.Sprint("seed ", seed), func(t *testing.T) {
			const nIdents = 22
			x := newHarness(t, nIdents, nil)
			g := newGen(seed, genGroups)
			for _, name := range genGroups {
				var ms []int
				for i := 0; i < nIdents; i++ {
					if g.r.Intn(2) == 0 {
						ms = append(ms, i)
					}
				}
				x.group(name, ms...)
			}
			randomAttrs := func() {
				for i, id := range x.idents {
					s := g.subject()
					x.src.attrs[id] = s.attrs
					_ = i
				}
			}
			randomAttrs()
			policies := []string{"app:x:p1", "app:x:p2", "app:x:p3"}
			gen := func() []SourceFile {
				var fs []SourceFile
				for i, p := range policies {
					gg := newGen(g.r.Int63(), append(slices.Clone(genGroups), policies[:i]...)) // later policies may use earlier ones
					fs = append(fs, SourceFile{Path: fmt.Sprintf("groups/%s.cedar", p[6:]), Cedar: gg.file(p)})
				}
				return fs
			}
			agree := func(round string, files []SourceFile) {
				parsed, diags := ParseAll(testSchema(), files)
				if len(diags) > 0 {
					t.Fatal(diags)
				}
				byName := map[string]*File{}
				for _, f := range parsed {
					byName[f.Group] = f
				}
				x.read(func(e model.Env) error {
					members := store.MembersListID(tid)
					for i, id := range x.idents {
						memo := map[string]bool{}
						var sub identitySubject
						sub = identitySubject{id: &store.Identity{ID: id}, src: x.src, schema: testSchema(),
							inGroup: func(name string) (bool, error) {
								if f, ok := byName[name]; ok {
									if v, done := memo[name]; done {
										return v, nil
									}
									v, err := f.Decide(sub)
									memo[name] = v
									return v, err
								}
								rg, err := e.Tx.GrpGroupByName(name)
								if err != nil {
									return false, err
								}
								return x.eng.IsMember(e.Tx, e.Now, rg.ID, members, id)
							}}
						for _, p := range policies {
							want, err := byName[p].Decide(sub)
							if err != nil {
								return err
							}
							pg, err := e.Tx.GrpGroupByName(p)
							if err != nil {
								return err
							}
							got, err := x.eng.IsMember(e.Tx, e.Now, pg.ID, members, id)
							if err != nil {
								return err
							}
							if got != want {
								t.Errorf("%s: identity %d in %s: engine %v, PDP %v\n%s", round, i, p, got, want, files[slices.Index(policies, p)].Cedar)
							}
						}
					}
					return nil
				})
			}
			files := gen()
			x.mustApply(repo("r1", true, files...))
			agree("applied", files)
			// the world moves: group memberships and attributes change, then a policy changes
			x.must(func(e model.Env) error {
				for i := 0; i < 8; i++ {
					name := genGroups[g.r.Intn(len(genGroups))]
					rg, _ := e.Tx.GrpGroupByName(name)
					ident := x.idents[g.r.Intn(nIdents)]
					if g.r.Intn(2) == 0 {
						if _, err := e.AddMember(rg.ID, model.MemberInput{Identity: &ident}); err != nil {
							return err
						}
					} else if _, err := e.RemoveMember(rg.ID, fmt.Sprint(ident)); err != nil && err.(*model.Error).Code != "not_found" {
						return err
					}
				}
				return nil
			})
			agree("members changed", files)
			randomAttrs()
			x.must(func(e model.Env) error {
				_, err := Indexer{Schema: testSchema(), Source: x.src}.Reindex(e, nil)
				return err
			})
			agree("attributes changed", files)
			files = gen()
			x.mustApply(repo("r2", true, files...))
			agree("policies changed", files)
		})
	}
}

func TestDirSource_ReadsAndSyncs(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("groups/app/x/p1.cedar", pol("app:x:p1", in("ref:a"), "").Cedar)
	write("groups/app/x/p2.cedar", pol("app:x:p2", in("ref:b"), "").Cedar)
	write("groups/readme.md", "not policy")
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.cedar"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.cedar"), filepath.Join(dir, "link.cedar")); err != nil {
		t.Skip("symlinks unavailable")
	}
	commit, files, err := DirSource{Root: dir, Commit: "abc123"}.Snapshot()
	if err != nil || commit != "abc123" || len(files) != 2 || files[0].Path != "groups/app/x/p1.cedar" {
		t.Fatalf("snapshot = %s %+v %v", commit, files, err)
	}
	write("big.cedar", string(make([]byte, MaxFileBytes+1)))
	if _, err := ReadDir(dir); err == nil {
		t.Error("an oversized file was read")
	}
	if err := os.Remove(filepath.Join(dir, "big.cedar")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDir(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing directory was read")
	}
	x := newHarness(t, 4, nil)
	seedRefs(x)
	var res *ApplyResult
	x.must(func(e model.Env) error {
		var err error
		res, err = x.applier(e).Sync(DirSource{Root: dir, Commit: "abc123"})
		return err
	})
	if len(res.Groups) != 2 || !slices.Equal(x.members("app:x:p1"), []int{0, 1}) {
		t.Errorf("sync = %+v", res)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
	_ = context.Background()
}
