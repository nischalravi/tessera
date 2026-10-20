package loaders_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func wantMembers(t *testing.T, h *harness, group string, want []string) {
	t.Helper()
	if got := h.members(group); !slices.Equal(got, want) {
		t.Errorf("members of %s = %v, want %v", group, got, want)
	}
}

func tripRules(t *testing.T, run *store.GrpLoaderRun) []string {
	t.Helper()
	if run.FailsafeTripped == nil {
		return nil
	}
	var trips []loaders.Trip
	if err := json.Unmarshal([]byte(*run.FailsafeTripped), &trips); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, tr := range trips {
		out = append(out, tr.Rule)
	}
	return out
}

func impactOf(t *testing.T, run *store.GrpLoaderRun) loaders.Impact {
	t.Helper()
	var imp loaders.Impact
	if run.Impact == nil {
		t.Fatal("the run has no impact")
	}
	if err := json.Unmarshal([]byte(*run.Impact), &imp); err != nil {
		t.Fatal(err)
	}
	return imp
}

func errCode(err error) string {
	var me *model.Error
	if errors.As(err, &me) {
		return me.Code
	}
	return ""
}

// TestFailsafe_HoldsAndShowsImpact: a run that would remove too many members is
// held: nothing is applied, the run keeps the plan and the downstream impact,
// the loader refuses further runs, and an approval applies the plan as it was
// computed (not as the source reads by then) while a rejection discards it.
func TestFailsafe_HoldsAndShowsImpact(t *testing.T) {
	h := newHarness(t)
	h.write("staff.csv", people(seq(0, 10)...))
	l := h.create(h.csvSpec("Staff", "staff.csv", "staff"), "")
	first := h.run(l, store.RunFull)
	if first.Status != store.RunApplied || *first.Adds != 10 {
		t.Fatalf("first run = %+v, want applied with 10 adds", first)
	}
	wantMembers(t, h, "ref:staff", seq(0, 10))

	// something depends on the loader's group: a policy group (composite) that unions it with another
	var policy store.GroupID
	h.must(func(e model.Env) error {
		other, err := e.CreateGroup(model.CreateGroupInput{Folder: h.ref, Extension: "other"})
		if err != nil {
			return err
		}
		p, err := e.CreateGroup(model.CreateGroupInput{Folder: h.ref, Extension: "policy", Definition: store.DefinitionComposite,
			Op: store.CompUnion, Factors: []store.GroupID{h.group("ref:staff").ID, other.ID}})
		policy = p.ID
		return err
	})
	// two of the people who would be removed used some access last week
	h.usage(map[string]time.Duration{"u7": 3 * 24 * time.Hour, "u8": 2 * 24 * time.Hour, "u9": 60 * 24 * time.Hour})

	// the source now lists only u0..u3: six of ten would go (60%, limit 20%)
	h.now = h.now.Add(24 * time.Hour)
	h.write("staff.csv", people(seq(0, 4)...))
	held := h.run(l, store.RunFull)
	if held.Status != store.RunHeld {
		t.Fatalf("run = %s (%v), want held", held.Status, held.Error)
	}
	if rules := tripRules(t, held); !slices.Contains(rules, "max_removed_percent") {
		t.Errorf("tripped %v, want max_removed_percent", rules)
	}
	wantMembers(t, h, "ref:staff", seq(0, 10)) // nothing was applied
	if got := h.loader(l.ID).Status; got != store.LoaderHeld {
		t.Errorf("loader status = %s, want held", got)
	}
	imp := impactOf(t, held)
	if imp.RemovedIdentities != 6 || imp.AddedIdentities != 0 || len(imp.Groups) != 1 || imp.Groups[0].Name != "ref:staff" ||
		imp.Groups[0].Removed != 6 || imp.Groups[0].Current != 10 || imp.Groups[0].Size != 4 {
		t.Errorf("impact = %+v", imp)
	}
	if len(imp.PolicyGroups) != 1 || imp.PolicyGroups[0].Name != "ref:policy" || imp.PolicyGroups[0].ID != string(policy) ||
		imp.PolicyGroups[0].Because != "ref:staff" || imp.PolicyGroups[0].Definition != "composite" {
		t.Errorf("policy groups = %+v, want ref:policy", imp.PolicyGroups)
	}
	if imp.RemovedUsedLast30Days != 2 { // u7 and u8 used something in the last 30 days, u9 did not
		t.Errorf("removed people who used access last 30 days = %d, want 2", imp.RemovedUsedLast30Days)
	}
	if imp.ProvisionedTargets == nil || len(imp.ProvisionedTargets) != 0 {
		t.Errorf("provisioned targets = %v, want an empty list", imp.ProvisionedTargets)
	}
	if held.Plan == nil || held.Adds == nil || *held.Removes != 6 {
		t.Errorf("held run = %+v", held)
	}
	// the hold is audited, evented and listed as a task, and no membership changed
	if acts := h.auditActions(); !has(acts, "groups.loader.run.held") {
		t.Errorf("audit actions %v lack groups.loader.run.held", acts)
	}
	if evs := h.eventTypes("loader", l.ID); !has(evs, "loader.run.held") || has(evs, "loader.run.approved") {
		t.Errorf("loader events = %v", evs)
	}
	g := h.group("ref:staff")
	removedEvents := 0
	for _, e := range h.eventTypes("group", string(g.ID)) {
		if e == "membership.direct.removed" {
			removedEvents++
		}
	}
	if removedEvents != 0 {
		t.Errorf("%d membership.direct.removed events while the run is held", removedEvents)
	}
	h.read(func(tx *store.TenantTx) error {
		hs, err := tx.GrpLoaderHeldRuns()
		if err != nil || len(hs) != 1 || hs[0].ID != held.ID {
			t.Errorf("held runs = %v, %v", hs, err)
		}
		return nil
	})
	// a held loader runs no more (a preview is still allowed)
	if _, err := h.svc.Run(context.Background(), tid, l.ID, store.RunFull, loaders.Actor{}); errCode(err) != "loader_held" {
		t.Errorf("run of a held loader = %v, want loader_held", err)
	}
	if p := h.run(l, store.RunPreview); p.Status != store.RunPreviewed || p.Plan == nil {
		t.Errorf("preview of a held loader = %+v", p)
	}

	// the source recovers, but the approval applies the plan as it was computed
	h.write("staff.csv", people(seq(0, 10)...))
	apr, err := h.svc.Approve(context.Background(), tid, l.ID, held.ID, loaders.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	if apr.Status != store.RunApproved || *apr.Removes != 6 || apr.DecidedAt == nil {
		t.Errorf("approved run = %+v", apr)
	}
	wantMembers(t, h, "ref:staff", seq(0, 4))
	if got := h.loader(l.ID).Status; got != store.LoaderEnabled {
		t.Errorf("loader status after approval = %s", got)
	}
	if acts := h.auditActions(); !has(acts, "groups.loader.run.approved") {
		t.Errorf("audit actions lack groups.loader.run.approved")
	}
	if evs := h.eventTypes("loader", l.ID); !has(evs, "loader.run.approved") {
		t.Errorf("loader events = %v", evs)
	}
	if _, err := h.svc.Approve(context.Background(), tid, l.ID, held.ID, loaders.Actor{}); errCode(err) != "not_held" {
		t.Errorf("a decided run was approved again: %v", err)
	}
	// the next run reconciles with the recovered source
	h.now = h.now.Add(24 * time.Hour)
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied || *r.Adds != 6 {
		t.Errorf("run after the approval = %+v", r)
	}
	wantMembers(t, h, "ref:staff", seq(0, 10))

	// a rejection discards the plan
	h.now = h.now.Add(24 * time.Hour)
	h.write("staff.csv", people(seq(0, 3)...))
	again := h.run(l, store.RunFull)
	if again.Status != store.RunHeld {
		t.Fatalf("second hold = %s", again.Status)
	}
	rej, err := h.svc.Reject(context.Background(), tid, l.ID, again.ID, loaders.Actor{})
	if err != nil || rej.Status != store.RunRejected {
		t.Fatalf("reject = %+v, %v", rej, err)
	}
	wantMembers(t, h, "ref:staff", seq(0, 10))
	if got := h.loader(l.ID).Status; got != store.LoaderEnabled {
		t.Errorf("loader status after a rejection = %s", got)
	}
	if evs := h.eventTypes("loader", l.ID); !has(evs, "loader.run.rejected") {
		t.Errorf("loader events = %v", evs)
	}
	// a run of another loader is not decided through this one
	if _, err := h.svc.Reject(context.Background(), tid, l.ID, "00000000-0000-4000-8000-00000000dead", loaders.Actor{}); errCode(err) != "not_found" {
		t.Errorf("reject of an unknown run = %v", err)
	}
}

// TestFailsafe_Rules: each limit holds a run by itself, and a small change under
// every limit applies.
func TestFailsafe_Rules(t *testing.T) {
	loose := func(mut func(*loaders.Failsafe)) loaders.Failsafe {
		f := loaders.Failsafe{}
		hundred, big := 100.0, 1000
		f.MaxRemovedPercent, f.MaxGroupsEmptiedPercent, f.MaxUnresolvedPercent, f.MaxRemoved = &hundred, &hundred, &hundred, &big
		mut(&f)
		return f
	}
	two, three := 2, 3
	pct := 20.0
	for name, c := range map[string]struct {
		fs     loaders.Failsafe
		second string // the second read of the source
		want   string // the rule that trips, "" for applied
	}{
		"percent":      {loose(func(f *loaders.Failsafe) { f.MaxRemovedPercent = &pct }), people(seq(0, 7)...), "max_removed_percent"},
		"percent ok":   {loose(func(f *loaders.Failsafe) { f.MaxRemovedPercent = &pct }), people(seq(0, 8)...), ""},
		"absolute":     {loose(func(f *loaders.Failsafe) { f.MaxRemoved = &two }), people(seq(0, 7)...), "max_removed"},
		"absolute ok":  {loose(func(f *loaders.Failsafe) { f.MaxRemoved = &three }), people(seq(0, 7)...), ""},
		"minimum size": {loose(func(f *loaders.Failsafe) { f.MinGroupSize = &three }), people(seq(0, 2)...), "min_group_size"},
		"emptied":      {loose(func(f *loaders.Failsafe) { p := 5.0; f.MaxGroupsEmptiedPercent = &p }), people(), "max_groups_emptied_percent"},
		"unresolved":   {loose(func(f *loaders.Failsafe) { p := 10.0; f.MaxUnresolvedPercent = &p }), people(append(seq(0, 10), "x1", "x2")...), "max_unresolved_percent"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.write("a.csv", people(seq(0, 10)...))
			spec := h.csvSpec("A", "a.csv", "a")
			spec.Failsafe = &c.fs
			l := h.create(spec, "")
			if r := h.run(l, store.RunFull); r.Status != store.RunApplied {
				t.Fatalf("first run = %s %v", r.Status, r.Error)
			}
			h.now = h.now.Add(time.Hour * 24)
			h.write("a.csv", c.second)
			r := h.run(l, store.RunFull)
			switch {
			case c.want == "" && r.Status != store.RunApplied:
				t.Errorf("run = %s, want applied (tripped %v)", r.Status, tripRules(t, r))
			case c.want != "" && (r.Status != store.RunHeld || !slices.Contains(tripRules(t, r), c.want)):
				t.Errorf("run = %s, tripped %v, want held by %s", r.Status, tripRules(t, r), c.want)
			}
		})
	}
}

// TestUnresolved_NeverDropped: a subject no identity matches is listed with the
// groups that named it, counted in the failsafe, retried on every run and
// removed from the list only when it resolves or the source stops naming it.
func TestUnresolved_NeverDropped(t *testing.T) {
	h := newHarness(t)
	h.write("staff.csv", people(append(seq(0, 5), "ghost1", "ghost2")...))
	l := h.create(h.csvSpec("Staff", "staff.csv", "staff"), "")
	held := h.run(l, store.RunFull)
	if held.Status != store.RunHeld || !slices.Contains(tripRules(t, held), "max_unresolved_percent") || *held.Unresolved != 2 {
		t.Fatalf("run = %+v (tripped %v), want held by max_unresolved_percent with 2 unresolved", held, tripRules(t, held))
	}
	us := h.unresolved(l.ID)
	if len(us) != 2 || us[0].Identifier != "ghost1" || us[0].Source != "identity" || us[0].Groups != `["ref:staff"]` {
		t.Fatalf("unresolved = %+v", us)
	}
	var plan loaders.Plan
	if err := json.Unmarshal([]byte(*held.Plan), &plan); err != nil || len(plan.Unresolved) != 2 || plan.Counts.UnresolvedRefs != 2 || plan.Counts.SourceRefs != 7 {
		t.Errorf("the held plan lost its unresolved subjects: %+v, %v", plan, err)
	}
	h.read(func(tx *store.TenantTx) error { // nothing was applied: the group was not even created
		if _, err := tx.GrpGroupByName("ref:staff"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("group ref:staff after a held run = %v, want none", err)
		}
		return nil
	})
	if _, err := h.svc.Reject(context.Background(), tid, l.ID, held.ID, loaders.Actor{}); err != nil {
		t.Fatal(err)
	}
	firstSeen := us[0].FirstSeen

	// the loader tolerates them: the run applies, the subjects stay listed
	var spec loaders.Spec
	h.read(func(tx *store.TenantTx) error {
		cur, err := tx.GrpLoader(l.ID)
		if err != nil {
			return err
		}
		spec, err = loaders.SpecOf(cur)
		return err
	})
	hundred := 100.0
	spec.Failsafe = &loaders.Failsafe{MaxUnresolvedPercent: &hundred}
	if err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		_, err := loaders.Update(loaders.SaveEnv{Tx: tx, Now: h.now, Sealer: h.sealer}, l.ID, nil, spec, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(24 * time.Hour)
	r := h.run(l, store.RunFull)
	if r.Status != store.RunApplied || *r.Unresolved != 2 {
		t.Fatalf("run = %+v", r)
	}
	wantMembers(t, h, "ref:staff", seq(0, 5))
	if us := h.unresolved(l.ID); len(us) != 2 || !us[0].FirstSeen.Equal(firstSeen) || !us[0].LastSeen.After(firstSeen) {
		t.Errorf("unresolved after the run = %+v (first seen %v)", us, firstSeen)
	}

	// ghost1 becomes an identity: it joins the group on the next run and leaves the list; ghost2 stays
	h.must(func(e model.Env) error {
		_, err := e.Tx.InsertIdentity(&store.Identity{ExternalID: "ghost1", Name: "Ghost", Type: "human", Status: "active", CreatedAt: h.now})
		return err
	})
	h.now = h.now.Add(24 * time.Hour)
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied || *r.Unresolved != 1 || *r.Adds != 1 {
		t.Errorf("run after ghost1 exists = %+v", r)
	}
	if us := h.unresolved(l.ID); len(us) != 1 || us[0].Identifier != "ghost2" {
		t.Errorf("unresolved = %+v, want ghost2 only", us)
	}
	// the source stops naming ghost2: it leaves the list
	h.now = h.now.Add(24 * time.Hour)
	h.write("staff.csv", people(append(seq(0, 5), "ghost1")...))
	h.run(l, store.RunFull)
	if us := h.unresolved(l.ID); len(us) != 0 {
		t.Errorf("unresolved = %+v, want none", us)
	}
	// a preview does not touch the list
	h.write("staff.csv", people(append(seq(0, 5), "ghost1", "ghost3")...))
	if p := h.run(l, store.RunPreview); *p.Unresolved != 1 {
		t.Errorf("preview = %+v", p)
	}
	if us := h.unresolved(l.ID); len(us) != 0 {
		t.Errorf("a preview recorded unresolved subjects: %+v", us)
	}
}

// TestSQLLoader_RejectsWrites: a loader's query is one SELECT or WITH; anything
// that writes, attaches or runs a second statement is refused when the loader
// is saved (and again when it runs, on a read-only connection), and a source
// file outside the data directory is never opened.
func TestSQLLoader_RejectsWrites(t *testing.T) {
	good := []string{`SELECT external_id AS subject_id FROM identities`, "select 1 as subject_id;",
		`WITH x AS (SELECT external_id FROM identities) SELECT external_id AS subject_id FROM x`,
		`SELECT replace(external_id, 'a', 'b') AS subject_id FROM identities`,
		`SELECT "update" AS subject_id FROM t`}
	for _, q := range good {
		if err := loaders.CheckReadOnlySQL(q); err != nil {
			t.Errorf("%q refused: %v", q, err)
		}
	}
	bad := map[string]string{
		"insert": `INSERT INTO identities (external_id) VALUES ('x')`, "update": `UPDATE identities SET name = 'x'`,
		"delete": `DELETE FROM identities`, "drop": `DROP TABLE identities`, "create": `CREATE TABLE x (a)`,
		"attach": `ATTACH DATABASE 'x.db' AS x`, "pragma": `PRAGMA writable_schema = 1`, "vacuum": `VACUUM INTO 'x.db'`,
		"two statements": `SELECT 1; DROP TABLE identities`, "with delete": `WITH x AS (SELECT 1) DELETE FROM identities`,
		"comment": `SELECT 1 -- ; DROP TABLE x`, "block comment": `SELECT 1 /* x */`, "empty": ``, "blank": "  \n",
		"starts with a word": `EXPLAIN SELECT 1`, "load extension": `SELECT load_extension('x')`, "nul": "SELECT 1\x00",
		"huge": `SELECT ` + strings.Repeat("1,", 20000) + `1`,
	}
	h := newHarness(t)
	for name, q := range bad {
		if err := loaders.CheckReadOnlySQL(q); err == nil {
			t.Errorf("%s: %q was accepted", name, q)
		}
		spec := loaders.Spec{Name: "W " + name, Type: loaders.TypeSQLGroupList, TargetFolder: string(h.ref),
			Config: []byte(fmt.Sprintf(`{"database":"hr.db","query":%q}`, q))}
		err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
			_, err := loaders.Create(loaders.SaveEnv{Tx: tx, Now: h.now}, spec, "")
			return err
		})
		if errCode(err) != "invalid_config" {
			t.Errorf("%s: saving the loader = %v, want invalid_config", name, err)
		}
	}

	// a good loader runs against a source that cannot be changed through it
	h.hrAdd("hr.db", hrRow{xid: "u0", dept: "eng"}, hrRow{xid: "u1", dept: "eng"}, hrRow{xid: "u2", dept: "ops"})
	spec := loaders.Spec{Name: "HR", Type: loaders.TypeSQLGroupList, TargetFolder: string(h.ref),
		Config: []byte(`{"database":"hr.db","query":"SELECT department AS group_name, external_id AS subject_id FROM identities"}`)}
	l := h.create(spec, "")
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied || *r.SourceRows != 3 {
		t.Fatalf("run = %+v", r)
	}
	wantMembers(t, h, "ref:eng", []string{"u0", "u1"})
	wantMembers(t, h, "ref:ops", []string{"u2"})
	var n int
	h.hr("hr.db", func(tx *store.TenantTx) error {
		ids, err := tx.Identities()
		n = len(ids)
		return err
	})
	if n != 3 {
		t.Errorf("the source database has %d rows after the run, want 3", n)
	}

	// the database name is a file under the data directory: no path out of it
	for i, db := range []string{"../hr.db", "/etc/passwd", "a/../../hr.db", "", ".hidden/..", "hr.db\x00", "x y.db", strings.Repeat("a", 300)} {
		s := spec
		s.Name = fmt.Sprintf("Path %d", i)
		s.Config = []byte(fmt.Sprintf(`{"database":%q,"query":"SELECT 1 AS group_name, 1 AS subject_id"}`, db))
		err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
			_, err := loaders.Create(loaders.SaveEnv{Tx: tx, Now: h.now}, s, "")
			return err
		})
		if errCode(err) != "invalid_config" {
			t.Errorf("database %q: saving the loader = %v, want invalid_config", db, err)
		}
	}
}

// TestRecentMemberships_FromPIT: recent_memberships is exact because it reads
// the point-in-time history: the people who were members at some time in the
// window and are not now, and with include_current the current members too.
func TestRecentMemberships_FromPIT(t *testing.T) {
	h := newHarness(t)
	day := 24 * time.Hour
	var src store.GroupID
	h.must(func(e model.Env) error {
		g, err := e.CreateGroup(model.CreateGroupInput{Folder: h.ref, Extension: "staff"})
		src = g.ID
		return err
	})
	add := func(x string) {
		h.must(func(e model.Env) error {
			id := h.idents[x]
			_, err := e.AddMember(src, model.MemberInput{Identity: &id})
			return err
		})
	}
	remove := func(x string) {
		h.must(func(e model.Env) error {
			_, err := e.RemoveMember(src, fmt.Sprint(h.idents[x]))
			return err
		})
	}
	add("u0") // t0: a member throughout
	add("u1") // t0: left long ago
	add("u2") // t0: left within the window
	h.now = t0.Add(20 * day)
	remove("u1") // t0+20d: 80 days before "now"
	h.now = t0.Add(90 * day)
	remove("u2") // t0+90d: 10 days before "now"
	h.now = t0.Add(95 * day)
	add("u3") // t0+95d: joined 5 days before "now", still a member
	h.now = t0.Add(100 * day)

	mk := func(name string, include bool) *store.GrpLoader {
		return h.create(loaders.Spec{Name: name, Type: loaders.TypeRecent, TargetFolder: string(h.ref),
			Config: []byte(fmt.Sprintf(`{"source_group":"ref:staff","days":30,"include_current":%t,"group":%q}`, include, name))}, "")
	}
	left := mk("left", false)
	if r := h.run(left, store.RunFull); r.Status != store.RunApplied {
		t.Fatalf("run = %+v", r)
	}
	wantMembers(t, h, "ref:left", []string{"u2"}) // u1 left outside the window; u0 and u3 are current
	all := mk("all", true)
	h.run(all, store.RunFull)
	wantMembers(t, h, "ref:all", []string{"u0", "u2", "u3"})

	// a window of 5 days: u2 left 10 days ago and is out; u3 joined inside it
	short := h.create(loaders.Spec{Name: "short", Type: loaders.TypeRecent, TargetFolder: string(h.ref),
		Config: []byte(`{"source_group":"ref:staff","days":6,"include_current":true,"group":"short"}`)}, "")
	h.run(short, store.RunFull)
	wantMembers(t, h, "ref:short", []string{"u0", "u3"})

	// the history moves on: u0 leaves today, and the next run of "left" has two people
	remove("u0")
	h.now = h.now.Add(day)
	h.run(left, store.RunFull)
	wantMembers(t, h, "ref:left", []string{"u0", "u2"})
	// the group the source names must exist
	bad := h.create(loaders.Spec{Name: "bad", Type: loaders.TypeRecent, TargetFolder: string(h.ref),
		Config: []byte(`{"source_group":"ref:nothing","days":30,"group":"bad"}`)}, "")
	if r := h.run(bad, store.RunFull); r.Status != store.RunFailed || !strings.Contains(*r.Error, "source_group_missing") {
		t.Errorf("run with an unknown source group = %+v", r)
	}
	// the window is bounded by the history's longest window
	err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		_, err := loaders.Create(loaders.SaveEnv{Tx: tx, Now: h.now}, loaders.Spec{Name: "long", Type: loaders.TypeRecent,
			TargetFolder: string(h.ref), Config: []byte(`{"source_group":"ref:staff","days":400,"group":"long"}`)}, "")
		return err
	})
	if errCode(err) != "invalid_config" {
		t.Errorf("a window of 400 days = %v, want invalid_config", err)
	}
}
