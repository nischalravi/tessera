package loaders_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func TestValidateConfig(t *testing.T) {
	type c struct {
		typ, cfg string
		conn     bool
		want     string // "" for valid, else a fragment of the error
	}
	for name, tc := range map[string]c{
		"sql_simple ok":       {loaders.TypeSQLSimple, `{"database":"hr.db","group":"staff","query":"SELECT id AS subject_id FROM t"}`, false, ""},
		"sql_simple no group": {loaders.TypeSQLSimple, `{"database":"hr.db","query":"SELECT 1"}`, false, "group"},
		"sql_simple groups_query": {loaders.TypeSQLSimple, `{"database":"hr.db","group":"g","query":"SELECT 1","groups_query":"SELECT 1"}`, false,
			"groups_query is only for sql_group_list"},
		"sql_group_list group": {loaders.TypeSQLGroupList, `{"database":"hr.db","group":"g","query":"SELECT 1"}`, false, "group is only for sql_simple"},
		"sql incremental":      {loaders.TypeSQLGroupList, `{"database":"hr.db","query":"SELECT 1","incremental_query":"SELECT 1"}`, false, "@cursor"},
		"sql incremental ok":   {loaders.TypeSQLGroupList, `{"database":"hr.db","query":"SELECT 1","incremental_query":"SELECT 1 WHERE 1 > @cursor"}`, false, ""},
		"sql incremental write": {loaders.TypeSQLGroupList, `{"database":"hr.db","query":"SELECT 1","incremental_query":"DELETE FROM t WHERE x > @cursor"}`, false,
			"incremental_query"},
		"sql unknown field": {loaders.TypeSQLGroupList, `{"database":"hr.db","query":"SELECT 1","shell":"rm -rf /"}`, false, "unknown field"},
		"sql trailing":      {loaders.TypeSQLGroupList, `{"database":"hr.db","query":"SELECT 1"} {}`, false, "trailing data"},
		"sql dsn":           {loaders.TypeSQLGroupList, `{"database":"postgres://u:p@host/db","query":"SELECT 1"}`, false, "database is a file name"},
		"csv path ok":       {loaders.TypeCSV, `{"path":"a/b.csv","group":"g","subject_column":"id"}`, false, ""},
		"csv url ok":        {loaders.TypeCSV, `{"url":"https://example.org/a.csv","group_column":"g","subject_column":"id"}`, false, ""},
		"csv both":          {loaders.TypeCSV, `{"path":"a.csv","url":"https://example.org/a.csv","group":"g","subject_column":"id"}`, false, "exactly one of path and url"},
		"csv neither":       {loaders.TypeCSV, `{"group":"g","subject_column":"id"}`, false, "exactly one of path and url"},
		"csv url creds":     {loaders.TypeCSV, `{"url":"https://u:p@example.org/a.csv","group":"g","subject_column":"id"}`, false, "without credentials"},
		"csv file url":      {loaders.TypeCSV, `{"url":"file:///etc/passwd","group":"g","subject_column":"id"}`, false, "https URL"},
		"csv no group":      {loaders.TypeCSV, `{"path":"a.csv","subject_column":"id"}`, false, "group (one group"},
		"csv group and col": {loaders.TypeCSV, `{"path":"a.csv","group":"g","group_column":"g","subject_column":"id"}`, false, "not both"},
		"csv bad group":     {loaders.TypeCSV, `{"path":"a.csv","group":"a b","subject_column":"id"}`, false, "group:"},
		"csv delimiter":     {loaders.TypeCSV, `{"path":"a.csv","group":"g","subject_column":"id","delimiter":"ab"}`, false, "delimiter"},
		"csv quote delim":   {loaders.TypeCSV, `{"path":"a.csv","group":"g","subject_column":"id","delimiter":"\""}`, false, "delimiter"},
		"csv source twice":  {loaders.TypeCSV, `{"path":"a.csv","group":"g","subject_column":"id","source_column":"s","subject_source":"hris"}`, false, "not both"},
		"csv no column":     {loaders.TypeCSV, `{"path":"a.csv","group":"g"}`, false, "subject_column"},
		"csv up path":       {loaders.TypeCSV, `{"path":"../a.csv","group":"g","subject_column":"id"}`, false, "path is a file name"},
		"connector ok":      {loaders.TypeConnectorGroups, `{"name_prefix":"okta_"}`, true, ""},
		"connector no conn": {loaders.TypeConnectorGroups, `{}`, false, "connection_id"},
		"connector prefix":  {loaders.TypeConnectorGroups, `{"name_prefix":"a b"}`, true, "prefix"},
		"attribute ok":      {loaders.TypeAttribute, `{"attribute":"department","prefix":"dept-"}`, false, ""},
		"attribute unknown": {loaders.TypeAttribute, `{"attribute":"password_hash"}`, false, "attribute is one of"},
		"recent ok":         {loaders.TypeRecent, `{"source_group":"a:b","days":30,"group":"g"}`, false, ""},
		"recent days":       {loaders.TypeRecent, `{"source_group":"a:b","days":0,"group":"g"}`, false, "days"},
		"recent no group":   {loaders.TypeRecent, `{"source_group":"a:b","days":3}`, false, "segment"},
		"ldap unavailable":  {"ldap_attribute", `{}`, false, "not available yet"},
		"sftp unavailable":  {"sftp_csv", `{}`, false, "not available yet"},
		"unknown type":      {"shell", `{}`, false, "type is one of"},
		"empty":             {loaders.TypeCSV, ``, false, "config is required"},
		"not an object":     {loaders.TypeCSV, `[]`, false, "cannot unmarshal"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := loaders.ValidateConfig(tc.typ, json.RawMessage(tc.cfg), tc.conn)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("refused: %v", err)
			case tc.want == "" && !json.Valid(out):
				t.Errorf("canonical config %q is not JSON", out)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("error = %v, want one that says %q", err, tc.want)
			}
		})
	}
	// a config that is valid is returned in canonical form: the same input twice gives the same bytes
	a, _ := loaders.ValidateConfig(loaders.TypeCSV, json.RawMessage(`{"subject_column":"id", "path":"a.csv", "group":"g"}`), false)
	b, _ := loaders.ValidateConfig(loaders.TypeCSV, json.RawMessage(`{"group":"g","path":"a.csv","subject_column":"id"}`), false)
	if string(a) != string(b) {
		t.Errorf("canonical forms differ: %s vs %s", a, b)
	}
}

func TestNameTemplate(t *testing.T) {
	for tmpl, want := range map[string]string{"{{.Name}}": "x", "prefix_{{.Name}}": "prefix_x", "{{.Name}}.src": "x.src"} {
		if err := loaders.ValidateTemplate(tmpl); err != nil {
			t.Errorf("%q refused: %v", tmpl, err)
		}
		if got := loaders.ApplyTemplate(tmpl, "x"); got != want {
			t.Errorf("ApplyTemplate(%q) = %q, want %q", tmpl, got, want)
		}
	}
	// no code runs: anything but the one name token is refused
	for _, bad := range []string{"", "plain", "{{.Name}}{{.Name}}", "{{ .Name }}", `{{printf "%s" .Name}}`, "{{.Name}} x", "a:{{.Name}}", "{{.Name | html}}"} {
		if err := loaders.ValidateTemplate(bad); err == nil {
			t.Errorf("template %q was accepted", bad)
		}
	}
}

func TestSchedule(t *testing.T) {
	at := func(s string) time.Time {
		tt, err := time.Parse("2006-01-02 15:04", s)
		if err != nil {
			t.Fatal(err)
		}
		return tt
	}
	for _, c := range []struct{ expr, after, want string }{
		{"@daily", "2026-10-08 09:30", "2026-10-09 00:00"},
		{"@hourly", "2026-10-08 09:30", "2026-10-08 10:00"},
		{"@weekly", "2026-10-08 09:30", "2026-10-11 00:00"}, // the 8th is a Thursday
		{"*/15 * * * *", "2026-10-08 09:30", "2026-10-08 09:45"},
		{"0 3 * * *", "2026-10-08 03:00", "2026-10-09 03:00"}, // strictly after
		{"30 2 1 * *", "2026-10-08 09:30", "2026-11-01 02:30"},
		{"0 9 * * mon-fri", "2026-10-09 09:00", "2026-10-12 09:00"}, // Friday to Monday
		{"0 0 29 feb *", "2026-10-08 09:30", "2028-02-29 00:00"},
		{"5,35 8-10 * * *", "2026-10-08 09:40", "2026-10-08 10:05"},
		{"5,35 8-10 * * *", "2026-10-08 10:35", "2026-10-09 08:05"},
		{"0 0 1,15 * 1", "2026-10-08 09:30", "2026-10-12 00:00"}, // a restricted day of month and of week: either
		{"0 12 * * 7", "2026-10-08 09:30", "2026-10-11 12:00"},   // 7 is Sunday
		{"0 0 * jan *", "2026-10-08 09:30", "2027-01-01 00:00"},
	} {
		s, err := loaders.ParseSchedule(c.expr)
		if err != nil {
			t.Errorf("%s: %v", c.expr, err)
			continue
		}
		if got := s.Next(at(c.after)); !got.Equal(at(c.want)) {
			t.Errorf("%s after %s = %s, want %s", c.expr, c.after, got.Format("2006-01-02 15:04"), c.want)
		}
	}
	if s, _ := loaders.ParseSchedule("0 0 30 feb *"); !s.Next(at("2026-10-08 09:30")).IsZero() {
		t.Error("30 February fires")
	}
	for _, bad := range []string{"", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "*/0 * * * *",
		"5-1 * * * *", "a * * * *", "@yearly", "@reboot", "1,,2 * * * *"} {
		if _, err := loaders.ParseSchedule(bad); err == nil {
			t.Errorf("schedule %q was accepted", bad)
		}
	}
	s, _ := loaders.ParseSchedule("0 3 * * *")
	if s.Due(at("2026-10-08 03:00"), at("2026-10-09 02:59")) || !s.Due(at("2026-10-08 03:00"), at("2026-10-09 03:00")) {
		t.Error("Due is not 'the schedule fired since the last run'")
	}
}

func TestFailsafe_NormalizeAndEvaluate(t *testing.T) {
	f, err := loaders.Failsafe{}.Normalize()
	if err != nil || *f.MaxRemovedPercent != 20 || *f.MaxRemoved != 500 || *f.MaxGroupsEmptiedPercent != 5 || *f.MaxUnresolvedPercent != 2 || f.MinGroupSize != nil {
		t.Fatalf("defaults = %+v, %v", f, err)
	}
	neg, hundred1 := -1, 101.0
	for name, bad := range map[string]loaders.Failsafe{"percent": {MaxRemovedPercent: &hundred1}, "removed": {MaxRemoved: &neg},
		"min": {MinGroupSize: &neg}, "unresolved": {MaxUnresolvedPercent: &hundred1}, "emptied": {MaxGroupsEmptiedPercent: &hundred1}} {
		if _, err := bad.Normalize(); err == nil {
			t.Errorf("%s: an invalid failsafe was accepted", name)
		}
	}
	plan := &loaders.Plan{Groups: []loaders.GroupPlan{
		{Name: "a", Current: 100, Size: 70, Remove: make([]int64, 30)},         // 30%: over the percent
		{Name: "b", Current: 10000, Size: 9400, Remove: make([]int64, 600)},    // 6%: over the absolute
		{Name: "c", Current: 4, Size: 0, Remove: make([]int64, 4)},             // emptied
		{Name: "d", Current: 0, Size: 0},                                       // nothing there to empty
		{Name: "e", Missing: true, Action: "delete", Current: 0},               // a deleted group counts
		{Name: "f", Current: 50, Size: 49, Remove: make([]int64, 1), Add: nil}, // fine
	}}
	trips := f.Evaluate(plan, loaders.Counts{LoaderGroups: 6, SourceRefs: 200, UnresolvedRefs: 10})
	var rules []string
	for _, tr := range trips {
		rules = append(rules, tr.Rule+":"+tr.Group)
	}
	want := []string{"max_groups_emptied_percent:", "max_removed:b", "max_removed_percent:a", "max_removed_percent:c", "max_unresolved_percent:"}
	if fmt.Sprint(rules) != fmt.Sprint(want) {
		t.Errorf("trips = %v, want %v", rules, want)
	}
	for _, tr := range trips {
		if tr.Detail == "" {
			t.Errorf("trip %s says nothing", tr.Rule)
		}
	}
	// no groups yet: nothing can be emptied; no references: no unresolved percentage
	if trips := f.Evaluate(&loaders.Plan{Groups: []loaders.GroupPlan{{Name: "new", Create: true, Size: 5}}}, loaders.Counts{}); len(trips) != 0 {
		t.Errorf("a first run tripped %v", trips)
	}
	min := 3
	f.MinGroupSize = &min
	if trips := f.Evaluate(&loaders.Plan{Groups: []loaders.GroupPlan{{Name: "tiny", Size: 2}, {Name: "gone", Missing: true, Action: "empty"}}}, loaders.Counts{}); len(trips) != 1 || trips[0].Rule != "min_group_size" {
		t.Errorf("minimum size trips = %v", trips)
	}
}

// TestResolver: subjects match exactly, by the source they name, and follow merges.
func TestResolver(t *testing.T) {
	h := newHarness(t)
	h.must(func(e model.Env) error {
		// an account of the system "okta" that belongs to u4, an account that belongs to no one, and identities of source "workday"
		if _, err := e.Tx.InsertAccount(&store.Account{System: "okta", ExternalID: "00u4", IdentityID: ptr(h.idents["u4"]), Username: "u4", Kind: "human", Status: "active"}); err != nil {
			return err
		}
		if _, err := e.Tx.InsertAccount(&store.Account{System: "okta", ExternalID: "00uX", Username: "x", Kind: "human", Status: "active"}); err != nil {
			return err
		}
		src := "workday"
		xid := "W-100"
		_, err := e.Tx.InsertIdentity(&store.Identity{ExternalID: xid, Name: "WD", Type: "human", Status: "active", Source: &src, CreatedAt: t0})
		return err
	})
	var r *loaders.Resolver
	h.read(func(tx *store.TenantTx) error {
		var err error
		r, err = loaders.NewResolver(tx)
		return err
	})
	for name, c := range map[string]struct {
		ref  loaders.SubjectRef
		want string // external id of the identity, "" for unresolved
	}{
		"external id":         {loaders.SubjectRef{Source: "identity", Identifier: "u1"}, "u1"},
		"no source":           {loaders.SubjectRef{Identifier: "u2"}, "u2"},
		"spaces":              {loaders.SubjectRef{Identifier: "  u2 "}, "u2"},
		"email":               {loaders.SubjectRef{Source: "email", Identifier: "U3@Example.edu"}, "u3"},
		"tessera id":          {loaders.SubjectRef{Source: "tessera_id", Identifier: fmt.Sprint(h.idents["u5"])}, "u5"},
		"account":             {loaders.SubjectRef{Source: "okta", Identifier: "00u4"}, "u4"},
		"account source case": {loaders.SubjectRef{Source: "OKTA", Identifier: "00u4"}, "u4"},
		"account of no one":   {loaders.SubjectRef{Source: "okta", Identifier: "00uX"}, ""},
		"identity source":     {loaders.SubjectRef{Source: "workday", Identifier: "W-100"}, "W-100"},
		"wrong source":        {loaders.SubjectRef{Source: "sis", Identifier: "W-100"}, ""},
		"unknown":             {loaders.SubjectRef{Identifier: "nobody"}, ""},
		"empty":               {loaders.SubjectRef{Identifier: " "}, ""},
		"email unknown":       {loaders.SubjectRef{Source: "email", Identifier: "x@example.edu"}, ""},
		"bad tessera id":      {loaders.SubjectRef{Source: "tessera_id", Identifier: "99999"}, ""},
		"not a number":        {loaders.SubjectRef{Source: "tessera_id", Identifier: "abc"}, ""},
		"no fuzzy match":      {loaders.SubjectRef{Identifier: "U1"}, ""},
	} {
		id, ok := r.Resolve(c.ref)
		got := ""
		if ok {
			h.read(func(tx *store.TenantTx) error {
				i, err := tx.Identity(id)
				got = i.ExternalID
				return err
			})
		}
		if got != c.want {
			t.Errorf("%s: resolved to %q, want %q", name, got, c.want)
		}
	}
	// two identities with one email match no one
	h.must(func(e model.Env) error {
		em := "dup@example.edu"
		for _, x := range []string{"d1", "d2"} {
			if _, err := e.Tx.InsertIdentity(&store.Identity{ExternalID: x, Name: x, Email: &em, Type: "human", Status: "active", CreatedAt: t0}); err != nil {
				return err
			}
		}
		return nil
	})
	h.read(func(tx *store.TenantTx) error {
		var err error
		r, err = loaders.NewResolver(tx)
		return err
	})
	if _, ok := r.Resolve(loaders.SubjectRef{Source: "email", Identifier: "dup@example.edu"}); ok {
		t.Error("an email two identities share resolved to one of them")
	}
}

// TestSave: what a loader's definition must satisfy, and what a save records.
func TestSave(t *testing.T) {
	h := newHarness(t)
	base := h.csvSpec("Base", "a.csv", "g")
	save := func(spec loaders.Spec) (*store.GrpLoader, error) {
		var l *store.GrpLoader
		err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
			var err error
			l, err = loaders.Create(loaders.SaveEnv{Tx: tx, Now: h.now, Sealer: h.sealer}, spec, "")
			return err
		})
		return l, err
	}
	l, err := save(base)
	if err != nil {
		t.Fatal(err)
	}
	if l.NameTemplate != "{{.Name}}" || l.OnMissingGroup != "empty" || l.Schedule != "@daily" || l.Status != store.LoaderEnabled || l.Version != 1 {
		t.Errorf("defaults = %+v", l)
	}
	if fs, err := loaders.ParseFailsafe(l.Failsafe); err != nil || *fs.MaxRemovedPercent != 20 {
		t.Errorf("the stored failsafe has no defaults filled: %q, %v", l.Failsafe, err)
	}
	mut := func(f func(*loaders.Spec)) loaders.Spec {
		s := base
		s.Name = fmt.Sprintf("S%d", time.Now().UnixNano())
		f(&s)
		return s
	}
	for name, c := range map[string]struct {
		spec loaders.Spec
		want string
	}{
		"name taken":      {mut(func(s *loaders.Spec) { s.Name = "base" }), "name_taken"},
		"blank name":      {mut(func(s *loaders.Spec) { s.Name = "  " }), "invalid_name"},
		"control name":    {mut(func(s *loaders.Spec) { s.Name = "a\nb" }), "invalid_name"},
		"long name":       {mut(func(s *loaders.Spec) { s.Name = strings.Repeat("n", 129) }), "invalid_name"},
		"no folder":       {mut(func(s *loaders.Spec) { s.TargetFolder = "" }), "invalid_target_folder"},
		"unknown folder":  {mut(func(s *loaders.Spec) { s.TargetFolder = "00000000-0000-4000-8000-00000000dead" }), "unknown_folder"},
		"unknown group":   {mut(func(s *loaders.Spec) { s.AndGroup = "00000000-0000-4000-8000-00000000dead" }), "unknown_group"},
		"unknown type":    {mut(func(s *loaders.Spec) { s.Type = "shell" }), "invalid_type"},
		"ldap":            {mut(func(s *loaders.Spec) { s.Type = "ldap_attribute" }), "loader_type_unavailable"},
		"template":        {mut(func(s *loaders.Spec) { s.NameTemplate = "x" }), "invalid_name_template"},
		"on missing":      {mut(func(s *loaders.Spec) { s.OnMissingGroup = "explode" }), "invalid_on_missing_group"},
		"schedule":        {mut(func(s *loaders.Spec) { s.Schedule = "every day" }), "invalid_schedule"},
		"status":          {mut(func(s *loaders.Spec) { s.Status = "held" }), "invalid_status"},
		"incremental":     {mut(func(s *loaders.Spec) { v := int64(60); s.IncrementalSecs = &v }), "invalid_incremental"},
		"incremental low": {mut(func(s *loaders.Spec) { v := int64(5); s.IncrementalSecs = &v }), "invalid_incremental"},
		"failsafe":        {mut(func(s *loaders.Spec) { v := 150.0; s.Failsafe = &loaders.Failsafe{MaxRemovedPercent: &v} }), "invalid_failsafe"},
		"a valid copy":    {mut(func(s *loaders.Spec) {}), ""},
	} {
		_, err := save(c.spec)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if errCode(err) != c.want {
			t.Errorf("%s: %v, want %s", name, err, c.want)
		}
	}
	// update: the type is fixed, the version is checked, the audit event says what changed
	spec, _ := loaders.SpecOf(l)
	spec.Schedule = "0 3 * * *"
	update := func(version *int64, s loaders.Spec, secret *string) (*store.GrpLoader, error) {
		var out *store.GrpLoader
		err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
			var err error
			out, err = loaders.Update(loaders.SaveEnv{Tx: tx, Now: h.now, Sealer: h.sealer}, l.ID, version, s, secret)
			return err
		})
		return out, err
	}
	stale := int64(7)
	if _, err := update(&stale, spec, nil); errCode(err) != "version_conflict" {
		t.Errorf("stale update = %v", err)
	}
	cur := int64(1)
	u, err := update(&cur, spec, nil)
	if err != nil || u.Version != 2 || u.Schedule != "0 3 * * *" {
		t.Fatalf("update = %+v, %v", u, err)
	}
	spec.Type = loaders.TypeAttribute
	if _, err := update(nil, spec, nil); errCode(err) != "type_immutable" {
		t.Errorf("type change = %v", err)
	}
	if acts := h.auditActions(); !has(acts, "groups.loader.created") || !has(acts, "groups.loader.updated") {
		t.Errorf("audit actions = %v", acts)
	}
	if _, err := update(nil, loaders.Spec{}, nil); err == nil {
		t.Error("an empty spec updated a loader")
	}
	// a held loader cannot be disabled by hand, an enabled one can
	if err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		return tx.SetGrpLoaderStatus(l.ID, store.LoaderHeld, h.now)
	}); err != nil {
		t.Fatal(err)
	}
	spec2, _ := loaders.SpecOf(h.loader(l.ID))
	if spec2.Status != "" {
		t.Errorf("the spec of a held loader says status %q", spec2.Status)
	}
	spec2.Status = store.LoaderDisabled
	if _, err := update(nil, spec2, nil); errCode(err) != "loader_held" {
		t.Errorf("disabling a held loader = %v", err)
	}
	spec2.Status = ""
	if u, err := update(nil, spec2, nil); err != nil || u.Status != store.LoaderHeld {
		t.Errorf("a change to a held loader = %+v, %v", u, err)
	}
	// an unknown loader
	if _, err := h.svc.Run(context.Background(), tid, "00000000-0000-4000-8000-00000000dead", store.RunFull, loaders.Actor{}); errCode(err) != "not_found" {
		t.Errorf("run of an unknown loader = %v", err)
	}
	if _, err := h.svc.Run(context.Background(), tid, l.ID, "nightly", loaders.Actor{}); errCode(err) != "invalid_kind" {
		t.Errorf("run of an unknown kind = %v", err)
	}
}
