package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// Group loaders over HTTP (issue #53, GR-10): configuration needs
// groups.loader.admin, a fresh step-up and stem_admin on the loader's folder; a
// SQL loader waits for a second admin; a held run is an Inbox task that an
// approval applies as it was computed.

// newLoaderEnv is tenant B's server with a data directory for the loaders'
// files and a sealer, and a tenant_admin client.
func newLoaderEnv(t *testing.T) (*privEnv, string) {
	t.Helper()
	f := storetest.TwoTenants(t)
	dir := t.TempDir()
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Config{Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Connectors: func(now time.Time) ([]connectors.Connector, error) {
			return []connectors.Connector{connectors.Tiny{Now: now}}, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AllowedOrigins: []string{"http://localhost:5173"}, Env: "test",
		RateLimits: noRateLimits, Sealer: sealer, LoaderDataDir: dir})
	e := &privEnv{t: t, f: f, srv: srv}
	e.admin = e.as("admin", []auth.Role{auth.RoleTenantAdmin}, nil)
	own := filepath.Join(dir, f.B.ID.String()) // tenant B's files: <data dir>/<tenant id>/
	if err := os.MkdirAll(own, 0o750); err != nil {
		t.Fatal(err)
	}
	return e, own
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func csvLoaderBody(name, folder, file, group string, extra string) string {
	return fmt.Sprintf(`{"name":%q,"type":"csv","target_folder":%q,"config":{"path":%q,"group":%q,"subject_column":"id"}%s}`,
		name, folder, file, group, extra)
}

func lItems(m map[string]any) []any { v, _ := m["items"].([]any); return v }

func TestLoadersAPI_Lifecycle(t *testing.T) {
	e, dir := newLoaderEnv(t)
	writeFile(t, dir, "people.csv", "id\nalice\nbob\ncarol\ndave\n")
	app := e.admin.folder("", "app")
	ld := e.admin.call("POST", "/api/groups/loaders", csvLoaderBody("Staff", app, "people.csv", "staff", ""), 201)
	id := ld["id"].(string)
	if ld["status"] != "enabled" || ld["requires_approval"] != false || ld["has_secret"] != false || ld["version"] != float64(1) ||
		ld["target_folder"] != "app" || ld["type"] != "csv" || ld["schedule"] != "@daily" {
		t.Fatalf("created loader = %v", ld)
	}
	if fs, _ := ld["failsafe"].(map[string]any); fs["max_removed_percent"] != float64(20) || fs["max_removed"] != float64(500) {
		t.Errorf("failsafe = %v, want the defaults filled in", ld["failsafe"])
	}
	if cfg, _ := ld["config"].(map[string]any); cfg["path"] != "people.csv" {
		t.Errorf("config = %v", ld["config"])
	}
	job, _ := ld["job"].(map[string]any)
	if job["state"] != "idle" || job["next_full_at"] == nil || job["last_run"] != nil {
		t.Errorf("job = %v", job)
	}

	// validation: a bad body is refused before anything is stored
	for name, body := range map[string]string{
		"duplicate":       csvLoaderBody("staff", app, "people.csv", "other", ""),
		"unknown field":   csvLoaderBody("X", app, "people.csv", "x", `,"shell":"rm -rf /"`),
		"bad cron":        csvLoaderBody("X", app, "people.csv", "x", `,"schedule":"whenever"`),
		"no folder":       `{"name":"X","type":"csv","config":{"path":"a.csv","group":"x","subject_column":"id"}}`,
		"folder not uuid": csvLoaderBody("X", "app", "people.csv", "x", ""),
		"unknown folder":  csvLoaderBody("X", "00000000-0000-4000-8000-00000000dead", "people.csv", "x", ""),
		"path out":        csvLoaderBody("X", app, "../people.csv", "x", ""),
		"ldap":            `{"name":"X","type":"ldap_simple","target_folder":"` + app + `","config":{}}`,
		"template":        csvLoaderBody("X", app, "people.csv", "x", `,"name_template":"{{.Name | html}}"`),
		"failsafe":        csvLoaderBody("X", app, "people.csv", "x", `,"failsafe":{"max_removed_percent":500}`),
		"secret for file": csvLoaderBody("X", app, "people.csv", "x", `,"secret":"tok"`),
		"empty body":      ``,
		"not an object":   `[]`,
	} {
		rec := e.admin.do("POST", "/api/groups/loaders", body)
		if rec.Code < 400 || rec.Code == http.StatusForbidden {
			t.Errorf("%s: status %d %.200s, want a refusal", name, rec.Code, rec.Body.String())
		}
	}
	if n := len(lItems(e.admin.call("GET", "/api/groups/loaders", "", 200))); n != 1 {
		t.Errorf("%d loaders after the refusals, want 1", n)
	}
	if code := e.admin.do("GET", "/api/groups/loaders/not-a-uuid", "").Code; code != 404 {
		t.Errorf("GET of a malformed id = %d, want 404", code)
	}

	// a preview applies nothing; a run applies everything
	pv := e.admin.call("POST", "/api/groups/loaders/"+id+"/run", `{"kind":"preview"}`, 200)
	if pv["status"] != "previewed" || pv["adds"] != float64(4) {
		t.Fatalf("preview = %v", pv)
	}
	if plan, _ := pv["plan"].(map[string]any); len(plan["groups"].([]any)) != 1 || plan["groups"].([]any)[0].(map[string]any)["create"] != true {
		t.Errorf("preview plan = %v", pv["plan"])
	}
	if n := len(lItems(e.admin.call("GET", "/api/groups/native?folder="+app, "", 200))); n != 0 {
		t.Errorf("a preview created %d groups", n)
	}
	run := e.admin.call("POST", "/api/groups/loaders/"+id+"/run", `{}`, 200)
	if run["status"] != "applied" || run["adds"] != float64(4) || run["kind"] != "full" {
		t.Fatalf("run = %v", run)
	}
	groups := lItems(e.admin.call("GET", "/api/groups/native?folder="+app, "", 200))
	if len(groups) != 1 || groups[0].(map[string]any)["managed_by"] != "loader" || groups[0].(map[string]any)["name"] != "app:staff" {
		t.Fatalf("groups = %v", groups)
	}
	gid := groups[0].(map[string]any)["id"].(string)
	if total := e.admin.call("GET", "/api/groups/"+gid+"/members", "", 200)["total"]; total != float64(4) {
		t.Errorf("members = %v, want 4", total)
	}
	// the loader's group is read-only to everyone, tenant admin included
	if rec := e.admin.do("POST", "/api/groups/"+gid+"/members", fmt.Sprintf(`{"identity":%d}`, e.ident("svc-etl"))); rec.Code != 409 ||
		!strings.Contains(rec.Body.String(), "group_loader_managed") {
		t.Errorf("manual add to a loader's group = %d %s", rec.Code, rec.Body.String())
	}
	e.admin.call("DELETE", fmt.Sprintf("/api/groups/%s/members/%d", gid, e.ident("alice")), "", 409)
	e.admin.call("PATCH", "/api/groups/"+gid, `{"description":"the staff"}`, 200)
	runs := e.admin.call("GET", "/api/groups/loaders/"+id+"/runs", "", 200)
	if runs["total"] != float64(2) || len(lItems(runs)) != 2 { // the preview and the run
		t.Errorf("runs = %v", runs)
	}
	for _, r := range lItems(runs) {
		if _, ok := r.(map[string]any)["plan"]; ok {
			t.Error("the run list carries plans")
		}
	}
	if d := e.admin.call("GET", "/api/groups/loaders/"+id+"/runs/"+pv["id"].(string), "", 200); d["id"] != pv["id"] || d["plan"] == nil || d["impact"] == nil {
		t.Errorf("preview detail = %v", d)
	}
	if d := e.admin.call("GET", "/api/groups/loaders/"+id+"/runs/"+run["id"].(string), "", 200); d["id"] != run["id"] || d["status"] != "applied" {
		t.Errorf("run detail = %v", d)
	}
	e.admin.call("GET", "/api/groups/loaders/"+id+"/runs/00000000-0000-4000-8000-00000000dead", "", 404)

	// the source shrinks by half: the run is held and is an Inbox task
	writeFile(t, dir, "people.csv", "id\nalice\nbob\n")
	held := e.admin.call("POST", "/api/groups/loaders/"+id+"/run", `{}`, 200)
	if held["status"] != "held" || held["removes"] != float64(2) {
		t.Fatalf("held run = %v", held)
	}
	trips, _ := held["failsafe_tripped"].([]any)
	if len(trips) == 0 || trips[0].(map[string]any)["rule"] != "max_removed_percent" {
		t.Errorf("failsafe_tripped = %v", held["failsafe_tripped"])
	}
	imp, _ := held["impact"].(map[string]any)
	if imp["removed_identities"] != float64(2) || len(imp["groups"].([]any)) != 1 {
		t.Errorf("impact = %v", held["impact"])
	}
	if total := e.admin.call("GET", "/api/groups/"+gid+"/members", "", 200)["total"]; total != float64(4) {
		t.Errorf("members while held = %v, want 4", total)
	}
	tasks := lItems(e.admin.call("GET", "/api/groups/loader-tasks", "", 200))
	if len(tasks) != 1 || tasks[0].(map[string]any)["type"] != "loader_held" || tasks[0].(map[string]any)["run_id"] != held["id"] ||
		tasks[0].(map[string]any)["loader_name"] != "Staff" {
		t.Fatalf("tasks = %v", tasks)
	}
	if got := e.admin.call("GET", "/api/groups/loaders/"+id, "", 200)["job"].(map[string]any)["state"]; got != "held" {
		t.Errorf("job state = %v, want held", got)
	}
	e.admin.call("POST", "/api/groups/loaders/"+id+"/run", `{}`, 409) // loader_held
	// the source recovers, but approving applies what was held
	writeFile(t, dir, "people.csv", "id\nalice\nbob\ncarol\ndave\n")
	apr := e.admin.call("POST", "/api/groups/loaders/"+id+"/runs/"+held["id"].(string)+"/approve", "", 200)
	if apr["status"] != "approved" || apr["decided_by"] == nil || apr["removes"] != float64(2) {
		t.Errorf("approved run = %v", apr)
	}
	if total := e.admin.call("GET", "/api/groups/"+gid+"/members", "", 200)["total"]; total != float64(2) {
		t.Errorf("members after the approval = %v, want 2", total)
	}
	if n := len(lItems(e.admin.call("GET", "/api/groups/loader-tasks", "", 200))); n != 0 {
		t.Errorf("%d tasks after the decision", n)
	}
	e.admin.call("POST", "/api/groups/loaders/"+id+"/runs/"+held["id"].(string)+"/approve", "", 409) // not held any more
	// a rejection leaves the group alone
	writeFile(t, dir, "people.csv", "id\nalice\n")
	h2 := e.admin.call("POST", "/api/groups/loaders/"+id+"/run", `{}`, 200)
	if h2["status"] != "held" {
		t.Fatalf("second run = %v", h2)
	}
	rej := e.admin.call("POST", "/api/groups/loaders/"+id+"/runs/"+h2["id"].(string)+"/reject", "", 200)
	if rej["status"] != "rejected" {
		t.Errorf("rejected run = %v", rej)
	}
	if total := e.admin.call("GET", "/api/groups/"+gid+"/members", "", 200)["total"]; total != float64(2) {
		t.Errorf("members after the rejection = %v, want 2", total)
	}

	// turning a loader off is a change of its own and stops its runs
	off := e.admin.call("PATCH", "/api/groups/loaders/"+id, `{"status":"disabled"}`, 200)
	if off["status"] != "disabled" || off["version"] != float64(2) {
		t.Errorf("disabled loader = %v", off)
	}
	e.admin.call("POST", "/api/groups/loaders/"+id+"/run", `{}`, 409)
	e.admin.call("POST", "/api/groups/loaders/"+id+"/run", `{"kind":"sideways"}`, 422)
	e.admin.call("PATCH", "/api/groups/loaders/"+id, `{"status":"enabled","version":1}`, 409) // stale
	e.admin.call("PATCH", "/api/groups/loaders/"+id, `{}`, 422)

	// a source that cannot be read is a failed run, answered 502 with the run in the body
	bad := e.admin.call("POST", "/api/groups/loaders", csvLoaderBody("Broken", app, "nowhere.csv", "broken", ""), 201)
	fr := e.admin.do("POST", "/api/groups/loaders/"+bad["id"].(string)+"/run", `{}`)
	if fr.Code != http.StatusBadGateway || !strings.Contains(fr.Body.String(), "loader_run_failed") || !strings.Contains(fr.Body.String(), `"status":"failed"`) {
		t.Errorf("failed run = %d %s", fr.Code, fr.Body.String())
	}
	// subjects that match no identity are listed
	writeFile(t, dir, "ghosts.csv", "id\nalice\nghost-1\n")
	u := e.admin.call("POST", "/api/groups/loaders", csvLoaderBody("Ghosts", app, "ghosts.csv", "ghosts",
		`,"failsafe":{"max_unresolved_percent":100}`), 201)
	if r := e.admin.call("POST", "/api/groups/loaders/"+u["id"].(string)+"/run", `{}`, 200); r["status"] != "applied" || r["unresolved"] != float64(1) {
		t.Errorf("run with an unresolved subject = %v", r)
	}
	un := e.admin.call("GET", "/api/groups/loaders/"+u["id"].(string)+"/unresolved", "", 200)
	if len(lItems(un)) != 1 || un["total"] != float64(1) || lItems(un)[0].(map[string]any)["identifier"] != "ghost-1" {
		t.Errorf("unresolved = %v", un)
	}
}

// TestLoadersAPI_PermissionAndPrivilege: what each caller may do. Configuring
// and running need groups.loader.admin and stem_admin on the folder; reading
// needs stem_view (the definition, runs' detail and unresolved subjects, stem_admin).
func TestLoadersAPI_PermissionAndPrivilege(t *testing.T) {
	e, dir := newLoaderEnv(t)
	writeFile(t, dir, "people.csv", "id\nalice\nbob\n")
	app := e.admin.folder("", "app")
	other := e.admin.folder("", "other")
	ld := e.admin.call("POST", "/api/groups/loaders", csvLoaderBody("Staff", app, "people.csv", "staff", ""), 201)["id"].(string)
	e.admin.call("POST", "/api/groups/loaders/"+ld+"/run", `{}`, 200)
	bobID := e.ident("bob")
	pa := e.as("pa", []auth.Role{auth.RolePolicyAdmin}, &bobID) // policy admin: groups.loader.admin, no privilege yet
	op := e.user("op", "bob")                                   // operator: no groups.loader.admin
	viewer := e.as("viewer", []auth.Role{auth.RoleViewer}, &bobID)

	// without stem_view nothing of the loader shows
	for _, c := range []client{pa.client, op.client} {
		if n := len(lItems(grpClient{c}.call("GET", "/api/groups/loaders", "", 200))); n != 0 {
			t.Errorf("a caller without stem_view sees %d loaders", n)
		}
		denied(t, grpClient{c}, "GET", "/api/groups/loaders/"+ld, "", "stem_view")
	}
	// stem_view shows the loader without its definition
	e.grant("/api/groups/folders/"+app, "stem_view", "bob", "")
	got := op.call("GET", "/api/groups/loaders/"+ld, "", 200)
	if got["name"] != "Staff" || got["config"] != nil || got["failsafe"] != nil {
		t.Errorf("a viewer of the folder sees %v", got)
	}
	if n := len(lItems(op.call("GET", "/api/groups/loaders", "", 200))); n != 1 {
		t.Errorf("a caller with stem_view sees %d loaders, want 1", n)
	}
	op.call("GET", "/api/groups/loaders/"+ld+"/runs", "", 200)
	denied(t, op, "GET", "/api/groups/loaders/"+ld+"/unresolved", "", "stem_admin")
	denied(t, op, "GET", "/api/groups/loaders/"+ld+"/runs/00000000-0000-4000-8000-00000000dead", "", "stem_admin")
	if n := len(lItems(op.call("GET", "/api/groups/loader-tasks", "", 200))); n != 0 {
		t.Errorf("a caller without stem_admin sees %d tasks", n)
	}
	// a viewer role reads and does nothing else
	viewer.call("GET", "/api/groups/loaders/"+ld+"/runs", "", 200)
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/groups/loaders/" + ld + "/run", `{}`}, {"PATCH", "/api/groups/loaders/" + ld, `{"schedule":"@hourly"}`},
		{"POST", "/api/groups/loaders", csvLoaderBody("V", app, "people.csv", "v", "")},
	} {
		if rec := viewer.do(c.method, c.path, c.body); rec.Code != 403 || !strings.Contains(rec.Body.String(), `"forbidden"`) {
			t.Errorf("viewer %s %s = %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	// an operator holds stem_admin and still lacks groups.loader.admin
	e.grant("/api/groups/folders/"+app, "stem_admin", "bob", "")
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/groups/loaders/" + ld + "/run", `{}`}, {"PATCH", "/api/groups/loaders/" + ld, `{"schedule":"@hourly"}`},
		{"POST", "/api/groups/loaders", csvLoaderBody("O", app, "people.csv", "o", "")},
	} {
		if rec := op.do(c.method, c.path, c.body); rec.Code != 403 || strings.Contains(rec.Body.String(), "privilege_required") {
			t.Errorf("operator with stem_admin %s %s = %d %s, want 403 from the role", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	// the policy admin, now with stem_admin on app, may configure and run there, and only there
	if got := pa.call("GET", "/api/groups/loaders/"+ld, "", 200); got["config"] == nil {
		t.Errorf("a folder admin does not see the definition: %v", got)
	}
	pa.call("POST", "/api/groups/loaders/"+ld+"/run", `{"kind":"preview"}`, 200)
	made := pa.call("POST", "/api/groups/loaders", csvLoaderBody("Mine", app, "people.csv", "mine", ""), 201)
	if made["created_by"] == nil {
		t.Errorf("created_by = %v", made["created_by"])
	}
	pa.call("PATCH", "/api/groups/loaders/"+made["id"].(string), `{"schedule":"0 2 * * *"}`, 200)
	denied(t, pa, "POST", "/api/groups/loaders", csvLoaderBody("Elsewhere", other, "people.csv", "e", ""), "stem_admin")
	// moving a loader to a folder needs the right there too
	denied(t, pa, "PATCH", "/api/groups/loaders/"+made["id"].(string), `{"target_folder":"`+other+`"}`, "stem_admin")
	if got := e.admin.call("GET", "/api/groups/loaders/"+made["id"].(string), "", 200); got["target_folder_id"] != app {
		t.Errorf("a refused move changed the loader: %v", got)
	}
	// the tasks list follows stem_admin
	writeFile(t, dir, "people.csv", "id\nalice\n")
	if r := e.admin.call("POST", "/api/groups/loaders/"+ld+"/run", `{}`, 200); r["status"] != "held" {
		t.Fatalf("run = %v", r)
	}
	if n := len(lItems(pa.call("GET", "/api/groups/loader-tasks", "", 200))); n != 1 {
		t.Errorf("a folder admin sees %d tasks, want 1", n)
	}
	if n := len(lItems(op.call("GET", "/api/groups/loader-tasks", "", 200))); n != 1 { // op is bob too: stem_admin granted
		t.Errorf("tasks of an identity with stem_admin = %d, want 1", n)
	}
	if n := len(lItems(e.user("carol", "carol").call("GET", "/api/groups/loader-tasks", "", 200))); n != 0 {
		t.Errorf("a stranger sees %d tasks", n)
	}
	// another tenant's loader is not found, whoever asks (tenant A's admin has no session here, so use an unknown id)
	e.admin.call("GET", "/api/groups/loaders/00000000-0000-4000-8000-00000000dead", "", 404)
	e.admin.call("POST", "/api/groups/loaders/00000000-0000-4000-8000-00000000dead/run", `{}`, 404)
}

// hrSource makes a SQLite database under dir that a SQL loader reads: the
// identities table of a second Tessera database (the tests of this package may
// not open a database themselves).
func hrSource(t *testing.T, dir, name string, people ...string) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hr := tenancy.MustParse("00000000-0000-4000-8000-0000000000e6")
	_ = db.InSystem(ctx, "test", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: hr, Slug: "hrsource", Name: "hr", CreatedAt: storetest.Now})
		return err
	})
	if err := db.InTenant(ctx, hr, func(tx *store.TenantTx) error {
		for _, p := range people {
			dept := "eng"
			if _, err := tx.InsertIdentity(&store.Identity{ExternalID: p, Name: p, Type: "human", Status: "active", Department: &dept,
				CreatedAt: storetest.Now}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

const sqlLoaderBody = `{"name":"HR","type":"sql_group_list","target_folder":%q,"config":{"database":"hr.db",
	"query":"SELECT department AS group_name, external_id AS subject_id FROM identities"}%s}`

// TestLoadersAPI_SQLNeedsSecondApprover: a loader that runs a query is not
// saved by the request that asks for it: a second admin approves a
// groups.loader.save change request (the Phase 0 admin-change workflow), and
// only then does the loader exist.
func TestLoadersAPI_SQLNeedsSecondApprover(t *testing.T) {
	e, dir := newLoaderEnv(t)
	hrSource(t, dir, "hr.db", "alice", "bob", "carol")
	app := e.admin.folder("", "app")
	admin2 := e.as("admin2", []auth.Role{auth.RoleTenantAdmin}, nil) // two active admins: no bootstrap restriction
	bobID := e.ident("bob")
	pa := e.as("pa", []auth.Role{auth.RolePolicyAdmin}, &bobID)
	e.grant("/api/groups/folders/"+app, "stem_admin", "bob", "")
	op := e.user("op", "carol")

	// without the permission, or the privilege, nothing is filed
	if rec := op.do("POST", "/api/groups/loaders", fmt.Sprintf(sqlLoaderBody, app, "")); rec.Code != 403 {
		t.Errorf("operator = %d %s", rec.Code, rec.Body.String())
	}
	other := e.admin.folder("", "other")
	denied(t, pa, "POST", "/api/groups/loaders", fmt.Sprintf(sqlLoaderBody, other, ""), "stem_admin")
	// a query that writes is refused when it is asked for, before anyone is asked to approve
	if rec := pa.do("POST", "/api/groups/loaders", strings.Replace(fmt.Sprintf(sqlLoaderBody, app, ""), "SELECT department", "DELETE FROM identities; SELECT department", 1)); rec.Code != 422 ||
		!strings.Contains(rec.Body.String(), "invalid_config") {
		t.Errorf("a query that writes = %d %s", rec.Code, rec.Body.String())
	}
	if rec := pa.do("POST", "/api/groups/loaders", fmt.Sprintf(sqlLoaderBody, app, `,"secret":"x"`)); rec.Code != 422 {
		t.Errorf("a secret on a SQL loader = %d %s", rec.Code, rec.Body.String())
	}

	acc := pa.call("POST", "/api/groups/loaders", fmt.Sprintf(sqlLoaderBody, app, ""), 202)
	cid := acc["change_request_id"].(string)
	if acc["status"] != "pending_approval" || acc["type"] != "groups.loader.save" || acc["loader_id"] != nil {
		t.Fatalf("answer = %v", acc)
	}
	if n := len(lItems(e.admin.call("GET", "/api/groups/loaders", "", 200))); n != 0 {
		t.Fatalf("the loader exists before it is approved (%d loaders)", n)
	}
	one := e.admin.call("GET", "/api/admin/change-requests/"+cid, "", 200)
	if one["status"] != "pending_approval" || one["two_person"] != true || !strings.Contains(one["summary"].(string), `Create sql_group_list loader "HR"`) {
		t.Fatalf("change request = %v", one)
	}
	hash := one["payload_hash"].(string)
	body := fmt.Sprintf(`{"payload_hash":%q}`, hash)
	// the requester is not the approver; a policy admin has no say; another admin approves
	pa.call("POST", "/api/admin/change-requests/"+cid+"/approve", body, 403)
	e.admin.call("POST", "/api/admin/change-requests/"+cid+"/approve", `{"payload_hash":"`+strings.Repeat("0", 64)+`"}`, 409)
	done := admin2.call("POST", "/api/admin/change-requests/"+cid+"/approve", body, 200)
	if done["status"] != "applied" {
		t.Fatalf("approved request = %v", done)
	}
	list := lItems(e.admin.call("GET", "/api/groups/loaders", "", 200))
	if len(list) != 1 {
		t.Fatalf("loaders after the approval = %v", list)
	}
	l := list[0].(map[string]any)
	id := l["id"].(string)
	if l["name"] != "HR" || l["requires_approval"] != true || l["created_by"] == nil {
		t.Errorf("loader = %v", l)
	}
	// it runs against the file under the data directory
	r := e.admin.call("POST", "/api/groups/loaders/"+id+"/run", `{}`, 200)
	if r["status"] != "applied" || r["adds"] != float64(3) {
		t.Fatalf("run = %v", r)
	}

	// a change goes the same way; the stale version is refused; turning it off is immediate
	patch := pa.call("PATCH", "/api/groups/loaders/"+id, `{"schedule":"0 4 * * *"}`, 202)
	pid := patch["change_request_id"].(string)
	if patch["loader_id"] != id {
		t.Errorf("answer = %v", patch)
	}
	if got := e.admin.call("GET", "/api/groups/loaders/"+id, "", 200); got["schedule"] != "@daily" {
		t.Errorf("the schedule changed before the approval: %v", got["schedule"])
	}
	ph := e.admin.call("GET", "/api/admin/change-requests/"+pid, "", 200)["payload_hash"].(string)
	admin2.call("POST", "/api/admin/change-requests/"+pid+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, ph), 200)
	if got := e.admin.call("GET", "/api/groups/loaders/"+id, "", 200); got["schedule"] != "0 4 * * *" || got["version"] != float64(2) {
		t.Errorf("the schedule after the approval: %v", got)
	}
	// a request that went stale while it waited is refused, not applied
	stale := pa.call("PATCH", "/api/groups/loaders/"+id, `{"schedule":"0 5 * * *"}`, 202)["change_request_id"].(string)
	e.admin.call("PATCH", "/api/groups/loaders/"+id, `{"status":"disabled"}`, 200)
	sh := e.admin.call("GET", "/api/admin/change-requests/"+stale, "", 200)["payload_hash"].(string)
	if rec := admin2.do("POST", "/api/admin/change-requests/"+stale+"/approve", fmt.Sprintf(`{"payload_hash":%q}`, sh)); rec.Code != 409 {
		t.Errorf("approving a stale request = %d %s, want 409", rec.Code, rec.Body.String())
	}
	if got := e.admin.call("GET", "/api/groups/loaders/"+id, "", 200); got["schedule"] != "0 4 * * *" || got["status"] != "disabled" {
		t.Errorf("a stale request was applied: %v", got)
	}
	// a rejected request changes nothing
	rj := pa.call("PATCH", "/api/groups/loaders/"+id, `{"schedule":"0 6 * * *"}`, 202)["change_request_id"].(string)
	admin2.call("POST", "/api/admin/change-requests/"+rj+"/reject", "", 200)
	if got := e.admin.call("GET", "/api/groups/loaders/"+id, "", 200); got["schedule"] != "0 4 * * *" {
		t.Errorf("a rejected request changed the loader: %v", got)
	}
	// the workflow files no other kind of change through this route, and refuses a loader that needs no approval
	rec := e.admin.do("POST", "/api/admin/change-requests", `{"type":"groups.loader.save","payload":{"spec":`+
		csvLoaderBody("Direct", app, "people.csv", "d", "")+`}}`)
	if rec.Code != 422 {
		t.Errorf("a csv loader through the workflow = %d %s", rec.Code, rec.Body.String())
	}
}

// TestLoadersAPI_SecretIsNeverReturned: the bearer token of a CSV URL is stored
// sealed and shows in no answer, listing or audit event.
func TestLoadersAPI_SecretIsNeverReturned(t *testing.T) {
	e, _ := newLoaderEnv(t)
	app := e.admin.folder("", "app")
	body := `{"name":"Web","type":"csv","target_folder":"` + app + `","secret":"tok-very-secret",
		"config":{"url":"https://example.org/people.csv","group":"web","subject_column":"id"}}`
	l := e.admin.call("POST", "/api/groups/loaders", body, 201)
	if l["has_secret"] != true {
		t.Errorf("loader = %v", l)
	}
	id := l["id"].(string)
	for _, p := range []string{"/api/groups/loaders", "/api/groups/loaders/" + id, "/api/groups/loaders/" + id + "/runs"} {
		if rec := e.admin.do("GET", p, ""); strings.Contains(rec.Body.String(), "tok-very-secret") || strings.Contains(rec.Body.String(), "secret_enc") {
			t.Errorf("GET %s shows the secret", p)
		}
	}
	// replaced, kept and cleared
	if got := e.admin.call("PATCH", "/api/groups/loaders/"+id, `{"secret":"tok-2"}`, 200); got["has_secret"] != true {
		t.Errorf("replaced = %v", got)
	}
	if got := e.admin.call("PATCH", "/api/groups/loaders/"+id, `{"schedule":"@hourly"}`, 200); got["has_secret"] != true {
		t.Errorf("kept = %v", got)
	}
	if got := e.admin.call("PATCH", "/api/groups/loaders/"+id, `{"secret":""}`, 200); got["has_secret"] != false {
		t.Errorf("cleared = %v", got)
	}
	// no sealer, no secret: a server without a key-encryption key refuses to hold one
	f := storetest.TwoTenants(t)
	srv := New(Config{Store: f.DB, Clock: timeutil.Frozen(storetest.Now), Policies: policy.NewLoader(policies.FS),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AllowedOrigins: []string{"http://localhost:5173"}, Env: "test", RateLimits: noRateLimits})
	e2 := &privEnv{t: t, f: f, srv: srv}
	e2.admin = e2.as("admin", []auth.Role{auth.RoleTenantAdmin}, nil)
	app2 := e2.admin.folder("", "app")
	rec := e2.admin.do("POST", "/api/groups/loaders", strings.Replace(body, app, app2, 1))
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "sealer_unavailable") {
		t.Errorf("a secret with no key = %d %s", rec.Code, rec.Body.String())
	}
}
