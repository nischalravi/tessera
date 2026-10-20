package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Native groups, folder and group CRUD (issue #44, GR-1).

type grpClient struct {
	client
}

func newGrp(t *testing.T) (grpClient, *storetest.Fixture) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return grpClient{client{t, isolationServer(t, f, f.B.ID).Handler()}}, f
}

// call sends a request and decodes the JSON object answer.
func (c grpClient) call(method, path, body string, want int) map[string]any {
	c.t.Helper()
	rec := c.do(method, path, body)
	if rec.Code != want {
		c.t.Fatalf("%s %s %s: status %d, want %d: %.300s", method, path, body, rec.Code, want, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		c.t.Fatalf("%s %s: %v: %s", method, path, err, rec.Body.String())
	}
	return out
}

func (c grpClient) folder(parent, ext string) string {
	c.t.Helper()
	body := `{"extension":"` + ext + `"`
	if parent != "" {
		body += `,"parent":"` + parent + `"`
	}
	return c.call("POST", "/api/groups/folders", body+`}`, 201)["id"].(string)
}

func (c grpClient) group(folder, ext string) string {
	c.t.Helper()
	return c.call("POST", "/api/groups", `{"folder":"`+folder+`","extension":"`+ext+`"}`, 201)["id"].(string)
}

func (c grpClient) rootID() string {
	c.t.Helper()
	items := c.call("GET", "/api/groups/folders?limit=500", "", 200)["items"].([]any)
	for _, it := range items {
		if m := it.(map[string]any); m["parent_id"] == nil {
			return m["id"].(string)
		}
	}
	c.t.Fatal("no root folder")
	return ""
}

func TestGroupsFolderCRUD(t *testing.T) {
	c, _ := newGrp(t)
	// before the first write there is no root, and the list is empty
	if items := c.call("GET", "/api/groups/folders", "", 200)["items"].([]any); len(items) != 0 {
		t.Fatalf("folders before any write: %v", items)
	}
	app := c.call("POST", "/api/groups/folders", `{"extension":"App","display_extension":"The app","description":"d"}`, 201)
	if app["name"] != "App" || app["display_name"] != "The app" || app["managed_by"] != "ui" || app["version"] != float64(1) ||
		app["parent_id"] != c.rootID() {
		t.Fatalf("created folder = %v", app)
	}
	id := app["id"].(string)
	if got := c.call("GET", "/api/groups/folders/"+id, "", 200); got["name"] != "App" {
		t.Errorf("get = %v", got)
	}
	sub := c.folder(id, "sub")
	// list: children, subtree, search
	if n := len(c.call("GET", "/api/groups/folders?parent="+id, "", 200)["items"].([]any)); n != 1 {
		t.Errorf("children = %d", n)
	}
	if n := len(c.call("GET", "/api/groups/folders?parent="+c.rootID()+"&scope=sub", "", 200)["items"].([]any)); n != 2 {
		t.Errorf("subtree of the root = %d", n)
	}
	if n := len(c.call("GET", "/api/groups/folders?q=SUB", "", 200)["items"].([]any)); n != 1 {
		t.Errorf("search = %d", n)
	}
	// edit descriptive fields
	got := c.call("PATCH", "/api/groups/folders/"+id, `{"description":"new","data_owner":"alice","version":1}`, 200)
	if got["description"] != "new" || got["data_owner"] != "alice" || got["version"] != float64(2) || got["name"] != "App" {
		t.Errorf("patched = %v", got)
	}
	// rename moves the subtree and keeps the old names resolving
	got = c.call("PATCH", "/api/groups/folders/"+id, `{"extension":"Application"}`, 200)
	if got["name"] != "Application" || got["display_extension"] != "The app" {
		t.Errorf("renamed = %v", got)
	}
	if s := c.call("GET", "/api/groups/folders/"+sub, "", 200); s["name"] != "Application:sub" {
		t.Errorf("subfolder after rename = %v", s)
	}
	c.call("POST", "/api/groups/folders", `{"extension":"app"}`, 409)
	// move and copy
	other := c.folder("", "other")
	if m := c.call("POST", "/api/groups/folders/"+sub+"/move", `{"parent":"`+other+`"}`, 200); m["name"] != "other:sub" {
		t.Errorf("moved = %v", m)
	}
	cp := c.call("POST", "/api/groups/folders/"+id+"/copy", `{"parent":"`+other+`","extension":"copy"}`, 201)
	if cp["name"] != "other:copy" || cp["id"] == id {
		t.Errorf("copy = %v", cp)
	}
	// delete: non-empty is refused with the counts, empty goes
	g := c.group(other, "g")
	e := c.call("DELETE", "/api/groups/folders/"+other, "", 409)
	if e["error"] != "folder_not_empty" || e["groups"] != float64(1) || e["folders"] != float64(2) {
		t.Errorf("delete non-empty = %v", e)
	}
	c.call("DELETE", "/api/groups/"+g, "", 200)
	empty := c.folder("", "empty")
	if d := c.call("DELETE", "/api/groups/folders/"+empty, "", 200); d["deleted"] != true {
		t.Errorf("delete = %v", d)
	}
	c.call("GET", "/api/groups/folders/"+empty, "", 404)
}

func TestGroupsGroupCRUD(t *testing.T) {
	c, _ := newGrp(t)
	app := c.folder("", "app")
	g := c.call("POST", "/api/groups", `{"folder":"`+app+`","extension":"Admins","type":"role","requestable":true,"description":"x"}`, 201)
	if g["name"] != "app:Admins" || g["type"] != "role" || g["definition"] != "basic" || g["status"] != "active" ||
		g["requestable"] != true || g["folder_id"] != app {
		t.Fatalf("created group = %v", g)
	}
	id := g["id"].(string)
	c.call("GET", "/api/groups/"+id, "", 200)
	// the existing connected-system list is untouched, the native list is separate
	if rec := c.do("GET", "/api/groups", ""); rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "[") {
		t.Errorf("GET /api/groups = %d %.80s", rec.Code, rec.Body.String())
	}
	if n := len(c.call("GET", "/api/groups/native", "", 200)["items"].([]any)); n != 1 {
		t.Errorf("native list = %d", n)
	}
	if n := len(c.call("GET", "/api/groups/native?type=group", "", 200)["items"].([]any)); n != 0 {
		t.Errorf("type=group listed %d", n)
	}
	if n := len(c.call("GET", "/api/groups/native?folder="+app+"&q=admin", "", 200)["items"].([]any)); n != 1 {
		t.Errorf("folder and q = %d", n)
	}
	// edit, rename, disable
	got := c.call("PATCH", "/api/groups/"+id, `{"description":"y","status":"disabled","requestable":false,"version":1}`, 200)
	if got["status"] != "disabled" || got["requestable"] != false || got["description"] != "y" || got["version"] != float64(2) {
		t.Errorf("patched = %v", got)
	}
	if got := c.call("PATCH", "/api/groups/"+id, `{"extension":"Owners"}`, 200); got["name"] != "app:Owners" {
		t.Errorf("renamed = %v", got)
	}
	// move and copy
	b := c.folder("", "b")
	if m := c.call("POST", "/api/groups/"+id+"/move", `{"folder":"`+b+`"}`, 200); m["name"] != "b:Owners" || m["folder_id"] != b {
		t.Errorf("moved = %v", m)
	}
	// app:Owners is now an old name of the moved group, so it stays reserved
	if e := c.call("POST", "/api/groups/"+id+"/copy", `{"folder":"`+app+`"}`, 409); e["error"] != "name_reserved_by_alias" {
		t.Errorf("copy onto an old name = %v", e)
	}
	if cp := c.call("POST", "/api/groups/"+id+"/copy", `{"folder":"`+app+`","extension":"dup"}`, 201); cp["name"] != "app:dup" || cp["id"] == id {
		t.Errorf("copy = %v", cp)
	}
	// soft delete, hidden from the default list, restore
	c.call("DELETE", "/api/groups/"+id, "", 200)
	if gone := c.call("GET", "/api/groups/"+id, "", 200); gone["status"] != "deleted" {
		t.Errorf("deleted group = %v", gone)
	}
	if n := len(c.call("GET", "/api/groups/native?folder="+b, "", 200)["items"].([]any)); n != 0 {
		t.Errorf("deleted group listed: %d", n)
	}
	if n := len(c.call("GET", "/api/groups/native?folder="+b+"&deleted=true", "", 200)["items"].([]any)); n != 1 {
		t.Errorf("deleted=true listed %d", n)
	}
	c.call("PATCH", "/api/groups/"+id, `{"description":"z"}`, 409)
	c.call("POST", "/api/groups/"+id+"/restore", "", 200)
	if e := c.call("POST", "/api/groups/"+id+"/restore", "", 409); e["error"] != "not_deleted" {
		t.Errorf("restore of an active group = %v", e)
	}
}

func TestGroupsConflictsAndValidation(t *testing.T) {
	c, f := newGrp(t)
	app := c.folder("", "App")
	g := c.group(app, "Admins")
	root := c.rootID()
	for _, tc := range []struct {
		name, method, path, body string
		status                   int
		code                     string
	}{
		{"folder name, other case", "POST", "/api/groups/folders", `{"extension":"APP"}`, 409, "name_taken"},
		{"group name, other case", "POST", "/api/groups", `{"folder":"` + app + `","extension":"admins"}`, 409, "name_taken"},
		{"folder over a group name", "POST", "/api/groups/folders", `{"parent":"` + app + `","extension":"ADMINS"}`, 409, "name_taken"},
		{"root delete", "DELETE", "/api/groups/folders/" + root, "", 409, "root_folder"},
		{"root rename", "PATCH", "/api/groups/folders/" + root, `{"extension":"x"}`, 409, "root_folder"},
		{"root move", "POST", "/api/groups/folders/" + root + "/move", `{"parent":"` + app + `"}`, 409, "root_folder"},
		{"root copy", "POST", "/api/groups/folders/" + root + "/copy", `{"parent":"` + app + `"}`, 409, "root_folder"},
		{"move into itself", "POST", "/api/groups/folders/" + app + "/move", `{"parent":"` + app + `"}`, 409, "move_into_self"},
		{"copy into itself", "POST", "/api/groups/folders/" + app + "/copy", `{"parent":"` + app + `"}`, 409, "copy_into_self"},
		{"stale version", "PATCH", "/api/groups/" + g, `{"description":"x","version":7}`, 409, "version_conflict"},
		{"folder not empty", "DELETE", "/api/groups/folders/" + app, "", 409, "folder_not_empty"},
		{"colon in name", "POST", "/api/groups/folders", `{"extension":"a:b"}`, 422, "invalid_name"},
		{"space in name", "POST", "/api/groups", `{"folder":"` + app + `","extension":"a b"}`, 422, "invalid_name"},
		{"empty name", "POST", "/api/groups/folders", `{"extension":""}`, 422, "invalid_name"},
		{"long name", "POST", "/api/groups/folders", `{"extension":"` + strings.Repeat("a", 256) + `"}`, 422, "invalid_name"},
		{"bad type", "POST", "/api/groups", `{"folder":"` + app + `","extension":"x","type":"weird"}`, 422, "invalid_type"},
		{"bad status", "PATCH", "/api/groups/" + g, `{"status":"deleted"}`, 422, "invalid_status"},
		{"unknown field", "POST", "/api/groups/folders", `{"extension":"x","name":"y"}`, 422, "invalid_body"},
		{"no body", "POST", "/api/groups", "", 422, "invalid_body"},
		{"no folder", "POST", "/api/groups", `{"extension":"x"}`, 422, "invalid_folder"},
		{"folder not a uuid", "POST", "/api/groups", `{"folder":"nope","extension":"x"}`, 422, "invalid_folder"},
		{"bad scope", "GET", "/api/groups/folders?parent=" + app + "&scope=deep", "", 422, "invalid_scope"},
		{"bad limit", "GET", "/api/groups/folders?limit=0", "", 422, "invalid_limit"},
		{"unknown folder", "GET", "/api/groups/folders/00000000-0000-4000-8000-00000000dead", "", 404, "not_found"},
		{"malformed folder id", "GET", "/api/groups/folders/nope", "", 404, "not_found"},
		{"unknown group", "GET", "/api/groups/00000000-0000-4000-8000-00000000dead", "", 404, "not_found"},
		{"group in unknown folder", "POST", "/api/groups", `{"folder":"00000000-0000-4000-8000-00000000dead","extension":"x"}`, 404, "not_found"},
		{"unknown group move", "POST", "/api/groups/00000000-0000-4000-8000-00000000dead/move", `{"folder":"` + app + `"}`, 404, "not_found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := c.do(tc.method, tc.path, tc.body)
			var body map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if rec.Code != tc.status || body["error"] != tc.code {
				t.Errorf("%s %s: %d %.200s, want %d %s", tc.method, tc.path, rec.Code, rec.Body.String(), tc.status, tc.code)
			}
		})
	}
	// an old name stays reserved
	c.call("PATCH", "/api/groups/folders/"+app, `{"extension":"Renamed"}`, 200)
	if e := c.call("POST", "/api/groups/folders", `{"extension":"app"}`, 409); e["error"] != "name_reserved_by_alias" {
		t.Errorf("old name = %v", e)
	}
	// a mirrored folder refuses writes
	err := f.DB.InTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		return tx.SetGrpFolderManagedBy(store.FolderID(app), store.ManagedByGrouperMirror)
	})
	if err != nil {
		t.Fatal(err)
	}
	if e := c.call("POST", "/api/groups", `{"folder":"`+app+`","extension":"new"}`, 409); e["error"] != "folder_mirrored" {
		t.Errorf("mirrored = %v", e)
	}
	c.call("GET", "/api/groups/folders/"+app, "", 200) // reads still work
}

func TestGroupsTenantIsolation(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := grpClient{client{t, isolationServer(t, f, f.A.ID).Handler()}}
	b := grpClient{client{t, isolationServer(t, f, f.B.ID).Handler()}}
	af := a.folder("", "app")
	ag := a.group(af, "admins")
	b.folder("", "app") // the same name is free in B
	for _, tc := range [][3]string{
		{"GET", "/api/groups/folders/" + af, ""}, {"PATCH", "/api/groups/folders/" + af, `{"description":"x"}`},
		{"DELETE", "/api/groups/folders/" + af, ""}, {"POST", "/api/groups/folders/" + af + "/move", `{"parent":"` + b.rootID() + `"}`},
		{"POST", "/api/groups/folders", `{"parent":"` + af + `","extension":"x"}`},
		{"GET", "/api/groups/" + ag, ""}, {"PATCH", "/api/groups/" + ag, `{"description":"x"}`},
		{"DELETE", "/api/groups/" + ag, ""}, {"POST", "/api/groups/" + ag + "/restore", ""},
		{"POST", "/api/groups", `{"folder":"` + af + `","extension":"x"}`},
		{"POST", "/api/groups/" + ag + "/copy", `{"folder":"` + b.rootID() + `"}`},
	} {
		if rec := b.do(tc[0], tc[1], tc[2]); rec.Code != 404 {
			t.Errorf("B %s %s = %d %.100s, want 404", tc[0], tc[1], rec.Code, rec.Body.String())
		}
	}
	if n := len(b.call("GET", "/api/groups/native", "", 200)["items"].([]any)); n != 0 {
		t.Errorf("B lists %d of A's groups", n)
	}
	if got := a.call("GET", "/api/groups/"+ag, "", 200); got["status"] != "active" || got["description"] != "" {
		t.Errorf("A's group changed: %v", got)
	}
}

// TestGroupsRoutesNeedAGroupsPermission: the route permission is the first
// gate. break_glass holds no groups permission, and a role that holds one is
// still refused by the folder's or group's privilege (groups_privs_test.go).
func TestGroupsRoutesNeedAGroupsPermission(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	bg := signIn(t, f.DB, f.B.ID, authtest.User{Email: "bg@b.example", Roles: []auth.Role{auth.RoleBreakGlass}}, authtest.Phr, storetest.Now)
	for _, tc := range [][3]string{{"GET", "/api/groups/folders", ""}, {"POST", "/api/groups/folders", `{"extension":"x"}`},
		{"GET", "/api/groups/native", ""}, {"POST", "/api/groups", `{"folder":"x","extension":"x"}`}} {
		if rec := serve(h, authed(bg, tc[0], tc[1], tc[2])); rec.Code != http.StatusForbidden {
			t.Errorf("break_glass %s %s = %d, want 403", tc[0], tc[1], rec.Code)
		}
	}
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	if rec := serve(h, authed(admin, "POST", "/api/groups/folders", `{"extension":"x"}`)); rec.Code != http.StatusCreated {
		t.Errorf("tenant_admin create = %d %s", rec.Code, rec.Body.String())
	}
}

// TestGroupsAuditedInTheChangeTransaction: each change writes its domain
// event with the acting user, and a refused change writes none.
func TestGroupsAuditedInTheChangeTransaction(t *testing.T) {
	c, f := newGrp(t)
	app := c.folder("", "app")
	g := c.group(app, "g")
	c.call("PATCH", "/api/groups/"+g, `{"extension":"h"}`, 200)
	c.call("POST", "/api/groups/"+g+"/move", `{"folder":"`+c.rootID()+`"}`, 200)
	c.call("DELETE", "/api/groups/"+g, "", 200)
	c.call("POST", "/api/groups/"+g+"/restore", "", 200)
	c.call("POST", "/api/groups/folders", `{"extension":"APP"}`, 409) // refused: no event
	count := func(action string) (n int, targets []string) {
		err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
			evs, err := tx.AuditEvents(store.AuditFilter{Action: action})
			for _, e := range evs {
				n++
				if e.ActorType != store.ActorUser || e.ActorID == nil {
					t.Errorf("%s event actor = %s %v", action, e.ActorType, e.ActorID)
				}
				if e.TargetID != nil {
					targets = append(targets, *e.TargetID)
				}
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return n, targets
	}
	for action, want := range map[string]int{"groups.folder.created": 1, "groups.group.created": 1, "groups.group.renamed": 1,
		"groups.group.moved": 1, "groups.group.deleted": 1, "groups.group.restored": 1} {
		if n, _ := count(action); n != want {
			t.Errorf("%s events = %d, want %d", action, n, want)
		}
	}
	if _, targets := count("groups.group.deleted"); len(targets) != 1 || targets[0] != g {
		t.Errorf("deleted event targets = %v, want %s", targets, g)
	}
}
