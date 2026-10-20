package api

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Attribute framework, object types and services (issue #50, GR-7).

func (c grpClient) attrDef(folder, ext, extra string) string {
	c.t.Helper()
	body := `{"folder":"` + folder + `","extension":"` + ext + `"`
	if extra != "" {
		body += "," + extra
	}
	return c.call("POST", "/api/groups/attr-defs", body+`}`, 201)["id"].(string)
}

func (c grpClient) attrName(def, ext string) string {
	c.t.Helper()
	return c.call("POST", "/api/groups/attr-names", `{"def":"`+def+`","extension":"`+ext+`"}`, 201)["id"].(string)
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestGroupsAttrsFlow(t *testing.T) {
	c, _ := newGrp(t)
	app := c.folder("", "app")
	g := c.group(app, "g")
	g2 := c.group(app, "g2")

	d := c.call("POST", "/api/groups/attr-defs", `{"folder":"`+app+`","extension":"weights","description":"d","value_type":"floating","multi_valued":true,`+
		`"assign_to":["group","assignment","folder"]}`, 201)
	id := d["id"].(string)
	if d["name"] != "app:weights" || d["attr_type"] != "attr" || d["value_type"] != "floating" || d["multi_assign"] != false ||
		d["system"] != false || d["version"] != float64(1) || !slices.Equal(strs(d["assign_to"]), []string{"folder", "group", "assignment"}) {
		t.Fatalf("created definition = %v", d)
	}
	c.call("POST", "/api/groups/attr-defs", `{"folder":"`+app+`","extension":"WEIGHTS","assign_to":["group"]}`, 409)
	for _, body := range []string{`{"folder":"` + app + `","extension":"a","assign_to":[]}`, `{"folder":"` + app + `","extension":"a","assign_to":["x"]}`,
		`{"folder":"` + app + `","extension":"a b","assign_to":["group"]}`, `{"folder":"nope","extension":"a","assign_to":["group"]}`,
		`{"folder":"` + app + `","extension":"a","assign_to":["group"],"attr_type":"x"}`, `{"folder":"` + app + `","extension":"a","assign_to":["group"],"junk":1}`} {
		if rec := c.do("POST", "/api/groups/attr-defs", body); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("POST attr-defs %s = %d, want 422", body, rec.Code)
		}
	}
	// list, search, scope
	if n := len(c.call("GET", "/api/groups/attr-defs", "", 200)["items"].([]any)); n != 1 {
		t.Errorf("defs = %d", n)
	}
	sub := c.folder(app, "sub")
	c.attrDef(sub, "inner", `"assign_to":["group"]`)
	for q, want := range map[string]int{"?folder=" + app: 1, "?folder=" + app + "&scope=sub": 2, "?q=INNER": 1, "?type=attr": 2, "?type=perm": 0, "?folder=" + sub: 1} {
		if n := len(c.call("GET", "/api/groups/attr-defs"+q, "", 200)["items"].([]any)); n != want {
			t.Errorf("GET attr-defs%s = %d items, want %d", q, n, want)
		}
	}
	c.call("GET", "/api/groups/attr-defs?scope=x&folder="+app, "", 422)
	c.call("GET", "/api/groups/attr-defs?type=x", "", 422)
	c.call("GET", "/api/groups/attr-defs/"+id, "", 200)
	c.call("GET", "/api/groups/attr-defs/nope", "", 404)
	c.call("GET", "/api/groups/attr-defs/00000000-0000-4000-8000-000000000000", "", 404)

	// names and implications
	a, b, cc := c.attrName(id, "a"), c.attrName(id, "b"), c.attrName(id, "c")
	c.call("POST", "/api/groups/attr-names", `{"def":"`+id+`","extension":"A"}`, 409)
	if got := c.call("GET", "/api/groups/attr-names/"+a, "", 200); got["name"] != "app:weights:a" {
		t.Errorf("name = %v", got)
	}
	if n := len(c.call("GET", "/api/groups/attr-names?def="+id, "", 200)["items"].([]any)); n != 3 {
		t.Errorf("names = %d", n)
	}
	got := c.call("PUT", "/api/groups/attr-names/"+a+"/implies", `{"implies":["`+b+`"]}`, 200)
	if !slices.Equal(strs(got["implies"]), []string{b}) || !slices.Equal(strs(got["implies_all"]), []string{b}) {
		t.Errorf("a implies = %v", got)
	}
	c.call("PUT", "/api/groups/attr-names/"+b+"/implies", `{"implies":["`+cc+`"]}`, 200)
	if got := c.call("GET", "/api/groups/attr-names/"+a, "", 200); !slices.Equal(strs(got["implies_all"]), sortedStrings(b, cc)) ||
		!slices.Equal(strs(got["implies"]), []string{b}) {
		t.Errorf("a after b->c = %v", got)
	}
	cyc := c.call("PUT", "/api/groups/attr-names/"+cc+"/implies", `{"implies":["`+a+`"]}`, 409)
	if cyc["error"] != "cycle" || len(cyc["path"].([]any)) < 3 {
		t.Errorf("cycle = %v", cyc)
	}
	c.call("PUT", "/api/groups/attr-names/"+a+"/implies", `{"implies":["`+a+`"]}`, 422)
	c.call("PUT", "/api/groups/attr-names/"+a+"/implies", `{"implies":["nope"]}`, 422)
	c.call("PATCH", "/api/groups/attr-names/"+a, `{"description":"the a"}`, 200)

	// actions
	acts := c.call("GET", "/api/groups/attr-defs/"+id+"/actions", "", 200)["items"].([]any)
	if len(acts) != 1 || acts[0].(map[string]any)["name"] != "assign" {
		t.Fatalf("actions = %v", acts)
	}
	defAction := acts[0].(map[string]any)["id"].(string)
	extra := c.call("POST", "/api/groups/attr-defs/"+id+"/actions", `{"name":"review"}`, 201)["id"].(string)
	c.call("POST", "/api/groups/attr-defs/"+id+"/actions", `{"name":"REVIEW"}`, 409)
	if got := c.call("PUT", "/api/groups/attr-defs/"+id+"/actions/"+extra+"/implies", `{"implies":["`+defAction+`"]}`, 200); !slices.Equal(strs(got["implies"]), []string{defAction}) {
		t.Errorf("action implies = %v", got)
	}
	if e := c.call("DELETE", "/api/groups/attr-defs/"+id+"/actions/"+defAction, "", 409); e["error"] != "default_action" {
		t.Errorf("deleting the default action = %v", e)
	}

	// assignments, with a floating value as a string
	asg := c.call("POST", "/api/groups/attr-assignments", `{"name":"`+a+`","owner_type":"group","owner":"`+g+`","values":["1.50","2"]}`, 201)
	if !slices.Equal(strs(asg["values"]), []string{"1.5", "2"}) || asg["name"] != "app:weights:a" || asg["action"] != "assign" ||
		asg["active"] != true || asg["version"] != float64(1) || asg["owner"] != g {
		t.Fatalf("assignment = %v", asg)
	}
	aid := asg["id"].(string)
	for _, v := range []string{`[1.5]`, `[2]`, `["1e3"]`, `["x"]`, `[null]`, `["1","1.0"]`} {
		if rec := c.do("POST", "/api/groups/attr-assignments", `{"name":"`+b+`","owner_type":"group","owner":"`+g+`","values":`+v+`}`); rec.Code != 422 {
			t.Errorf("values %s = %d %.100s, want 422", v, rec.Code, rec.Body.String())
		}
	}
	// by full name, with a named action
	byName := c.call("POST", "/api/groups/attr-assignments", `{"name":"app:weights:b","action":"review","owner_type":"folder","owner":"`+app+`","values":["3"]}`, 201)
	if byName["action"] != "review" || byName["name"] != "app:weights:b" {
		t.Errorf("by name = %v", byName)
	}
	// a single-assign definition refuses a second assignment of the name
	single := c.attrDef(app, "single", `"assign_to":["group"]`)
	sn := c.attrName(single, "s")
	c.call("POST", "/api/groups/attr-assignments", `{"name":"`+sn+`","owner_type":"group","owner":"`+g+`"}`, 201)
	if e := c.call("POST", "/api/groups/attr-assignments", `{"name":"`+sn+`","owner_type":"group","owner":"`+g+`"}`, 409); e["error"] != "already_assigned" || e["assignment"] == nil {
		t.Errorf("second single assignment = %v", e)
	}
	// owner checks
	c.call("POST", "/api/groups/attr-assignments", `{"name":"`+sn+`","owner_type":"folder","owner":"`+app+`"}`, 422) // not in assign_to
	c.call("POST", "/api/groups/attr-assignments", `{"name":"`+sn+`","owner_type":"group","owner":"00000000-0000-4000-8000-000000000000"}`, 404)
	c.call("POST", "/api/groups/attr-assignments", `{"name":"`+sn+`","owner_type":"group","owner":"nope"}`, 422)
	c.call("POST", "/api/groups/attr-assignments", `{"name":"`+sn+`","owner_type":"bogus","owner":"x"}`, 422)
	c.call("POST", "/api/groups/attr-assignments", `{"name":"`+sn+`","owner_type":"identity","owner":"0"}`, 422)
	if e := c.call("POST", "/api/groups/attr-assignments", `{"name":"`+sn+`","owner_type":"effective_membership","owner":"`+g+`"}`, 422); e["error"] != "effective_membership_read_only" {
		t.Errorf("effective_membership = %v", e)
	}
	c.call("POST", "/api/groups/attr-assignments", `{"name":"`+sn+`","owner_type":"group","owner":"`+g2+`","enabled_from":"nope"}`, 422)
	c.call("POST", "/api/groups/attr-assignments", `{"name":"nope","owner_type":"group","owner":"`+g2+`"}`, 404)
	// an assignment on an assignment
	on := c.call("POST", "/api/groups/attr-assignments", `{"name":"`+b+`","owner_type":"assignment","owner":"`+aid+`","values":["9"]}`, 201)
	// read, list, effective
	if got := c.call("GET", "/api/groups/attr-assignments/"+aid, "", 200); got["owner_type"] != "group" {
		t.Errorf("get = %v", got)
	}
	for q, want := range map[string]int{"?owner_type=group&owner=" + g: 2, "?owner_type=assignment&owner=" + aid: 1, "?def=" + id: 3, "?name=" + a: 1,
		"?owner_type=group&owner=" + g2: 0} {
		if n := len(c.call("GET", "/api/groups/attr-assignments"+q, "", 200)["items"].([]any)); n != want {
			t.Errorf("GET attr-assignments%s = %d, want %d", q, n, want)
		}
	}
	c.call("GET", "/api/groups/attr-assignments?owner_type=group", "", 422)
	eff := c.call("GET", "/api/groups/attr-assignments?owner_type=group&owner="+g+"&effective=true", "", 200)
	var names []string
	for _, it := range eff["items"].([]any) {
		m := it.(map[string]any)
		names = append(names, m["name"].(string)+fmt.Sprint(m["implied"]))
	}
	slices.Sort(names)
	if want := []string{"app:single:sfalse", "app:weights:afalse", "app:weights:btrue", "app:weights:ctrue"}; !slices.Equal(names, want) {
		t.Errorf("effective names = %v, want %v", names, want)
	}
	// edit dates, values, flag
	up := c.call("PATCH", "/api/groups/attr-assignments/"+aid, `{"enabled_from":"2020-01-01T00:00:00Z","disabled_at":"2020-02-01T00:00:00Z"}`, 200)
	if up["active"] != false || up["version"] != float64(2) || up["disabled_at"] != "2020-02-01T00:00:00.000000Z" {
		t.Errorf("patched = %v", up)
	}
	c.call("PATCH", "/api/groups/attr-assignments/"+aid, `{"disabled_at":"2019-01-01T00:00:00Z"}`, 422)
	c.call("PATCH", "/api/groups/attr-assignments/"+aid, `{"version":1}`, 409)
	c.call("PATCH", "/api/groups/attr-assignments/"+aid, `{"junk":1}`, 422)
	c.call("PATCH", "/api/groups/attr-assignments/"+aid, `{"disallowed":true}`, 422) // not a perm definition
	if up := c.call("PATCH", "/api/groups/attr-assignments/"+aid, `{"enabled_from":null,"disabled_at":null}`, 200); up["active"] != true || up["disabled_at"] != nil {
		t.Errorf("cleared = %v", up)
	}
	if got := c.call("PUT", "/api/groups/attr-assignments/"+aid+"/values", `{"values":["7.0"]}`, 200); !slices.Equal(strs(got["values"]), []string{"7"}) {
		t.Errorf("values = %v", got)
	}
	c.call("PUT", "/api/groups/attr-assignments/"+aid+"/values", `{"values":[7]}`, 422)
	c.call("PUT", "/api/groups/attr-assignments/"+aid+"/values", `{}`, 200)
	if got := c.call("GET", "/api/groups/attr-assignments/"+aid, "", 200); len(got["values"].([]any)) != 0 {
		t.Errorf("values after an empty set = %v", got["values"])
	}
	// in use: a name, an action, a definition
	for path, code := range map[string]string{"/api/groups/attr-names/" + a: "attr_name_in_use", "/api/groups/attr-defs/" + id: "attr_def_in_use"} {
		if e := c.call("DELETE", path, "", 409); e["error"] != code {
			t.Errorf("DELETE %s = %v, want %s", path, e, code)
		}
	}
	// the review action is used by the assignment made by name above
	if e := c.call("DELETE", "/api/groups/attr-defs/"+id+"/actions/"+extra, "", 409); e["error"] != "attr_action_in_use" {
		t.Errorf("deleting an action in use = %v", e)
	}
	// removing an assignment removes the ones on it
	if got := c.call("DELETE", "/api/groups/attr-assignments/"+aid, "", 200); got["removed"] != float64(2) {
		t.Errorf("removed = %v", got)
	}
	c.call("GET", "/api/groups/attr-assignments/"+on["id"].(string), "", 404)
	c.call("DELETE", "/api/groups/attr-assignments/"+aid, "", 404)
	c.call("DELETE", "/api/groups/attr-assignments/"+byName["id"].(string), "", 200)
	c.call("DELETE", "/api/groups/attr-defs/"+id+"/actions/"+extra, "", 200)
	c.call("DELETE", "/api/groups/attr-names/"+cc, "", 200)
	c.call("DELETE", "/api/groups/attr-names/"+b, "", 200)
	if got := c.call("GET", "/api/groups/attr-names/"+a, "", 200); len(got["implies"].([]any)) != 0 {
		t.Errorf("a still implies %v after b and c are deleted", got["implies"])
	}
	c.call("DELETE", "/api/groups/attr-names/"+a, "", 200)
	if got := c.call("PATCH", "/api/groups/attr-defs/"+id, `{"multi_assign":true,"version":1}`, 200); got["multi_assign"] != true || got["version"] != float64(2) {
		t.Errorf("patched definition = %v", got)
	}
	c.call("PATCH", "/api/groups/attr-defs/"+id, `{"version":1}`, 409)
	c.call("PATCH", "/api/groups/attr-defs/"+id, `{"attr_type":"perm"}`, 422) // the type never changes
	c.call("DELETE", "/api/groups/attr-defs/"+id, "", 200)
	c.call("GET", "/api/groups/attr-defs/"+id, "", 404)
	// a folder that holds a definition is not empty
	if e := c.call("DELETE", "/api/groups/folders/"+sub, "", 409); e["error"] != "folder_not_empty" || e["attr_defs"] != float64(1) {
		t.Errorf("delete a folder with a definition = %v", e)
	}
}

func sortedStrings(s ...string) []string { slices.Sort(s); return s }

// TestGroupsAttrsPrivileges: over the API, each side of an assignment, the
// definition's own privileges, and what a listing shows follow the attr_*
// privileges of GR-4.
func TestGroupsAttrsPrivileges(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	foo := e.admin.folder(app, "foo")
	g := e.admin.group(app, "g")
	def := e.admin.attrDef(foo, "tags", `"value_type":"string","multi_valued":true,"multi_assign":true,"assign_to":["group","identity","membership"]`)
	n := e.admin.attrName(def, "n")
	hidden := e.admin.attrDef(foo, "hidden", `"assign_to":["group"]`)
	bob := e.user("bob", "bob")
	alice := e.user("alice", "alice")
	defPath := "/api/groups/attr-defs/" + def
	assign := `{"name":"` + n + `","owner_type":"group","owner":"` + g + `","values":["x"]}`

	// a user who holds nothing sees nothing
	denied(t, bob, "GET", defPath, "", "attr_view")
	if items := bob.call("GET", "/api/groups/attr-defs", "", 200)["items"].([]any); len(items) != 0 {
		t.Errorf("bob lists %d definitions", len(items))
	}
	e.grant(defPath, "attr_view", "bob", "")
	bob.call("GET", defPath, "", 200)
	bob.call("GET", "/api/groups/attr-names?def="+def, "", 200)
	bob.call("GET", defPath+"/actions", "", 200)
	if items := bob.call("GET", "/api/groups/attr-defs", "", 200)["items"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] != def {
		t.Errorf("bob lists %v, want only the definition he may view", items)
	}
	denied(t, bob, "PATCH", defPath, `{"description":"x"}`, "attr_admin")
	denied(t, bob, "POST", "/api/groups/attr-names", `{"def":"`+def+`","extension":"z"}`, "attr_admin")
	denied(t, bob, "POST", "/api/groups/attr-assignments", assign, "attr_update")
	denied(t, bob, "GET", defPath+"/privileges", "", "attr_admin")
	bob.call("GET", defPath+"/privileges/effective", "", 200) // his own, with view
	// browse of names: only the definitions he may view
	if items := bob.call("GET", "/api/groups/attr-names", "", 200)["items"].([]any); len(items) != 1 {
		t.Errorf("bob lists %d names", len(items))
	}

	// the definition's attr_update is not enough: the group's group_attr_update is asked next
	e.grant(defPath, "attr_update", "bob", "")
	denied(t, bob, "POST", "/api/groups/attr-assignments", assign, "group_attr_update")
	e.grant("/api/groups/"+g, "group_attr_update", "bob", "")
	made := bob.call("POST", "/api/groups/attr-assignments", assign, 201)["id"].(string)
	// reading needs attr_read and group_attr_read: update implies neither on the definition
	denied(t, bob, "GET", "/api/groups/attr-assignments/"+made, "", "attr_read")
	if items := bob.call("GET", "/api/groups/attr-assignments", "", 200)["items"].([]any); len(items) != 0 {
		t.Errorf("bob lists %d assignments without attr_read", len(items))
	}
	e.grant(defPath, "attr_read", "bob", "")
	bob.call("GET", "/api/groups/attr-assignments/"+made, "", 200) // group_attr_update implies group_attr_read
	if items := bob.call("GET", "/api/groups/attr-assignments?owner_type=group&owner="+g, "", 200)["items"].([]any); len(items) != 1 {
		t.Errorf("bob lists %d assignments", len(items))
	}
	bob.call("PUT", "/api/groups/attr-assignments/"+made+"/values", `{"values":["y"]}`, 200)
	bob.call("PATCH", "/api/groups/attr-assignments/"+made, `{"disabled_at":null}`, 200)
	// alice reads the definition only: group_attr_read without attr_read shows nothing
	e.grant(defPath, "attr_view", "alice", "")
	e.grant("/api/groups/"+g, "group_attr_read", "alice", "")
	denied(t, alice, "GET", "/api/groups/attr-assignments/"+made, "", "attr_read")
	if items := alice.call("GET", "/api/groups/attr-assignments", "", 200)["items"].([]any); len(items) != 0 {
		t.Errorf("alice lists %d assignments", len(items))
	}
	e.grant(defPath, "attr_read", "alice", "")
	alice.call("GET", "/api/groups/attr-assignments/"+made, "", 200)
	denied(t, alice, "DELETE", "/api/groups/attr-assignments/"+made, "", "attr_update")
	bob.call("DELETE", "/api/groups/attr-assignments/"+made, "", 200)

	// opt in and out: a person on themselves, nobody else
	me := fmt.Sprintf(`{"name":"%s","owner_type":"identity","owner":"%d"}`, n, e.ident("alice"))
	you := fmt.Sprintf(`{"name":"%s","owner_type":"identity","owner":"%d"}`, n, e.ident("bob"))
	denied(t, alice, "POST", "/api/groups/attr-assignments", me, "attr_update")
	e.grant(defPath, "attr_optin", "alice", "")
	mine := alice.call("POST", "/api/groups/attr-assignments", me, 201)["id"].(string)
	denied(t, alice, "POST", "/api/groups/attr-assignments", you, "attr_update")
	denied(t, alice, "DELETE", "/api/groups/attr-assignments/"+mine, "", "attr_update")
	e.grant(defPath, "attr_optout", "alice", "")
	alice.call("DELETE", "/api/groups/attr-assignments/"+mine, "", 200)

	// attr_admin: edit the definition, its names and actions, and its privileges
	denied(t, bob, "PATCH", defPath, `{"description":"x"}`, "attr_admin")
	e.grant(defPath, "attr_admin", "bob", "")
	bob.call("PATCH", defPath, `{"description":"by bob"}`, 200)
	bob.call("POST", "/api/groups/attr-names", `{"def":"`+def+`","extension":"z"}`, 201)
	bob.call("POST", defPath+"/actions", `{"name":"more"}`, 201)
	rows := bob.call("GET", defPath+"/privileges", "", 200)["items"].([]any)
	if len(rows) < 5 {
		t.Errorf("rows on the definition = %d", len(rows))
	}
	// the privilege of another definition does not carry over
	denied(t, bob, "PATCH", "/api/groups/attr-defs/"+hidden, `{"description":"x"}`, "attr_admin")

	// inherited from the folder: attr_admin for attr_defs below foo, by scope
	e.admin.call("POST", "/api/groups/folders/"+foo+"/privileges", fmt.Sprintf(`{"privilege":"attr_view","holder_type":"identity","identity":%d,"applies_to":"attr_defs","scope":"one"}`, e.ident("alice")), 201)
	alice.call("GET", "/api/groups/attr-defs/"+hidden, "", 200)
	// a definition is created with create on its folder, and its creator administers it
	denied(t, alice, "POST", "/api/groups/attr-defs", `{"folder":"`+foo+`","extension":"alices","assign_to":["group"]}`, "create")
	e.grant("/api/groups/folders/"+foo, "create", "alice", "")
	mineDef := alice.call("POST", "/api/groups/attr-defs", `{"folder":"`+foo+`","extension":"alices","assign_to":["group"]}`, 201)["id"].(string)
	alice.call("PATCH", "/api/groups/attr-defs/"+mineDef, `{"description":"mine"}`, 200)
	alice.call("DELETE", "/api/groups/attr-defs/"+mineDef, "", 200)
	// grants on a definition are made on its path
	e.admin.call("POST", defPath+"/privileges", `{"privilege":"attr_view","holder_type":"everyone"}`, 201)
	// a group privilege is not an attribute definition privilege, and attr_admin is never given to everyone
	e.admin.call("POST", defPath+"/privileges", `{"privilege":"admin","holder_type":"everyone"}`, 422)
	e.admin.call("POST", defPath+"/privileges", `{"privilege":"attr_admin","holder_type":"everyone"}`, 422)
	if eff := bob.call("GET", defPath+"/privileges/effective?identity="+fmt.Sprint(e.ident("alice")), "", 200); eff["identity_id"] != float64(e.ident("alice")) {
		t.Errorf("effective = %v", eff)
	}
}

// TestGroupsObjectTypesAndLint: object types are set with the owner's
// attribute-update privilege, validated against the vocabulary, and drive lint.
func TestGroupsObjectTypesAndLint(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	g := e.admin.group(app, "g")
	bob := e.user("bob", "bob")
	vocab := e.admin.call("GET", "/api/groups/object-types", "", 200)
	if !slices.Equal(strs(vocab["group"]), []string{"ref", "basis", "policy", "bundle", "manual", "intermediate"}) ||
		!slices.Equal(strs(vocab["folder"]), []string{"etc", "org", "test", "service", "app", "security"}) || vocab["created"] != false {
		t.Errorf("vocabulary = %v", vocab)
	}
	if got := e.admin.call("GET", "/api/groups/"+g+"/object-types", "", 200); len(got["types"].([]any)) != 0 || len(got["lint"].([]any)) != 0 {
		t.Errorf("before any type = %v", got)
	}
	// clearing before the definition exists creates nothing
	e.admin.call("PUT", "/api/groups/"+g+"/object-types", `{"types":[]}`, 200)
	if got := e.admin.call("GET", "/api/groups/object-types", "", 200); got["created"] != false {
		t.Error("clearing created the built-in definition")
	}
	denied(t, bob, "PUT", "/api/groups/"+g+"/object-types", `{"types":["ref"]}`, "group_attr_update")
	e.grant("/api/groups/"+g, "group_attr_update", "bob", "")
	got := bob.call("PUT", "/api/groups/"+g+"/object-types", `{"types":["policy","ref"]}`, 200)
	if !slices.Equal(strs(got["types"]), []string{"ref", "policy"}) || got["object_type"] != "group" {
		t.Errorf("types = %v", got)
	}
	if got := e.admin.call("GET", "/api/groups/object-types", "", 200); got["created"] != true {
		t.Error("the built-in definition was not created")
	}
	// the built-in definition is owned by the system, not by bob
	def := e.admin.call("GET", "/api/groups/attr-defs?q=objectTypes", "", 200)["items"].([]any)
	if len(def) != 1 || def[0].(map[string]any)["name"] != "etc:objectTypes" || def[0].(map[string]any)["system"] != true {
		t.Fatalf("built-in definition = %v", def)
	}
	denied(t, bob, "GET", "/api/groups/attr-defs/"+def[0].(map[string]any)["id"].(string), "", "attr_view")
	e.admin.call("PATCH", "/api/groups/attr-defs/"+def[0].(map[string]any)["id"].(string), `{"description":"x"}`, 409)
	e.admin.call("DELETE", "/api/groups/attr-defs/"+def[0].(map[string]any)["id"].(string), "", 409)
	// the vocabulary is by kind, and the body is strict
	bob.call("PUT", "/api/groups/"+g+"/object-types", `{"types":["service"]}`, 422)
	bob.call("PUT", "/api/groups/"+g+"/object-types", `{"types":["nope"]}`, 422)
	bob.call("PUT", "/api/groups/"+g+"/object-types", `{}`, 422)
	bob.call("PUT", "/api/groups/"+g+"/object-types", `{"types":"ref"}`, 422)
	// reading: view for the types, read for the lint findings
	carol := e.user("carol", "carol")
	denied(t, carol, "GET", "/api/groups/"+g+"/object-types", "", "view")
	e.grant("/api/groups/"+g, "view", "carol", "")
	if r := carol.call("GET", "/api/groups/"+g+"/object-types", "", 200); !slices.Equal(strs(r["types"]), []string{"ref", "policy"}) || len(r["lint"].([]any)) != 0 {
		t.Errorf("carol (view only) = %v", r)
	}
	// a bundle holds groups: a direct identity member is a finding, which read can see
	bundle := e.admin.group(app, "bundle")
	e.admin.call("PUT", "/api/groups/"+bundle+"/object-types", `{"types":["bundle"]}`, 200)
	e.admin.call("POST", "/api/groups/"+bundle+"/members", fmt.Sprintf(`{"identity":%d}`, e.ident("alice")), 201)
	lint := e.admin.call("GET", "/api/groups/"+bundle+"/object-types", "", 200)["lint"].([]any)
	if len(lint) < 1 || lint[0].(map[string]any)["rule"] != "bundle_direct_members" || lint[0].(map[string]any)["severity"] != "warning" ||
		!strings.Contains(lint[0].(map[string]any)["message"].(string), "1 direct identity members") {
		t.Errorf("lint = %v", lint)
	}
	e.grant("/api/groups/"+bundle, "view", "carol", "")
	if r := carol.call("GET", "/api/groups/"+bundle+"/object-types", "", 200); len(r["lint"].([]any)) != 0 {
		t.Errorf("view alone shows the lint findings: %v", r["lint"])
	}
	e.grant("/api/groups/"+bundle, "read", "carol", "")
	if r := carol.call("GET", "/api/groups/"+bundle+"/object-types", "", 200); len(r["lint"].([]any)) < 1 {
		t.Errorf("read does not show the lint findings: %v", r["lint"])
	}
	// folders: a service with no policy group is a finding
	svc := e.admin.folder(app, "svc")
	f := e.admin.call("PUT", "/api/groups/folders/"+svc+"/object-types", `{"types":["service"]}`, 200)
	if !slices.Equal(strs(f["types"]), []string{"service"}) {
		t.Errorf("folder types = %v", f)
	}
	if r := e.admin.call("GET", "/api/groups/folders/"+svc+"/object-types", "", 200)["lint"].([]any); len(r) != 1 || r[0].(map[string]any)["rule"] != "service_without_policy_groups" {
		t.Errorf("folder lint = %v", r)
	}
	e.admin.call("PUT", "/api/groups/folders/"+svc+"/object-types", `{"types":["policy"]}`, 422)
	denied(t, bob, "PUT", "/api/groups/folders/"+svc+"/object-types", `{"types":["app"]}`, "stem_attr_update")
	// a copy of a group keeps its types
	cp := e.admin.call("POST", "/api/groups/"+g+"/copy", `{"folder":"`+svc+`"}`, 201)["id"].(string)
	if r := e.admin.call("GET", "/api/groups/"+cp+"/object-types", "", 200); !slices.Equal(strs(r["types"]), []string{"ref", "policy"}) {
		t.Errorf("the copy's types = %v", r)
	}
	// the change is in the audit trail and the change events
	n := 0
	err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{Action: "groups.attr.assigned"})
		n = len(evs)
		return err
	})
	if err != nil || n < 4 {
		t.Errorf("groups.attr.assigned events = %d, %v", n, err)
	}
}

// TestGroupsServices: "Services I can use" lists the service folders whose
// policy groups the caller belongs to.
func TestGroupsServices(t *testing.T) {
	e := newPrivEnv(t)
	app := e.admin.folder("", "app")
	svc := e.admin.folder(app, "payroll")
	policy := e.admin.group(svc, "policy")
	e.admin.call("PUT", "/api/groups/folders/"+svc+"/object-types", `{"types":["service"]}`, 200)
	e.admin.call("PUT", "/api/groups/"+policy+"/object-types", `{"types":["policy"]}`, 200)
	e.admin.call("POST", "/api/groups/"+policy+"/members", fmt.Sprintf(`{"identity":%d}`, e.ident("bob")), 201)
	bob, alice := e.user("bob", "bob"), e.user("alice", "alice")
	list := func(c grpClient) []any { return c.call("GET", "/api/groups/services", "", 200)["items"].([]any) }
	if len(list(bob)) != 0 {
		t.Error("bob sees a service he cannot view")
	}
	e.grant("/api/groups/folders/"+svc, "stem_view", "bob", "")
	e.grant("/api/groups/"+policy, "view", "bob", "")
	got := list(bob)
	if len(got) != 1 {
		t.Fatalf("bob's services = %v", got)
	}
	s := got[0].(map[string]any)
	if s["folder"].(map[string]any)["name"] != "app:payroll" || len(s["groups"].([]any)) != 1 ||
		s["groups"].([]any)[0].(map[string]any)["name"] != "app:payroll:policy" {
		t.Errorf("service = %v", s)
	}
	e.grant("/api/groups/folders/"+svc, "stem_view", "alice", "")
	e.grant("/api/groups/"+policy, "view", "alice", "")
	if len(list(alice)) != 0 {
		t.Error("alice is in no policy group and has a service")
	}
	// a caller with no identity link is nobody
	if got := e.admin.call("GET", "/api/groups/services", "", 200)["items"].([]any); len(got) != 0 {
		t.Errorf("an admin without an identity has %d services", len(got))
	}
}

// TestGroupsAttrsTenantIsolation: another tenant's definitions, names, actions
// and assignments look nonexistent, and the same names are free in this one.
func TestGroupsAttrsTenantIsolation(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := grpClient{client{t, isolationServer(t, f, f.A.ID).Handler()}}
	b := grpClient{client{t, isolationServer(t, f, f.B.ID).Handler()}}
	af := a.folder("", "app")
	ag := a.group(af, "g")
	ad := a.attrDef(af, "tags", `"assign_to":["group"],"multi_assign":true`)
	an := a.attrName(ad, "n")
	act := a.call("GET", "/api/groups/attr-defs/"+ad+"/actions", "", 200)["items"].([]any)[0].(map[string]any)["id"].(string)
	aa := a.call("POST", "/api/groups/attr-assignments", `{"name":"`+an+`","owner_type":"group","owner":"`+ag+`"}`, 201)["id"].(string)
	bf := b.folder("", "app")
	bg := b.group(bf, "g")
	for _, tc := range [][3]string{
		{"GET", "/api/groups/attr-defs/" + ad, ""}, {"PATCH", "/api/groups/attr-defs/" + ad, `{"description":"x"}`}, {"DELETE", "/api/groups/attr-defs/" + ad, ""},
		{"GET", "/api/groups/attr-defs/" + ad + "/actions", ""}, {"POST", "/api/groups/attr-defs/" + ad + "/actions", `{"name":"x"}`},
		{"DELETE", "/api/groups/attr-defs/" + ad + "/actions/" + act, ""}, {"GET", "/api/groups/attr-defs/" + ad + "/privileges", ""},
		{"POST", "/api/groups/attr-defs", `{"folder":"` + af + `","extension":"x","assign_to":["group"]}`},
		{"GET", "/api/groups/attr-names/" + an, ""}, {"DELETE", "/api/groups/attr-names/" + an, ""},
		{"POST", "/api/groups/attr-names", `{"def":"` + ad + `","extension":"x"}`}, {"GET", "/api/groups/attr-names?def=" + ad, ""},
		{"PUT", "/api/groups/attr-names/" + an + "/implies", `{"implies":[]}`},
		{"GET", "/api/groups/attr-assignments/" + aa, ""}, {"DELETE", "/api/groups/attr-assignments/" + aa, ""},
		{"PATCH", "/api/groups/attr-assignments/" + aa, `{"disabled_at":null}`}, {"PUT", "/api/groups/attr-assignments/" + aa + "/values", `{"values":[]}`},
		{"POST", "/api/groups/attr-assignments", `{"name":"` + an + `","owner_type":"group","owner":"` + bg + `"}`},
		{"POST", "/api/groups/attr-assignments", `{"name":"app:tags:n","owner_type":"group","owner":"` + bg + `"}`},
		{"GET", "/api/groups/" + ag + "/object-types", ""}, {"PUT", "/api/groups/" + ag + "/object-types", `{"types":["ref"]}`},
		{"GET", "/api/groups/folders/" + af + "/object-types", ""},
	} {
		if rec := b.do(tc[0], tc[1], tc[2]); rec.Code != 404 {
			t.Errorf("B %s %s = %d %.100s, want 404", tc[0], tc[1], rec.Code, rec.Body.String())
		}
	}
	for _, p := range []string{"/api/groups/attr-defs", "/api/groups/attr-names", "/api/groups/attr-assignments"} {
		if n := len(b.call("GET", p, "", 200)["items"].([]any)); n != 0 {
			t.Errorf("B lists %d of A's items at %s", n, p)
		}
	}
	// the same names are free in B, and A's data is as it was
	bd := b.attrDef(bf, "tags", `"assign_to":["group"],"multi_assign":true`)
	bn := b.attrName(bd, "n")
	b.call("POST", "/api/groups/attr-assignments", `{"name":"app:tags:n","owner_type":"group","owner":"`+bg+`"}`, 201)
	if bn == an || bd == ad {
		t.Error("two tenants share ids")
	}
	if got := a.call("GET", "/api/groups/attr-assignments/"+aa, "", 200); got["owner"] != ag {
		t.Errorf("A's assignment = %v", got)
	}
	if n := len(a.call("GET", "/api/groups/attr-assignments?def="+ad, "", 200)["items"].([]any)); n != 1 {
		t.Errorf("A's assignments = %d", n)
	}
}

// TestGroupsAttrsRefusedChangeWritesNoEvent: a refused change leaves no audit
// event and no change event, and an accepted one leaves both.
func TestGroupsAttrsRefusedChangeWritesNoEvent(t *testing.T) {
	c, f := newGrp(t)
	app := c.folder("", "app")
	g := c.group(app, "g")
	d := c.attrDef(app, "one", `"assign_to":["group"]`)
	n := c.attrName(d, "n")
	count := func() (audit, events int) {
		err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
			evs, err := tx.AuditEvents(store.AuditFilter{})
			if err != nil {
				return err
			}
			for _, e := range evs {
				if strings.HasPrefix(e.Action, "groups.attr") {
					audit++
				}
			}
			h, err := tx.GrpEventHead()
			events = int(h.LastSeq)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return audit, events
	}
	body := `{"name":"` + n + `","owner_type":"group","owner":"` + g + `","values":[]}`
	a0, e0 := count()
	c.call("POST", "/api/groups/attr-assignments", body, 201)
	a1, e1 := count()
	if a1 != a0+1 || e1 != e0+1 {
		t.Errorf("an accepted assignment wrote %d audit events and %d change events, want 1 and 1", a1-a0, e1-e0)
	}
	// single-assign, then a marker with a value
	c.call("POST", "/api/groups/attr-assignments", body, 409)
	c.call("POST", "/api/groups/attr-assignments", `{"name":"`+n+`","owner_type":"group","owner":"`+g+`","values":["x"]}`, 422)
	if a2, e2 := count(); a2 != a1 || e2 != e1 {
		t.Errorf("a refused assignment wrote %d audit events and %d change events", a2-a1, e2-e1)
	}
}
