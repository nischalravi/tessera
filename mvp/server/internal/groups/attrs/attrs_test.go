package attrs_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// world is tenant B with folders app and app:foo, groups app:g1, app:g2 and
// app:foo:policy, and identities Ivan, Alice and Pat.
type world struct {
	f                *storetest.Fixture
	app, foo         store.FolderID
	g1, g2, policy   store.GroupID
	ivan, alice, pat int64
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{f: storetest.TwoTenants(t)}
	w.tx(t, func(c *store.TenantTx) {
		e := model.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
		folder := func(parent store.FolderID, ext string) store.FolderID {
			f, err := e.CreateFolder(model.CreateFolderInput{Parent: parent, Extension: ext})
			if err != nil {
				t.Fatal(err)
			}
			return f.ID
		}
		group := func(folder store.FolderID, ext string) store.GroupID {
			g, err := e.CreateGroup(model.CreateGroupInput{Folder: folder, Extension: ext})
			if err != nil {
				t.Fatal(err)
			}
			return g.ID
		}
		w.app = folder("", "app")
		w.foo = folder(w.app, "foo")
		w.g1, w.g2, w.policy = group(w.app, "g1"), group(w.app, "g2"), group(w.foo, "policy")
		ident := func(name string) int64 {
			id, err := c.InsertIdentity(&store.Identity{ExternalID: name, Name: name, Type: "person", Status: "active", CreatedAt: storetest.Now})
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
		w.ivan, w.alice, w.pat = ident("Ivan"), ident("Alice"), ident("Pat")
	})
	return w
}

func (w *world) tx(t *testing.T, fn func(c *store.TenantTx)) {
	t.Helper()
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) error { fn(c); return nil }); err != nil {
		t.Fatal(err)
	}
}

func env(c *store.TenantTx) attrs.Env {
	return attrs.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
}

// def creates a definition in the folder.
func def(t *testing.T, c *store.TenantTx, folder store.FolderID, in attrs.DefInput) *store.GrpAttrDef {
	t.Helper()
	in.Folder = folder
	d, err := attrs.CreateDef(env(c), in)
	if err != nil {
		t.Fatalf("CreateDef(%s): %v", in.Extension, err)
	}
	return d
}

func name(t *testing.T, c *store.TenantTx, d *store.GrpAttrDef, ext string) *store.GrpAttrName {
	t.Helper()
	n, err := attrs.CreateName(env(c), attrs.NameInput{Def: d.ID, Extension: ext})
	if err != nil {
		t.Fatalf("CreateName(%s): %v", ext, err)
	}
	return n
}

func raw(vs ...string) []json.RawMessage {
	out := make([]json.RawMessage, len(vs))
	for i, v := range vs {
		out[i] = json.RawMessage(v)
	}
	return out
}

func group(id store.GroupID) attrs.Owner {
	return attrs.Owner{Type: store.AttrOwnerGroup, ID: string(id)}
}
func folder(id store.FolderID) attrs.Owner {
	return attrs.Owner{Type: store.AttrOwnerFolder, ID: string(id)}
}

// wantErr checks the error is an *attrs.Error of the kind and code.
func wantErr(t *testing.T, err error, kind attrs.Kind, code string) {
	t.Helper()
	var ae *attrs.Error
	if !errors.As(err, &ae) || ae.Kind != kind || ae.Code != code {
		t.Errorf("err = %v, want kind %d code %s", err, kind, code)
	}
}

func allTypes() []string {
	return []string{store.AttrOwnerFolder, store.AttrOwnerGroup, store.AttrOwnerIdentity, store.AttrOwnerMembership,
		store.AttrOwnerAttrDef, store.AttrOwnerAssignment}
}

// ---------------------------------------------------------------- values

func TestCanonicalFloat(t *testing.T) {
	for in, want := range map[string]string{"12.5": "12.5", "1.50": "1.5", "1.0": "1", "0": "0", "-0": "0", "-0.00": "0",
		"-3.14159": "-3.14159", "100": "100", "0.10": "0.1", "123456789012345678901234567890.5": "123456789012345678901234567890.5"} {
		if got, err := attrs.CanonicalFloat(in); err != nil || got != want {
			t.Errorf("CanonicalFloat(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "1e3", "1E3", "NaN", "Inf", "-Inf", ".5", "5.", "+1", " 1", "1 ", "01", "1.2.3", "0x10", "1,5",
		strings.Repeat("9", 41)} {
		if got, err := attrs.CanonicalFloat(in); err == nil {
			t.Errorf("CanonicalFloat(%q) = %q, want an error", in, got)
		}
	}
}

// TestValues_NoFloats: a floating value is a decimal string end to end. No
// stored or returned value type has a float field, a JSON number is refused for
// a floating attribute, an integer attribute takes only an integer literal, and
// the audit event and the change event carry the value as a string.
func TestValues_NoFloats(t *testing.T) {
	for _, v := range []any{store.GrpAttrValue{}, store.GrpAttrAssign{}, attrs.Assigned{}, attrs.EffectiveName{}, attrs.Finding{}} {
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			k := typ.Field(i).Type
			for k.Kind() == reflect.Pointer || k.Kind() == reflect.Slice {
				k = k.Elem()
			}
			if k.Kind() == reflect.Float32 || k.Kind() == reflect.Float64 {
				t.Errorf("%s.%s is a float", typ.Name(), typ.Field(i).Name)
			}
		}
	}
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		fl := def(t, c, w.app, attrs.DefInput{Extension: "weight", ValueType: store.AttrValueFloating, MultiValued: true,
			AssignTo: []string{store.AttrOwnerGroup}})
		in := def(t, c, w.app, attrs.DefInput{Extension: "count", ValueType: store.AttrValueInteger, AssignTo: []string{store.AttrOwnerGroup}})
		flName, inName := name(t, c, fl, "w"), name(t, c, in, "n")
		// a JSON number is not a floating value, however it is written
		for _, v := range []string{"12.5", "12", "1e3", "-0.5"} {
			_, err := attrs.Assign(env(c), attrs.AssignInput{Name: flName.ID, Owner: group(w.g1), Values: raw(v)})
			wantErr(t, err, attrs.Invalid, "float_must_be_string")
		}
		for _, v := range []string{`"1e3"`, `"NaN"`, `".5"`, `true`, `null`, `[]`} {
			if _, err := attrs.Assign(env(c), attrs.AssignInput{Name: flName.ID, Owner: group(w.g1), Values: raw(v)}); err == nil {
				t.Errorf("floating value %s was accepted", v)
			}
		}
		// an integer is an integer literal
		for _, v := range []string{"1.0", "1e2", `"5"`, "5.5", "9223372036854775808", "-", "true", "01"} {
			if _, err := attrs.Assign(env(c), attrs.AssignInput{Name: inName.ID, Owner: group(w.g1), Values: raw(v)}); err == nil {
				t.Errorf("integer value %s was accepted", v)
			}
		}
		got, err := attrs.Assign(env(c), attrs.AssignInput{Name: flName.ID, Owner: group(w.g1), Values: raw(`"12.50"`)})
		if err != nil {
			t.Fatal(err)
		}
		if v := got.Values[0]; v.ValueString == nil || *v.ValueString != "12.5" || v.ValueInteger != nil || v.Key != "f:12.5" {
			t.Errorf("stored floating value = %+v, want the string 12.5", v)
		}
		if j := attrs.JSON(got.Values[0]); j != "12.5" {
			t.Errorf("JSON(value) = %#v, want the string \"12.5\"", j)
		}
		// 12.5 and 12.50 are the same value
		if _, err := attrs.SetValues(env(c), got.Assign.ID, raw(`"12.5"`, `"12.50"`)); err == nil {
			t.Error("two spellings of one value were accepted")
		}
		if _, err := attrs.Assign(env(c), attrs.AssignInput{Name: inName.ID, Owner: group(w.g1), Values: raw("-42")}); err != nil {
			t.Errorf("an integer was refused: %v", err)
		}
		// audit and change events carry strings, so their hash input has no float
		evs, err := c.AuditEvents(store.AuditFilter{Action: "groups.attr.assigned"})
		if err != nil || len(evs) != 2 {
			t.Fatalf("audit events = %d, %v", len(evs), err)
		}
		bareNumber := regexp.MustCompile(`[:\[,]-?[0-9]+\.[0-9]+[,\]}]`)
		for _, ev := range evs {
			if s := string(ev.Detail); bareNumber.MatchString(s) {
				t.Errorf("audit detail carries a bare decimal number: %s", s)
			}
		}
		gevs, err := c.GrpEventsOfObject("attribute", got.Assign.ID, 0, 10)
		if err != nil || len(gevs) != 1 {
			t.Fatalf("change events = %d, %v", len(gevs), err)
		}
		if s := string(gevs[0].Data); bareNumber.MatchString(s) {
			t.Errorf("change event carries a bare decimal number: %s", s)
		}
		var data struct {
			Values []any `json:"values"`
		}
		if err := json.Unmarshal(gevs[0].Data, &data); err != nil || len(data.Values) != 1 || data.Values[0] != "f:12.5" {
			t.Errorf("change event values = %v, %v", data.Values, err)
		}
	})
}

func TestValues_Types(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		mk := func(ext, vt string, multi bool) *store.GrpAttrName {
			d := def(t, c, w.app, attrs.DefInput{Extension: ext, ValueType: vt, MultiValued: multi, MultiAssign: true,
				AssignTo: []string{store.AttrOwnerGroup}})
			return name(t, c, d, "x")
		}
		str := mk("s", store.AttrValueString, true)
		ts := mk("t", store.AttrValueTimestamp, false)
		mem := mk("m", store.AttrValueMemberID, false)
		mk2 := mk("mk", store.AttrValueMarker, false)
		for _, tc := range []struct {
			n    *store.GrpAttrName
			vals []string
			ok   bool
			code string
		}{
			{str, []string{`"a"`, `"b"`}, true, ""},
			{str, []string{`"a"`, `"a"`}, false, "duplicate_value"},
			{str, []string{`""`}, false, "invalid_value"},
			{str, []string{`5`}, false, "invalid_value"},
			{str, []string{`"` + strings.Repeat("x", attrs.MaxValueLen+1) + `"`}, false, "invalid_value"},
			{str, []string{`"a\u0007b"`}, false, "invalid_value"},
			{ts, []string{`"2026-01-02T03:04:05Z"`}, true, ""},
			{ts, []string{`"2026-01-02T03:04:05+02:00"`}, true, ""},
			{ts, []string{`"yesterday"`}, false, "invalid_value"},
			{ts, []string{`"2026-01-02T03:04:05Z"`, `"2026-01-03T03:04:05Z"`}, false, "single_valued"},
			{mem, []string{`1`}, false, "unknown_identity"},
			{mk2, nil, true, ""},
			{mk2, []string{`"x"`}, false, "marker_has_no_values"},
		} {
			_, err := attrs.Assign(env(c), attrs.AssignInput{Name: tc.n.ID, Owner: group(w.g1), Values: raw(tc.vals...)})
			if tc.ok != (err == nil) {
				t.Errorf("%s %v: err = %v", tc.n.ID[:4], tc.vals, err)
			} else if !tc.ok {
				wantErr(t, err, attrs.Invalid, tc.code)
			}
		}
		a, err := attrs.Assign(env(c), attrs.AssignInput{Name: mem.ID, Owner: group(w.g2), Values: raw(jsonInt(w.ivan))})
		if err != nil || a.Values[0].ValueMemberID == nil || *a.Values[0].ValueMemberID != w.ivan {
			t.Errorf("member id value = %+v, %v", a, err)
		}
		// a timestamp is stored in UTC
		a, err = attrs.Assign(env(c), attrs.AssignInput{Name: ts.ID, Owner: group(w.g2), Values: raw(`"2026-01-02T03:04:05+02:00"`)})
		if err != nil || a.Values[0].ValueTimestamp == nil || !a.Values[0].ValueTimestamp.Equal(time.Date(2026, 1, 2, 1, 4, 5, 0, time.UTC)) {
			t.Errorf("timestamp value = %+v, %v", a, err)
		}
	})
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// ---------------------------------------------------------------- implication closures

func TestImplies_ClosureMaintenance(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		d := def(t, c, w.app, attrs.DefInput{Extension: "levels", AssignTo: []string{store.AttrOwnerGroup}, MultiAssign: true})
		other := def(t, c, w.app, attrs.DefInput{Extension: "other", AssignTo: []string{store.AttrOwnerGroup}})
		a, b, cc, dd := name(t, c, d, "a"), name(t, c, d, "b"), name(t, c, d, "c"), name(t, c, d, "d")
		foreign := name(t, c, other, "z")
		closure := func(n *store.GrpAttrName) (direct, all []string) {
			direct, all, err := attrs.Implied(c, store.ImpliesNames, n.ID)
			if err != nil {
				t.Fatal(err)
			}
			return direct, all
		}
		ids := func(ns ...*store.GrpAttrName) []string {
			out := make([]string, len(ns))
			for i, n := range ns {
				out[i] = n.ID
			}
			slices.Sort(out)
			return out
		}
		set := func(n *store.GrpAttrName, to ...*store.GrpAttrName) error {
			_, err := attrs.SetNameImplies(env(c), n.ID, ids(to...))
			return err
		}
		check := func(what string, n *store.GrpAttrName, direct, all []*store.GrpAttrName) {
			t.Helper()
			gd, ga := closure(n)
			if !slices.Equal(gd, ids(direct...)) || !slices.Equal(ga, ids(all...)) {
				t.Errorf("%s: direct %v all %v, want %v %v", what, gd, ga, ids(direct...), ids(all...))
			}
		}
		// a -> b -> c
		if err := errors.Join(set(a, b), set(b, cc)); err != nil {
			t.Fatal(err)
		}
		check("a after a->b->c", a, []*store.GrpAttrName{b}, []*store.GrpAttrName{b, cc})
		check("b", b, []*store.GrpAttrName{cc}, []*store.GrpAttrName{cc})
		check("c", cc, nil, nil)
		// c -> d lengthens a's closure; a also gets a direct edge to c, which stays direct
		if err := errors.Join(set(cc, dd), set(a, b, cc)); err != nil {
			t.Fatal(err)
		}
		check("a after c->d and a->c", a, []*store.GrpAttrName{b, cc}, []*store.GrpAttrName{b, cc, dd})
		// dropping b->c leaves c reachable from a directly, and d through it
		if err := set(b); err != nil {
			t.Fatal(err)
		}
		check("a after b loses c", a, []*store.GrpAttrName{b, cc}, []*store.GrpAttrName{b, cc, dd})
		check("b after losing c", b, nil, nil)
		if err := set(a, b); err != nil {
			t.Fatal(err)
		}
		check("a after a->b only", a, []*store.GrpAttrName{b}, []*store.GrpAttrName{b})
		if err := set(a, b, cc); err != nil {
			t.Fatal(err)
		}
		// a cycle is refused with its path, and nothing changes
		err := set(dd, a)
		var ae *attrs.Error
		if !errors.As(err, &ae) || ae.Kind != attrs.Conflict || ae.Code != "cycle" {
			t.Fatalf("a cycle: %v", err)
		}
		if p, _ := ae.Extra["path"].([]string); len(p) < 3 || p[0] != p[len(p)-1] {
			t.Errorf("cycle path = %v", ae.Extra["path"])
		}
		check("d after the refused cycle", dd, nil, nil)
		wantErr(t, set(a, a), attrs.Invalid, "invalid_implies")
		wantErr(t, set(a, foreign), attrs.Invalid, "invalid_implies")
		// deleting a name rebuilds the closure without it
		if err := attrs.DeleteName(env(c), cc.ID); err != nil {
			t.Fatal(err)
		}
		check("a after c is deleted", a, []*store.GrpAttrName{b}, []*store.GrpAttrName{b})
		rows, err := c.GrpAttrImpliesOfDef(store.ImpliesNames, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.From == cc.ID || r.To == cc.ID {
				t.Errorf("closure row names the deleted name: %+v", r)
			}
		}
		// the effective names of an assignment are the name and its closure
		if ids, err := attrs.EffectiveNameIDs(c, a.ID); err != nil || !slices.Equal(ids, ids2(a, b)) {
			t.Errorf("EffectiveNameIDs(a) = %v, %v", ids, err)
		}
	})
}

func ids2(ns ...*store.GrpAttrName) []string {
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.ID
	}
	slices.Sort(out)
	return out
}

func TestImplies_Actions(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		d := def(t, c, w.app, attrs.DefInput{Extension: "perm", AttrType: store.AttrTypePerm, AssignTo: []string{store.AttrOwnerGroup}})
		read, err := attrs.CreateAction(env(c), d.ID, "read", "")
		if err != nil {
			t.Fatal(err)
		}
		write, _ := attrs.CreateAction(env(c), d.ID, "write", "")
		admin, _ := attrs.CreateAction(env(c), d.ID, "admin", "")
		if _, err := attrs.CreateAction(env(c), d.ID, "READ", ""); err == nil {
			t.Error("an action was created twice (case-insensitively)")
		}
		if _, err := attrs.CreateAction(env(c), d.ID, "bad name", ""); err == nil {
			t.Error("an invalid action name was accepted")
		}
		if _, err := attrs.SetActionImplies(env(c), admin.ID, []string{write.ID}); err != nil {
			t.Fatal(err)
		}
		if _, err := attrs.SetActionImplies(env(c), write.ID, []string{read.ID}); err != nil {
			t.Fatal(err)
		}
		_, all, _ := attrs.Implied(c, store.ImpliesActions, admin.ID)
		if want := []string{read.ID, write.ID}; !slices.Equal(all, sorted(want)) {
			t.Errorf("admin implies %v, want %v", all, want)
		}
		_, err = attrs.SetActionImplies(env(c), read.ID, []string{admin.ID})
		wantErr(t, err, attrs.Conflict, "cycle")
		// the default action stays, and an action in use cannot go
		acts, _ := c.GrpAttrActionsOf(d.ID)
		for _, a := range acts {
			if a.Name == attrs.DefaultAction {
				wantErr(t, attrs.DeleteAction(env(c), a.ID), attrs.Conflict, "default_action")
			}
		}
		n := name(t, c, d, "n")
		if _, err := attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Action: write.ID, Owner: group(w.g1)}); err != nil {
			t.Fatal(err)
		}
		wantErr(t, attrs.DeleteAction(env(c), write.ID), attrs.Conflict, "attr_action_in_use")
		if err := attrs.DeleteAction(env(c), admin.ID); err != nil {
			t.Fatal(err)
		}
		if _, all, _ := attrs.Implied(c, store.ImpliesActions, write.ID); !slices.Equal(all, []string{read.ID}) {
			t.Errorf("write implies %v after admin is deleted", all)
		}
	})
}

func sorted(s []string) []string { slices.Sort(s); return s }

// ---------------------------------------------------------------- assignments

func TestAssign_OnAssignment(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		onGroup := def(t, c, w.app, attrs.DefInput{Extension: "tag", ValueType: store.AttrValueString, MultiValued: true,
			AssignTo: []string{store.AttrOwnerGroup, store.AttrOwnerAssignment}, MultiAssign: true})
		groupOnly := def(t, c, w.app, attrs.DefInput{Extension: "only", AssignTo: []string{store.AttrOwnerGroup}})
		tag, only := name(t, c, onGroup, "tag"), name(t, c, groupOnly, "only")
		l1, err := attrs.Assign(env(c), attrs.AssignInput{Name: tag.ID, Owner: group(w.g1), Values: raw(`"level 1"`)})
		if err != nil {
			t.Fatal(err)
		}
		owner := func(a *attrs.Assigned) attrs.Owner {
			return attrs.Owner{Type: store.AttrOwnerAssignment, ID: a.Assign.ID}
		}
		l2, err := attrs.Assign(env(c), attrs.AssignInput{Name: tag.ID, Owner: owner(l1), Values: raw(`"level 2"`)})
		if err != nil {
			t.Fatalf("an assignment on an assignment: %v", err)
		}
		l3, err := attrs.Assign(env(c), attrs.AssignInput{Name: tag.ID, Owner: owner(l2), Values: raw(`"level 3"`)})
		if err != nil {
			t.Fatalf("an assignment on an assignment on an assignment: %v", err)
		}
		_, err = attrs.Assign(env(c), attrs.AssignInput{Name: tag.ID, Owner: owner(l3), Values: raw(`"level 4"`)})
		wantErr(t, err, attrs.Invalid, "assignment_too_deep")
		// a definition that is not for assignments cannot sit on one
		_, err = attrs.Assign(env(c), attrs.AssignInput{Name: only.ID, Owner: owner(l1)})
		wantErr(t, err, attrs.Invalid, "owner_type_not_allowed")
		_, err = attrs.Assign(env(c), attrs.AssignInput{Name: tag.ID, Owner: attrs.Owner{Type: store.AttrOwnerAssignment, ID: "00000000-0000-4000-8000-000000000000"}})
		wantErr(t, err, attrs.NotFound, "not_found")
		// the assignments on an assignment are listed under it, and go with it
		on, err := c.GrpAttrAssigns(store.GrpAttrAssignFilter{OwnerType: store.AttrOwnerAssignment, OwnerID: l1.Assign.ID})
		if err != nil || len(on) != 1 || on[0].ID != l2.Assign.ID {
			t.Errorf("assignments on level 1 = %v, %v", on, err)
		}
		n, err := attrs.Unassign(env(c), l1.Assign.ID)
		if err != nil || n != 3 {
			t.Fatalf("Unassign removed %d, %v; want 3", n, err)
		}
		for _, id := range []string{l1.Assign.ID, l2.Assign.ID, l3.Assign.ID} {
			if _, err := c.GrpAttrAssign(id); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("assignment %s survived: %v", id[:6], err)
			}
			if vs, _ := c.GrpAttrValuesOf(id); len(vs) != 0 {
				t.Errorf("values of %s survived", id[:6])
			}
		}
		// each removal wrote its change event, deepest first
		var removed []string
		for _, id := range []string{l3.Assign.ID, l2.Assign.ID, l1.Assign.ID} {
			evs, _ := c.GrpEventsOfObject("attribute", id, 0, 10)
			if len(evs) == 0 || evs[len(evs)-1].Type != "attribute.removed" {
				t.Errorf("no attribute.removed event for %s", id[:6])
			} else {
				removed = append(removed, id)
			}
		}
		if len(removed) != 3 {
			t.Errorf("removed events: %d", len(removed))
		}
	})
}

func TestAssign_OwnerTypes(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		d := def(t, c, w.app, attrs.DefInput{Extension: "any", MultiAssign: true, AssignTo: append(allTypes(), store.AttrOwnerEffectiveMembership)})
		n := name(t, c, d, "n")
		e := model.Env{Tx: c, Now: storetest.Now, TenantAdmin: true}
		m, err := e.AddMember(w.g1, model.MemberInput{Identity: &w.ivan})
		if err != nil {
			t.Fatal(err)
		}
		owners := []attrs.Owner{folder(w.app), group(w.g1), {Type: store.AttrOwnerIdentity, ID: jsonInt(w.alice)},
			{Type: store.AttrOwnerMembership, ID: m.Member.ID}, {Type: store.AttrOwnerAttrDef, ID: d.ID}}
		var made []*attrs.Assigned
		for _, o := range owners {
			a, err := attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: o})
			if err != nil {
				t.Fatalf("assign to a %s: %v", o.Type, err)
			}
			made = append(made, a)
		}
		// an owner that does not exist, in the right shape
		for _, o := range []attrs.Owner{{Type: store.AttrOwnerFolder, ID: "00000000-0000-4000-8000-000000000000"},
			{Type: store.AttrOwnerGroup, ID: "nope"}, {Type: store.AttrOwnerIdentity, ID: "999999"}, {Type: store.AttrOwnerIdentity, ID: "x"},
			{Type: store.AttrOwnerMembership, ID: "nope"}, {Type: store.AttrOwnerAttrDef, ID: "nope"}} {
			_, err := attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: o})
			wantErr(t, err, attrs.NotFound, "not_found")
		}
		_, err = attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: attrs.Owner{Type: "bogus", ID: "x"}})
		wantErr(t, err, attrs.Invalid, "owner_type_not_allowed")
		// an effective membership is derived: read-only
		_, err = attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: attrs.Owner{Type: store.AttrOwnerEffectiveMembership,
			ID: string(w.g1) + ":" + jsonInt(w.ivan)}})
		wantErr(t, err, attrs.Invalid, "effective_membership_read_only")
		// a deleted group takes no attributes
		if err := e.DeleteGroup(w.g2); err != nil {
			t.Fatal(err)
		}
		_, err = attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: group(w.g2)})
		wantErr(t, err, attrs.Conflict, "group_deleted")
		// removing the membership removes its attributes with it
		if _, err := e.RemoveMember(w.g1, jsonInt(w.ivan)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.GrpAttrAssign(made[3].Assign.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the membership's assignment survived its removal: %v", err)
		}
		// deleting the definition's own assignment on itself, then the definition
		wantErr(t, attrs.DeleteDef(env(c), d.ID), attrs.Conflict, "attr_def_in_use")
	})
}

func TestAssign_RulesAndDates(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		single := def(t, c, w.app, attrs.DefInput{Extension: "single", AssignTo: []string{store.AttrOwnerGroup}})
		multi := def(t, c, w.app, attrs.DefInput{Extension: "multi", AssignTo: []string{store.AttrOwnerGroup}, MultiAssign: true})
		perm := def(t, c, w.app, attrs.DefInput{Extension: "perm", AttrType: store.AttrTypePerm, AssignTo: []string{store.AttrOwnerGroup}})
		sn, mn, pn := name(t, c, single, "n"), name(t, c, multi, "n"), name(t, c, perm, "n")
		if _, err := attrs.Assign(env(c), attrs.AssignInput{Name: sn.ID, Owner: group(w.g1)}); err != nil {
			t.Fatal(err)
		}
		_, err := attrs.Assign(env(c), attrs.AssignInput{Name: sn.ID, Owner: group(w.g1)})
		wantErr(t, err, attrs.Conflict, "already_assigned")
		if _, err := attrs.Assign(env(c), attrs.AssignInput{Name: sn.ID, Owner: group(w.g2)}); err != nil {
			t.Errorf("another owner: %v", err)
		}
		for i := 0; i < 2; i++ {
			if _, err := attrs.Assign(env(c), attrs.AssignInput{Name: mn.ID, Owner: group(w.g1)}); err != nil {
				t.Errorf("multi-assign #%d: %v", i, err)
			}
		}
		// disallow is for perm only
		_, err = attrs.Assign(env(c), attrs.AssignInput{Name: sn.ID, Owner: group(w.g2), Disallowed: true})
		wantErr(t, err, attrs.Invalid, "disallow_not_allowed")
		dis, err := attrs.Assign(env(c), attrs.AssignInput{Name: pn.ID, Owner: group(w.g1), Disallowed: true})
		if err != nil || !dis.Assign.Disallowed {
			t.Fatalf("a disallowed perm: %+v, %v", dis, err)
		}
		// dates
		from, to := storetest.Now.Add(time.Hour), storetest.Now.Add(2*time.Hour)
		_, err = attrs.Assign(env(c), attrs.AssignInput{Name: mn.ID, Owner: group(w.g2), EnabledFrom: &to, DisabledAt: &from})
		wantErr(t, err, attrs.Invalid, "invalid_dates")
		dated, err := attrs.Assign(env(c), attrs.AssignInput{Name: mn.ID, Owner: group(w.g2), EnabledFrom: &from, DisabledAt: &to})
		if err != nil {
			t.Fatal(err)
		}
		for at, want := range map[time.Time]bool{storetest.Now: false, from: true, from.Add(time.Minute): true, to: false} {
			if got := attrs.Active(dated.Assign, at); got != want {
				t.Errorf("Active at %v = %v, want %v", at, got, want)
			}
		}
		if attrs.Active(dis.Assign, storetest.Now) {
			t.Error("a disallowed assignment is active")
		}
		// an unknown action, an action of another definition
		_, err = attrs.Assign(env(c), attrs.AssignInput{Name: mn.ID, Owner: group(w.g2), Action: "00000000-0000-4000-8000-000000000000"})
		wantErr(t, err, attrs.NotFound, "not_found")
		foreign, _ := c.GrpAttrActionsOf(single.ID)
		_, err = attrs.Assign(env(c), attrs.AssignInput{Name: mn.ID, Owner: group(w.g2), Action: foreign[0].ID})
		wantErr(t, err, attrs.Invalid, "unknown_action")
		// update: dates move, a stale version is refused
		later := to.Add(time.Hour)
		up, err := attrs.UpdateAssign(env(c), dated.Assign.ID, attrs.AssignUpdate{DisabledAt: &later})
		if err != nil || !up.Assign.DisabledAt.Equal(later) || up.Assign.Version != 2 {
			t.Fatalf("UpdateAssign = %+v, %v", up, err)
		}
		stale := int64(1)
		_, err = attrs.UpdateAssign(env(c), dated.Assign.ID, attrs.AssignUpdate{Version: &stale})
		wantErr(t, err, attrs.Conflict, "version_conflict")
		up, err = attrs.UpdateAssign(env(c), dated.Assign.ID, attrs.AssignUpdate{ClearDisabledAt: true, ClearEnabledFrom: true})
		if err != nil || up.Assign.DisabledAt != nil || up.Assign.EnabledFrom != nil {
			t.Errorf("cleared dates = %+v, %v", up, err)
		}
		_, err = attrs.UpdateAssign(env(c), dated.Assign.ID, attrs.AssignUpdate{EnabledFrom: &to, DisabledAt: &from})
		wantErr(t, err, attrs.Invalid, "invalid_dates")
	})
}

func TestEffective_ThroughImplication(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		d := def(t, c, w.app, attrs.DefInput{Extension: "role", AssignTo: []string{store.AttrOwnerGroup}, MultiAssign: true})
		boss, staff, badge := name(t, c, d, "boss"), name(t, c, d, "staff"), name(t, c, d, "badge")
		if _, err := attrs.SetNameImplies(env(c), boss.ID, []string{staff.ID}); err != nil {
			t.Fatal(err)
		}
		if _, err := attrs.SetNameImplies(env(c), staff.ID, []string{badge.ID}); err != nil {
			t.Fatal(err)
		}
		past := storetest.Now.Add(-time.Hour)
		if _, err := attrs.Assign(env(c), attrs.AssignInput{Name: boss.ID, Owner: group(w.g1)}); err != nil {
			t.Fatal(err)
		}
		// an ended assignment of staff on the same group adds nothing
		if _, err := attrs.Assign(env(c), attrs.AssignInput{Name: staff.ID, Owner: group(w.g2), DisabledAt: &past, EnabledFrom: ptr(past.Add(-time.Hour))}); err != nil {
			t.Fatal(err)
		}
		got, err := attrs.Effective(c, group(w.g1), storetest.Now)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{boss.ID: false, staff.ID: true, badge.ID: true} // name -> implied
		if len(got) != 3 {
			t.Fatalf("effective names = %+v", got)
		}
		for _, e := range got {
			if imp, ok := want[e.NameID]; !ok || imp != e.Implied {
				t.Errorf("effective %+v, want implied=%v", e, imp)
			}
		}
		if got, _ := attrs.Effective(c, group(w.g2), storetest.Now); len(got) != 0 {
			t.Errorf("an ended assignment gives %+v", got)
		}
	})
}

func ptr[T any](v T) *T { return &v }

func TestDef_Lifecycle(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		d := def(t, c, w.app, attrs.DefInput{Extension: "tags", ValueType: store.AttrValueString, MultiValued: true, MultiAssign: true,
			AssignTo: []string{store.AttrOwnerGroup, store.AttrOwnerFolder}})
		if d.Name() != "app:tags" || d.Version != 1 {
			t.Errorf("created = %s v%d", d.Name(), d.Version)
		}
		acts, err := c.GrpAttrActionsOf(d.ID)
		if err != nil || len(acts) != 1 || acts[0].Name != attrs.DefaultAction {
			t.Errorf("a new definition's actions = %v, %v", acts, err)
		}
		_, err = attrs.CreateDef(env(c), attrs.DefInput{Folder: w.app, Extension: "TAGS", AssignTo: []string{store.AttrOwnerGroup}})
		wantErr(t, err, attrs.Conflict, "name_taken")
		def(t, c, w.foo, attrs.DefInput{Extension: "tags", AssignTo: []string{store.AttrOwnerGroup}}) // another folder: fine
		for name, in := range map[string]attrs.DefInput{
			"bad type":      {Extension: "a1", AttrType: "bogus", AssignTo: allTypes()},
			"bad value":     {Extension: "a2", ValueType: "bogus", AssignTo: allTypes()},
			"no owners":     {Extension: "a3"},
			"bad owner":     {Extension: "a4", AssignTo: []string{"bogus"}},
			"marker multi":  {Extension: "a5", ValueType: store.AttrValueMarker, MultiValued: true, AssignTo: allTypes()},
			"bad extension": {Extension: "a b", AssignTo: allTypes()},
			"dot":           {Extension: "..", AssignTo: allTypes()},
		} {
			in.Folder = w.app
			if _, err := attrs.CreateDef(env(c), in); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
		_, err = attrs.CreateDef(env(c), attrs.DefInput{Folder: "00000000-0000-4000-8000-000000000000", Extension: "x", AssignTo: allTypes()})
		wantErr(t, err, attrs.NotFound, "not_found")
		// the creator administers it, and the tenant's defaults apply
		// narrowing is refused while assignments need the wider form
		n := name(t, c, d, "n")
		for i := 0; i < 2; i++ {
			if _, err := attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: group(w.g1), Values: raw(`"a"`, `"b"`)}); err != nil {
				t.Fatal(err)
			}
		}
		_, err = attrs.UpdateDef(env(c), d.ID, attrs.DefUpdate{MultiValued: ptr(false)})
		wantErr(t, err, attrs.Conflict, "attr_def_in_use")
		_, err = attrs.UpdateDef(env(c), d.ID, attrs.DefUpdate{MultiAssign: ptr(false)})
		wantErr(t, err, attrs.Conflict, "attr_def_in_use")
		_, err = attrs.UpdateDef(env(c), d.ID, attrs.DefUpdate{AssignTo: &[]string{store.AttrOwnerFolder}})
		wantErr(t, err, attrs.Conflict, "attr_def_in_use")
		up, err := attrs.UpdateDef(env(c), d.ID, attrs.DefUpdate{Description: ptr("new"), AssignTo: &[]string{store.AttrOwnerGroup, store.AttrOwnerIdentity, store.AttrOwnerFolder}})
		if err != nil || up.Description != "new" || up.Version != 2 || !slices.Equal(up.AssignTo, []string{store.AttrOwnerFolder, store.AttrOwnerGroup, store.AttrOwnerIdentity}) {
			t.Errorf("updated = %+v, %v", up, err)
		}
		v := int64(1)
		_, err = attrs.UpdateDef(env(c), d.ID, attrs.DefUpdate{Description: ptr("x"), Version: &v})
		wantErr(t, err, attrs.Conflict, "version_conflict")
		// a name, an action or a definition in use cannot be deleted
		wantErr(t, attrs.DeleteName(env(c), n.ID), attrs.Conflict, "attr_name_in_use")
		wantErr(t, attrs.DeleteDef(env(c), d.ID), attrs.Conflict, "attr_def_in_use")
		as, _ := c.GrpAttrAssigns(store.GrpAttrAssignFilter{DefID: d.ID})
		for _, a := range as {
			if _, err := attrs.Unassign(env(c), a.ID); err != nil {
				t.Fatal(err)
			}
		}
		if err := attrs.DeleteDef(env(c), d.ID); err != nil {
			t.Fatal(err)
		}
		for what, err := range map[string]error{"def": errOf(c.GrpAttrDef(d.ID)), "name": errOf(c.GrpAttrName(n.ID))} {
			if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("deleted %s: %v", what, err)
			}
		}
		if acts, _ := c.GrpAttrActionsOf(d.ID); len(acts) != 0 {
			t.Error("a deleted definition kept its actions")
		}
	})
}

func errOf[T any](_ T, err error) error { return err }

func TestDef_MirroredFolderIsReadOnly(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		d := def(t, c, w.app, attrs.DefInput{Extension: "tags", AssignTo: []string{store.AttrOwnerGroup}})
		n := name(t, c, d, "n")
		if err := c.SetGrpFolderManagedBy(w.app, store.ManagedByGrouperMirror); err != nil {
			t.Fatal(err)
		}
		_, err := attrs.CreateDef(env(c), attrs.DefInput{Folder: w.app, Extension: "more", AssignTo: allTypes()})
		wantErr(t, err, attrs.Conflict, "folder_mirrored")
		_, err = attrs.CreateName(env(c), attrs.NameInput{Def: d.ID, Extension: "m"})
		wantErr(t, err, attrs.Conflict, "folder_mirrored")
		_, err = attrs.UpdateDef(env(c), d.ID, attrs.DefUpdate{Description: ptr("x")})
		wantErr(t, err, attrs.Conflict, "folder_mirrored")
		wantErr(t, attrs.DeleteDef(env(c), d.ID), attrs.Conflict, "folder_mirrored")
		// an assignment on a group of a mirrored folder
		_, err = attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: group(w.g1)}) // g1 lives in app
		wantErr(t, err, attrs.Conflict, "folder_mirrored")
	})
}

// TestAssign_MirroredGroup: a group mirrored from Grouper is read-only here even
// when its folder is not (K11).
func TestAssign_MirroredGroup(t *testing.T) {
	w := newWorld(t)
	w.tx(t, func(c *store.TenantTx) {
		d := def(t, c, w.app, attrs.DefInput{Extension: "tags", MultiAssign: true, AssignTo: []string{store.AttrOwnerGroup, store.AttrOwnerAssignment}})
		n := name(t, c, d, "n")
		mg := &store.NativeGroup{FolderID: w.foo, Extension: "mir", DisplayExtension: "mir", Name: "app:foo:mir", DisplayName: "app:foo:mir",
			ManagedBy: store.ManagedByGrouperMirror, CreatedAt: storetest.Now}
		if err := c.InsertGrpGroup(mg); err != nil {
			t.Fatal(err)
		}
		_, err := attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: group(mg.ID)})
		wantErr(t, err, attrs.Conflict, "folder_mirrored")
		// a group of the same folder that is not mirrored takes it
		if _, err := attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: group(w.policy)}); err != nil {
			t.Errorf("a group that is not mirrored: %v", err)
		}
	})
}

// ---------------------------------------------------------------- change events

// TestEvents_InTheChangeTransaction: an assignment, its change event and its
// audit event are one transaction: when it rolls back none of them stays.
func TestEvents_InTheChangeTransaction(t *testing.T) {
	w := newWorld(t)
	var d *store.GrpAttrDef
	var n *store.GrpAttrName
	w.tx(t, func(c *store.TenantTx) {
		d = def(t, c, w.app, attrs.DefInput{Extension: "tags", ValueType: store.AttrValueString, MultiAssign: true, MultiValued: true,
			AssignTo: []string{store.AttrOwnerGroup}})
		n = name(t, c, d, "n")
	})
	count := func(c *store.TenantTx) (assigns, auditN, events int) {
		as, _ := c.GrpAttrAssigns(store.GrpAttrAssignFilter{DefID: d.ID})
		au, _ := c.AuditEvents(store.AuditFilter{Action: "groups.attr.assigned"})
		h, _ := c.GrpEventHead()
		return len(as), len(au), int(h.LastSeq)
	}
	var a0, u0, e0 int
	w.tx(t, func(c *store.TenantTx) { a0, u0, e0 = count(c) })
	boom := errors.New("boom")
	err := w.f.DB.InTenant(context.Background(), w.f.B.ID, func(c *store.TenantTx) error {
		if _, err := attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: group(w.g1), Values: raw(`"x"`)}); err != nil {
			return err
		}
		if a, u, e := count(c); a != a0+1 || u != u0+1 || e != e0+1 {
			t.Errorf("inside: %d assignments, %d audit events, %d change events; want +1 each", a-a0, u-u0, e-e0)
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	w.tx(t, func(c *store.TenantTx) {
		if a, u, e := count(c); a != a0 || u != u0 || e != e0 {
			t.Errorf("after the rollback: %d, %d, %d; want %d, %d, %d", a, u, e, a0, u0, e0)
		}
		// committed, each change has its own events, with the object's snapshot
		a, err := attrs.Assign(env(c), attrs.AssignInput{Name: n.ID, Owner: group(w.g1), Values: raw(`"x"`)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := attrs.SetValues(env(c), a.Assign.ID, raw(`"y"`, `"z"`)); err != nil {
			t.Fatal(err)
		}
		if _, err := attrs.Unassign(env(c), a.Assign.ID); err != nil {
			t.Fatal(err)
		}
		evs, err := c.GrpEventsOfObject("attribute", a.Assign.ID, 0, 10)
		if err != nil || len(evs) != 3 {
			t.Fatalf("events = %d, %v", len(evs), err)
		}
		for i, typ := range []string{"attribute.assigned", "attribute.value_changed", "attribute.removed"} {
			if evs[i].Type != typ || evs[i].CauseType != store.CauseAPI {
				t.Errorf("event %d = %s (%s), want %s", i, evs[i].Type, evs[i].CauseType, typ)
			}
		}
		var snap struct {
			OwnerType string   `json:"owner_type"`
			OwnerID   string   `json:"owner_id"`
			Values    []string `json:"values"`
		}
		if err := json.Unmarshal(evs[1].Data, &snap); err != nil || snap.OwnerID != string(w.g1) || !slices.Equal(snap.Values, []string{"s:y", "s:z"}) {
			t.Errorf("value_changed data = %s, %v", evs[1].Data, err)
		}
		for _, action := range []string{"groups.attr.assigned", "groups.attr.values_set", "groups.attr.removed"} {
			if au, _ := c.AuditEvents(store.AuditFilter{Action: action, TargetID: a.Assign.ID}); len(au) != 1 {
				t.Errorf("%s audit events = %d", action, len(au))
			}
		}
	})
}
