package flatfile_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/deleteguard"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

const dsys = "hr-sheet"

func people(n int) string {
	var b strings.Builder
	b.WriteString("email,name,department\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "p%02d@t.example,Person %02d,Ops\n", i, i)
	}
	return b.String()
}

// imp plans or applies a file in its own transaction.
func (e *env) imp(target, csv string, apply bool) (*flatfile.ImportOutcome, *flatfile.Plan, error) {
	e.t.Helper()
	var out *flatfile.ImportOutcome
	var pl *flatfile.Plan
	var err error
	if ferr := e.f.DB.InTenant(context.Background(), e.f.B.ID, func(c *store.TenantTx) error {
		e.now = e.now.Add(time.Minute)
		in := flatfile.ImportInput{System: dsys, Name: "HR spreadsheet", Target: target, Filename: "f.csv", Raw: []byte(csv), By: "Ivan"}
		if apply {
			out, err = flatfile.ApplyImport(c, e.now, in)
		} else {
			pl, err = flatfile.PlanImport(c, e.now, in)
		}
		return nil // a refusal is an answer, the transaction still commits
	}); ferr != nil {
		e.t.Fatal(ferr)
	}
	return out, pl, err
}

func (e *env) identity(xid string) *store.Identity {
	e.t.Helper()
	var i *store.Identity
	e.read(func(c *store.TenantTx) {
		var err error
		if i, err = c.IdentityByExternalID(xid); err != nil {
			e.t.Fatalf("identity %s: %v", xid, err)
		}
	})
	return i
}

func (e *env) setPolicy(cat string, max int, mode string) {
	e.tx(func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: cat, MaxCount: &max, WindowMinutes: 60, Mode: mode}, nil, e.now)
	})
}

func manyColumns(n int) string {
	var h []string
	for i := 0; i < n; i++ {
		h = append(h, fmt.Sprintf("c%d", i))
	}
	return strings.Join(h, ",") + "\n"
}

func (e *env) manualAccount(xid string) *store.Account {
	e.t.Helper()
	var a *store.Account
	e.read(func(c *store.TenantTx) {
		var err error
		if a, err = c.AccountByXID(dsys, xid); err != nil {
			e.t.Fatalf("account %s: %v", xid, err)
		}
	})
	return a
}

func TestParseWith_DirectoryLimits(t *testing.T) {
	row := "a@t.example,A\n"
	for name, c := range map[string]struct {
		raw  string
		lim  flatfile.Limits
		code string
	}{
		"10000 rows is the limit":          {"email,name\n" + strings.Repeat(row, 10000), flatfile.DirectoryLimits, ""},
		"10001 rows is one too many":       {"email,name\n" + strings.Repeat(row, 10001), flatfile.DirectoryLimits, flatfile.CodeTooManyRows},
		"the flat-file default stays 5000": {"email,name\n" + strings.Repeat(row, 5001), flatfile.Limits{}, flatfile.CodeTooManyRows},
		"5 MiB is the limit":               {"email,name\n" + strings.Repeat("x", 5<<20-11), flatfile.DirectoryLimits, ""},
		"5 MiB and a byte is too large":    {"email,name\n" + strings.Repeat("x", 5<<20-10), flatfile.DirectoryLimits, flatfile.CodeFileTooLarge},
		"the flat-file default stays 512K": {"email,name\n" + strings.Repeat("x", 600<<10), flatfile.Limits{}, flatfile.CodeFileTooLarge},
		"binary":                           {"email,name\n\x00\x01", flatfile.DirectoryLimits, flatfile.CodeNotUTF8},
		"latin-1":                          {"email,name\na@t.example,Ren\xe9\n", flatfile.DirectoryLimits, flatfile.CodeNotUTF8},
		"no header":                        {"", flatfile.DirectoryLimits, flatfile.CodeNoHeader},
		"too many columns":                 {manyColumns(65), flatfile.DirectoryLimits, flatfile.CodeTooManyColumns},
	} {
		tbl, errs := flatfile.ParseWith([]byte(c.raw), c.lim)
		got := ""
		if len(errs) > 0 {
			got = errs[0].Code
		}
		if got != c.code || (c.code == "" && tbl == nil) {
			t.Errorf("%s: code %q, want %q", name, got, c.code)
		}
	}
}

func TestImport_PeoplePlanThenApply(t *testing.T) {
	e := newEnv(t)
	before := e.auditCounts()
	_, pl, err := e.imp(flatfile.TargetPeople, people(3), false)
	if err != nil || pl.Added != 3 || pl.Removed != 0 || len(pl.Errors) != 0 {
		t.Fatalf("plan = %+v, %v", pl, err)
	}
	if got := e.auditCounts(); got["directory.import"] != before["directory.import"] {
		t.Error("a plan wrote a domain event")
	}
	e.read(func(c *store.TenantTx) {
		if rows, _ := c.ImportRecords(dsys, store.ImportPeople); len(rows) != 0 {
			t.Errorf("a plan wrote %d snapshot rows", len(rows))
		}
		if _, err := c.IdentityByExternalID("p00@t.example"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a plan created an identity: %v", err)
		}
	})
	out, _, err := e.imp(flatfile.TargetPeople, people(3), true)
	if err != nil || out.Plan.Added != 3 || out.Held != 0 {
		t.Fatalf("apply = %+v, %v", out, err)
	}
	if i := e.identity("p01@t.example"); i.Name != "Person 01" || i.Status != "active" || i.Type != "human" {
		t.Errorf("identity = %+v", i)
	}
	if got := e.auditCounts(); got["directory.import"] != before["directory.import"]+1 {
		t.Errorf("directory.import events = %d", got["directory.import"])
	}
	// replanning the same file: nothing to do; a changed cell: one change
	if _, pl, _ = e.imp(flatfile.TargetPeople, people(3), false); pl.Unchanged != 3 || pl.Added+pl.Changed+pl.Removed != 0 {
		t.Errorf("replan = %+v", pl)
	}
	_, pl, _ = e.imp(flatfile.TargetPeople, strings.Replace(people(3), "Ops", "Legal", 1), false)
	if pl.Changed != 1 || pl.Changes[0].Detail != "department" {
		t.Errorf("changed plan = %+v", pl)
	}
}

func TestImport_PeopleRowErrorsListEveryRowAndChangeNothing(t *testing.T) {
	e := newEnv(t)
	csv := "email,name,status,manager_email\n" +
		"ok@t.example,Ok,,\n" + // fine
		"notanemail,Bad,,\n" + // invalid_email
		"=cmd@t.example,Formula,,\n" + // formula_prefix
		"x@t.example,,,\n" + // required name
		"ok@t.example,Dup,,\n" + // duplicate
		"y@t.example,Y,gone,\n" + // invalid_status
		"z@t.example,Z,,bad\n" // invalid manager email
	out, _, err := e.imp(flatfile.TargetPeople, csv, true)
	if err != nil {
		t.Fatal(err)
	}
	codes := map[int]string{}
	for _, re := range out.Plan.Errors {
		codes[re.Row] = re.Code
	}
	want := map[int]string{2: "invalid_email", 3: "formula_prefix", 4: "required", 5: "duplicate_key", 6: "invalid_status", 7: "invalid_email"}
	for row, code := range want {
		if codes[row] != code {
			t.Errorf("row %d: %q, want %q (all: %v)", row, codes[row], code, codes)
		}
	}
	e.read(func(c *store.TenantTx) {
		if _, err := c.IdentityByExternalID("ok@t.example"); !errors.Is(err, store.ErrNotFound) {
			t.Error("a file with a bad row created its good row")
		}
	})
	if got := e.auditCounts(); got["directory.import"] != 1 {
		t.Errorf("the refused file left %d directory.import events, want 1 (the failure)", got["directory.import"])
	}
	e.read(func(c *store.TenantTx) {
		evs, _ := c.AuditEvents(store.AuditFilter{Action: "directory.import"})
		if len(evs) != 1 || evs[0].Outcome != store.OutcomeFailure {
			t.Errorf("events = %+v", evs)
		}
	})
}

func TestImport_PeopleNeverTakeOverAnotherSourcesPerson(t *testing.T) {
	e := newEnv(t)
	var xid, email string
	e.read(func(c *store.TenantTx) {
		all, _ := c.Identities()
		for _, i := range all {
			if i.Email != nil {
				xid, email = i.ExternalID, *i.Email
				break
			}
		}
	})
	if xid == "" {
		t.Fatal("no identity with an email in the fixture")
	}
	before := e.identity(xid)
	for name, csv := range map[string]string{
		"same external id":       "email,name,external_id\nother@t.example,Hijack," + xid + "\n",
		"same email, another id": "email,name,external_id\n" + email + ",Hijack,brand-new\n",
	} {
		out, _, err := e.imp(flatfile.TargetPeople, csv, true)
		if err != nil || len(out.Plan.Errors) != 1 || (out.Plan.Errors[0].Code != flatfile.CodeOwnedElsewhere && out.Plan.Errors[0].Code != flatfile.CodeEmailInUse) {
			t.Errorf("%s: %+v, %v", name, out.Plan.Errors, err)
		}
	}
	if after := e.identity(xid); after.Name != before.Name {
		t.Errorf("another source's person was renamed to %q", after.Name)
	}
}

func TestImport_PeopleRemovalsAreOnlyThisSourcesAndGoThroughTheGuard(t *testing.T) {
	e := newEnv(t)
	// a person that another source owns is never listed as removed, whatever the file says
	if out, _, err := e.imp(flatfile.TargetPeople, people(4), true); err != nil || out.Held != 0 {
		t.Fatalf("seed: %+v %v", out, err)
	}
	_, pl, _ := e.imp(flatfile.TargetPeople, people(1), false)
	if pl.Removed != 3 || pl.Guard == nil || pl.Guard.Removals != 3 {
		t.Fatalf("plan = %+v", pl)
	}
	for _, c := range pl.Changes {
		if c.Type == flatfile.Removed && !strings.HasPrefix(c.Label, "p0") {
			t.Errorf("the plan removes %q, which this source never imported", c.Label)
		}
	}
	// the default guard holds the removals of a feed (a shorter file is not trusted): nobody is ended
	out, _, err := e.imp(flatfile.TargetPeople, people(1), true)
	if err != nil || out.Held != 3 || !pl.Guard.WouldHold {
		t.Fatalf("apply = %+v, %v (plan guard %+v)", out, err, pl.Guard)
	}
	for i := 1; i < 4; i++ {
		if st := e.identity(fmt.Sprintf("p%02d@t.example", i)).Status; st != "active" {
			t.Errorf("p%02d is %s while its removal is held", i, st)
		}
	}
	e.read(func(c *store.TenantTx) {
		if rows, _ := c.ImportRecords(dsys, store.ImportPeople); len(rows) != 4 {
			t.Errorf("snapshot has %d rows, want the 4 (the held ones stay this source's)", len(rows))
		}
		hs, err := c.DeletionHolds("held", deleteguard.CatIdentities, 10, 0)
		if err != nil || len(hs) != 1 || hs[0].ItemCount != 3 {
			t.Errorf("holds = %+v, %v", hs, err)
		}
	})
	// a second admin releases the hold: the three are ended
	e.tx(func(c *store.TenantTx) error {
		hs, _ := c.DeletionHolds("held", deleteguard.CatIdentities, 10, 0)
		res, err := deleteguard.Release(c, e.now, hs[0].ID, "approver", nil, deleteguard.Appliers{ingest.ItemIdentityStatus: ingest.ReleaseIdentity})
		if err != nil || res.Released != 3 {
			t.Fatalf("release = %+v, %v", res, err)
		}
		return nil
	})
	if st := e.identity("p02@t.example").Status; st == "active" {
		t.Error("p02 is still active after the release")
	}
	// with the guard off the next removal applies at once; the ended people stay in the snapshot as terminated
	e.setPolicy(deleteguard.CatIdentities, 100, deleteguard.ModeOff)
	if out, _, err = e.imp(flatfile.TargetPeople, people(1)+"p09@t.example,Nine,Ops\n", true); err != nil || out.Held != 0 {
		t.Fatalf("apply with the guard off = %+v, %v", out, err)
	}
	e.read(func(c *store.TenantTx) {
		rows, _ := c.ImportRecords(dsys, store.ImportPeople)
		if len(rows) != 5 {
			t.Errorf("snapshot has %d rows, want 5 (p00, the three ended, p09)", len(rows))
		}
	})
}

func TestImport_PeopleReturnTheHoldIDOfHeldRemovals(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.imp(flatfile.TargetPeople, people(4), true); err != nil {
		t.Fatal(err)
	}
	out, _, err := e.imp(flatfile.TargetPeople, people(1), true)
	if err != nil || out.Held != 3 || out.HoldID == "" {
		t.Fatalf("apply = %+v, %v; want 3 held and a hold id", out, err)
	}
	e.read(func(c *store.TenantTx) {
		hs, _ := c.DeletionHolds("held", deleteguard.CatIdentities, 10, 0)
		if len(hs) != 1 || hs[0].ID != out.HoldID {
			t.Errorf("hold id %q, holds %+v", out.HoldID, hs)
		}
	})
}

func TestImport_PeopleDroppedByAnEarlierFileComeBack(t *testing.T) {
	e := newEnv(t)
	e.setPolicy(deleteguard.CatIdentities, 100, deleteguard.ModeOff)
	if _, _, err := e.imp(flatfile.TargetPeople, people(3), true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.imp(flatfile.TargetPeople, people(1), true); err != nil {
		t.Fatal(err)
	}
	if st := e.identity("p02@t.example").Status; st == "active" {
		t.Fatalf("p02 is %s after being dropped", st)
	}
	// (A) the same source lists them again: not owned elsewhere, and they are active again
	out, _, err := e.imp(flatfile.TargetPeople, people(3), true)
	if err != nil || len(out.Plan.Errors) > 0 || out.Plan.Changed+out.Plan.Added != 2 {
		t.Fatalf("re-add = %+v, %v", out.Plan, err)
	}
	for i := 0; i < 3; i++ {
		if st := e.identity(fmt.Sprintf("p%02d@t.example", i)).Status; st != "active" {
			t.Errorf("p%02d is %s after the re-add", i, st)
		}
	}
}

func TestImport_PeopleRestoredAfterAHeldRemovalIsReleased(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.imp(flatfile.TargetPeople, people(4), true); err != nil {
		t.Fatal(err)
	}
	out, _, err := e.imp(flatfile.TargetPeople, people(1), true)
	if err != nil || out.Held != 3 {
		t.Fatalf("apply = %+v, %v", out, err)
	}
	e.tx(func(c *store.TenantTx) error {
		res, err := deleteguard.Release(c, e.now, out.HoldID, "approver", nil, deleteguard.Appliers{ingest.ItemIdentityStatus: ingest.ReleaseIdentity})
		if err != nil || res.Released != 3 {
			t.Fatalf("release = %+v, %v", res, err)
		}
		return nil
	})
	// (B) the original file lists them as active: the plan says so and the apply restores them
	_, pl, _ := e.imp(flatfile.TargetPeople, people(4), false)
	if pl.Changed != 3 || pl.Unchanged != 1 {
		t.Fatalf("plan = %+v, want 3 changed", pl)
	}
	if _, _, err := e.imp(flatfile.TargetPeople, people(4), true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if st := e.identity(fmt.Sprintf("p%02d@t.example", i)).Status; st != "active" {
			t.Errorf("p%02d is %s after the re-import", i, st)
		}
	}
	// and the next run of the same file has nothing to do
	if _, pl, _ = e.imp(flatfile.TargetPeople, people(4), false); pl.Unchanged != 4 {
		t.Errorf("plan after = %+v", pl)
	}
}

func TestImport_EntitlementsAreGroupsOfTheManualSourceAndRetireThroughTheGuard(t *testing.T) {
	e := newEnv(t)
	csv := "name,external_id,kind,privileged,description\nApprovers,ap,group,yes,Can approve\nReaders,rd,role,no,\nAuditors,au,team,no,\n"
	out, _, err := e.imp(flatfile.TargetEntitlements, csv, true)
	if err != nil || out.Plan.Added != 3 {
		t.Fatalf("apply = %+v, %v", out, err)
	}
	e.read(func(c *store.TenantTx) {
		g, err := c.GroupByXID(dsys, "ap")
		if err != nil || !g.Privileged || !g.Requestable || g.Kind != "group" || g.Name != "Approvers" {
			t.Errorf("group = %+v, %v", g, err)
		}
	})
	// a file that shrinks like this is not trusted to say what is gone: the guard holds every removal
	e.setPolicy(deleteguard.CatGroups, 1, deleteguard.ModeHoldExcess)
	out, _, err = e.imp(flatfile.TargetEntitlements, "name,external_id\nApprovers,ap\n", true)
	if err != nil || out.Plan.Removed != 2 || out.Held != 2 {
		t.Fatalf("shorter file = %+v, %v", out, err)
	}
	e.read(func(c *store.TenantTx) {
		for _, x := range []string{"rd", "au"} {
			if g, _ := c.GroupByXID(dsys, x); !g.Requestable {
				t.Errorf("%s retired while its removal is held", x)
			}
		}
		if rows, _ := c.ImportRecords(dsys, store.ImportEntitlements); len(rows) != 3 {
			t.Errorf("snapshot has %d rows, want 3: the kept one and the two held", len(rows))
		}
	})
	e.tx(func(c *store.TenantTx) error {
		hs, _ := c.DeletionHolds("held", deleteguard.CatGroups, 10, 0)
		if len(hs) != 1 {
			t.Fatalf("holds = %+v", hs)
		}
		res, err := deleteguard.Release(c, e.now, hs[0].ID, "approver", nil, deleteguard.Appliers{flatfile.ItemRetireEntitlement: flatfile.ReleaseRetire})
		if err != nil || res.Released != 2 {
			t.Fatalf("release = %+v, %v", res, err)
		}
		return nil
	})
	e.read(func(c *store.TenantTx) {
		for _, x := range []string{"rd", "au"} {
			if g, _ := c.GroupByXID(dsys, x); g.Requestable {
				t.Errorf("%s is still requestable after the release", x)
			}
		}
		if g, _ := c.GroupByXID(dsys, "ap"); !g.Requestable {
			t.Error("the listed entitlement was retired")
		}
		if rows, _ := c.ImportRecords(dsys, store.ImportEntitlements); len(rows) != 1 {
			t.Errorf("snapshot has %d rows after the release, want 1", len(rows))
		}
	})
	// with the guard off a removal retires at once
	e.setPolicy(deleteguard.CatGroups, 100, deleteguard.ModeOff)
	if out, _, err = e.imp(flatfile.TargetEntitlements, "name,external_id\nNew,nw\n", true); err != nil || out.Held != 0 || out.Plan.Removed != 1 {
		t.Fatalf("guard off = %+v, %v", out, err)
	}
	e.read(func(c *store.TenantTx) {
		if g, _ := c.GroupByXID(dsys, "ap"); g.Requestable {
			t.Error("ap was not retired with the guard off")
		}
	})
}

func TestImport_AccountsUseTheCanonicalMappingAndTheFlatFilePath(t *testing.T) {
	e := newEnv(t)
	csv := "account_id,username,email,identity_id,status\na1,one,,,active\na2,two,,,active\na3,three,,,active\n"
	_, pl, err := e.imp(flatfile.TargetAccounts, csv, false)
	if err != nil || pl.Added != 3 {
		t.Fatalf("plan = %+v, %v", pl, err)
	}
	e.read(func(c *store.TenantTx) {
		if _, err := c.FlatMapping(dsys); !errors.Is(err, store.ErrNotFound) {
			t.Error("a plan saved the mapping")
		}
	})
	if out, _, err := e.imp(flatfile.TargetAccounts, csv, true); err != nil || out.Plan.Added != 3 {
		t.Fatalf("apply = %+v, %v", out, err)
	}
	e.read(func(c *store.TenantTx) {
		if _, err := c.FlatMapping(dsys); err != nil {
			t.Errorf("mapping not saved: %v", err)
		}
		a, err := c.AccountByXID(dsys, "a2")
		if err != nil || a.Status != "active" {
			t.Errorf("account = %+v, %v", a, err)
		}
	})
	got := e.auditCounts()
	if got["directory.import"] != 1 || got["flatfile.upload"] != 1 || got["flatfile.mapping_saved"] < 1 {
		t.Errorf("audit = %v", got)
	}
	// a shorter file: the plan shows the removals and the guard's view, apply holds them (a feed that shrinks)
	_, pl, _ = e.imp(flatfile.TargetAccounts, "account_id,username,email,identity_id,status\na1,one,,,active\n", false)
	if pl.Removed != 2 || pl.Guard == nil || !pl.Guard.WouldHold {
		t.Fatalf("plan = %+v guard %+v", pl, pl.Guard)
	}
	out, _, err := e.imp(flatfile.TargetAccounts, "account_id,username,email,identity_id,status\na1,one,,,active\n", true)
	if err != nil || out.Held != 2 || e.manualAccount("a3").Status != "active" {
		t.Fatalf("apply = %+v, %v", out, err)
	}
}

func TestImport_NeverWritesToAConnectorsSystem(t *testing.T) {
	e := newEnv(t)
	for _, target := range []string{flatfile.TargetPeople, flatfile.TargetAccounts, flatfile.TargetEntitlements} {
		for _, apply := range []bool{false, true} {
			var gotErr error
			e.tx(func(c *store.TenantTx) error {
				in := flatfile.ImportInput{System: "okta", Target: target, Filename: "f.csv", Raw: []byte("email,name\na@t.example,A\n"), By: "Ivan"}
				if apply {
					_, gotErr = flatfile.ApplyImport(c, e.now, in)
				} else {
					_, gotErr = flatfile.PlanImport(c, e.now, in)
				}
				return nil
			})
			var fe *flatfile.Error
			if !errors.As(gotErr, &fe) || fe.Code != "system_not_manual" {
				t.Errorf("%s apply=%v: %v, want system_not_manual", target, apply, gotErr)
			}
		}
	}
	var gotErr error
	e.tx(func(c *store.TenantTx) error {
		_, gotErr = flatfile.PlanImport(c, e.now, flatfile.ImportInput{System: "Not A Slug", Target: "people", Raw: []byte("email,name\n")})
		return nil
	})
	var fe *flatfile.Error
	if !errors.As(gotErr, &fe) || fe.Code != "invalid_system" {
		t.Errorf("bad name: %v", gotErr)
	}
}

func TestUpsertRecord_CreateAndEditOneObject(t *testing.T) {
	e := newEnv(t)
	up := func(target string, f map[string]string) (*flatfile.ImportOutcome, error) {
		var out *flatfile.ImportOutcome
		var err error
		e.tx(func(c *store.TenantTx) error {
			e.now = e.now.Add(time.Minute)
			out, err = flatfile.UpsertRecord(c, e.now, flatfile.RecordInput{System: dsys, Name: "HR spreadsheet", Target: target, Fields: f, By: "Ivan"})
			return nil
		})
		return out, err
	}
	if out, err := up("people", map[string]string{"email": "a@t.example", "name": "A"}); err != nil || out.Plan.Added != 1 {
		t.Fatalf("create = %+v, %v", out, err)
	}
	if out, err := up("people", map[string]string{"email": "b@t.example", "name": "B"}); err != nil || out.Plan.Added != 1 || out.Plan.Unchanged != 1 {
		t.Fatalf("second = %+v, %v", out, err)
	}
	out, err := up("people", map[string]string{"email": "a@t.example", "name": "A Prime"})
	if err != nil || out.Plan.Changed != 1 || out.Plan.Removed != 0 || out.Plan.Unchanged != 1 || out.Held != 0 {
		t.Fatalf("edit = %+v, %v", out, err)
	}
	if i := e.identity("a@t.example"); i.Name != "A Prime" {
		t.Errorf("name = %q", i.Name)
	}
	if out, err = up("accounts", map[string]string{"account_id": "x1", "username": "xone"}); err != nil || out.Plan.Added != 1 {
		t.Fatalf("account = %+v, %v", out, err)
	}
	if out, err = up("accounts", map[string]string{"account_id": "x1", "username": "xone", "status": "disabled"}); err != nil || out.Plan.Changed != 1 {
		t.Fatalf("account edit = %+v, %v", out, err)
	}
	if e.manualAccount("x1").Status != "disabled" {
		t.Error("the edit did not reach the account")
	}
	if out, err = up("entitlements", map[string]string{"name": "Team lead", "privileged": "yes"}); err != nil || out.Plan.Added != 1 {
		t.Fatalf("entitlement = %+v, %v", out, err)
	}
	if _, err = up("people", map[string]string{"email": "c@t.example", "name": "C", "salary": "1"}); err == nil {
		t.Error("an unknown field was accepted")
	}
}

// Security review of #915: an entitlements import never takes over a group of its system that another feed
// wrote (a connector that began writing to the system after the source was named): the row is refused and the
// group is left as it was. The source's own entitlements stay editable.
func TestImport_EntitlementsNeverTakeOverAnotherFeedsGroup(t *testing.T) {
	e := newEnv(t)
	if out, _, err := e.imp(flatfile.TargetEntitlements, "name,external_id,privileged\nOurs,ours,no\n", true); err != nil || out.Plan.Added != 1 {
		t.Fatalf("first import = %+v, %v", out, err)
	}
	// another feed writes a privileged, non-requestable group into the same system
	e.tx(func(c *store.TenantTx) error {
		_, err := ingest.Import(c, e.now, &connectors.DiscoveryResult{System: dsys, Groups: []connectors.GroupRecord{
			{System: dsys, ExternalID: "admins", Name: "Admins", Kind: "group", Privileged: true}}})
		return err
	})
	csv := "name,external_id,privileged\nOurs,ours,yes\nAdmins,admins,no\n"
	for _, apply := range []bool{false, true} {
		out, pl, err := e.imp(flatfile.TargetEntitlements, csv, apply)
		if apply {
			if err != nil || out == nil {
				t.Fatalf("apply: %+v, %v", out, err)
			}
			pl = out.Plan
		}
		if err != nil || len(pl.Errors) != 1 || pl.Errors[0].Code != flatfile.CodeOwnedElsewhere || pl.Errors[0].Row != 2 {
			t.Fatalf("apply=%v: plan %+v, %v; want one owned_by_other_source on row 2", apply, pl, err)
		}
	}
	e.read(func(c *store.TenantTx) {
		g, err := c.GroupByXID(dsys, "admins")
		if err != nil || !g.Privileged || g.Requestable {
			t.Errorf("the other feed's group changed: %+v, %v", g, err)
		}
		if g, _ := c.GroupByXID(dsys, "ours"); g.Privileged {
			t.Error("a refused file changed the source's own entitlement")
		}
		if rows, _ := c.ImportRecords(dsys, store.ImportEntitlements); len(rows) != 1 {
			t.Errorf("snapshot has %d rows, want 1", len(rows))
		}
	})
	// the source's own row alone is applied
	if out, _, err := e.imp(flatfile.TargetEntitlements, "name,external_id,privileged\nOurs,ours,yes\n", true); err != nil || out.Plan.Changed != 1 {
		t.Fatalf("own edit = %+v, %v", out, err)
	}
}

// A system a configured connector writes to without a connection row is refused on every call, also once a
// manual source of that name exists (named before the connector's first sync); the forms refuse it too.
func TestImport_RefusesAReservedConnectorSystem(t *testing.T) {
	e := newEnv(t)
	if out, _, err := e.imp(flatfile.TargetPeople, people(1), true); err != nil || out.Plan.Added != 1 {
		t.Fatalf("setup = %+v, %v", out, err)
	}
	reserved := map[string]bool{dsys: true}
	fieldOf := map[string]string{flatfile.TargetPeople: "name", flatfile.TargetAccounts: "account_id", flatfile.TargetEntitlements: "name"}
	for _, target := range []string{flatfile.TargetPeople, flatfile.TargetAccounts, flatfile.TargetEntitlements} {
		var errs [3]error
		e.tx(func(c *store.TenantTx) error {
			in := flatfile.ImportInput{System: dsys, Target: target, Filename: "f.csv", Raw: []byte("name\nX\n"), By: "Ivan", Reserved: reserved}
			_, errs[0] = flatfile.PlanImport(c, e.now, in)
			_, errs[1] = flatfile.ApplyImport(c, e.now, in)
			_, errs[2] = flatfile.UpsertRecord(c, e.now, flatfile.RecordInput{System: dsys, Target: target,
				Fields: map[string]string{fieldOf[target]: "x"}, By: "Ivan", Reserved: reserved})
			return nil
		})
		for i, err := range errs {
			var fe *flatfile.Error
			if !errors.As(err, &fe) || fe.Code != "system_not_manual" {
				t.Errorf("%s call %d: %v, want system_not_manual", target, i, err)
			}
		}
	}
}

// The directory.import event names the file's digest and the keys it added, changed and removed, so the
// ledger says which people a file touched.
func TestImport_AuditNamesTheFileAndTheKeys(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.imp(flatfile.TargetPeople, people(2), true); err != nil {
		t.Fatal(err)
	}
	e.setPolicy(deleteguard.CatIdentities, 100, deleteguard.ModeOff)
	if _, _, err := e.imp(flatfile.TargetPeople, "email,name,department\np00@t.example,Person 00,Finance\n", true); err != nil {
		t.Fatal(err)
	}
	e.read(func(c *store.TenantTx) {
		evs, err := c.AuditEvents(store.AuditFilter{})
		if err != nil {
			t.Fatal(err)
		}
		var last string // the second import's event: the one that changed a row
		for _, ev := range evs {
			b, _ := json.Marshal(ev.Detail)
			if ev.Action == "directory.import" && strings.Contains(string(b), `"changed":1`) {
				last = string(b)
			}
		}
		for _, want := range []string{`"sha256":"`, `"changed":["p00@t.example"]`, `"removed":["p01@t.example"]`, `"keys_truncated":false`} {
			if !strings.Contains(last, want) {
				t.Errorf("directory.import detail %s lacks %s", last, want)
			}
		}
	})
}

func TestImport_PlanReportsTheExistingAccountsAPersonWouldClaim(t *testing.T) {
	e := newEnv(t)
	e.tx(func(c *store.TenantTx) error {
		for _, a := range []*store.Account{
			{System: "okta", ExternalID: "o1", Username: "P00@t.example", Kind: "user", Status: "active"},
			{System: "github", ExternalID: "g1", Username: "p00@t.example", Kind: "user", Status: "active"},
			{System: "github", ExternalID: "g2", Username: "p01@t.example", Kind: "user", Status: "active"},
			{System: "okta", ExternalID: "o2", Username: "p02-handle", Kind: "user", Status: "active"}, // no email: not matched
		} {
			if err := c.UpsertAccount(a); err != nil {
				return err
			}
		}
		// an account somebody owns is not claimed
		ids, err := c.Identities()
		if err != nil || len(ids) == 0 {
			t.Fatalf("identities: %v", err)
		}
		a, err := c.AccountByXID("github", "g2")
		if err != nil {
			return err
		}
		a.IdentityID = &ids[0].ID
		return c.UpsertAccount(a)
	})
	_, pl, err := e.imp(flatfile.TargetPeople, people(3), false)
	if err != nil {
		t.Fatal(err)
	}
	var got []flatfile.Claim
	for _, c := range pl.Claims {
		if c.Key == "p00@t.example" || c.Key == "p01@t.example" || c.Key == "p02@t.example" {
			got = append(got, c)
		}
	}
	if len(got) != 1 || got[0].Key != "p00@t.example" || got[0].Accounts != 2 || strings.Join(got[0].Systems, ",") != "github,okta" {
		t.Fatalf("claims = %+v", pl.Claims)
	}
	// nothing is written by the plan, and the same rows are not claims once the person exists unchanged
	if out, _, err := e.imp(flatfile.TargetPeople, people(3), true); err != nil || out == nil {
		t.Fatalf("apply: %v", err)
	}
	if _, pl, _ = e.imp(flatfile.TargetPeople, people(3), false); len(pl.Claims) != 0 {
		t.Errorf("unchanged people claim %+v", pl.Claims)
	}
}

func TestImport_ReimportKeepsRequestableAndTheTerminationDate(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.imp(flatfile.TargetEntitlements, "name,external_id,description\nReaders,rd,one\nWriters,wr,one\n", true); err != nil {
		t.Fatal(err)
	}
	e.tx(func(c *store.TenantTx) error { // a catalog admin takes Readers out of the catalog
		g, err := c.GroupByXID(dsys, "rd")
		if err != nil {
			return err
		}
		g.Requestable = false
		return c.UpsertGroup(g)
	})
	if _, _, err := e.imp(flatfile.TargetEntitlements, "name,external_id,description\nReaders,rd,two\nWriters,wr,one\nNew,nw,\n", true); err != nil {
		t.Fatal(err)
	}
	e.read(func(c *store.TenantTx) {
		if g, _ := c.GroupByXID(dsys, "rd"); g.Requestable || g.Description == nil || *g.Description != "two" {
			t.Errorf("rd = %+v: the description follows the file, requestable stays as the admin set it", g)
		}
		if g, _ := c.GroupByXID(dsys, "nw"); !g.Requestable {
			t.Error("a new entitlement is requestable")
		}
	})

	csv := "email,name,department,status\nleaver@t.example,Leaver,Ops,terminated\nstay@t.example,Stay,Ops,active\n"
	if _, _, err := e.imp(flatfile.TargetPeople, csv, true); err != nil {
		t.Fatal(err)
	}
	first := e.identity("leaver@t.example").TerminatedAt
	if first == nil {
		t.Fatal("the terminated person has no termination date")
	}
	e.now = e.now.Add(48 * time.Hour)
	if _, _, err := e.imp(flatfile.TargetPeople, strings.Replace(csv, "Ops,terminated", "Sales,terminated", 1), true); err != nil {
		t.Fatal(err)
	}
	if got := e.identity("leaver@t.example"); got.TerminatedAt == nil || !got.TerminatedAt.Equal(*first) || got.Department == nil || *got.Department != "Sales" {
		t.Errorf("leaver = %+v, want the first date %v kept and the new department", got, first)
	}
}

func TestImport_PeopleRemovalsAreJudgedAgainstTheSourcesOwnSize(t *testing.T) {
	e := newEnv(t)
	if out, _, err := e.imp(flatfile.TargetPeople, people(60), true); err != nil || out.Held != 0 {
		t.Fatalf("seed: %+v %v", out, err)
	}
	e.tx(func(c *store.TenantTx) error { // other sources make the tenant's identities far more than this source's
		res := &connectors.DiscoveryResult{System: "hr-other"}
		for i := 0; i < 100; i++ {
			res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: fmt.Sprintf("o%03d@x.example", i), Name: "Other", Type: "human"})
		}
		_, err := ingest.Import(c, e.now, res)
		return err
	})
	var tenantPop int
	e.read(func(c *store.TenantTx) { tenantPop, _ = c.DeletionPopulation(deleteguard.CatIdentities) })
	pct := 10.0
	e.tx(func(c *store.TenantTx) error {
		return deleteguard.Set(c, deleteguard.Policy{Category: deleteguard.CatIdentities, MaxPercent: &pct, WindowMinutes: 60, Mode: deleteguard.ModeHoldExcess}, nil, e.now)
	})
	// 10% of the source's 60 people is 6; of the tenant's identities it would be 16
	if tenantPop < 150 {
		t.Fatalf("the tenant has only %d identities: the test needs a population much larger than the source", tenantPop)
	}
	_, pl, err := e.imp(flatfile.TargetPeople, people(50), false)
	if err != nil || pl.Guard == nil || pl.Guard.Active != 60 || pl.Guard.Limit == nil || *pl.Guard.Limit != 6 || !pl.Guard.WouldHold {
		t.Fatalf("plan guard = %+v, %v", pl.Guard, err)
	}
	out, _, err := e.imp(flatfile.TargetPeople, people(50), true)
	if err != nil || out.Held != 4 {
		t.Fatalf("apply = %+v, %v: want 6 removed and 4 held under the source's own limit", out, err)
	}
	e.read(func(c *store.TenantTx) {
		hs, err := c.DeletionHolds("held", deleteguard.CatIdentities, 10, 0)
		if err != nil || len(hs) != 1 || hs[0].CorrelationID != "ingest:identities:"+dsys {
			t.Errorf("holds = %+v, %v: the hold is the source's own", hs, err)
		}
	})
}

// terminate ends a person the way an admin, a leaver plan or containment's leaver path does: outside the import.
func (e *env) terminate(xid string) {
	e.t.Helper()
	e.now = e.now.Add(time.Minute)
	e.tx(func(c *store.TenantTx) error {
		i, err := c.IdentityByExternalID(xid)
		if err != nil {
			return err
		}
		return c.TerminateIdentity(i.ID, e.now)
	})
}

func (e *env) reactivations() int {
	n := 0
	e.read(func(c *store.TenantTx) {
		evs, err := c.AuditEvents(store.AuditFilter{Action: "directory.person_reactivated"})
		if err != nil {
			e.t.Fatal(err)
		}
		n = len(evs)
	})
	return n
}

func TestImport_PeopleAnImportNeverUndoesSomeoneElsesTermination(t *testing.T) {
	e := newEnv(t)
	e.setPolicy(deleteguard.CatIdentities, 100, deleteguard.ModeOff)
	if _, _, err := e.imp(flatfile.TargetPeople, people(3), true); err != nil {
		t.Fatal(err)
	}
	// (1) an admin terminates p01 while the file still lists them: the same file again leaves them terminated
	e.terminate("p01@t.example")
	if _, _, err := e.imp(flatfile.TargetPeople, people(3), true); err != nil {
		t.Fatal(err)
	}
	if st := e.identity("p01@t.example").Status; st != "terminated" {
		t.Fatalf("p01 is %s after a re-import; an admin's termination must stand", st)
	}
	// (2) the file drops p01 and then lists them again: the source did not end them, so it does not restore them
	if _, _, err := e.imp(flatfile.TargetPeople, people(1)+"p02@t.example,Person 02,Ops\n", true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.imp(flatfile.TargetPeople, people(3), true); err != nil {
		t.Fatal(err)
	}
	if st := e.identity("p01@t.example").Status; st != "terminated" {
		t.Fatalf("p01 is %s after drop and re-add; an admin's termination must stand", st)
	}
	// (3) the source ends p02, a leaver plan ends them again later: the later end wins too
	if _, _, err := e.imp(flatfile.TargetPeople, people(1), true); err != nil {
		t.Fatal(err)
	}
	e.terminate("p02@t.example")
	if _, _, err := e.imp(flatfile.TargetPeople, people(3), true); err != nil {
		t.Fatal(err)
	}
	if st := e.identity("p02@t.example").Status; st != "terminated" {
		t.Fatalf("p02 is %s; a termination after the source's must stand", st)
	}
	if n := e.reactivations(); n != 0 {
		t.Errorf("%d reactivations audited, want 0", n)
	}
}

func TestImport_PeopleAdminTerminationDuringAHeldRemovalStands(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.imp(flatfile.TargetPeople, people(4), true); err != nil {
		t.Fatal(err)
	}
	out, _, err := e.imp(flatfile.TargetPeople, people(1), true)
	if err != nil || out.Held != 3 {
		t.Fatalf("apply = %+v, %v", out, err)
	}
	// an admin ends p02 while the removal waits; the release then has nothing to do for p02
	e.terminate("p02@t.example")
	e.tx(func(c *store.TenantTx) error {
		_, err := deleteguard.Release(c, e.now, out.HoldID, "approver", nil, deleteguard.Appliers{ingest.ItemIdentityStatus: ingest.ReleaseIdentity})
		return err
	})
	if _, _, err := e.imp(flatfile.TargetPeople, people(4), true); err != nil {
		t.Fatal(err)
	}
	if st := e.identity("p02@t.example").Status; st != "terminated" {
		t.Errorf("p02 is %s; the admin's termination must stand", st)
	}
	for _, x := range []string{"p01@t.example", "p03@t.example"} {
		if st := e.identity(x).Status; st != "active" {
			t.Errorf("%s is %s; the source's own released removal is undone by its file", x, st)
		}
	}
	if n := e.reactivations(); n != 2 {
		t.Errorf("%d reactivations audited, want 2", n)
	}
}

func TestImport_PeopleMassReactivationIsHeldByTheGuard(t *testing.T) {
	e := newEnv(t)
	e.setPolicy(deleteguard.CatIdentities, 100, deleteguard.ModeOff)
	if _, _, err := e.imp(flatfile.TargetPeople, people(4), true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.imp(flatfile.TargetPeople, people(1), true); err != nil {
		t.Fatal(err)
	}
	e.setPolicy(deleteguard.CatIdentities, 0, deleteguard.ModeHoldExcess)
	if _, _, err := e.imp(flatfile.TargetPeople, people(4), true); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 4; i++ {
		if st := e.identity(fmt.Sprintf("p%02d@t.example", i)).Status; st != "terminated" {
			t.Fatalf("p%02d is %s; a batch over the limit must wait for a second admin", i, st)
		}
	}
	e.read(func(c *store.TenantTx) {
		rows, _ := c.ImportRecords(dsys, store.ImportPeople)
		for _, r := range rows {
			if r.Key != "p00@t.example" && flatfile.RecordFields(r.Data)["status"] != "terminated" {
				t.Errorf("snapshot row %s says active while its restore waits", r.Key)
			}
		}
	})
	// an admin ends p03 again while the restore waits: the release leaves p03 alone
	e.terminate("p03@t.example")
	var hold string
	e.read(func(c *store.TenantTx) {
		hs, _ := c.DeletionHolds("held", deleteguard.CatIdentities, 10, 0)
		if len(hs) != 1 {
			t.Fatalf("holds %+v", hs)
		}
		hold = hs[0].ID
	})
	e.tx(func(c *store.TenantTx) error {
		res, err := deleteguard.Release(c, e.now, hold, "approver", nil, deleteguard.Appliers{flatfile.ItemReactivatePerson: flatfile.ReleaseReactivate})
		if err != nil || res.Released != 2 {
			t.Fatalf("release = %+v, %v; want 2", res, err)
		}
		return nil
	})
	for x, want := range map[string]string{"p01@t.example": "active", "p02@t.example": "active", "p03@t.example": "terminated"} {
		if st := e.identity(x).Status; st != want {
			t.Errorf("%s is %s, want %s", x, st, want)
		}
	}
	if n := e.reactivations(); n != 2 {
		t.Errorf("%d reactivations audited, want 2", n)
	}
}

func TestImport_PeopleEndNoteIsNeverAFieldOrAColumn(t *testing.T) {
	e := newEnv(t)
	e.setPolicy(deleteguard.CatIdentities, 100, deleteguard.ModeOff)
	if _, _, err := e.imp(flatfile.TargetPeople, people(2), true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.imp(flatfile.TargetPeople, people(1), true); err != nil {
		t.Fatal(err)
	}
	e.read(func(c *store.TenantTx) {
		rows, _ := c.ImportRecords(dsys, store.ImportPeople)
		for _, r := range rows {
			if _, ok := flatfile.RecordFields(r.Data)["~ended_at"]; ok {
				t.Errorf("the end note of %s is shown as a field", r.Key)
			}
		}
	})
	// a file cannot forge the note: an unknown column is not read
	e.terminate("p00@t.example")
	if _, _, err := e.imp(flatfile.TargetPeople, "email,name,department,~ended_at\np00@t.example,Person 00,Ops,x\np01@t.example,Person 01,Ops,x\n", true); err != nil {
		t.Fatal(err)
	}
	if st := e.identity("p00@t.example").Status; st != "terminated" {
		t.Errorf("p00 is %s", st)
	}
}
