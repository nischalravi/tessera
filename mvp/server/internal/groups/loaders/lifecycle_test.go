package loaders_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func (h *harness) folder(ext string) store.FolderID {
	h.t.Helper()
	var id store.FolderID
	h.must(func(e model.Env) error {
		f, err := e.CreateFolder(model.CreateFolderInput{Parent: h.root, Extension: ext})
		if err == nil {
			id = f.ID
		}
		return err
	})
	return id
}

// loose is a failsafe that holds nothing back.
func loose() *loaders.Failsafe {
	hundred, big := 100.0, 100000
	return &loaders.Failsafe{MaxRemovedPercent: &hundred, MaxGroupsEmptiedPercent: &hundred, MaxUnresolvedPercent: &hundred, MaxRemoved: &big}
}

// TestLoader_RunLifecycle: a full run creates the loader's groups and fills
// them, with the events (cause "loader"), the audit event and the run row; a
// repeat changes nothing; the groups cannot be edited by hand; a deleted group
// is restored; a name that is taken is a failed run, not a takeover.
func TestLoader_RunLifecycle(t *testing.T) {
	h := newHarness(t)
	h.write("staff.csv", people(seq(0, 6)...))
	spec := h.csvSpec("Staff", "staff.csv", "staff")
	l := h.create(spec, "")
	r := h.run(l, store.RunFull)
	if r.Status != store.RunApplied || *r.Adds != 6 || *r.Removes != 0 || *r.GroupsSeen != 1 || r.FinishedAt == nil {
		t.Fatalf("run = %+v", r)
	}
	wantMembers(t, h, "ref:staff", seq(0, 6))
	g := h.group("ref:staff")
	if g.ManagedBy != store.ManagedByLoader || g.LoaderID == nil || *g.LoaderID != l.ID || g.Status != store.GroupActive {
		t.Errorf("group = %+v, want one managed by the loader", g)
	}
	if got := h.loader(l.ID); got.LastFullAt == nil || !got.LastFullAt.Equal(h.now) {
		t.Errorf("loader after the run = %+v", got)
	}
	acts := h.auditActions()
	for _, want := range []string{"groups.loader.created", "groups.group.created", "groups.loader.run.applied"} {
		if !has(acts, want) {
			t.Errorf("audit actions lack %s: %v", want, acts)
		}
	}
	// every change is an event, with the loader as its cause
	h.read(func(tx *store.TenantTx) error {
		evs, err := tx.GrpEventsOfObject("group", string(g.ID), 0, 1000)
		if err != nil {
			return err
		}
		added := 0
		for _, e := range evs {
			switch e.Type {
			case "membership.direct.added":
				added++
				if e.CauseType != store.CauseLoader {
					t.Errorf("event %s has cause %s, want loader", e.Type, e.CauseType)
				}
			case "group.created":
				if e.CauseType != store.CauseLoader {
					t.Errorf("event %s has cause %s, want loader", e.Type, e.CauseType)
				}
			}
		}
		if added != 6 {
			t.Errorf("%d membership.direct.added events, want 6", added)
		}
		rows, err := tx.GrpDirectBySource(g.ID, store.MembersListID(tid), "loader", l.ID)
		if err != nil || len(rows) != 6 {
			t.Errorf("rows from the loader = %d, %v", len(rows), err)
		}
		return nil
	})
	if evs := h.eventTypes("loader", l.ID); !has(evs, "loader.run.applied") {
		t.Errorf("loader events = %v", evs)
	}

	// a repeat changes nothing and writes no membership events
	before := len(h.eventTypes("group", string(g.ID)))
	h.now = h.now.Add(time.Hour)
	if r2 := h.run(l, store.RunFull); r2.Status != store.RunApplied || *r2.Adds != 0 || *r2.Removes != 0 {
		t.Errorf("repeat = %+v", r2)
	}
	if after := len(h.eventTypes("group", string(g.ID))); after != before {
		t.Errorf("a repeat wrote %d events", after-before)
	}

	// the loader is the only writer of what it owns
	id := h.idents["u9"]
	refuse := func(name string, fn func(e model.Env) error) {
		t.Helper()
		err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error { return fn(h.env(tx)) })
		if errCode(err) != "group_loader_managed" {
			t.Errorf("%s = %v, want group_loader_managed", name, err)
		}
	}
	refuse("add a member", func(e model.Env) error { _, err := e.AddMember(g.ID, model.MemberInput{Identity: &id}); return err })
	refuse("remove a member", func(e model.Env) error { _, err := e.RemoveMember(g.ID, fmt.Sprint(h.idents["u0"])); return err })
	refuse("batch", func(e model.Env) error {
		_, err := e.ApplyBatch(g.ID, []model.BatchOp{{Kind: model.BatchAdd, Identity: &id}}, true, nil)
		return err
	})
	refuse("convert to composite", func(e model.Env) error {
		_, _, err := e.ConvertToComposite(g.ID, model.CompositeInput{Op: store.CompUnion, Factors: []store.GroupID{h.group("ref:staff").ID}, DiscardMembers: true})
		return err
	})
	refuse("rename", func(e model.Env) error {
		x := "renamed"
		_, err := e.UpdateGroup(g.ID, model.UpdateGroupInput{Extension: &x})
		return err
	})
	refuse("move", func(e model.Env) error { _, err := e.MoveGroup(g.ID, h.root); return err })
	// but its description is its own
	h.must(func(e model.Env) error {
		d := "People on staff"
		_, err := e.UpdateGroup(g.ID, model.UpdateGroupInput{Description: &d})
		return err
	})
	wantMembers(t, h, "ref:staff", seq(0, 6))

	// deleted by hand: the next run restores it with its members
	h.must(func(e model.Env) error { return e.DeleteGroup(g.ID) })
	wantMembers(t, h, "ref:staff", nil)
	h.now = h.now.Add(time.Hour)
	if r3 := h.run(l, store.RunFull); r3.Status != store.RunApplied {
		t.Fatalf("run after a delete = %+v", r3)
	}
	wantMembers(t, h, "ref:staff", seq(0, 6))
	if got := h.group("ref:staff"); got.Status != store.GroupActive {
		t.Errorf("group status = %s, want restored", got.Status)
	}

	// a name that is not the loader's is never taken over
	h.must(func(e model.Env) error {
		_, err := e.CreateGroup(model.CreateGroupInput{Folder: h.ref, Extension: "clash"})
		return err
	})
	h.write("clash.csv", people(seq(0, 2)...))
	clash := h.create(h.csvSpec("Clash", "clash.csv", "clash"), "")
	cr := h.run(clash, store.RunFull)
	if cr.Status != store.RunFailed || !strings.Contains(*cr.Error, "loader_name_taken") {
		t.Errorf("run over a taken name = %+v", cr)
	}
	wantMembers(t, h, "ref:clash", nil)
	if got := h.group("ref:clash"); got.ManagedBy != store.ManagedByUI {
		t.Errorf("the group the loader would have taken is now %s", got.ManagedBy)
	}
	if !has(h.auditActions(), "groups.loader.run.failed") {
		t.Error("a failed run was not audited")
	}
}

// TestLoader_DisplayAndAnd: the source's display name and description follow
// it, and a loader with an AND group keeps only the people who are also in it.
func TestLoader_DisplayAndAnd(t *testing.T) {
	h := newHarness(t)
	var and store.GroupID
	h.must(func(e model.Env) error {
		g, err := e.CreateGroup(model.CreateGroupInput{Folder: h.ref, Extension: "and"})
		if err != nil {
			return err
		}
		and = g.ID
		for i := 0; i < 5; i++ {
			id := h.idents[fmt.Sprintf("u%d", i)]
			if _, err := e.AddMember(g.ID, model.MemberInput{Identity: &id}); err != nil {
				return err
			}
		}
		return nil
	})
	h.write("p.csv", "grp,id,label\nall,u0,All of us\nall,u3,\nall,u7,\nall,u9,\n")
	spec := loaders.Spec{Name: "P", Type: loaders.TypeCSV, TargetFolder: string(h.folder("out")), AndGroup: string(and),
		Config: []byte(`{"path":"p.csv","group_column":"grp","display_column":"label","subject_column":"id"}`)}
	l := h.create(spec, "")
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied || *r.Unresolved != 0 {
		t.Fatalf("run = %+v", r)
	}
	wantMembers(t, h, "out:all", []string{"u0", "u3"}) // u7 and u9 are not in the AND group (and are not unresolved)
	if g := h.group("out:all"); g.DisplayExtension != "All of us" {
		t.Errorf("display name = %q", g.DisplayExtension)
	}
	// the people who leave the AND group leave the loader's group
	h.must(func(e model.Env) error {
		_, err := e.RemoveMember(and, fmt.Sprint(h.idents["u3"]))
		return err
	})
	h.now = h.now.Add(time.Hour)
	spec2, _ := loaders.SpecOf(h.loader(l.ID))
	spec2.Failsafe = loose()
	if err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		_, err := loaders.Update(loaders.SaveEnv{Tx: tx, Now: h.now}, l.ID, nil, spec2, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h.write("p.csv", "grp,id,label\nall,u0,Everyone\nall,u3,\n")
	h.run(l, store.RunFull)
	wantMembers(t, h, "out:all", []string{"u0"})
	if g := h.group("out:all"); g.DisplayExtension != "Everyone" {
		t.Errorf("display name after the source changed = %q", g.DisplayExtension)
	}
}

// TestLoader_OnMissingGroup: a group the source stops returning is emptied,
// disabled, deleted or left alone, as the loader says.
func TestLoader_OnMissingGroup(t *testing.T) {
	for _, c := range []struct {
		mode  string
		check func(t *testing.T, h *harness, g *store.NativeGroup)
	}{
		{"empty", func(t *testing.T, h *harness, g *store.NativeGroup) {
			if g.Status != store.GroupActive {
				t.Errorf("status = %s", g.Status)
			}
			wantMembers(t, h, g.Name, nil)
		}},
		{"disable", func(t *testing.T, h *harness, g *store.NativeGroup) {
			if g.Status != store.GroupDisabled {
				t.Errorf("status = %s, want disabled", g.Status)
			}
			wantMembers(t, h, g.Name, nil)
		}},
		{"delete", func(t *testing.T, h *harness, g *store.NativeGroup) {
			if g.Status != store.GroupDeleted {
				t.Errorf("status = %s, want deleted", g.Status)
			}
		}},
		{"keep", func(t *testing.T, h *harness, g *store.NativeGroup) {
			if g.Status != store.GroupActive {
				t.Errorf("status = %s", g.Status)
			}
			wantMembers(t, h, g.Name, []string{"u3", "u4"})
		}},
	} {
		t.Run(c.mode, func(t *testing.T) {
			h := newHarness(t)
			h.write("g.csv", "grp,id\na,u0\na,u1\nb,u3\nb,u4\n")
			spec := loaders.Spec{Name: "G", Type: loaders.TypeCSV, TargetFolder: string(h.folder("out")), OnMissingGroup: c.mode,
				Failsafe: loose(), Config: []byte(`{"path":"g.csv","group_column":"grp","subject_column":"id"}`)}
			l := h.create(spec, "")
			if r := h.run(l, store.RunFull); r.Status != store.RunApplied || *r.GroupsSeen != 2 {
				t.Fatalf("first run = %+v", r)
			}
			h.now = h.now.Add(time.Hour)
			h.write("g.csv", "grp,id\na,u0\na,u1\n")
			r := h.run(l, store.RunFull)
			if r.Status != store.RunApplied {
				t.Fatalf("second run = %+v", r)
			}
			wantMembers(t, h, "out:a", []string{"u0", "u1"})
			c.check(t, h, h.group("out:b"))
			// a third run with the same source changes nothing more
			h.now = h.now.Add(time.Hour)
			if r3 := h.run(l, store.RunFull); r3.Status != store.RunApplied || *r3.Removes != 0 || *r3.Adds != 0 {
				t.Errorf("third run = %+v", r3)
			}
			// and when the source returns the group again it comes back
			if c.mode == "delete" || c.mode == "disable" || c.mode == "empty" {
				h.now = h.now.Add(time.Hour)
				h.write("g.csv", "grp,id\na,u0\na,u1\nb,u3\nb,u4\n")
				h.run(l, store.RunFull)
				wantMembers(t, h, "out:b", []string{"u3", "u4"})
			}
		})
	}
}

// TestCSV_Sources: the CSV source is header-mapped (with a delimiter, a byte
// order mark, a display column and the subjects named by email), records the
// file's hash, and refuses what it cannot read exactly.
func TestCSV_Sources(t *testing.T) {
	h := newHarness(t)
	content := "\xef\xbb\xbfdept;Email;label\nstaff;u0@example.edu;Staff\nstaff;U1@EXAMPLE.EDU;Staff\nfaculty;u2@example.edu;Faculty\n"
	h.write("sub/people.csv", content)
	spec := loaders.Spec{Name: "People", Type: loaders.TypeCSV, TargetFolder: string(h.ref),
		Config: []byte(`{"path":"sub/people.csv","group_column":"dept","display_column":"label","subject_column":"email","subject_source":"email","delimiter":";"}`)}
	l := h.create(spec, "")
	r := h.run(l, store.RunFull)
	if r.Status != store.RunApplied || *r.SourceRows != 3 || *r.GroupsSeen != 2 {
		t.Fatalf("run = %+v (%v)", r, r.Error)
	}
	sum := sha256.Sum256([]byte(content))
	if r.SourceHash == nil || *r.SourceHash != hex.EncodeToString(sum[:]) {
		t.Errorf("source hash = %v, want the file's sha256", r.SourceHash)
	}
	wantMembers(t, h, "ref:staff", []string{"u0", "u1"})
	wantMembers(t, h, "ref:faculty", []string{"u2"})
	if g := h.group("ref:faculty"); g.DisplayExtension != "Faculty" {
		t.Errorf("display name = %q", g.DisplayExtension)
	}

	fail := func(name, file, want string, cfg string) {
		t.Helper()
		if file != "" {
			h.write(name+".csv", file)
		}
		s := loaders.Spec{Name: name, Type: loaders.TypeCSV, TargetFolder: string(h.folder(name)), Config: []byte(cfg)}
		run := h.run(h.create(s, ""), store.RunFull)
		if run.Status != store.RunFailed || !strings.Contains(*run.Error, want) {
			t.Errorf("%s: run = %s %v, want a failure with %q", name, run.Status, deref(run.Error), want)
		}
	}
	fail("emptysubject", "id\nu0\n\nu1\n,\n", "source_empty_subject", `{"path":"emptysubject.csv","group":"g","subject_column":"id"}`)
	fail("nocolumn", "name\nu0\n", "source_column_missing", `{"path":"nocolumn.csv","group":"g","subject_column":"id"}`)
	fail("badgroup", "g,id\nbad name!,u0\n", "invalid_group_name", `{"path":"badgroup.csv","group_column":"g","subject_column":"id"}`)
	fail("emptygroup", "g,id\n,u0\n", "source_empty_group", `{"path":"emptygroup.csv","group_column":"g","subject_column":"id"}`)
	fail("twice", "g,id\nA,u0\na,u1\n", "duplicate_group", `{"path":"twice.csv","group_column":"g","subject_column":"id"}`) // names are case-insensitive
	fail("missingfile", "", "source_file_missing", `{"path":"nowhere.csv","group":"g","subject_column":"id"}`)
	h.write("noheader.csv", "")
	fail("noheader", "", "source_csv_invalid", `{"path":"noheader.csv","group":"g","subject_column":"id"}`)
	fail("quote", "id\n\"u0\n", "source_csv_invalid", `{"path":"quote.csv","group":"g","subject_column":"id"}`)

	// a link that leads out of the data directory is not followed
	outside := filepath.Join(t.TempDir(), "secret.csv")
	if err := os.WriteFile(outside, []byte("id\nu0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(h.dir, "link.csv")); err != nil {
		t.Skipf("no symbolic links: %v", err)
	}
	fail("link", "", "source_file_outside", `{"path":"link.csv","group":"g","subject_column":"id"}`)

	// no data directory: file sources are off
	h.svc.DataDir = ""
	run := h.run(h.create(h.csvSpec("nodir", "staff.csv", "g"), ""), store.RunFull)
	if run.Status != store.RunFailed || !strings.Contains(*run.Error, "loader_data_dir_unset") {
		t.Errorf("run with no data directory = %+v", run)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// TestCSV_URLUsesSealedSecretThroughSafehttp: a CSV URL is fetched through the
// SSRF-guarded client with the loader's secret as a bearer token; the secret is
// sealed at rest, bound to its tenant and loader, and appears in no audit event,
// run or error.
func TestCSV_URLUsesSealedSecretThroughSafehttp(t *testing.T) {
	h := newHarness(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer tok-123-secret" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(people(seq(0, 3)...)))
	}))
	defer srv.Close()
	hc, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	h.svc.HTTP = hc
	mk := func(name, secret string) *store.GrpLoader {
		return h.create(loaders.Spec{Name: name, Type: loaders.TypeCSV, TargetFolder: string(h.folder(name)),
			Config: []byte(fmt.Sprintf(`{"url":%q,"group":"web","subject_column":"id"}`, srv.URL+"/people.csv"))}, secret)
	}
	l := mk("web", "tok-123-secret")
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied || *r.Adds != 3 {
		t.Fatalf("run = %+v (%v)", r, deref(r.Error))
	}
	wantMembers(t, h, "web:web", seq(0, 3))

	// sealed at rest, bound to the tenant and the loader
	stored := h.loader(l.ID)
	if len(stored.SecretEnc) == 0 || strings.Contains(string(stored.SecretEnc), "tok-123") {
		t.Errorf("the secret is stored as %q", stored.SecretEnc)
	}
	aad := seal.AAD(tid, "grp_loaders", "secret_enc", l.ID)
	if b, err := h.sealer.Open(stored.SecretEnc, aad); err != nil || string(b) != "tok-123-secret" {
		t.Errorf("open = %q, %v", b, err)
	}
	if _, err := h.sealer.Open(stored.SecretEnc, seal.AAD(tid, "grp_loaders", "secret_enc", uuid.NewString())); err == nil {
		t.Error("the sealed secret opened under another loader's id")
	}
	// nowhere is it written
	h.read(func(tx *store.TenantTx) error {
		log, err := tx.AuditLog(-1)
		if err != nil {
			return err
		}
		for _, e := range log {
			if b, _ := json.Marshal(e); strings.Contains(string(b), "tok-123") {
				t.Errorf("audit event %s holds the secret", e.Action)
			}
		}
		rs, err := tx.GrpLoaderRuns(l.ID, 10, 0)
		for _, r := range rs {
			if b, _ := json.Marshal(r); strings.Contains(string(b), "tok-123") {
				t.Error("a run holds the secret")
			}
		}
		return err
	})

	// without the token the server says no: a failed run that tells nothing of the token
	bad := mk("bad", "")
	br := h.run(bad, store.RunFull)
	if br.Status != store.RunFailed || !strings.Contains(*br.Error, "401") {
		t.Errorf("run without a token = %+v", br)
	}
	wrong := mk("wrong", "tok-WRONG")
	if wr := h.run(wrong, store.RunFull); wr.Status != store.RunFailed || strings.Contains(*wr.Error, "tok-WRONG") {
		t.Errorf("run with a wrong token = %+v", wr)
	}
	// the guard refuses addresses that are not for a loader to reach
	meta := h.create(loaders.Spec{Name: "meta", Type: loaders.TypeCSV, TargetFolder: string(h.folder("meta")),
		Config: []byte(`{"url":"http://169.254.169.254/latest/meta-data","group":"g","subject_column":"id"}`)}, "")
	if mr := h.run(meta, store.RunFull); mr.Status != store.RunFailed {
		t.Errorf("a run against the metadata address = %+v", mr)
	}
	// no client, no fetch
	h.svc.HTTP = nil
	if nr := h.run(l, store.RunFull); nr.Status != store.RunFailed || !strings.Contains(*nr.Error, "source_http_unavailable") {
		t.Errorf("a run with no outbound client = %+v", nr)
	}
	// a secret belongs to a URL source only
	err = h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		_, err := loaders.Create(loaders.SaveEnv{Tx: tx, Now: h.now, Sealer: h.sealer}, h.csvSpec("file", "staff.csv", "g"), "tok")
		return err
	})
	if errCode(err) != "secret_not_used" {
		t.Errorf("a secret on a file loader = %v, want secret_not_used", err)
	}
	// with no sealer there is no way to store one
	err = h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		_, err := loaders.Create(loaders.SaveEnv{Tx: tx, Now: h.now}, loaders.Spec{Name: "nosealer", Type: loaders.TypeCSV, TargetFolder: string(h.ref),
			Config: []byte(`{"url":"https://example.org/x.csv","group":"g","subject_column":"id"}`)}, "tok")
		return err
	})
	if errCode(err) != "sealer_unavailable" {
		t.Errorf("a secret with no sealer = %v, want sealer_unavailable", err)
	}
}

// TestSQL_GroupListAndIncremental: the group-list loader makes a group per
// name with its display text, and an incremental feed (the rows after @cursor)
// applies change by change, advancing the cursor only when a run applies; a
// feed that trips a failsafe is held and a decision moves the cursor on.
func TestSQL_GroupListAndIncremental(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 10; i++ {
		dept := "eng"
		if i >= 5 {
			dept = "ops"
		}
		h.hrAdd("hr.db", hrRow{xid: fmt.Sprintf("u%d", i), dept: dept, title: fmt.Sprintf("u%d", i)})
	}
	secs := int64(60)
	spec := loaders.Spec{Name: "HR", Type: loaders.TypeSQLGroupList, TargetFolder: string(h.folder("hr")), IncrementalSecs: &secs,
		Config: []byte(`{"database":"hr.db",
			"query":"SELECT department AS group_name, external_id AS subject_id FROM identities WHERE external_id NOT LIKE 'chg-%'",
			"groups_query":"SELECT DISTINCT department AS group_name, upper(department) AS display_name, 'People of ' || department AS description FROM identities",
			"incremental_query":"SELECT department AS group_name, title AS subject_id, CASE status WHEN 'active' THEN 'add' ELSE 'remove' END AS op, id AS seq FROM identities WHERE id > @cursor ORDER BY id"}`)}
	l := h.create(spec, "")
	if _, err := h.svc.Run(context.Background(), tid, l.ID, store.RunIncremental, loaders.Actor{}); errCode(err) != "no_full_run" {
		t.Errorf("incremental run before a full one = %v, want no_full_run", err)
	}
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied || *r.GroupsSeen != 2 {
		t.Fatalf("full run = %+v (%v)", r, deref(r.Error))
	}
	wantMembers(t, h, "hr:eng", seq(0, 5))
	wantMembers(t, h, "hr:ops", seq(5, 10))
	if g := h.group("hr:eng"); g.DisplayExtension != "ENG" || g.Description != "People of eng" {
		t.Errorf("group text = %q / %q", g.DisplayExtension, g.Description)
	}

	// the first incremental read sees every row (all adds of existing members) and sets the cursor
	h.now = h.now.Add(2 * time.Minute)
	if r := h.run(l, store.RunIncremental); r == nil || r.Status != store.RunApplied || *r.Adds != 0 || *r.Removes != 0 {
		t.Fatalf("first incremental = %+v", r)
	}
	if c := h.loader(l.ID).Cursor; c == nil || *c != "10" {
		t.Errorf("cursor = %v, want 10", c)
	}
	// nothing new: no run is recorded
	h.now = h.now.Add(2 * time.Minute)
	n := len(h.runs(l.ID))
	if r := h.run(l, store.RunIncremental); r != nil || len(h.runs(l.ID)) != n {
		t.Errorf("incremental with no changes = %+v, %d runs recorded", r, len(h.runs(l.ID))-n)
	}
	// one leaves (1 of 5: at the limit)
	h.hrAdd("hr.db", hrRow{xid: "chg-1", dept: "eng", status: "terminated", title: "u1"})
	h.now = h.now.Add(2 * time.Minute)
	if r := h.run(l, store.RunIncremental); r.Status != store.RunApplied || *r.Removes != 1 || r.CursorAfter == nil || *r.CursorAfter != "11" {
		t.Fatalf("incremental removal = %+v", r)
	}
	wantMembers(t, h, "hr:eng", []string{"u0", "u2", "u3", "u4"})
	wantMembers(t, h, "hr:ops", seq(5, 10))
	// the same person joins again: last change wins
	h.hrAdd("hr.db", hrRow{xid: "chg-1b", dept: "eng", title: "u1"})
	h.now = h.now.Add(2 * time.Minute)
	h.run(l, store.RunIncremental)
	wantMembers(t, h, "hr:eng", seq(0, 5))

	// two leave: 40% of the group, so the run is held, the cursor stays and nothing applies
	h.hrAdd("hr.db", hrRow{xid: "chg-2", dept: "eng", status: "terminated", title: "u2"}, hrRow{xid: "chg-3", dept: "eng", status: "terminated", title: "u3"})
	h.now = h.now.Add(2 * time.Minute)
	cursorBefore := *h.loader(l.ID).Cursor
	held := h.run(l, store.RunIncremental)
	if held.Status != store.RunHeld || !slices.Contains(tripRules(t, held), "max_removed_percent") {
		t.Fatalf("incremental = %+v (%v)", held, tripRules(t, held))
	}
	if c := *h.loader(l.ID).Cursor; c != cursorBefore {
		t.Errorf("cursor moved to %s while the run is held", c)
	}
	wantMembers(t, h, "hr:eng", seq(0, 5))
	apr, err := h.svc.Approve(context.Background(), tid, l.ID, held.ID, loaders.Actor{})
	if err != nil || apr.Status != store.RunApproved {
		t.Fatalf("approve = %+v, %v", apr, err)
	}
	wantMembers(t, h, "hr:eng", []string{"u0", "u1", "u4"})
	if c := *h.loader(l.ID).Cursor; c != "14" {
		t.Errorf("cursor after the approval = %s, want 14", c)
	}
	// a rejection discards the changes and moves the cursor on, so they are not held again
	h.hrAdd("hr.db", hrRow{xid: "chg-4", dept: "eng", status: "terminated", title: "u0"}, hrRow{xid: "chg-5", dept: "eng", status: "terminated", title: "u1"})
	h.now = h.now.Add(2 * time.Minute)
	held2 := h.run(l, store.RunIncremental)
	if held2.Status != store.RunHeld {
		t.Fatalf("second hold = %+v", held2)
	}
	if _, err := h.svc.Reject(context.Background(), tid, l.ID, held2.ID, loaders.Actor{}); err != nil {
		t.Fatal(err)
	}
	wantMembers(t, h, "hr:eng", []string{"u0", "u1", "u4"})
	h.now = h.now.Add(2 * time.Minute)
	if r := h.run(l, store.RunIncremental); r != nil {
		t.Errorf("incremental after a rejection = %+v, want nothing to do", r)
	}
	// the next full run reconciles the loader's groups with the full source
	h.now = h.now.Add(24 * time.Hour)
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied || *r.Adds != 2 {
		t.Errorf("full run = %+v", r)
	}
	wantMembers(t, h, "hr:eng", seq(0, 5))

	// a query that returns the wrong columns is a failed run that says which
	badSpec := spec
	badSpec.Name = "HR2"
	badSpec.TargetFolder, badSpec.IncrementalSecs = string(h.folder("hr2")), nil
	badSpec.Config = []byte(`{"database":"hr.db","query":"SELECT department AS dept, external_id AS who FROM identities"}`)
	if r := h.run(h.create(badSpec, ""), store.RunFull); r.Status != store.RunFailed || !strings.Contains(*r.Error, "source_column_missing") {
		t.Errorf("run with the wrong columns = %+v", r)
	}
	// a missing source database is a failed run too
	missing := badSpec
	missing.Name = "HR3"
	missing.TargetFolder = string(h.folder("hr3"))
	missing.Config = []byte(`{"database":"nope.db","query":"SELECT 1 AS group_name, 1 AS subject_id"}`)
	if r := h.run(h.create(missing, ""), store.RunFull); r.Status != store.RunFailed || !strings.Contains(*r.Error, "source_file_missing") {
		t.Errorf("run against a missing database = %+v", r)
	}
}

// TestSQL_Simple: sql_simple fills one group from a one-column query, and an
// empty result is an empty group (the failsafe, not a silent no-op, guards it).
func TestSQL_Simple(t *testing.T) {
	h := newHarness(t)
	h.hrAdd("hr.db", hrRow{xid: "u0", dept: "eng"}, hrRow{xid: "u1", dept: "eng"}, hrRow{xid: "u2", dept: "ops"})
	spec := loaders.Spec{Name: "Eng", Type: loaders.TypeSQLSimple, TargetFolder: string(h.ref),
		Config: []byte(`{"database":"hr.db","group":"eng","query":"SELECT external_id AS subject_id FROM identities WHERE department = 'eng'"}`)}
	l := h.create(spec, "")
	if r := h.run(l, store.RunFull); r.Status != store.RunApplied {
		t.Fatalf("run = %+v", r)
	}
	wantMembers(t, h, "ref:eng", []string{"u0", "u1"})
	h.hr("hr.db", func(tx *store.TenantTx) error {
		for _, x := range []string{"u0", "u1"} {
			i, err := tx.IdentityByExternalID(x)
			if err != nil {
				return err
			}
			if err := tx.SetIdentityStatus(i.ID, "terminated"); err != nil {
				return err
			}
		}
		return nil
	})
	// the source's engineers all left, so the query returns nothing: 100% of the group
	h.hr("hr.db", func(tx *store.TenantTx) error { return nil })
	spec2, _ := loaders.SpecOf(h.loader(l.ID))
	spec2.Config = []byte(`{"database":"hr.db","group":"eng","query":"SELECT external_id AS subject_id FROM identities WHERE department = 'eng' AND status = 'active'"}`)
	if err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		_, err := loaders.Update(loaders.SaveEnv{Tx: tx, Now: h.now}, l.ID, nil, spec2, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(time.Hour)
	held := h.run(l, store.RunFull)
	if held.Status != store.RunHeld || *held.Removes != 2 {
		t.Fatalf("run = %+v, want held", held)
	}
	wantMembers(t, h, "ref:eng", []string{"u0", "u1"})
}

// TestConnectorGroups_AndAttribute: a connection's groups become native groups
// (members mapped through their accounts to identities; an account that
// belongs to no identity is unresolved), and an attribute makes a group per value.
func TestConnectorGroups_AndAttribute(t *testing.T) {
	h := newHarness(t)
	conn := &store.Connection{ID: uuid.NewString(), Name: "okta-main", ConnectorType: "okta", System: "okta", Role: "account_source",
		CreatedAt: t0, UpdatedAt: t0}
	h.must(func(e model.Env) error {
		if err := e.Tx.InsertConnection(conn); err != nil {
			return err
		}
		for _, g := range []store.Group{{System: "okta", ExternalID: "g1", Name: "Engineers (US)", Kind: "group"},
			{System: "okta", ExternalID: "g2", Name: "Ops", Kind: "group"}, {System: "aws", ExternalID: "g3", Name: "Other system", Kind: "group"}} {
			g := g
			if err := e.Tx.UpsertGroup(&g); err != nil {
				return err
			}
		}
		member := func(system, xid, group string, ident *int64, expires *time.Time) error {
			a, err := e.Tx.InsertAccount(&store.Account{System: system, ExternalID: xid, IdentityID: ident, Username: xid, Kind: "human", Status: "active"})
			if err != nil {
				return err
			}
			g, err := e.Tx.GroupByXID(system, group)
			if err != nil {
				return err
			}
			_, err = e.Tx.InsertEdge(&store.GrantEdge{Src: fmt.Sprintf("account:%d", a), Dst: fmt.Sprintf("group:%d", g.ID), Relation: "member_of",
				Source: "connector", ExpiresAt: expires, CreatedAt: t0})
			return err
		}
		past := t0.Add(-time.Hour)
		for _, m := range []struct {
			system, xid, group string
			ident              *int64
			expires            *time.Time
		}{
			{"okta", "a0", "g1", ptr(h.idents["u0"]), nil}, {"okta", "a1", "g1", ptr(h.idents["u1"]), nil},
			{"okta", "a99", "g1", nil, nil},                  // an account no identity owns
			{"okta", "a5", "g1", ptr(h.idents["u5"]), &past}, // an expired grant
			{"okta", "a2", "g2", ptr(h.idents["u2"]), nil},
			{"aws", "b0", "g3", ptr(h.idents["u3"]), nil}, // another system's group is not this connection's
		} {
			if err := member(m.system, m.xid, m.group, m.ident, m.expires); err != nil {
				return err
			}
		}
		return nil
	})
	spec := loaders.Spec{Name: "Okta", Type: loaders.TypeConnectorGroups, ConnectionID: conn.ID, TargetFolder: string(h.folder("okta")),
		Failsafe: loose(), Config: []byte(`{"name_prefix":"okta_"}`)}
	l := h.create(spec, "")
	r := h.run(l, store.RunFull)
	if r.Status != store.RunApplied || *r.GroupsSeen != 2 || *r.Unresolved != 1 {
		t.Fatalf("run = %+v (%v)", r, deref(r.Error))
	}
	wantMembers(t, h, "okta:okta_Engineers__US_", []string{"u0", "u1"})
	wantMembers(t, h, "okta:okta_Ops", []string{"u2"})
	if g := h.group("okta:okta_Engineers__US_"); g.DisplayExtension != "Engineers (US)" {
		t.Errorf("display name = %q", g.DisplayExtension)
	}
	if us := h.unresolved(l.ID); len(us) != 1 || us[0].Source != "okta" || us[0].Identifier != "a99" {
		t.Errorf("unresolved = %+v", us)
	}
	// a connector_groups loader needs a connection that exists
	err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		s := spec
		s.Name, s.ConnectionID = "none", ""
		_, err := loaders.Create(loaders.SaveEnv{Tx: tx, Now: h.now}, s, "")
		return err
	})
	if errCode(err) != "invalid_config" {
		t.Errorf("a connector_groups loader with no connection = %v", err)
	}
	err = h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		s := spec
		s.Name, s.ConnectionID = "ghost", uuid.NewString()
		_, err := loaders.Create(loaders.SaveEnv{Tx: tx, Now: h.now}, s, "")
		return err
	})
	if errCode(err) != "unknown_connection" {
		t.Errorf("a loader of a connection that does not exist = %v", err)
	}

	// attribute: one group per department, active people only
	h.must(func(e model.Env) error { return e.Tx.SetIdentityStatus(h.idents["u9"], "terminated") })
	attr := h.create(loaders.Spec{Name: "Depts", Type: loaders.TypeAttribute, TargetFolder: string(h.folder("dept")),
		Failsafe: loose(), Config: []byte(`{"attribute":"department","prefix":"dept-"}`)}, "")
	if ar := h.run(attr, store.RunFull); ar.Status != store.RunApplied || *ar.GroupsSeen != 2 || *ar.Unresolved != 0 {
		t.Fatalf("attribute run = %+v (%v)", ar, deref(ar.Error))
	}
	wantMembers(t, h, "dept:dept-eng", seq(0, 5))
	wantMembers(t, h, "dept:dept-ops", seq(5, 9))
}

func ptr[T any](v T) *T { return &v }
