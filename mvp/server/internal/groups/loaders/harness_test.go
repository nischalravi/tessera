package loaders_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var (
	t0  = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	tid = tenancy.MustParse("00000000-0000-4000-8000-0000000000d5")
)

// harness is a one-tenant database with a root folder, a folder "ref" the
// loaders write into, ten identities u0..u9 and a clock the test moves by hand.
// The loader data directory is a temp directory that holds the test's CSV files
// and SQLite source databases.
type harness struct {
	t      testing.TB
	db     *store.DB
	eng    *engine.Engine
	svc    *loaders.Service
	sealer *seal.Sealer
	now    time.Time
	base   string // the loader data directory
	dir    string // this tenant's directory under it
	root   store.FolderID
	ref    store.FolderID
	idents map[string]int64 // "u0" -> identity id
}

func newHarness(t testing.TB) *harness {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "loaders.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.InSystem(ctx, "test", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: tid, Slug: "loaders", Name: "loaders", CreatedAt: t0})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	dir := filepath.Join(base, tid.String()) // a tenant's files live in <data dir>/<tenant id>/
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, db: db, eng: engine.New(0), sealer: sealer, now: t0, base: base, dir: dir, idents: map[string]int64{}}
	h.svc = &loaders.Service{DB: db, Engine: h.eng, Clock: func() time.Time { return h.now }, Sealer: sealer, DataDir: base}
	h.must(func(e model.Env) error {
		root, err := e.EnsureRoot()
		if err != nil {
			return err
		}
		h.root = root.ID
		ref, err := e.CreateFolder(model.CreateFolderInput{Parent: root.ID, Extension: "ref"})
		if err != nil {
			return err
		}
		h.ref = ref.ID
		for i := 0; i < 10; i++ {
			dept := "eng"
			if i >= 5 {
				dept = "ops"
			}
			email := fmt.Sprintf("u%d@example.edu", i)
			dp := dept
			id, err := e.Tx.InsertIdentity(&store.Identity{ExternalID: fmt.Sprintf("u%d", i), Name: fmt.Sprintf("User %d", i), Email: &email,
				Type: "human", Status: "active", Department: &dp, CreatedAt: t0})
			if err != nil {
				return err
			}
			h.idents[fmt.Sprintf("u%d", i)] = id
		}
		return nil
	})
	return h
}

func (h *harness) env(tx *store.TenantTx) model.Env {
	return model.Env{Tx: tx, Now: h.now, Engine: h.eng}
}

func (h *harness) must(fn func(e model.Env) error) {
	h.t.Helper()
	if err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error { return fn(h.env(tx)) }); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) read(fn func(tx *store.TenantTx) error) {
	h.t.Helper()
	if err := h.db.ReadTenant(context.Background(), tid, fn); err != nil {
		h.t.Fatal(err)
	}
}

// write puts a file into the loader data directory.
func (h *harness) write(name, content string) {
	h.t.Helper()
	path := filepath.Join(h.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// people returns a CSV with the subjects (external ids) in one column.
func people(ids ...string) string { return "id\n" + strings.Join(ids, "\n") + "\n" }

// seq returns "u<from>".."u<to-1>".
func seq(from, to int) []string {
	var out []string
	for i := from; i < to; i++ {
		out = append(out, fmt.Sprintf("u%d", i))
	}
	return out
}

// spec is a csv loader that fills one group from people.csv.
func (h *harness) csvSpec(name, file, group string) loaders.Spec {
	return loaders.Spec{Name: name, Type: loaders.TypeCSV, TargetFolder: string(h.ref), Schedule: "@daily",
		Config: []byte(fmt.Sprintf(`{"path":%q,"group":%q,"subject_column":"id"}`, file, group))}
}

// create saves a loader as the harness's user.
func (h *harness) create(spec loaders.Spec, secret string) *store.GrpLoader {
	h.t.Helper()
	var l *store.GrpLoader
	err := h.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		var err error
		l, err = loaders.Create(loaders.SaveEnv{Tx: tx, Now: h.now, Sealer: h.sealer}, spec, secret)
		return err
	})
	if err != nil {
		h.t.Fatalf("create loader %q: %v", spec.Name, err)
	}
	return l
}

// run runs a loader and returns the recorded run.
func (h *harness) run(l *store.GrpLoader, kind string) *store.GrpLoaderRun {
	h.t.Helper()
	r, err := h.svc.Run(context.Background(), tid, l.ID, kind, loaders.Actor{})
	if err != nil {
		h.t.Fatalf("run %s: %v", kind, err)
	}
	return r
}

// members is the external ids of a group's effective members, sorted.
func (h *harness) members(name string) []string {
	h.t.Helper()
	var out []string
	h.read(func(tx *store.TenantTx) error {
		g, err := tx.GrpGroupByName(name)
		if err != nil {
			return err
		}
		ids, err := tx.GrpEffectiveIdentitiesAfter(g.ID, store.MembersListID(tid), 0, 1000)
		if err != nil {
			return err
		}
		for _, id := range ids {
			for ext, v := range h.idents {
				if v == id {
					out = append(out, ext)
				}
			}
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func (h *harness) group(name string) *store.NativeGroup {
	h.t.Helper()
	var g *store.NativeGroup
	h.read(func(tx *store.TenantTx) error {
		var err error
		g, err = tx.GrpGroupByName(name)
		return err
	})
	return g
}

func (h *harness) loader(id string) *store.GrpLoader {
	h.t.Helper()
	var l *store.GrpLoader
	h.read(func(tx *store.TenantTx) error {
		var err error
		l, err = tx.GrpLoader(id)
		return err
	})
	return l
}

func (h *harness) runs(id string) []*store.GrpLoaderRun {
	h.t.Helper()
	var out []*store.GrpLoaderRun
	h.read(func(tx *store.TenantTx) error {
		var err error
		out, err = tx.GrpLoaderRuns(id, 100, 0)
		return err
	})
	return out
}

func (h *harness) unresolved(id string) []*store.GrpLoaderUnresolved {
	h.t.Helper()
	var out []*store.GrpLoaderUnresolved
	h.read(func(tx *store.TenantTx) error {
		var err error
		out, err = tx.GrpLoaderUnresolved(id, 100, 0)
		return err
	})
	return out
}

// auditActions is the actions of the tenant's audit events.
func (h *harness) auditActions() []string {
	h.t.Helper()
	var out []string
	h.read(func(tx *store.TenantTx) error {
		log, err := tx.AuditLog(-1)
		for _, e := range log {
			out = append(out, e.Action)
		}
		return err
	})
	return out
}

// eventTypes is the group events of an object, oldest first.
func (h *harness) eventTypes(objectType, id string) []string {
	h.t.Helper()
	var out []string
	h.read(func(tx *store.TenantTx) error {
		evs, err := tx.GrpEventsOfObject(objectType, id, 0, 10000)
		for _, e := range evs {
			out = append(out, e.Type)
		}
		return err
	})
	return out
}

func has(list []string, want string) bool { return slices.Contains(list, want) }

// usage records that identities used a permission, each a duration ago.
func (h *harness) usage(ago map[string]time.Duration) {
	h.t.Helper()
	h.must(func(e model.Env) error {
		if err := e.Tx.UpsertResource(&store.Resource{System: "aws", ExternalID: "bucket", Name: "bucket", Kind: "bucket", Tags: []string{}}); err != nil {
			return err
		}
		res, err := e.Tx.Resources()
		if err != nil {
			return err
		}
		if err := e.Tx.UpsertPermission(&store.Permission{System: "aws", ExternalID: "get", Action: "s3:Get", ResourceID: res[0].ID}); err != nil {
			return err
		}
		perms, err := e.Tx.Permissions()
		if err != nil {
			return err
		}
		var rows []store.UsageEvent
		for x, d := range ago {
			rows = append(rows, store.UsageEvent{IdentityID: h.idents[x], PermissionID: perms[0].ID, Day: h.now.Add(-d), Count: 1})
		}
		return e.Tx.InsertUsageEvents(rows)
	})
}

// hrTenant is the tenant of the "HR" source databases.
var hrTenant = tenancy.MustParse("00000000-0000-4000-8000-0000000000e6")

// hrRow is a person in an HR source database: the identities table of a second
// Tessera database serves as the SQL source (the tests may not open a database
// themselves: only internal/store does).
type hrRow struct{ xid, dept, status, title string }

// hr changes the SQLite source database name under the data directory (made if
// it is not there): fn runs in its tenant.
func (h *harness) hr(name string, fn func(tx *store.TenantTx) error) {
	h.t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(h.dir, name))
	if err != nil {
		h.t.Fatal(err)
	}
	defer db.Close()
	_ = db.InSystem(ctx, "test", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: hrTenant, Slug: "hrsource", Name: "hrsource", CreatedAt: t0})
		return err // already there on the second call: ignored
	})
	if err := db.InTenant(ctx, hrTenant, fn); err != nil {
		h.t.Fatal(err)
	}
}

// hrAdd adds people to the source database.
func (h *harness) hrAdd(name string, rows ...hrRow) {
	h.t.Helper()
	h.hr(name, func(tx *store.TenantTx) error {
		for _, r := range rows {
			dept, status := r.dept, r.status
			if status == "" {
				status = "active"
			}
			title := r.title
			if _, err := tx.InsertIdentity(&store.Identity{ExternalID: r.xid, Name: r.xid, Type: "human", Status: status, Department: &dept,
				Title: &title, CreatedAt: t0}); err != nil {
				return err
			}
		}
		return nil
	})
}
