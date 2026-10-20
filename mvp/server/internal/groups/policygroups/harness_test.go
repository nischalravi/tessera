package policygroups

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var (
	t0  = time.Date(2026, 10, 12, 9, 30, 0, 0, time.UTC)
	tid = tenancy.MustParse("00000000-0000-4000-8000-0000000000c9")
)

// mapSource gives identities their attributes from a map, so a test can use any
// schema (the identity record has no set attribute).
type mapSource struct {
	attrs map[int64]map[string][]string
}

func (m *mapSource) Values(id *store.Identity, attr string) []string { return m.attrs[id.ID][attr] }

// harness is a one-tenant database with n identities, a clock and an attribute source.
type harness struct {
	t      testing.TB
	db     *store.DB
	eng    *engine.Engine
	now    time.Time
	idents []int64
	src    *mapSource
	refs   map[string]store.GroupID
}

func newHarness(t testing.TB, nIdents int, eng *engine.Engine) *harness {
	t.Helper()
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "policygroups-*")
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, filepath.Join(dir, "pg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Cleanup(func() { _ = db.Close() })
	if err := db.InSystem(ctx, "test", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: tid, Slug: "policygroups", Name: "policygroups", CreatedAt: t0})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if eng == nil {
		eng = engine.New(0)
	}
	x := &harness{t: t, db: db, eng: eng, now: t0, src: &mapSource{attrs: map[int64]map[string][]string{}}, refs: map[string]store.GroupID{}}
	x.must(func(e model.Env) error {
		if _, err := e.EnsureRoot(); err != nil {
			return err
		}
		for i := 0; i < nIdents; i++ {
			id, err := e.Tx.InsertIdentity(&store.Identity{ExternalID: fmt.Sprintf("u%d", i), Name: fmt.Sprintf("User %d", i),
				Type: "person", Status: "active", CreatedAt: t0})
			if err != nil {
				return err
			}
			x.idents = append(x.idents, id)
			x.src.attrs[id] = map[string][]string{"campus": {"main"}}
		}
		return nil
	})
	return x
}

func (x *harness) env(tx *store.TenantTx) model.Env {
	return model.Env{Tx: tx, Now: x.now, Engine: x.eng}
}

func (x *harness) run(fn func(e model.Env) error) error {
	return x.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error { return fn(x.env(tx)) })
}

func (x *harness) must(fn func(e model.Env) error) {
	x.t.Helper()
	if err := x.run(fn); err != nil {
		x.t.Fatal(err)
	}
}

func (x *harness) read(fn func(e model.Env) error) {
	x.t.Helper()
	if err := x.db.ReadTenant(context.Background(), tid, func(tx *store.TenantTx) error { return fn(x.env(tx)) }); err != nil {
		x.t.Fatal(err)
	}
}

// group creates a reference group with direct identity members (by index).
func (x *harness) group(name string, members ...int) store.GroupID {
	x.t.Helper()
	var id store.GroupID
	x.must(func(e model.Env) error {
		parent, ext := splitName(name)
		f, err := e.EnsureFolderPath(parent)
		if err != nil {
			return err
		}
		g, err := e.CreateGroup(model.CreateGroupInput{Folder: f.ID, Extension: ext})
		if err != nil {
			return err
		}
		id = g.ID
		for _, m := range members {
			ident := x.idents[m]
			if _, err := e.AddMember(g.ID, model.MemberInput{Identity: &ident}); err != nil {
				return err
			}
		}
		return nil
	})
	x.refs[name] = id
	return id
}

func splitName(name string) (string, string) {
	i := strings.LastIndex(name, ":")
	return name[:i], name[i+1:]
}

func (x *harness) applier(e model.Env) *Applier {
	return &Applier{Env: e, Schema: testSchema(), Attrs: x.src}
}

// apply runs a change in a write transaction; a refusal rolls it back.
func (x *harness) apply(in ApplyInput) (*ApplyResult, error) {
	var res *ApplyResult
	err := x.run(func(e model.Env) error {
		var err error
		res, err = x.applier(e).Apply(in)
		return err
	})
	return res, err
}

func (x *harness) mustApply(in ApplyInput) *ApplyResult {
	x.t.Helper()
	res, err := x.apply(in)
	if err != nil {
		x.t.Fatalf("apply: %v", err)
	}
	return res
}

// repo is a repository change at a commit.
func repo(commit string, full bool, files ...SourceFile) ApplyInput {
	return ApplyInput{Origin: store.PolicyOriginRepo, Commit: commit, Files: files, Full: full}
}

// pol builds a policy file for a group with one permit condition and, if given, one forbid.
func pol(group, permit, forbid string) SourceFile {
	src := fmt.Sprintf("permit (principal, action == Tessera::Action::\"member\", resource == Tessera::Group::%q) when { %s };\n", group, permit)
	if forbid != "" {
		src += fmt.Sprintf("forbid (principal, action == Tessera::Action::\"member\", resource == Tessera::Group::%q) when { %s };\n", group, forbid)
	}
	return SourceFile{Path: "groups/" + strings.ReplaceAll(group, ":", "/") + ".cedar", Cedar: src}
}

func in(g string) string { return fmt.Sprintf("principal in Tessera::Group::%q", g) }

// members returns the sorted effective identity ids (as indexes into idents) of a group.
func (x *harness) members(name string) []int {
	x.t.Helper()
	var out []int
	x.read(func(e model.Env) error {
		g, err := e.Tx.GrpGroupByName(name)
		if err != nil {
			return err
		}
		ids, err := e.Tx.GrpEffectiveIdentitiesAfter(g.ID, store.MembersListID(tid), -1<<62, 100000)
		if err != nil {
			return err
		}
		for _, id := range ids {
			out = append(out, slices.Index(x.idents, id))
		}
		return nil
	})
	slices.Sort(out)
	return out
}

func (x *harness) group2(name string) *store.NativeGroup {
	x.t.Helper()
	var g *store.NativeGroup
	x.read(func(e model.Env) error {
		var err error
		g, err = e.Tx.GrpGroupByName(name)
		return err
	})
	return g
}

func (x *harness) lastSeq() int64 {
	x.t.Helper()
	var n int64
	x.read(func(e model.Env) error {
		h, err := e.Tx.GrpEventHead()
		n = h.LastSeq
		return err
	})
	return n
}

func (x *harness) eventsAfter(seq int64) []*store.GrpEvent {
	x.t.Helper()
	var out []*store.GrpEvent
	x.read(func(e model.Env) error {
		h, err := e.Tx.GrpEventHead()
		if err != nil {
			return err
		}
		out, err = e.Tx.GrpEventsAfter(seq, h.LastSeq, 100000)
		return err
	})
	return out
}

func asValidation(t testing.TB, err error) *ValidationError {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want a ValidationError", err)
	}
	return ve
}

func hasCode(ve *ValidationError, code string) bool {
	return slices.ContainsFunc(ve.Diags, func(d Diagnostic) bool { return d.Code == code })
}
