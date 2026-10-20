package provisioning

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var (
	t0  = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	tid = tenancy.MustParse("00000000-0000-4000-8000-0000000000d7")
)

// ---------------------------------------------------------------- the fake target

// fakeTarget is an in-memory target with the knobs the tests need: writes that
// are silently lost, reads that fail, and counters of what it was asked.
type fakeTarget struct {
	mu     sync.Mutex
	caps   Capabilities
	groups map[string]*TargetGroup
	nextID int
	tokens bool
	ver    int

	// dropAdd: member references an add silently does not store (a lying target).
	dropAdd map[string]bool
	// failApply and failRead make every call fail.
	failApply, failRead error
	// failVerifyRead makes a Read that follows an Apply fail (the verification read).
	failVerifyRead error
	applied        bool

	applies, reads, readAlls, tokenReads int
	// writes counts ops that were applied (any kind).
	writes int
	// log is "apply" and "read" in call order.
	log []string
}

func newFake() *fakeTarget {
	return &fakeTarget{caps: Capabilities{Groups: true, Memberships: true, Incremental: true, Readable: true, MaxBatch: 3},
		groups: map[string]*TargetGroup{}, dropAdd: map[string]bool{}}
}

func (f *fakeTarget) Capabilities() Capabilities {
	c := f.caps
	c.ChangeTokens = f.tokens
	return c
}
func (f *fakeTarget) Close() error { return nil }

func copyGroup(g *TargetGroup) *TargetGroup {
	c := *g
	c.Members = slices.Clone(g.Members)
	c.Attrs = map[string][]string{}
	for k, v := range g.Attrs {
		c.Attrs[k] = slices.Clone(v)
	}
	return &c
}

func (f *fakeTarget) touch(g *TargetGroup) {
	f.ver++
	g.Token = fmt.Sprint(f.ver)
}

// seed puts a group on the target as if someone else had made it.
func (f *fakeTarget) seed(name string, members ...string) *TargetGroup {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	g := &TargetGroup{Ref: TargetRef{Name: name, ID: fmt.Sprintf("t%d", f.nextID)}, Members: slices.Clone(members), Attrs: map[string][]string{}}
	f.touch(g)
	f.groups[Key(name)] = g
	return g
}

func (f *fakeTarget) members(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := f.groups[Key(name)]
	if g == nil {
		return nil
	}
	out := slices.Clone(g.Members)
	slices.Sort(out)
	return out
}

func (f *fakeTarget) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, g := range f.groups {
		out = append(out, g.Ref.Name)
	}
	slices.Sort(out)
	return out
}

// snapshot is every group's sorted members by key, for comparing two targets.
func (f *fakeTarget) snapshot() map[string][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string][]string{}
	for k, g := range f.groups {
		m := slices.Clone(g.Members)
		slices.Sort(m)
		out[k] = m
	}
	return out
}

func (f *fakeTarget) ReadAll(_ context.Context, _ Scope) (TargetState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readAlls++
	f.log = append(f.log, "readall")
	st := NewState()
	if f.failRead != nil {
		return st, f.failRead
	}
	for k, g := range f.groups {
		st.Groups[k] = copyGroup(g)
	}
	return st, nil
}

func (f *fakeTarget) Read(_ context.Context, refs []TargetRef) (TargetState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	f.log = append(f.log, "read")
	st := NewState()
	if f.failRead != nil {
		return st, f.failRead
	}
	if f.failVerifyRead != nil && f.applied {
		return st, f.failVerifyRead
	}
	f.applied = false
	for _, r := range refs {
		if g := f.groups[Key(r.Name)]; g != nil {
			st.Groups[Key(r.Name)] = copyGroup(g)
		}
	}
	return st, nil
}

func (f *fakeTarget) Tokens(_ context.Context, _ Scope) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenReads++
	out := map[string]string{}
	for k, g := range f.groups {
		out[k] = g.Token
	}
	return out, nil
}

func (f *fakeTarget) Apply(_ context.Context, ops []Op) ([]OpResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	f.log = append(f.log, "apply")
	f.applied = true
	if f.failApply != nil {
		return nil, f.failApply
	}
	out := make([]OpResult, len(ops))
	for i, op := range ops {
		f.writes++
		out[i] = OpResult{ID: op.ID, Ref: op.Ref}
		k := Key(op.Ref.Name)
		switch op.Kind {
		case OpCreate:
			f.nextID++
			g := &TargetGroup{Ref: TargetRef{Name: op.Ref.Name, ID: fmt.Sprintf("t%d", f.nextID)}, Attrs: op.Attrs}
			for _, m := range op.Add {
				if !f.dropAdd[m] {
					g.Members = append(g.Members, m)
				}
			}
			f.touch(g)
			f.groups[k] = g
			out[i].Ref = g.Ref
		case OpUpdate:
			if g := f.groups[k]; g != nil {
				if g.Attrs == nil {
					g.Attrs = map[string][]string{}
				}
				for a, v := range op.Attrs {
					g.Attrs[a] = v
				}
				f.touch(g)
			}
		case OpMembers:
			g := f.groups[k]
			if g == nil && !f.caps.Groups {
				f.nextID++
				g = &TargetGroup{Ref: TargetRef{Name: op.Ref.Name}}
				f.groups[k] = g
			}
			if g == nil {
				out[i].Err = fmt.Errorf("no such group %s", op.Ref.Name)
				continue
			}
			for _, m := range op.Remove {
				g.Members = slices.DeleteFunc(g.Members, func(x string) bool { return NormMember(x) == NormMember(m) })
			}
			for _, m := range op.Add {
				if !f.dropAdd[m] && !slices.ContainsFunc(g.Members, func(x string) bool { return NormMember(x) == NormMember(m) }) {
					g.Members = append(g.Members, m)
				}
			}
			f.touch(g)
			if !f.caps.Groups && len(g.Members) == 0 {
				delete(f.groups, k)
			}
		case OpDelete:
			delete(f.groups, k)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- the harness

type harness struct {
	t       testing.TB
	db      *store.DB
	svc     *Service
	eng     *engine.Engine
	now     time.Time
	root    store.FolderID
	idents  []int64
	targets map[string]*fakeTarget
	mu      sync.Mutex
}

func newHarness(t testing.TB, nIdents int) *harness {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "prov.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.InSystem(ctx, "test", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: tid, Slug: "prov", Name: "prov", CreatedAt: t0})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	x := &harness{t: t, db: db, eng: engine.New(0), now: t0, targets: map[string]*fakeTarget{}}
	x.svc = &Service{DB: db, Sealer: sealer, Clock: func() time.Time { return x.now },
		Sleep: func(context.Context, time.Duration) {},
		Open: func(_ context.Context, spec TargetSpec) (Provisioner, error) {
			x.mu.Lock()
			defer x.mu.Unlock()
			f := x.targets[spec.ProvisionerID]
			if f == nil {
				return nil, fmt.Errorf("no fake target for %s", spec.ProvisionerID)
			}
			return f, nil
		}}
	x.must(func(e model.Env) error {
		root, err := e.EnsureRoot()
		if err != nil {
			return err
		}
		x.root = root.ID
		for i := 0; i < nIdents; i++ {
			id, err := e.Tx.InsertIdentity(&store.Identity{ExternalID: fmt.Sprintf("u%d", i), Name: fmt.Sprintf("User %d", i),
				Type: "person", Status: "active", CreatedAt: t0})
			if err != nil {
				return err
			}
			x.idents = append(x.idents, id)
			if _, err := e.Tx.InsertAccount(&store.Account{System: "dir", ExternalID: fmt.Sprintf("acc-%d", i), IdentityID: &id,
				Username: fmt.Sprintf("u%d", i), Kind: "user", Status: "active"}); err != nil {
				return err
			}
		}
		return nil
	})
	return x
}

func (x *harness) run(fn func(e model.Env) error) error {
	return x.db.InTenant(context.Background(), tid, func(tx *store.TenantTx) error {
		return fn(model.Env{Tx: tx, Now: x.now, Engine: x.eng})
	})
}

func (x *harness) must(fn func(e model.Env) error) {
	x.t.Helper()
	if err := x.run(fn); err != nil {
		x.t.Fatal(err)
	}
}

func (x *harness) read(fn func(tx *store.TenantTx) error) {
	x.t.Helper()
	if err := x.db.ReadTenant(context.Background(), tid, fn); err != nil {
		x.t.Fatal(err)
	}
}

// tick moves the clock.
func (x *harness) tick(d time.Duration) { x.now = x.now.Add(d) }

func (x *harness) folder(parent store.FolderID, ext string) store.FolderID {
	x.t.Helper()
	var id store.FolderID
	x.must(func(e model.Env) error {
		f, err := e.CreateFolder(model.CreateFolderInput{Parent: parent, Extension: ext})
		if err == nil {
			id = f.ID
		}
		return err
	})
	return id
}

func (x *harness) group(folder store.FolderID, ext string) store.GroupID {
	x.t.Helper()
	var id store.GroupID
	x.must(func(e model.Env) error {
		g, err := e.CreateGroup(model.CreateGroupInput{Folder: folder, Extension: ext})
		if err == nil {
			id = g.ID
		}
		return err
	})
	return id
}

func (x *harness) add(g store.GroupID, ident int64) {
	x.t.Helper()
	x.must(func(e model.Env) error { _, err := e.AddMember(g, model.MemberInput{Identity: &ident}); return err })
}

func (x *harness) remove(g store.GroupID, ident int64) {
	x.t.Helper()
	x.must(func(e model.Env) error { _, err := e.RemoveMember(g, fmt.Sprint(ident)); return err })
}

func mustJSON(t testing.TB, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// scimConfig is a config that validates as a SCIM target; the harness replaces
// the target with a fake, so only the common part is used.
func scimConfig(extra map[string]any) json.RawMessage {
	c := map[string]any{"account_system": "dir", "member_ref": "{{.Username}}",
		"group_name": `{{.Name | replace ":" "-"}}`, "target": map[string]any{"base_url": "https://scim.example.com/scim/v2"}}
	for k, v := range extra {
		c[k] = v
	}
	b, _ := json.Marshal(c)
	return b
}

// prov creates a provisioner (adopt mode, as every provisioner starts) with a fake target.
func (x *harness) prov(name string, failsafe string) (*store.Provisioner, *fakeTarget) {
	return x.provWith(name, failsafe, nil)
}

func (x *harness) provWith(name string, failsafe string, extra map[string]any) (*store.Provisioner, *fakeTarget) {
	x.t.Helper()
	var p *store.Provisioner
	x.must(func(e model.Env) error {
		var err error
		p, err = x.svc.Create(e.Tx, x.now, "tester", CreateInput{Name: name, TargetType: TypeSCIM2, Config: scimConfig(extra),
			Secret: map[string]string{"token": "s3cr3t-token"}, Failsafe: json.RawMessage(failsafe)})
		return err
	})
	f := newFake()
	x.mu.Lock()
	x.targets[p.ID] = f
	x.mu.Unlock()
	return p, f
}

func (x *harness) setMode(id, mode string) {
	x.t.Helper()
	if mode == store.ProvModeActive {
		// enabling needs a completed review run (adopt or dry run)
		var last *store.SyncRun
		x.read(func(tx *store.TenantTx) error {
			if r, err := tx.LastSyncRun(id, store.RunFull); err == nil {
				last = r
			}
			return nil
		})
		if last == nil || last.Status != store.RunDone {
			x.full(id)
		}
	}
	x.must(func(e model.Env) error {
		p, err := e.Tx.Provisioner(id)
		if err != nil {
			return err
		}
		_, err = x.svc.Update(e.Tx, x.now, "tester", id, UpdateInput{Version: p.Version, Mode: &mode})
		return err
	})
}

func (x *harness) mark(prov string, in MarkInput) {
	x.t.Helper()
	x.must(func(e model.Env) error { _, err := x.svc.SetMark(e.Tx, x.now, "tester", prov, in); return err })
}

func (x *harness) full(id string) *Report {
	x.t.Helper()
	rep, err := x.svc.Run(context.Background(), tid, id, RunOptions{Kind: store.RunFull})
	if err != nil {
		x.t.Fatalf("full sync: %v", err)
	}
	return rep
}

func (x *harness) incremental(id string) *Report {
	x.t.Helper()
	rep, err := x.svc.Run(context.Background(), tid, id, RunOptions{Kind: store.RunIncremental})
	if err != nil {
		x.t.Fatalf("incremental sync: %v", err)
	}
	return rep
}

func (x *harness) ops(prov, run string) []*store.SyncOp {
	x.t.Helper()
	var out []*store.SyncOp
	x.read(func(tx *store.TenantTx) error {
		var err error
		out, err = tx.SyncOps(prov, store.SyncOpFilter{RunID: run, Limit: 1000})
		return err
	})
	return out
}

func (x *harness) syncGroup(prov string, g store.GroupID) *store.SyncGroup {
	x.t.Helper()
	var sg *store.SyncGroup
	x.read(func(tx *store.TenantTx) error {
		var err error
		sg, err = tx.SyncGroup(prov, string(g))
		if err == store.ErrNotFound {
			sg, err = nil, nil
		}
		return err
	})
	return sg
}

func names(ops []*store.SyncOp) []string {
	var out []string
	for _, o := range ops {
		out = append(out, o.Op+":"+o.ObjectRef+":"+o.Status)
	}
	slices.Sort(out)
	return out
}
