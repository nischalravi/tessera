package benchgen

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/naming"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Tenant is a generated tenant and the handles the measurements use.
type Tenant struct {
	DB    *store.DB
	ID    tenancy.ID
	Spec  Spec
	Stats Stats
	// Now is the clock of every operation (the wall clock: the PIT queries need
	// event times in the past).
	Now func() time.Time
	// Eng is the engine with the production synchronous budget. The load itself
	// runs with an inline engine.
	Eng *engine.Engine

	Idents  []int64
	Levels  [4][]store.GroupID // 0 are the leaves that hold the direct rows
	Folders []*store.Folder    // the root first

	Chain  []store.GroupID // twelve nested groups, top first
	Tail   store.GroupID   // the bottom of the chain
	Ref    store.GroupID   // ref:student:enrolled
	Target store.GroupID   // the group every policy group uses
	Policy []store.GroupID
	// PolicyLeaf is the leaf group each policy group also uses (same order).
	PolicyLeaf []store.GroupID
	// EffectiveBytes is how much the database file (and its log) grew while the
	// effective memberships were written; zero when Spec.DBPath was not given.
	EffectiveBytes int64
	// PolicyFolder holds the policy groups; the provisioner covers it.
	PolicyFolder store.FolderID
	Leaf         store.GroupID // a leaf with direct members
	Top          store.GroupID // a level 3 group (the largest effective sets)
	BrowseFolder store.FolderID
	Root         store.FolderID
}

// fileSize is the size of a SQLite file and its write-ahead log (0: no path).
func fileSize(path string) int64 {
	if path == "" {
		return 0
	}
	var n int64
	for _, suffix := range []string{"", "-wal"} {
		if fi, err := os.Stat(path + suffix); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// CreateTenant adds the tenant row a Generate needs.
func CreateTenant(ctx context.Context, db *store.DB, id tenancy.ID, slug string) error {
	return db.InSystem(ctx, "benchgen", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: id, Slug: slug, Name: slug, CreatedAt: time.Now().UTC()})
		return err
	})
}

// write runs fn in a write transaction with the given engine.
func (t *Tenant) write(ctx context.Context, eng *engine.Engine, fn func(e model.Env) error) error {
	return t.DB.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		return fn(model.Env{Tx: tx, Now: t.Now(), Engine: eng})
	})
}

// read runs fn in a read transaction.
func (t *Tenant) read(ctx context.Context, fn func(e model.Env) error) error {
	return t.DB.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		return fn(model.Env{Tx: tx, Now: t.Now(), Engine: t.Eng})
	})
}

// chunks calls fn for [lo, hi) ranges of at most size items, each in its own
// transaction, so no load transaction grows with the tenant.
func (t *Tenant) chunks(ctx context.Context, eng *engine.Engine, n, size int, fn func(e model.Env, lo, hi int) error) error {
	for lo := 0; lo < n; lo += size {
		hi := min(n, lo+size)
		if err := t.write(ctx, eng, func(e model.Env) error { return fn(e, lo, hi) }); err != nil {
			return err
		}
	}
	return nil
}

// Generate loads a tenant shaped like the design's reference tenant (section
// 6.7) at spec.Percent of its size into an existing tenant: folders, identities
// with an account each, four levels of basic groups nested up to depth 4 plus a
// chain of 12, a reference group nested nowhere yet, a group every policy group
// uses, composite policy groups, a folder to browse, and materialized effective
// memberships (verified clean by the caller if it wants to).
func Generate(ctx context.Context, db *store.DB, id tenancy.ID, spec Spec) (*Tenant, error) {
	spec.defaults()
	start := time.Now()
	c := spec.Counts()
	t := &Tenant{DB: db, ID: id, Spec: spec, Now: spec.Now}
	if t.Now == nil {
		t.Now = func() time.Time { return time.Now().UTC() }
	}
	rng := rand.New(rand.NewSource(spec.Seed)) // #nosec G404 -- a repeatable shape, not a secret
	inline := engine.New(1 << 40)              // load inline, whatever the size
	list := store.MembersListID(id)

	// identities and their directory accounts
	spec.logf("identities: %d", c.Identities)
	t.Idents = make([]int64, 0, c.Identities)
	if err := t.chunks(ctx, inline, c.Identities, 5000, func(e model.Env, lo, hi int) error {
		for i := lo; i < hi; i++ {
			ident, err := e.Tx.InsertIdentity(&store.Identity{ExternalID: fmt.Sprintf("u%d", i), Name: fmt.Sprintf("User %06d", i),
				Type: "person", Status: "active", CreatedAt: e.Now})
			if err != nil {
				return err
			}
			if _, err := e.Tx.InsertAccount(&store.Account{System: "dir", ExternalID: fmt.Sprintf("acc-%d", i), IdentityID: &ident,
				Username: fmt.Sprintf("u%d", i), Kind: "user", Status: "active"}); err != nil {
				return err
			}
			t.Idents = append(t.Idents, ident)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("identities: %w", err)
	}

	// folders: a tree up to depth 6 under the root, plus the three the tests use
	spec.logf("folders: %d", c.Folders)
	var depth []int
	var regular []*store.Folder
	mkFolder := func(e model.Env, parent *store.Folder, ext string) (*store.Folder, error) {
		name, err := naming.Join(parent.Name, ext)
		if err != nil {
			return nil, err
		}
		pid := parent.ID
		f := &store.Folder{ParentID: &pid, Extension: ext, DisplayExtension: ext, Name: name, DisplayName: ext,
			ManagedBy: store.ManagedByUI, CreatedAt: e.Now}
		return f, e.Tx.InsertGrpFolder(f)
	}
	if err := t.write(ctx, inline, func(e model.Env) error {
		root, err := e.EnsureRoot()
		if err != nil {
			return err
		}
		t.Root = root.ID
		t.Folders, depth = []*store.Folder{root}, []int{0}
		for _, special := range []string{"policy", "browse"} {
			f, err := mkFolder(e, root, special)
			if err != nil {
				return err
			}
			switch special {
			case "policy":
				t.PolicyFolder = f.ID
			case "browse":
				t.BrowseFolder = f.ID
			}
			t.Folders, depth = append(t.Folders, f), append(depth, 1)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("folders: %w", err)
	}
	if err := t.chunks(ctx, inline, c.Folders, 2000, func(e model.Env, lo, hi int) error {
		for i := lo; i < hi; i++ {
			pi := 0
			if i > 0 {
				pi = rng.Intn(len(t.Folders))
			}
			if depth[pi] >= 6 {
				pi = 0
			}
			f, err := mkFolder(e, t.Folders[pi], fmt.Sprintf("f%d", i))
			if err != nil {
				return err
			}
			t.Folders, depth = append(t.Folders, f), append(depth, depth[pi]+1)
			regular = append(regular, f)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("folders: %w", err)
	}

	// groups in four levels (90%, 6%, 3%, 1%), spread over the regular folders
	spec.logf("groups: %d", c.Groups)
	share := [4]float64{0.90, 0.06, 0.03, 0.01}
	type gdef struct {
		lv, i int
	}
	var defs []gdef
	for lv := range t.Levels {
		for i := 0; i < max(1, int(float64(c.Groups)*share[lv])); i++ {
			defs = append(defs, gdef{lv, i})
		}
	}
	mkGroup := func(e model.Env, folder *store.Folder, ext string) (*store.NativeGroup, error) {
		name, err := naming.Join(folder.Name, ext)
		if err != nil {
			return nil, err
		}
		g := &store.NativeGroup{FolderID: folder.ID, Extension: ext, DisplayExtension: ext, Name: name, DisplayName: ext,
			Kind: store.KindGroup, Definition: store.DefinitionBasic, ManagedBy: store.ManagedByUI, Status: store.GroupActive, CreatedAt: e.Now}
		return g, e.Tx.InsertGrpGroup(g)
	}
	if err := t.chunks(ctx, inline, len(defs), 2000, func(e model.Env, lo, hi int) error {
		for _, d := range defs[lo:hi] {
			g, err := mkGroup(e, regular[rng.Intn(len(regular))], fmt.Sprintf("l%d_%d", d.lv, d.i))
			if err != nil {
				return err
			}
			t.Levels[d.lv] = append(t.Levels[d.lv], g.ID)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("groups: %w", err)
	}
	leaves := t.Levels[0]
	t.Leaf, t.Top = leaves[0], t.Levels[3][0]

	// direct identity rows on the leaves
	spec.logf("direct memberships: %d", c.Direct)
	per := max(1, c.Direct/len(leaves))
	if err := t.chunks(ctx, inline, len(leaves), 200, func(e model.Env, lo, hi int) error {
		if err := engine.Touch(e.Tx, e.Now); err != nil {
			return err
		}
		for _, g := range leaves[lo:hi] {
			seen := map[int64]bool{}
			for len(seen) < min(per, len(t.Idents)) {
				ident := t.Idents[rng.Intn(len(t.Idents))]
				if seen[ident] {
					continue
				}
				seen[ident] = true
				if err := e.Tx.InsertGrpDirect(&store.DirectMembership{GroupID: g, ListID: list, MemberType: store.MemberIdentity,
					MemberIdentity: &ident, Source: "benchgen", CreatedAt: e.Now}); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("direct memberships: %w", err)
	}

	// nesting: level n holds fan[n] groups of level n-1
	spec.logf("nesting")
	fan := [4]int{0, 10, 5, 5}
	nest := func(e model.Env, parent, child store.GroupID) error {
		if err := e.Tx.InsertGrpDirect(&store.DirectMembership{GroupID: parent, ListID: list, MemberType: store.MemberGroup,
			MemberGroup: &child, Source: "benchgen", CreatedAt: e.Now}); err != nil {
			return err
		}
		return inline.AddEdge(e.Tx, store.GrpDep{Parent: parent, Child: child, Kind: store.DepNest, List: list})
	}
	for lv := 1; lv < 4; lv++ {
		gs, below := t.Levels[lv], t.Levels[lv-1]
		if err := t.chunks(ctx, inline, len(gs), 500, func(e model.Env, lo, hi int) error {
			for _, g := range gs[lo:hi] {
				for _, k := range rng.Perm(len(below))[:min(fan[lv], len(below))] {
					if err := nest(e, g, below[k]); err != nil {
						return err
					}
				}
			}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("nesting: %w", err)
		}
	}

	// the chain of 12, the reference group, the target and the policy groups
	if err := t.write(ctx, inline, func(e model.Env) error {
		root := t.Folders[0]
		for i := 0; i < 12; i++ {
			g, err := mkGroup(e, root, fmt.Sprintf("chain%d", i))
			if err != nil {
				return err
			}
			t.Chain = append(t.Chain, g.ID)
		}
		for i := 0; i+1 < len(t.Chain); i++ { // chain[0] is the top
			if err := nest(e, t.Chain[i], t.Chain[i+1]); err != nil {
				return err
			}
		}
		t.Tail = t.Chain[len(t.Chain)-1]
		g, err := mkGroup(e, root, "ref_student_enrolled")
		if err != nil {
			return err
		}
		t.Ref = g.ID
		if g, err = mkGroup(e, root, "target"); err != nil {
			return err
		}
		t.Target = g.ID
		policyFolder := t.Folders[1]
		for i := 0; i < c.Policy; i++ {
			name, err := naming.Join(policyFolder.Name, fmt.Sprintf("policy%d", i))
			if err != nil {
				return err
			}
			op := store.CompUnion
			pg := &store.NativeGroup{FolderID: policyFolder.ID, Extension: fmt.Sprintf("policy%d", i), DisplayExtension: fmt.Sprintf("policy%d", i),
				Name: name, DisplayName: name, Kind: store.KindGroup, Definition: store.DefinitionComposite, CompositeOp: &op,
				ManagedBy: store.ManagedByUI, Status: store.GroupActive, CreatedAt: e.Now}
			if err := e.Tx.InsertGrpGroup(pg); err != nil {
				return err
			}
			leaf := leaves[rng.Intn(len(leaves))]
			if err := inline.SetFactors(e.Tx, e.Now, pg.ID, []store.GroupID{t.Target, leaf}); err != nil {
				return err
			}
			t.Policy, t.PolicyLeaf = append(t.Policy, pg.ID), append(t.PolicyLeaf, leaf)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("reference groups: %w", err)
	}

	// the folder the browser test lists
	spec.logf("browse folder: %d children", c.Browse)
	if err := t.chunks(ctx, inline, c.Browse, 2000, func(e model.Env, lo, hi int) error {
		for i := lo; i < hi; i++ {
			if _, err := mkGroup(e, t.Folders[2], fmt.Sprintf("b%d", i)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("browse folder: %w", err)
	}

	// materialize: recomputing the leaves carries every change up the graph
	spec.logf("effective memberships")
	sizeBefore := fileSize(spec.DBPath)
	if err := t.chunks(ctx, inline, len(leaves), 100, func(e model.Env, lo, hi int) error {
		for _, g := range leaves[lo:hi] {
			if _, err := inline.RecomputeGroup(e.Tx, e.Now, g); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("materialize: %w", err)
	}

	t.EffectiveBytes = fileSize(spec.DBPath) - sizeBefore
	// the reference group goes in through the model, so that it has events and
	// point-in-time rows (the "members as of T" target reads them)
	spec.logf("reference group: %d members", c.Ref)
	if err := t.chunks(ctx, inline, c.Ref, 500, func(e model.Env, lo, hi int) error {
		for _, ident := range t.Idents[lo:hi] {
			if _, err := e.AddMember(t.Ref, model.MemberInput{Identity: &ident}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("reference group: %w", err)
	}

	t.Eng = engine.New(0) // from here on, the production budget
	var eff int64
	if err := t.read(ctx, func(e model.Env) error {
		for _, lv := range t.Levels {
			for _, g := range lv {
				n, err := e.Tx.GrpEffectiveCount(g, list)
				if err != nil {
					return err
				}
				eff += int64(n)
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("count: %w", err)
	}
	t.Stats = Stats{Counts: c, Effective: eff, Built: time.Since(start)}
	spec.logf("generated: %s", t.Stats)
	return t, nil
}
