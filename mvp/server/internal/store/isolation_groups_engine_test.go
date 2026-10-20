package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Membership-engine tables (issue #45, GR-2): direct memberships, the
// dependency DAG, closure, levels, effective rows, composite factors, the
// engine queue and state. A tenant sees and changes only its own rows; another
// tenant's ids look nonexistent, and a row that names another tenant's group,
// list or identity is refused by the guard triggers.

type engIDs struct {
	g1, g2 store.GroupID
	ident  int64
	list   store.ListID
	dm     string // an identity row of g1
	dmg    string // a group row g1 <- g2
	job    int64  // a queued job only A has
}

func seedEngine(t *testing.T, f *storetest.Fixture) map[string]engIDs {
	t.Helper()
	base := seedGroups(t, f)
	out := map[string]engIDs{}
	soon := storetest.Now.Add(time.Hour)
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		var ids engIDs
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			ids.g1 = store.GroupID(base[tn.Slug].group)
			g2 := &store.NativeGroup{FolderID: store.FolderID(base[tn.Slug].folder), Extension: "eng2", DisplayExtension: "eng2",
				Name: "app:eng2", DisplayName: "app:eng2", CreatedAt: storetest.Now}
			if err := c.InsertGrpGroup(g2); err != nil {
				return err
			}
			ids.g2 = g2.ID
			var err error
			if ids.list, err = c.EnsureGrpMembersList(); err != nil {
				return err
			}
			if ids.ident, err = c.InsertIdentity(&store.Identity{ExternalID: "eng-u", Name: "Eng User", Type: "person",
				Status: "active", CreatedAt: storetest.Now}); err != nil {
				return err
			}
			m1 := &store.DirectMembership{GroupID: ids.g1, ListID: ids.list, MemberType: store.MemberIdentity, MemberIdentity: &ids.ident,
				EnabledFrom: &soon, Source: "test", CreatedAt: storetest.Now}
			if err := c.InsertGrpDirect(m1); err != nil {
				return err
			}
			m2 := &store.DirectMembership{GroupID: ids.g1, ListID: ids.list, MemberType: store.MemberGroup, MemberGroup: &ids.g2,
				Source: "test", CreatedAt: storetest.Now}
			if err := c.InsertGrpDirect(m2); err != nil {
				return err
			}
			ids.dm, ids.dmg = m1.ID, m2.ID
			for _, step := range []error{
				c.InsertGrpDep(store.GrpDep{Parent: ids.g1, Child: ids.g2, Kind: store.DepNest, List: ids.list}),
				c.AddGrpClosure(ids.g1, ids.g2, 1, 1),
				c.SetGrpLevel(ids.g1, 3),
				c.SetGrpEffective(ids.g1, ids.list, ids.ident, 2, storetest.Now),
				c.SetGrpFactors(ids.g1, []store.GroupID{ids.g2}),
				c.SetGrpWheelAt(storetest.Now),
			} {
				if step != nil {
					return step
				}
			}
			n := 1
			if tn.ID == f.A.ID {
				n = 2 // A has a job that B's sequence never reaches
			}
			for i := 0; i < n; i++ {
				if ids.job, err = c.EnqueueGrpJob(store.JobRecomputeGroup, `{"group":"`+string(ids.g1)+`"}`, storetest.Now); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		out[tn.Slug] = ids
	}
	return out
}

func TestIsolation_GroupsEngineTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedEngine(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	ctx := context.Background()
	isNotFound := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s = %v, want ErrNotFound", what, err)
		}
	}
	isCross := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("%s = %v, want ErrCrossTenant", what, err)
		}
	}
	empty := func(what string, n int, err error) {
		t.Helper()
		if err != nil || n != 0 {
			t.Errorf("%s = %d rows, %v; want none", what, n, err)
		}
	}
	// B reads: A's ids look nonexistent, and the tenant-wide lists hold only B's rows
	inB(t, f, func(c *store.TenantTx) error {
		_, err := c.GrpDirectMembership(a.dm)
		isNotFound("GrpDirectMembership(A's)", err)
		_, err = c.GrpDirectFind(a.g1, a.list, store.MemberGroup, string(a.g2))
		isNotFound("GrpDirectFind(A's group row)", err)
		_, err = c.GrpDirectFind(a.g1, a.list, store.MemberIdentity, "1")
		isNotFound("GrpDirectFind(A's identity row)", err)
		rows, err := c.GrpDirect(store.GrpDirectFilter{Group: a.g1})
		empty("GrpDirect(A's group)", len(rows), err)
		n, err := c.GrpDirectCount(store.GrpDirectFilter{Group: a.g1})
		empty("GrpDirectCount(A's group)", n, err)
		idn, err := c.GrpDirectIdentitiesAfter(a.g1, a.list, 0, 10)
		empty("GrpDirectIdentitiesAfter", len(idn), err)
		ls, err := c.GrpDirectLists(a.g1)
		empty("GrpDirectLists", len(ls), err)
		edges, err := c.GrpDirectGroupEdges()
		if err != nil || len(edges) != 1 || edges[0].Parent != b.g1 {
			t.Errorf("GrpDirectGroupEdges = %v, %v; want B's one", edges, err)
		}
		if s, err := c.GrpBasicSupport(a.g1, a.list, a.ident, storetest.Now.Add(2*time.Hour)); err != nil || s != 0 {
			t.Errorf("GrpBasicSupport(A's) = %d, %v", s, err)
		}
		if ok, err := c.GrpDirectIdentityActive(a.g1, a.list, a.ident, storetest.Now.Add(2*time.Hour)); err != nil || ok {
			t.Errorf("GrpDirectIdentityActive(A's) = %v, %v", ok, err)
		}
		kids, err := c.GrpDirectActiveChildren(a.g1, a.list, storetest.Now)
		empty("GrpDirectActiveChildren", len(kids), err)
		// both tenants have a row with the same enabled_from: B sees only its own
		en, err := c.GrpDirectEnabledIn(storetest.Now, storetest.Now.Add(2*time.Hour))
		if err != nil || len(en) != 1 || en[0].ID != b.dm {
			t.Errorf("GrpDirectEnabledIn = %v, %v; want B's row", en, err)
		}
		dis, err := c.GrpDirectDisabledIn(storetest.Now, storetest.Now.Add(2*time.Hour))
		empty("GrpDirectDisabledIn", len(dis), err)
		if nb, err := c.GrpNextBoundary(storetest.Now); err != nil || nb == nil || !nb.Equal(storetest.Now.Add(time.Hour)) {
			t.Errorf("GrpNextBoundary = %v, %v", nb, err)
		}
		if nb, err := c.GrpNextBoundary(storetest.Now.Add(time.Hour)); err != nil || nb != nil {
			t.Errorf("GrpNextBoundary after the only date = %v, %v; want none", nb, err)
		}

		if s, err := c.GrpEffectiveSupport(a.g1, a.list, a.ident); err != nil || s != 0 {
			t.Errorf("GrpEffectiveSupport(A's) = %d, %v", s, err)
		}
		n, err = c.GrpEffectiveCount(a.g1, "")
		empty("GrpEffectiveCount(A's)", n, err)
		idn, err = c.GrpEffectiveIdentitiesAfter(a.g1, a.list, 0, 10)
		empty("GrpEffectiveIdentitiesAfter", len(idn), err)
		er, err := c.GrpEffectiveList(a.g1, a.list, 10, 0)
		empty("GrpEffectiveList", len(er), err)
		pairs, err := c.GrpEffectivePairs()
		if err != nil || len(pairs) != 1 || pairs[0].Parent != b.g1 {
			t.Errorf("GrpEffectivePairs = %v, %v; want B's one", pairs, err)
		}
		gs, err := c.GrpEffectiveGroupsOf(a.ident, a.list)
		empty("GrpEffectiveGroupsOf(A's identity id)", len(gs), err)

		ds, err := c.GrpDepsOf(a.g1)
		empty("GrpDepsOf(A's)", len(ds), err)
		all, err := c.GrpDepsAll()
		if err != nil || len(all) != 1 || all[0].Parent != b.g1 {
			t.Errorf("GrpDepsAll = %v, %v; want B's one", all, err)
		}
		ps, err := c.GrpDepParents(a.g2, a.list)
		empty("GrpDepParents(A's)", len(ps), err)
		n, err = c.GrpDepPairCount(a.g1, a.g2)
		empty("GrpDepPairCount(A's)", n, err)
		ch, err := c.GrpDepChildren(a.g1, "")
		empty("GrpDepChildren(A's)", len(ch), err)

		an, err := c.GrpClosureAncestors(a.g2)
		empty("GrpClosureAncestors(A's)", len(an), err)
		de, err := c.GrpClosureDescendants(a.g1)
		empty("GrpClosureDescendants(A's)", len(de), err)
		cl, err := c.GrpClosureAll()
		if err != nil || len(cl) != 1 || cl[0].Ancestor != b.g1 {
			t.Errorf("GrpClosureAll = %v, %v; want B's one", cl, err)
		}
		n, err = c.GrpClosureAncestorCount(a.g2)
		empty("GrpClosureAncestorCount(A's)", n, err)
		_, err = c.GrpClosureGet(a.g1, a.g2)
		isNotFound("GrpClosureGet(A's)", err)

		if lv, err := c.GrpLevel(a.g1); err != nil || lv != 0 {
			t.Errorf("GrpLevel(A's) = %d, %v; want the default 0, not A's 3", lv, err)
		}
		lvs, err := c.GrpLevels()
		if err != nil || len(lvs) != 1 || lvs[0].Group != b.g1 {
			t.Errorf("GrpLevels = %v, %v; want B's one", lvs, err)
		}
		if m, err := c.GrpMaxChildLevel(a.g1); err != nil || m != -1 {
			t.Errorf("GrpMaxChildLevel(A's) = %d, %v; want -1", m, err)
		}
		fs, err := c.GrpFactors(a.g1)
		empty("GrpFactors(A's)", len(fs), err)
		fa, err := c.GrpFactorsAll()
		if err != nil || len(fa) != 1 || fa[0].Parent != b.g1 {
			t.Errorf("GrpFactorsAll = %v, %v; want B's one", fa, err)
		}
		grs, err := c.GrpGroupsAll()
		if err != nil || len(grs) != 2 {
			t.Errorf("GrpGroupsAll = %d groups, %v; want B's 2", len(grs), err)
		}
		for _, g := range grs {
			if g.ID == a.g1 || g.ID == a.g2 {
				t.Errorf("GrpGroupsAll returned A's group %s", g.ID)
			}
		}
		ge, err := c.GrpGroupsEnabledIn(storetest.Now, storetest.Now.Add(2*time.Hour))
		empty("GrpGroupsEnabledIn", len(ge), err)
		gd, err := c.GrpGroupsDisabledIn(storetest.Now, storetest.Now.Add(2*time.Hour))
		empty("GrpGroupsDisabledIn", len(gd), err)
		if s, err := c.GrpChildEffectiveSum(a.g1); err != nil || s != 0 {
			t.Errorf("GrpChildEffectiveSum(A's) = %d, %v", s, err)
		}

		st, err := c.GrpEngineState()
		if err != nil || st.NextSeq != 2 {
			t.Errorf("GrpEngineState = %+v, %v; want B's own counter (2), not A's (3)", st, err)
		}
		_, err = c.GrpJob(a.job)
		isNotFound("GrpJob(A's seq)", err)
		first, err := c.GrpFirstJob()
		if err != nil || first.Seq != 1 || first.Payload != `{"group":"`+string(b.g1)+`"}` {
			t.Errorf("GrpFirstJob = %+v, %v; want B's", first, err)
		}
		if n, err := c.GrpQueueLen(); err != nil || n != 1 {
			t.Errorf("GrpQueueLen = %d, %v; want B's 1", n, err)
		}
		if n, err := c.GrpQueuedFor(a.g1); err != nil || n != 0 {
			t.Errorf("GrpQueuedFor(A's group) = %d, %v", n, err)
		}
		if s, err := c.GrpOpState(a.job); err != nil || s != store.OpUnknown {
			t.Errorf("GrpOpState(A's op) = %s, %v; want unknown", s, err)
		}
		return nil
	})
	// B writes naming A's rows change nothing of A's
	err := f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		isNotFound("SetGrpDirectDates(A's)", c.SetGrpDirectDates(&store.DirectMembership{ID: a.dm}))
		isNotFound("DeleteGrpDirect(A's)", c.DeleteGrpDirect(a.dm))
		if n, err := c.DeleteGrpDirectOf(a.g1); err != nil || n != 0 {
			t.Errorf("DeleteGrpDirectOf(A's) = %d, %v", n, err)
		}
		for what, err := range map[string]error{
			"DeleteGrpEffective":   c.DeleteGrpEffective(a.g1, a.list, a.ident),
			"DeleteGrpEffectiveOf": c.DeleteGrpEffectiveOf(a.g1),
			"DeleteGrpDep":         c.DeleteGrpDep(store.GrpDep{Parent: a.g1, Child: a.g2, Kind: store.DepNest, List: a.list}),
			"SubGrpClosure":        c.SubGrpClosure(a.g1, a.g2, 1),
			"SetGrpClosureDepth":   c.SetGrpClosureDepth(a.g1, a.g2, 9),
			"DeleteGrpClosure":     c.DeleteGrpClosure(a.g1, a.g2),
		} {
			if err != nil {
				t.Errorf("%s(A's rows from B) = %v; it should do nothing", what, err)
			}
		}
		isNotFound("SetGrpGroupDefinition(A's)", c.SetGrpGroupDefinition(a.g1, store.DefinitionBasic, nil))
		isNotFound("AddGrpEffectiveCount(A's)", c.AddGrpEffectiveCount(a.g1, 5))
		isNotFound("SetGrpEffectiveCount(A's)", c.SetGrpEffectiveCount(a.g1, 5))
		isNotFound("SetGrpRecomputeState(A's)", c.SetGrpRecomputeState(a.g1, "failed"))
		isNotFound("SetGrpJobPayload(A's)", c.SetGrpJobPayload(a.job, "{}"))
		isNotFound("DeleteGrpJob(A's)", c.DeleteGrpJob(a.job))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// rows naming A's groups, list or identity are refused
	for name, fn := range map[string]func(c *store.TenantTx) error{
		"direct row in A's group": func(c *store.TenantTx) error {
			return c.InsertGrpDirect(&store.DirectMembership{GroupID: a.g1, ListID: b.list, MemberType: store.MemberIdentity,
				MemberIdentity: &b.ident, Source: "x", CreatedAt: storetest.Now})
		},
		"direct row of A's identity": func(c *store.TenantTx) error {
			return c.InsertGrpDirect(&store.DirectMembership{GroupID: b.g1, ListID: b.list, MemberType: store.MemberIdentity,
				MemberIdentity: &a.ident, Source: "x", CreatedAt: storetest.Now})
		},
		"direct row of A's group": func(c *store.TenantTx) error {
			return c.InsertGrpDirect(&store.DirectMembership{GroupID: b.g1, ListID: b.list, MemberType: store.MemberGroup,
				MemberGroup: &a.g2, Source: "x", CreatedAt: storetest.Now})
		},
		"direct row in A's list": func(c *store.TenantTx) error {
			return c.InsertGrpDirect(&store.DirectMembership{GroupID: b.g1, ListID: a.list, MemberType: store.MemberIdentity,
				MemberIdentity: &b.ident, Source: "x", CreatedAt: storetest.Now})
		},
		"direct row stamped with A": func(c *store.TenantTx) error {
			return c.InsertGrpDirect(&store.DirectMembership{TenantID: f.A.ID, GroupID: b.g1, ListID: b.list,
				MemberType: store.MemberIdentity, MemberIdentity: &b.ident, Source: "x", CreatedAt: storetest.Now})
		},
		"dep on A's groups": func(c *store.TenantTx) error {
			return c.InsertGrpDep(store.GrpDep{Parent: a.g1, Child: a.g2, Kind: store.DepFactor, List: b.list})
		},
		"level of A's group": func(c *store.TenantTx) error { return c.SetGrpLevel(a.g1, 1) },
		"factor of A's group": func(c *store.TenantTx) error {
			return c.SetGrpFactors(b.g1, []store.GroupID{a.g2})
		},
		"factors of A's group": func(c *store.TenantTx) error {
			return c.SetGrpFactors(a.g1, []store.GroupID{b.g2})
		},
	} {
		t.Run(name, func(t *testing.T) {
			isCross(name, f.DB.InTenant(ctx, f.B.ID, fn))
		})
	}
	// A's rows are all still there
	f.DB.ReadTenant(ctx, f.A.ID, func(c *store.TenantTx) error {
		if m, err := c.GrpDirectMembership(a.dm); err != nil || m.EnabledFrom == nil {
			t.Errorf("A's identity row = %+v, %v", m, err)
		}
		if _, err := c.GrpDirectMembership(a.dmg); err != nil {
			t.Errorf("A's group row: %v", err)
		}
		if s, err := c.GrpEffectiveSupport(a.g1, a.list, a.ident); err != nil || s != 2 {
			t.Errorf("A's effective support = %d, %v; want 2", s, err)
		}
		if d, err := c.GrpDepsOf(a.g1); err != nil || len(d) != 1 {
			t.Errorf("A's deps = %v, %v", d, err)
		}
		if cl, err := c.GrpClosureGet(a.g1, a.g2); err != nil || cl.Paths != 1 || cl.MinDepth != 1 {
			t.Errorf("A's closure = %+v, %v", cl, err)
		}
		if lv, err := c.GrpLevel(a.g1); err != nil || lv != 3 {
			t.Errorf("A's level = %d, %v", lv, err)
		}
		if fs, err := c.GrpFactors(a.g1); err != nil || len(fs) != 1 || fs[0] != a.g2 {
			t.Errorf("A's factors = %v, %v", fs, err)
		}
		if g, err := c.GrpGroup(a.g1); err != nil || g.RecomputeState != "clean" || g.EffectiveCount != 0 {
			t.Errorf("A's group = %+v, %v", g, err)
		}
		if j, err := c.GrpJob(a.job); err != nil || j.Payload != `{"group":"`+string(a.g1)+`"}` {
			t.Errorf("A's job = %+v, %v", j, err)
		}
		if q, err := c.GrpQueueLen(); err != nil || q != 2 {
			t.Errorf("A's queue = %d, %v", q, err)
		}
		return nil
	})
}

// TestIsolation_GroupsEngineQueueSequence: each tenant counts its own
// operation ids, and an id is never issued twice even after its job is deleted.
func TestIsolation_GroupsEngineQueueSequence(t *testing.T) {
	f := storetest.TwoTenants(t)
	enq := func(tn storetest.Tenant) int64 {
		var seq int64
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			var err error
			seq, err = c.EnqueueGrpJob(store.JobRecomputeGroup, "{}", storetest.Now)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return seq
	}
	if a1, b1 := enq(f.A), enq(f.B); a1 != 1 || b1 != 1 {
		t.Errorf("first ids = %d, %d; each tenant starts at 1", a1, b1)
	}
	inA(t, f, func(c *store.TenantTx) error { return c.DeleteGrpJob(1) })
	if a2 := enq(f.A); a2 != 2 {
		t.Errorf("A's id after deleting job 1 = %d, want 2 (ids are not reused)", a2)
	}
	inA(t, f, func(c *store.TenantTx) error {
		if s, err := c.GrpOpState(1); err != nil || s != store.OpDone {
			t.Errorf("state of deleted op 1 = %s, %v; want done", s, err)
		}
		if s, err := c.GrpOpState(2); err != nil || s != store.OpPending {
			t.Errorf("state of op 2 = %s, %v; want pending", s, err)
		}
		return nil
	})
}

func groupsEngineCovered() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{
		"GrpDirectMembership", "GrpDirectFind", "GrpDirect", "GrpDirectCount", "InsertGrpDirect", "SetGrpDirectDates",
		"DeleteGrpDirect", "DeleteGrpDirectOf", "GrpDirectIdentitiesAfter", "GrpDirectLists", "GrpDirectGroupEdges",
		"GrpBasicSupport", "GrpDirectIdentityActive", "GrpDirectActiveChildren", "GrpDirectEnabledIn", "GrpDirectDisabledIn",
		"GrpNextBoundary",
		"GrpEffectiveSupport", "SetGrpEffective", "DeleteGrpEffective", "DeleteGrpEffectiveOf", "GrpEffectiveCount",
		"GrpEffectiveIdentitiesAfter", "GrpEffectiveList", "GrpEffectivePairs", "GrpEffectiveGroupsOf",
		"InsertGrpDep", "DeleteGrpDep", "GrpDepsOf", "GrpDepsAll", "GrpDepParents", "GrpDepPairCount", "GrpDepChildren",
		"GrpClosureAncestors", "GrpClosureDescendants", "GrpClosureAll", "GrpClosureAncestorCount", "GrpClosureGet",
		"AddGrpClosure", "SubGrpClosure", "SetGrpClosureDepth", "DeleteGrpClosure",
		"GrpLevel", "SetGrpLevel", "GrpLevels", "GrpMaxChildLevel",
		"GrpFactors", "GrpFactorsAll", "SetGrpFactors", "SetGrpGroupDefinition", "AddGrpEffectiveCount",
		"SetGrpEffectiveCount", "SetGrpRecomputeState", "GrpGroupsAll", "GrpGroupsEnabledIn", "GrpGroupsDisabledIn",
		"GrpChildEffectiveSum",
		"GrpEngineState", "SetGrpWheelAt", "SetGrpVerifiedAt", "EnqueueGrpJob", "GrpFirstJob", "GrpJob", "SetGrpJobPayload",
		"DeleteGrpJob", "GrpQueueLen", "GrpQueuedFor", "GrpOpState",
	} {
		m[name] = true
	}
	return m
}
