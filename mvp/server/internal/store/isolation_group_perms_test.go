package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Permissions and limits (issue #62, GR-19; schema/0810_group_pit_assigns.sql):
// the permission, limit and membership reads and the assignment history of a
// tenant are its own; another tenant's rows are never seen, and the same
// assignment id can have history in two tenants.

type permIDs struct {
	assigns []string // the permission on a group, on a membership, and the limit
	ident   int64
	list    store.ListID
}

func seedGroupPerms(t *testing.T, f *storetest.Fixture) map[string]permIDs {
	t.Helper()
	base := seedEngine(t, f)
	out := map[string]permIDs{}
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			fo, err := c.GrpFolderByName("app")
			if err != nil {
				return err
			}
			mk := func(ext, typ, vt string, to ...string) (*store.GrpAttrDef, *store.GrpAttrName, *store.GrpAttrAction, error) {
				d := &store.GrpAttrDef{FolderID: fo.ID, Extension: ext, DisplayExtension: ext, AttrType: typ, ValueType: vt, MultiAssign: true,
					MultiValued: vt != store.AttrValueMarker, AssignTo: to, CreatedAt: storetest.Now}
				if err := c.InsertGrpAttrDef(d); err != nil {
					return nil, nil, nil, err
				}
				n := &store.GrpAttrName{DefID: d.ID, Extension: "n", DisplayExtension: "n", CreatedAt: storetest.Now}
				a := &store.GrpAttrAction{DefID: d.ID, Name: "assign", CreatedAt: storetest.Now}
				if err := c.InsertGrpAttrName(n); err != nil {
					return nil, nil, nil, err
				}
				return d, n, a, c.InsertGrpAttrAction(a)
			}
			pd, pn, pa, err := mk("perms", store.AttrTypePerm, store.AttrValueMarker, store.AttrOwnerGroup, store.AttrOwnerMembership)
			if err != nil {
				return err
			}
			ld, ln, la, err := mk("limits", store.AttrTypeLimit, store.AttrValueInteger, store.AttrOwnerAssignment)
			if err != nil {
				return err
			}
			onGroup := &store.GrpAttrAssign{DefID: pd.ID, NameID: pn.ID, ActionID: pa.ID, OwnerType: store.AttrOwnerGroup,
				OwnerID: string(base[tn.Slug].g1), CreatedAt: storetest.Now}
			onMember := &store.GrpAttrAssign{DefID: pd.ID, NameID: pn.ID, ActionID: pa.ID, OwnerType: store.AttrOwnerMembership,
				OwnerID: base[tn.Slug].dm, CreatedAt: storetest.Now}
			for _, a := range []*store.GrpAttrAssign{onGroup, onMember} {
				if err := c.InsertGrpAttrAssign(a); err != nil {
					return err
				}
			}
			lim := &store.GrpAttrAssign{DefID: ld.ID, NameID: ln.ID, ActionID: la.ID, OwnerType: store.AttrOwnerAssignment,
				OwnerID: onGroup.ID, CreatedAt: storetest.Now}
			if err := c.InsertGrpAttrAssign(lim); err != nil {
				return err
			}
			n := int64(5)
			if err := c.InsertGrpAttrValue(&store.GrpAttrValue{AssignID: lim.ID, ValueInteger: &n, Key: "i:5", CreatedAt: storetest.Now}); err != nil {
				return err
			}
			// the same assignment id has history in both tenants
			day := storetest.Now
			snap := json.RawMessage(`{"tenant":"` + tn.Slug + `"}`)
			if err := c.OpenPitAssign("shared-assign", pd.ID, store.AttrOwnerGroup, string(base[tn.Slug].g1), snap, day, 1); err != nil {
				return err
			}
			if err := c.OpenPitAssign("closed-"+tn.Slug, pd.ID, store.AttrOwnerGroup, string(base[tn.Slug].g1), snap, day, 2); err != nil {
				return err
			}
			if err := c.ClosePitAssign("closed-"+tn.Slug, day.Add(time.Minute), 3); err != nil {
				return err
			}
			// an interval of a limit definition and one of a plain attribute (which the permission view skips)
			if err := c.OpenPitAssign("limit-"+tn.Slug, ld.ID, store.AttrOwnerAssignment, onGroup.ID, snap, day, 4); err != nil {
				return err
			}
			out[tn.Slug] = permIDs{assigns: []string{onGroup.ID, onMember.ID, lim.ID}, ident: base[tn.Slug].ident, list: base[tn.Slug].list}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestIsolation_GroupPermissionTables(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedGroupPerms(t, f)
	a, bb := ids[f.A.Slug], ids[f.B.Slug]
	b := bb.assigns
	inB(t, f, func(c *store.TenantTx) error {
		as, err := c.GrpPermAssigns()
		if err != nil || len(as) != 2 {
			t.Fatalf("GrpPermAssigns = %v, %v; want B's two", as, err)
		}
		for _, a := range as {
			if a.ID != b[0] && a.ID != b[1] {
				t.Errorf("GrpPermAssigns holds %s, not B's", a.ID)
			}
		}
		if ls, err := c.GrpLimitAssigns(); err != nil || len(ls) != 1 || ls[0].ID != b[2] {
			t.Errorf("GrpLimitAssigns = %v, %v; want B's one", ls, err)
		}
		if vs, err := c.GrpLimitValues(); err != nil || len(vs) != 1 || vs[0].AssignID != b[2] {
			t.Errorf("GrpLimitValues = %v, %v; want B's one", vs, err)
		}
		if ms, err := c.GrpDirectsOfIdentity(bb.ident, bb.list); err != nil || len(ms) == 0 {
			t.Errorf("GrpDirectsOfIdentity(B's) = %v, %v; want B's rows", ms, err)
		} else {
			for _, m := range ms {
				if m.TenantID != f.B.ID {
					t.Errorf("GrpDirectsOfIdentity holds another tenant's row %+v", m)
				}
			}
		}
		if ms, err := c.GrpDirectsOfIdentity(a.ident, a.list); err != nil || len(ms) != 0 {
			t.Errorf("GrpDirectsOfIdentity(A's identity) = %v, %v; want none", ms, err)
		}
		return nil
	})
	for _, tn := range []storetest.Tenant{f.A, f.B} {
		other := f.B
		if tn.ID == f.B.ID {
			other = f.A
		}
		err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
			all, err := c.GrpPitAssigns()
			if err != nil || len(all) != 3 {
				t.Fatalf("%s: GrpPitAssigns = %v, %v; want its three", tn.Slug, all, err)
			}
			for _, p := range all {
				if p.AssignID == "closed-"+other.Slug || p.AssignID == "limit-"+other.Slug {
					t.Errorf("%s sees the other tenant's interval %s", tn.Slug, p.AssignID)
				}
				if p.AssignID == "shared-assign" && string(p.Snapshot) != `{"tenant":"`+tn.Slug+`"}` {
					t.Errorf("%s: shared id carries %s", tn.Slug, p.Snapshot)
				}
			}
			at, err := c.GrpPitPermAssignsAt(storetest.Now.Add(30 * time.Second))
			if err != nil || len(at) != 3 { // the closed one still held 30s in; the limit-definition one counts
				t.Errorf("%s: GrpPitPermAssignsAt = %d, %v; want 3", tn.Slug, len(at), err)
			}
			if at, err = c.GrpPitPermAssignsAt(storetest.Now.Add(2 * time.Minute)); err != nil || len(at) != 2 {
				t.Errorf("%s: GrpPitPermAssignsAt after the close = %d, %v; want 2", tn.Slug, len(at), err)
			}
			n, err := c.GrpPitStartedBefore("", 4)
			if err != nil || n.Assigns != 3 {
				t.Errorf("%s: GrpPitStartedBefore = %+v, %v", tn.Slug, n, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// prune and delete in A leave B's history alone
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		got, err := c.PruneGrpPit(storetest.Now.Add(time.Hour), 10)
		if err != nil || got.Assigns != 1 {
			t.Errorf("PruneGrpPit = %+v, %v; want the one closed interval", got, err)
		}
		return c.DeleteGrpPit("")
	})
	if err != nil {
		t.Fatal(err)
	}
	inB(t, f, func(c *store.TenantTx) error {
		if all, err := c.GrpPitAssigns(); err != nil || len(all) != 3 {
			t.Errorf("after A's prune and delete, B has %d intervals, %v; want 3", len(all), err)
		}
		return nil
	})
}

// groupPermsCovered lists the repository methods of GR-19 that
// TestIsolation_GroupPermissionTables exercises (GrpDirectsOfIdentity is covered by
// the permission tests of internal/groups/perms, which read it through SubjectOf).
func groupPermsCovered() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{
		"GrpPermAssigns", "GrpLimitAssigns", "GrpLimitValues", "GrpDirectsOfIdentity",
		"OpenPitAssign", "ClosePitAssign", "GrpPitAssigns", "GrpPitPermAssignsAt",
	} {
		m[name] = true
	}
	return m
}
