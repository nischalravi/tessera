package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// The groups REST API's statements (issue #48, GR-5): idempotency keys, member
// search, the groups of an identity, the identity pages of the SCIM server and
// savepoints. Another tenant's ids look nonexistent to every one of them, and
// a purge or a rollback in one tenant leaves the other alone.

func TestIsolation_GroupsAPIStatements(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedEngine(t, f)
	a, b := ids[f.A.Slug], ids[f.B.Slug]
	now := storetest.Now
	key := func(h string) *store.Idempotency {
		return &store.Idempotency{Principal: "user:u1", Key: "k1", RequestHash: h, Status: 201, Body: `{"ok":true}`, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	}
	inA(t, f, func(c *store.TenantTx) error {
		if err := c.InsertGrpIdempotency(key("a")); err != nil {
			return err
		}
		return c.OpenPitEffective(string(a.g1), string(a.list), a.ident, now, 1)
	})

	inB(t, f, func(c *store.TenantTx) error {
		// idempotency: A's key is not B's, B may use the same one, and B's purge does not touch A's
		if _, err := c.GrpIdempotency("user:u1", "k1"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GrpIdempotency(A's key) = %v, want ErrNotFound", err)
		}
		if n, err := c.GrpIdempotencyCount(); err != nil || n != 0 {
			t.Errorf("GrpIdempotencyCount in B = %d, %v; want 0", n, err)
		}
		if n, err := c.PurgeGrpIdempotency(now.Add(24 * time.Hour)); err != nil || n != 0 {
			t.Errorf("PurgeGrpIdempotency in B = %d, %v; want 0 (A's key is not B's to purge)", n, err)
		}
		if err := c.InsertGrpIdempotency(key("b")); err != nil {
			t.Errorf("B uses the key A has: %v", err)
		}
		if x, err := c.GrpIdempotency("user:u1", "k1"); err != nil || x.RequestHash != "b" || x.Body != `{"ok":true}` || x.Status != 201 {
			t.Errorf("B's own key = %+v, %v", x, err)
		}
		if err := c.InsertGrpIdempotency(key("b")); err == nil {
			t.Error("a key was stored twice in one tenant")
		}
		// member search names A's group: nothing, not even a count
		s := store.MemberSearch{Group: a.g1, List: a.list, Now: now, Limit: 50}
		if rows, n, err := c.GrpEffectiveSearch(s); err != nil || len(rows) != 0 || n != 0 {
			t.Errorf("GrpEffectiveSearch(A's group) = %v, %d, %v", rows, n, err)
		}
		if rows, n, err := c.GrpDirectSearch(s); err != nil || len(rows) != 0 || n != 0 {
			t.Errorf("GrpDirectSearch(A's group) = %v, %d, %v", rows, n, err)
		}
		if gs, err := c.GrpGroupsOfIdentity(a.ident, a.list, "effective", now, 50, 0); err != nil || len(gs) != 0 {
			t.Errorf("GrpGroupsOfIdentity(A's identity) = %v, %v", gs, err)
		}
		if rows, n, err := c.GrpPitGroupsOfIdentity(a.ident, a.list, now, 50, 0); err != nil || len(rows) != 0 || n != 0 {
			t.Errorf("GrpPitGroupsOfIdentity(A's identity) = %v, %d, %v", rows, n, err)
		}
		// identities: only B's own
		all, err := c.Identities()
		if err != nil {
			return err
		}
		page, err := c.IdentitiesPage(500, 0)
		if err != nil {
			return err
		}
		if n, err := c.IdentityCount(); err != nil || n != len(all) || len(page) != len(all) {
			t.Errorf("IdentityCount = %d (%v), page %d, want %d", n, err, len(page), len(all))
		}
		for _, i := range page {
			if i.TenantID != f.B.ID || i.ID == a.ident {
				t.Errorf("B's identity page holds %+v", i)
			}
		}
		if rows, err := c.IdentitiesPage(2, len(all)-1); err != nil || len(rows) != 1 || rows[0].ID != all[len(all)-1].ID {
			t.Errorf("last identity page = %v, %v", rows, err)
		}

		// B's own rows are found: the engine seed has an effective row (not a direct one that counts: it is enabled later)
		own := store.MemberSearch{Group: b.g1, List: b.list, Now: now, Limit: 50}
		if rows, n, err := c.GrpEffectiveSearch(own); err != nil || len(rows) != 1 || n != 1 || rows[0].Identity != b.ident {
			t.Errorf("GrpEffectiveSearch(B's group) = %v, %d, %v", rows, n, err)
		}
		own.Indirect = true // the identity's direct row does not count yet, so it is indirect
		if _, n, err := c.GrpEffectiveSearch(own); err != nil || n != 1 {
			t.Errorf("indirect search = %d, %v", n, err)
		}
		own.Indirect, own.Q = false, "no such name"
		if _, n, err := c.GrpEffectiveSearch(own); err != nil || n != 0 {
			t.Errorf("search for a name nobody has = %d, %v", n, err)
		}
		own.Q, own.Enabled = "", "false"
		if rows, n, err := c.GrpDirectSearch(own); err != nil || n != 1 || len(rows) != 1 || rows[0].MemberIdentity == nil {
			t.Errorf("direct rows that do not count = %v, %d, %v", rows, n, err)
		}
		own.Enabled = "true"
		if rows, n, err := c.GrpDirectSearch(own); err != nil || n != 1 || rows[0].MemberGroup == nil {
			t.Errorf("direct rows that count = %v, %d, %v", rows, n, err)
		}
		for filter, want := range map[string]int{"effective": 1, "direct": 0, "indirect": 1} {
			if gs, err := c.GrpGroupsOfIdentity(b.ident, b.list, filter, now, 50, 0); err != nil || len(gs) != want {
				t.Errorf("GrpGroupsOfIdentity(%s) = %d, %v; want %d", filter, len(gs), err, want)
			}
		}
		return nil
	})
	// A's key and A's history are still A's
	inA(t, f, func(c *store.TenantTx) error {
		if x, err := c.GrpIdempotency("user:u1", "k1"); err != nil || x.RequestHash != "a" {
			t.Errorf("A's key after B's writes = %+v, %v", x, err)
		}
		if rows, n, err := c.GrpPitGroupsOfIdentity(a.ident, a.list, now, 50, 0); err != nil || len(rows) != 1 || n != 1 || rows[0].Group != string(a.g1) {
			t.Errorf("A's own history = %v, %d, %v", rows, n, err)
		}
		if n, err := c.PurgeGrpIdempotency(now.Add(2 * time.Hour)); err != nil || n != 1 {
			t.Errorf("A's purge = %d, %v; want its one expired key", n, err)
		}
		return nil
	})
	inB(t, f, func(c *store.TenantTx) error {
		if n, _ := c.GrpIdempotencyCount(); n != 1 {
			t.Errorf("B has %d keys after A's purge, want 1", n)
		}
		return nil
	})
}

func TestSavepoint(t *testing.T) {
	f := storetest.TwoTenants(t)
	ids := seedEngine(t, f)
	b := ids[f.B.Slug]
	now := storetest.Now
	count := func(c *store.TenantTx) int {
		n, err := c.GrpIdempotencyCount()
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	add := func(c *store.TenantTx, k string) {
		t.Helper()
		if err := c.InsertGrpIdempotency(&store.Idempotency{Principal: "p", Key: k, RequestHash: "h", Status: 200, Body: "{}", CreatedAt: now,
			ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		add(c, "kept")
		// a rolled back savepoint undoes its writes (and an audit event it appended) and nothing before it
		sp, err := c.Savepoint()
		if err != nil {
			return err
		}
		add(c, "undone")
		if _, err := c.RecordAudit(store.AuditRecord{At: now, Action: "test.in_savepoint", LegacyActor: "t", TargetType: "group", TargetID: string(b.g1)}); err != nil {
			return err
		}
		if err := sp.Rollback(); err != nil {
			return err
		}
		if n := count(c); n != 1 {
			t.Errorf("%d keys after the rollback, want 1", n)
		}
		if log, _ := c.AuditLog(-1); hasAction(log, "test.in_savepoint") {
			t.Error("the audit event of the rolled back savepoint survived")
		}
		if err := sp.Rollback(); !errors.Is(err, store.ErrSavepointDone) {
			t.Errorf("second rollback = %v", err)
		}
		if err := sp.Release(); !errors.Is(err, store.ErrSavepointDone) {
			t.Errorf("release after rollback = %v", err)
		}
		// a released savepoint keeps its writes; they nest
		outer, err := c.Savepoint()
		if err != nil {
			return err
		}
		add(c, "outer")
		inner, err := c.Savepoint()
		if err != nil {
			return err
		}
		add(c, "inner")
		if err := inner.Rollback(); err != nil {
			return err
		}
		if err := outer.Release(); err != nil {
			return err
		}
		if n := count(c); n != 2 {
			t.Errorf("%d keys after nested savepoints, want kept and outer", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// the other tenant never saw any of it
	inA(t, f, func(c *store.TenantTx) error {
		if n := count(c); n != 0 {
			t.Errorf("tenant A has %d keys", n)
		}
		return nil
	})
	// and a read-only transaction has no savepoints
	err = f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if _, err := c.Savepoint(); !errors.Is(err, store.ErrReadOnly) {
			t.Errorf("Savepoint in a read-only transaction = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// the transaction's own error rolls everything back, savepoints or not
	_ = f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if _, err := c.Savepoint(); err != nil {
			t.Fatal(err)
		}
		add(c, "doomed")
		return errors.New("abort")
	})
	inB(t, f, func(c *store.TenantTx) error {
		if n := count(c); n != 2 {
			t.Errorf("%d keys after an aborted transaction, want 2", n)
		}
		return nil
	})
}

func hasAction(log []*store.AuditEvent, action string) bool {
	for _, e := range log {
		if e.Action == action {
			return true
		}
	}
	return false
}

// groupsAPICovered lists the repository methods of GR-5 that the tests above exercise.
func groupsAPICovered() map[string]bool {
	m := map[string]bool{}
	for _, name := range []string{"GrpIdempotency", "InsertGrpIdempotency", "PurgeGrpIdempotency", "GrpIdempotencyCount", "GrpEffectiveSearch",
		"GrpDirectSearch", "GrpGroupsOfIdentity", "GrpPitGroupsOfIdentity", "IdentitiesPage", "IdentityCount", "Savepoint"} {
		m[name] = true
	}
	return m
}
