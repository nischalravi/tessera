package jml_test

import (
	"strconv"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/ownership"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func p64(v int64) *int64 { return &v }

// TestLeaverHandsOverOwnership: alice leaves. The entitlement she owns goes
// to its backup (bob); the agent she owns goes to its backup (carol), in both
// identities.owner_id and the ownership row; where she is only the backup,
// the slot is cleared.
func TestLeaverHandsOverOwnership(t *testing.T) {
	st, ids := testkit.Tiny(t)
	pols := testkit.Policies(t)
	eng := strconv.FormatInt(ids["group:okta:eng"], 10)
	bot := strconv.FormatInt(ids["helper-bot"], 10)
	platform := strconv.FormatInt(ids["group:okta:platform"], 10)
	var evID int64
	testkit.Write(t, st, func(c *store.TenantTx) error {
		for _, x := range []struct {
			ref ownership.Ref
			s   ownership.Spec
		}{
			{ownership.Ref{Kind: store.OwnedGroup, Key: eng}, ownership.Spec{PrimaryID: p64(ids["alice"]), BackupID: p64(ids["bob"]), Purpose: "engineering"}},
			{ownership.Ref{Kind: store.OwnedIdentity, Key: bot}, ownership.Spec{PrimaryID: p64(ids["alice"]), BackupID: p64(ids["carol"])}},
			{ownership.Ref{Kind: store.OwnedGroup, Key: platform}, ownership.Spec{PrimaryID: p64(ids["carol"]), BackupID: p64(ids["alice"])}},
		} {
			if _, err := ownership.Set(c, x.ref, x.s, "test", nil, testkit.Now); err != nil {
				return err
			}
		}
		alice := ids["alice"]
		var err error
		evID, err = c.InsertHrisEvent(&store.HrisEvent{ExternalID: "t-own", Type: "leaver", IdentityID: &alice,
			EffectiveAt: testkit.Now, Status: "pending"})
		return err
	})
	plan, err := leaverPlan(st, ids["alice"], false, pols)
	if err != nil {
		t.Fatal(err)
	}
	ro := stepsWith(plan, "reassign_owner")
	if len(ro) != 1 || get(ro[0], "new_owner_id") != ids["carol"] {
		t.Fatalf("reassign_owner steps = %v, want helper-bot to carol (its backup)", ro)
	}
	if n := len(stepsWith(plan, "reassign_ownership")); n != 3 {
		t.Fatalf("reassign_ownership steps = %d, want 3", n)
	}
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := jml.ExecuteEvent(c, testkit.Now, evID, store.UserRef{Display: "jml-automation"}, pols)
		return err
	})
	testkit.Read(t, st, func(c *store.TenantTx) error {
		want := map[string][2]*int64{
			store.OwnedGroup + eng:      {p64(ids["bob"]), nil},
			store.OwnedIdentity + bot:   {p64(ids["carol"]), nil},
			store.OwnedGroup + platform: {p64(ids["carol"]), nil},
		}
		for _, o := range mustOwnerships(t, c) {
			w := want[o.Kind+o.Key]
			if !eqp(o.PrimaryID, w[0]) || !eqp(o.BackupID, w[1]) {
				t.Errorf("%s %s: primary %v backup %v, want %v %v", o.Kind, o.Key, deref(o.PrimaryID), deref(o.BackupID), deref(w[0]), deref(w[1]))
			}
		}
		b, err := c.Identity(ids["helper-bot"])
		if err != nil {
			return err
		}
		if !eqp(b.OwnerID, p64(ids["carol"])) {
			t.Errorf("helper-bot owner_id = %v, want carol", deref(b.OwnerID))
		}
		return nil
	})
}

// TestLeaverWithoutBackupFallsBackToManager: no backup, so the leaver's
// manager (or nobody) takes over, the same rule as for identities.
func TestLeaverWithoutBackupFallsBackToManager(t *testing.T) {
	st, ids := testkit.Tiny(t)
	eng := strconv.FormatInt(ids["group:okta:eng"], 10)
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := ownership.Set(c, ownership.Ref{Kind: store.OwnedGroup, Key: eng}, ownership.Spec{PrimaryID: p64(ids["bob"])}, "test", nil, testkit.Now)
		return err
	})
	plan, err := leaverPlan(st, ids["bob"], false, nil)
	if err != nil {
		t.Fatal(err)
	}
	bob := testkit.Get(t, st, func(c *store.TenantTx) (*store.Identity, error) { return c.Identity(ids["bob"]) })
	var want any
	if bob.ManagerID != nil {
		want = *bob.ManagerID
	}
	s := stepsWith(plan, "reassign_ownership")
	if len(s) != 1 || get(s[0], "new_primary_id") != want || get(s[0], "new_backup_id") != nil {
		t.Fatalf("steps = %v, want primary %v", s, want)
	}
}

// TestLeaverPlanUnchangedWithoutOwnership: no ownership rows, no new steps
// (the parity fixtures pin these plans).
func TestLeaverPlanUnchangedWithoutOwnership(t *testing.T) {
	st, ids := testkit.Tiny(t)
	plan, err := leaverPlan(st, ids["alice"], false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(stepsWith(plan, "reassign_ownership")); n != 0 {
		t.Fatalf("reassign_ownership steps = %d", n)
	}
}

func mustOwnerships(t *testing.T, c *store.TenantTx) []*store.Ownership {
	t.Helper()
	os, err := c.Ownerships("")
	if err != nil {
		t.Fatal(err)
	}
	return os
}

func eqp(a, b *int64) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }

func deref(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
