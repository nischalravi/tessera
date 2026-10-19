package ownership_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/ownership"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

func p64(v int64) *int64 { return &v }

func key(id int64) string { return strconv.FormatInt(id, 10) }

func code(err error) string {
	var oe *ownership.Error
	if errors.As(err, &oe) {
		return oe.Code
	}
	if err != nil {
		return "other: " + err.Error()
	}
	return ""
}

func set(st *testkit.DB, r ownership.Ref, s ownership.Spec) error {
	return st.InTenant(context.Background(), st.Tenant, func(c *store.TenantTx) error {
		_, err := ownership.Set(c, r, s, "test", nil, testkit.Now)
		return err
	})
}

func TestSetValidates(t *testing.T) {
	st, ids := testkit.Tiny(t)
	alice, bob, dave := ids["alice"], ids["bob"], ids["dave"]
	eng := ownership.Ref{Kind: store.OwnedGroup, Key: key(ids["group:okta:eng"])}
	cases := []struct {
		name string
		ref  ownership.Ref
		spec ownership.Spec
		want string
	}{
		{"ok", eng, ownership.Spec{PrimaryID: &alice, BackupID: &bob, Purpose: "engineering"}, ""},
		{"clear", eng, ownership.Spec{}, ""},
		{"app ok", ownership.Ref{Kind: store.OwnedApp, Key: "okta"}, ownership.Spec{PrimaryID: &alice}, ""},
		{"unknown app", ownership.Ref{Kind: store.OwnedApp, Key: "nope"}, ownership.Spec{PrimaryID: &alice}, "object_not_found"},
		{"unknown group", ownership.Ref{Kind: store.OwnedGroup, Key: "999999"}, ownership.Spec{}, "object_not_found"},
		{"bad key", ownership.Ref{Kind: store.OwnedGroup, Key: "eng"}, ownership.Spec{}, "object_not_found"},
		{"bad kind", ownership.Ref{Kind: "account", Key: "1"}, ownership.Spec{}, "invalid_kind"},
		{"person", ownership.Ref{Kind: store.OwnedIdentity, Key: key(bob)}, ownership.Spec{PrimaryID: &alice}, "person_not_ownable"},
		{"same", eng, ownership.Spec{PrimaryID: &alice, BackupID: &alice}, "same_owner"},
		{"backup only", eng, ownership.Spec{BackupID: &bob}, "backup_without_primary"},
		{"leaver owner", eng, ownership.Spec{PrimaryID: &dave}, "primary_not_active"},
		{"machine owner", eng, ownership.Spec{PrimaryID: p64(ids["svc-etl"])}, "primary_not_active"},
		{"leaver backup", eng, ownership.Spec{PrimaryID: &alice, BackupID: &dave}, "backup_not_active"},
		{"missing owner", eng, ownership.Spec{PrimaryID: p64(999999)}, "primary_not_found"},
		{"missing group", eng, ownership.Spec{PrimaryID: &alice, GroupID: p64(999999)}, "group_not_found"},
		{"long purpose", eng, ownership.Spec{Purpose: strings.Repeat("x", ownership.MaxPurpose+1)}, "invalid_purpose"},
	}
	for _, tc := range cases {
		if got := code(set(st, tc.ref, tc.spec)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestIdentityOwnerSurvivesSync: an owner set in Tessera is written to
// identities.owner_id and kept when the connector syncs again (the tiny
// connector says dave owns svc-etl).
func TestIdentityOwnerSurvivesSync(t *testing.T) {
	st, ids := testkit.Tiny(t)
	etl := ids["svc-etl"]
	if err := set(st, ownership.Ref{Kind: store.OwnedIdentity, Key: key(etl)}, ownership.Spec{PrimaryID: p64(ids["carol"])}); err != nil {
		t.Fatal(err)
	}
	owner := func() *int64 {
		return testkit.Get(t, st, func(c *store.TenantTx) (*int64, error) {
			i, err := c.Identity(etl)
			if err != nil {
				return nil, err
			}
			return i.OwnerID, nil
		})
	}
	if o := owner(); o == nil || *o != ids["carol"] {
		t.Fatalf("owner after set = %v", o)
	}
	testkit.Write(t, st, func(c *store.TenantTx) error {
		_, err := ingest.Sync(c, testkit.Now, []connectors.Connector{testkit.TinyConnector{Now: testkit.Now}}, nil)
		return err
	})
	if o := owner(); o == nil || *o != ids["carol"] {
		t.Fatalf("owner after sync = %v, want carol", o)
	}
	// Without a row the connector's owner applies (helper-bot: alice).
	if b := testkit.Get(t, st, func(c *store.TenantTx) (*store.Identity, error) { return c.Identity(ids["helper-bot"]) }); b.OwnerID == nil || *b.OwnerID != ids["alice"] {
		t.Fatalf("helper-bot owner = %v", b.OwnerID)
	}
}

func TestSetManyAllOrNothing(t *testing.T) {
	st, ids := testkit.Tiny(t)
	refs := []ownership.Ref{{Kind: store.OwnedGroup, Key: key(ids["group:okta:eng"])}, {Kind: store.OwnedApp, Key: "nope"}}
	err := st.InTenant(context.Background(), st.Tenant, func(c *store.TenantTx) error {
		_, err := ownership.SetMany(c, refs, ownership.Spec{PrimaryID: p64(ids["alice"])}, true, "test", nil, testkit.Now)
		return err
	})
	if code(err) != "object_not_found" {
		t.Fatalf("err = %v", err)
	}
	if rows := testkit.Get(t, st, func(c *store.TenantTx) ([]*store.Ownership, error) { return c.Ownerships("") }); len(rows) != 0 {
		t.Fatalf("rows written: %d", len(rows))
	}
	// The purpose survives a bulk assignment.
	eng := refs[0]
	if err := set(st, eng, ownership.Spec{PrimaryID: p64(ids["alice"]), Purpose: "engineering"}); err != nil {
		t.Fatal(err)
	}
	var n int
	testkit.Write(t, st, func(c *store.TenantTx) error {
		var err error
		n, err = ownership.SetMany(c, []ownership.Ref{eng, eng, {Kind: store.OwnedApp, Key: "okta"}},
			ownership.Spec{PrimaryID: p64(ids["bob"])}, true, "test", nil, testkit.Now)
		return err
	})
	o := testkit.Get(t, st, func(c *store.TenantTx) (*store.Ownership, error) { return c.Ownership(eng.Kind, eng.Key) })
	if n != 2 || o.Purpose != "engineering" || *o.PrimaryID != ids["bob"] {
		t.Fatalf("n=%d row=%+v", n, o)
	}
}

func TestList(t *testing.T) {
	st, ids := testkit.Tiny(t)
	if err := set(st, ownership.Ref{Kind: store.OwnedGroup, Key: key(ids["group:okta:eng"])}, ownership.Spec{PrimaryID: p64(ids["alice"])}); err != nil {
		t.Fatal(err)
	}
	testkit.Read(t, st, func(c *store.TenantTx) error {
		gs, err := ownership.List(c, store.OwnedGroup)
		if err != nil {
			return err
		}
		owned := 0
		for _, e := range gs {
			if e.PrimaryID != nil {
				owned++
			}
		}
		if owned != 1 || len(gs) < 5 {
			t.Errorf("groups %d, owned %d", len(gs), owned)
		}
		nhis, err := ownership.List(c, store.OwnedIdentity)
		if err != nil {
			return err
		}
		for _, e := range nhis {
			if e.Ownership != nil || e.PrimaryID == nil {
				t.Errorf("%s: connector owner expected, got %+v", e.Label, e)
			}
		}
		apps, err := ownership.List(c, store.OwnedApp)
		if err != nil || len(apps) == 0 {
			t.Errorf("apps %v %v", apps, err)
		}
		return nil
	})
}
