package containment_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestDisableEnable(t *testing.T) {
	now := storetest.Now
	type accts map[int64]string
	statuses := func(t *testing.T, c *store.TenantTx, id int64) accts {
		t.Helper()
		as, err := c.IdentityAccounts(id)
		if err != nil {
			t.Fatal(err)
		}
		out := accts{}
		for _, a := range as {
			out[a.ID] = a.Status
		}
		return out
	}
	tests := []struct {
		name string
		run  func(t *testing.T, c *store.TenantTx, id int64)
	}{
		{"disable sets accounts and status, enable restores both", func(t *testing.T, c *store.TenantTx, id int64) {
			res, err := containment.Disable(c, id, "pa", "suspected takeover", "done", now)
			if err != nil || len(res.Accounts) == 0 {
				t.Fatalf("Disable = %+v, %v", res, err)
			}
			for aid, st := range statuses(t, c, id) {
				if st != "disabled" {
					t.Errorf("account %d is %s after Disable", aid, st)
				}
			}
			if i, _ := c.Identity(id); i.Status != "disabled" {
				t.Errorf("identity status %s", i.Status)
			}
			en, err := containment.Enable(c, id, "pa", "false alarm", now.Add(time.Hour))
			if err != nil || len(en.Restored) != len(res.Accounts) || len(en.Skipped) != 0 {
				t.Fatalf("Enable = %+v, %v", en, err)
			}
			for aid, st := range statuses(t, c, id) {
				if st != "active" {
					t.Errorf("account %d is %s after Enable", aid, st)
				}
			}
			if i, _ := c.Identity(id); i.Status != "active" {
				t.Errorf("identity status %s after Enable", i.Status)
			}
		}},
		{"an account disabled before stays disabled after Enable", func(t *testing.T, c *store.TenantTx, id int64) {
			as, _ := c.IdentityAccounts(id)
			if len(as) < 1 {
				t.Skip("no accounts")
			}
			pre := as[0].ID
			if err := c.DisableAccount(pre); err != nil {
				t.Fatal(err)
			}
			res, err := containment.Disable(c, id, "pa", "suspected takeover", "none", now)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range res.Accounts {
				if a.ID == pre {
					t.Errorf("Disable claims to have disabled the already disabled account %d", pre)
				}
			}
			if _, err := containment.Enable(c, id, "pa", "false alarm", now); err != nil {
				t.Fatal(err)
			}
			if got := statuses(t, c, id)[pre]; got != "disabled" {
				t.Errorf("a previously disabled account is %s after Enable", got)
			}
		}},
		{"an account changed since is skipped, not forced", func(t *testing.T, c *store.TenantTx, id int64) {
			res, err := containment.Disable(c, id, "pa", "suspected takeover", "none", now)
			if err != nil || len(res.Accounts) == 0 {
				t.Fatalf("Disable = %+v, %v", res, err)
			}
			if _, err := c.EnableAccount(res.Accounts[0].ID); err != nil { // someone else re-enabled it
				t.Fatal(err)
			}
			en, err := containment.Enable(c, id, "pa", "false alarm", now)
			if err != nil || len(en.Skipped) != 1 || len(en.Restored) != len(res.Accounts)-1 {
				t.Fatalf("Enable = %+v, %v", en, err)
			}
		}},
		{"only an active identity can be disabled", func(t *testing.T, c *store.TenantTx, id int64) {
			if err := c.SetIdentityStatus(id, "terminated"); err != nil {
				t.Fatal(err)
			}
			if _, err := containment.Disable(c, id, "pa", "suspected takeover", "none", now); !errors.Is(err, containment.ErrNotActive) {
				t.Errorf("Disable of a terminated identity = %v", err)
			}
		}},
		{"a second Disable is refused and Enable needs a Disable", func(t *testing.T, c *store.TenantTx, id int64) {
			if _, err := containment.Enable(c, id, "pa", "x", now); !errors.Is(err, containment.ErrNotDisabled) {
				t.Errorf("Enable of an enabled identity = %v", err)
			}
			if _, err := containment.Disable(c, id, "pa", "suspected takeover", "none", now); err != nil {
				t.Fatal(err)
			}
			if _, err := containment.Disable(c, id, "pa", "suspected takeover", "none", now); !errors.Is(err, containment.ErrNotActive) {
				t.Errorf("second Disable = %v", err)
			}
		}},
		{"enable refuses the linked user and, for a linked identity, the disabler", func(t *testing.T, c *store.TenantTx, id int64) {
			if _, err := containment.Disable(c, id, "pa", "suspected takeover", "none", now); err != nil {
				t.Fatal(err)
			}
			// no linked user: the disabler may undo their own disable
			if got, err := containment.EnableRefusal(c, id, nil, "pa"); err != nil || got != "" {
				t.Errorf("unlinked, disabler = %q, %v", got, err)
			}
			u := &store.PlatformUser{ID: uuid.New(), DisplayName: "Alice", Status: "active", IdentityID: &id, CreatedAt: now}
			if err := c.InsertPlatformUser(u); err != nil {
				t.Fatal(err)
			}
			for name, tc := range map[string]struct {
				user *store.PlatformUser
				by   string
				want string
			}{
				"self":         {u, "alice@a.example", containment.RefuseSelfEnable},
				"disabler":     {nil, "pa", containment.RefuseFourEyes},
				"second admin": {nil, "pa2", ""},
			} {
				if got, err := containment.EnableRefusal(c, id, tc.user, tc.by); err != nil || got != tc.want {
					t.Errorf("%s: %q, %v, want %q", name, got, err, tc.want)
				}
			}
		}},
		{"a connector sync does not undo a disable", func(t *testing.T, c *store.TenantTx, id int64) {
			if _, err := containment.Disable(c, id, "pa", "suspected takeover", "none", now); err != nil {
				t.Fatal(err)
			}
			i, _ := c.Identity(id)
			i.Status = "active" // what the HR feed says
			if err := c.UpsertIdentity(i); err != nil {
				t.Fatal(err)
			}
			if i, _ = c.Identity(id); i.Status != "disabled" {
				t.Errorf("sync set a disabled identity to %s", i.Status)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := storetest.TwoTenants(t)
			err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
				tc.run(t, c, f.A.IDs["alice"])
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
