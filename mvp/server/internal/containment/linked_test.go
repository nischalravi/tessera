package containment_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// One person with two sign-in users disables an identity as the first user and tries to enable it
// as the second (issue #425): the display names differ, the users are linked to the same identity.
func TestEnableRefusal_LinkedUserOfTheDisabler(t *testing.T) {
	now := storetest.Now
	f := storetest.TwoTenants(t)
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		target, admin := f.A.IDs["alice"], f.A.IDs["bob"]
		// the target is linked to a user, so enabling needs four eyes
		if err := c.InsertPlatformUser(&store.PlatformUser{ID: uuid.New(), DisplayName: "Alice", Status: "active", IdentityID: &target, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		user := func(name string, identity *int64) *store.PlatformUser {
			u := &store.PlatformUser{ID: uuid.New(), DisplayName: name, Status: "active", IdentityID: identity, CreatedAt: now}
			if err := c.InsertPlatformUser(u); err != nil {
				t.Fatal(err)
			}
			return u
		}
		carol := f.A.IDs["carol"]
		first, second, other, unlinked := user("Bob (okta)", &admin), user("Bob (entra)", &admin), user("Carol", &carol), user("Unlinked", nil)
		if _, err := containment.DisableAs(c, target, first.DisplayName, first.ID.String(), "suspected takeover", "none", now); err != nil {
			t.Fatal(err)
		}
		for name, tc := range map[string]struct {
			user *store.PlatformUser
			want string
		}{
			"the disabler":               {first, containment.RefuseFourEyes},
			"the disabler's linked user": {second, containment.RefuseFourEyes},
			"another person":             {other, ""},
			"an unlinked user":           {unlinked, containment.RefuseUnlinked},
		} {
			if got, err := containment.EnableRefusal(c, target, tc.user, tc.user.DisplayName); err != nil || got != tc.want {
				t.Errorf("%s: %q, %v, want %q", name, got, err, tc.want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
