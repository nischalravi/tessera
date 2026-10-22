package oauthapps_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/oauthapps"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Two sign-in users linked to one identity are one admin: the second cannot complete the
// first's bulk revoke (issue #416).
func TestGateFourEyes_LinkedUsersAreOneAdmin(t *testing.T) {
	r := newRig(t, oauthapps.Google)
	r.seed()
	r.sync(t)
	drift, _ := r.app(t, oauthapps.Google, "drift.apps.googleusercontent.com")
	ident := r.f.A.IDs["alice"]
	var first, second uuid.UUID
	err := r.f.DB.InTenant(context.Background(), r.f.A.ID, func(tx *store.TenantTx) error {
		for i, id := range []*uuid.UUID{&first, &second} {
			u := &store.PlatformUser{DisplayName: []string{"first", "second"}[i], IdentityID: &ident, CreatedAt: r.now}
			if err := tx.InsertPlatformUser(u); err != nil {
				return err
			}
			*id = u.ID
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	app := planOf(t, r, oauthapps.ScopeApp, drift.ID, "")
	gate := func(by uuid.UUID, name string) string {
		var d string
		err := r.f.DB.InTenant(context.Background(), r.f.A.ID, func(tx *store.TenantTx) error {
			var err error
			d, _, err = oauthapps.Gate(tx, app, by, name, "vendor breached", r.now)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := gate(first, "first"); d != oauthapps.GatePending {
		t.Fatalf("first request: %s", d)
	}
	if d := gate(second, "second"); d != oauthapps.GateSameApprover {
		t.Errorf("the same person's other user: %s", d)
	}
}
