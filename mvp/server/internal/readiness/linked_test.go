package readiness

import (
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// One person with two sign-in users (linked to the same identity) cannot be both sides of the
// activation's two-person rule (issue #425): not requester and approver, not attester and approver.
func TestTwoPerson_LinkedUsers(t *testing.T) {
	st, s, id := newWriteEnabled(t)
	var req1, req2, att1, att2 *store.PlatformUser
	var revID string
	write(t, st, func(c *store.TenantTx) error {
		person := func(ext string) *int64 {
			i := &store.Identity{ExternalID: ext, Name: ext, Type: "human", Status: "active", CreatedAt: t0}
			if err := c.UpsertIdentity(i); err != nil {
				t.Fatal(err)
			}
			got, err := c.IdentityByExternalID(ext) // UpsertIdentity does not fill in the id
			if err != nil {
				t.Fatal(err)
			}
			return &got.ID
		}
		user := func(name string, identity *int64) *store.PlatformUser {
			u := &store.PlatformUser{DisplayName: name, Status: "active", IdentityID: identity, CreatedAt: t0}
			if err := c.InsertPlatformUser(u); err != nil {
				t.Fatal(err)
			}
			return u
		}
		r, a := person("requester"), person("attester")
		req1, req2, att1, att2 = user("Reqa (okta)", r), user("Reqa (entra)", r), user("Atta (okta)", a), user("Atta (entra)", a)
		b, err := s.Current(c, id, t0)
		if err != nil {
			return err
		}
		revID = b.Rev.ID
		// one attestation by the first attester user (the others in the fixture predate user ids)
		atts, err := c.Attestations(revID)
		if err != nil {
			return err
		}
		for _, at := range atts {
			uid := att1.ID.String()
			at.ActorUserID = &uid
			at.ActorID = att1.DisplayName
			return c.UpsertAttestation(at)
		}
		t.Fatal("no attestation in the fixture")
		return nil
	})
	key := func(u *store.PlatformUser) Person {
		return Person{Key: "user:" + u.ID.String(), Display: u.DisplayName}
	}
	write(t, st, func(c *store.TenantTx) error {
		_, err := s.RequestActivation(c, id, key(req1), t0)
		return err
	})
	for _, tc := range []struct {
		name string
		by   Person
	}{
		{"the requester's other user", key(req2)},
		{"the attester", key(att1)},
		{"the attester's other user", key(att2)},
	} {
		err := try(st, func(c *store.TenantTx) error {
			_, _, err := s.ApproveActivation(c, id, tc.by, "", t0.Add(time.Hour))
			return err
		})
		if codeOf(err) != "two_person_rule" {
			t.Errorf("%s approving: %v, want two_person_rule", tc.name, err)
		}
	}
	if got := state(t, s, st, id); got != store.StateDryRunReconciled {
		t.Fatalf("a refused approval changed the state to %s", got)
	}
}
