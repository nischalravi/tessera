package seed

import (
	"errors"
	"time"

	guestlife "github.com/nischalravi/tessera/mvp/server/internal/guests/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/jml"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// seedGuestLifecycle gives Governance → Guest lifecycle something to show: a
// contractor sponsored by an employee whose sponsorship ends in 10 days (it
// counts in the 14- and 30-day lists), and a contractor whose sponsor has left,
// so a transfer task waits for the sponsor's manager or a sponsor admin.
//
// Both go through the real services: the invitations through the sponsorship
// service, the leaver through the leaver plan and the lifecycle hook. It needs
// the identifier key and three employees the sponsor policy accepts; with fewer
// it does nothing.
func seedGuestLifecycle(c *store.TenantTx, k *identifiers.Keyer, skip map[int64]bool, now time.Time) error {
	if k == nil {
		return nil
	}
	people, err := c.Identities()
	if err != nil {
		return err
	}
	var candidates []*store.Identity
	for _, p := range people {
		if p.Type != "human" || p.Status != "active" || p.Email == nil || skip[p.ID] {
			continue
		}
		if _, err := c.LifecycleFor(p.ID); err == nil {
			continue
		}
		candidates = append(candidates, p)
	}
	if len(candidates) < 3 {
		return nil
	}
	svc := sponsorship.New(k)
	gl := guestlife.New(svc)
	invite := func(sponsor *store.Identity, given, email string, days int) error {
		sid := sponsor.ID
		_, err := svc.Invite(c, sponsorship.Actor{Display: "seed", IdentityID: &sid}, sponsorship.Invite{GivenName: given, FamilyName: "Contractor",
			Email: email, Population: "contractor", Purpose: "Demo: " + given + "'s contract", EndsAt: now.AddDate(0, 0, days)},
			store.ChannelSponsorInvite, "", now)
		var se *sponsorship.Error
		if errors.As(err, &se) {
			return nil // the demo sponsor is not eligible under this policy: nothing to show, no failure
		}
		return err
	}
	if err := invite(candidates[0], "Taylor", "taylor.contractor@vendor.example", 10); err != nil {
		return err
	}
	leaver := candidates[1]
	if err := invite(leaver, "Robin", "robin.contractor@vendor.example", 40); err != nil {
		return err
	}
	// the sponsor leaves: the leaver plan runs and the lifecycle hook opens the transfer task
	if _, err := jml.ExecuteLeaver(c, now, leaver.ID); err != nil {
		return err
	}
	_, err = gl.OnEvent(c, "leaver", leaver.ID, now)
	return err
}
