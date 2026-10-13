package seed

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/match"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// seedMatching gives the review queue (Identity matches) something to show: a
// sponsor invites a guest at the personal address of a colleague who is
// already an employee (the case of design §5.5.1: an invitation to
// alice@gmail.com that matches Alice). The invitation goes through the real
// sponsorship service, so the match is the one the matcher makes: Tier C,
// "verified email", flagged "suspected existing person", nothing linked.
//
// It needs the identifier key and a sponsor the policy accepts; with neither it
// does nothing. It writes no audit event of its own beyond the service's.
func seedMatching(c *store.TenantTx, k *identifiers.Keyer, skip map[int64]bool, now time.Time) error {
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
			continue // a contractor or vendor: not who a sponsor or the demo should be about
		}
		candidates = append(candidates, p)
	}
	if len(candidates) < 2 {
		return nil
	}
	sponsor, colleague := candidates[0], candidates[len(candidates)-1]
	// the colleague's verified personal address, which the sponsor happens to know
	first, last, _ := strings.Cut(strings.ToLower(colleague.Name), " ")
	if last == "" {
		last = first
	}
	personal := first + "." + last + "@mail.example"
	norm, mac, err := k.Digest(c.Tenant(), store.IdentEmail, "", personal)
	if err != nil {
		return nil
	}
	by, at := store.VerifiedByCode, now
	if err := c.InsertIdentifier(&store.Identifier{ID: uuid.NewString(), IdentityID: colleague.ID, Type: store.IdentEmail, ValueNorm: norm,
		ValueHMAC: mac, VerifiedAt: &at, VerifiedBy: &by, Status: store.RecordActive, CreatedAt: now}); err != nil {
		return err
	}
	svc := sponsorship.New(k)
	svc.Matcher = match.New(k)
	sid := sponsor.ID
	_, err = svc.Invite(c, sponsorship.Actor{Display: "seed", IdentityID: &sid}, sponsorship.Invite{
		GivenName: strings.ToUpper(first[:1]) + first[1:], FamilyName: strings.ToUpper(last[:1]) + last[1:], Email: strings.ToUpper(personal),
		Population: "visitor", Purpose: "Conference talk (demo of an identity match)", EndsAt: now.AddDate(0, 0, 14)},
		store.ChannelSponsorInvite, "", now)
	var se *sponsorship.Error
	if errors.As(err, &se) {
		return nil // the demo sponsor is not eligible under this policy: no demo match, no failure
	}
	return err
}
