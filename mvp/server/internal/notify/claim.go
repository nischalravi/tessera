package notify

import (
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Producers for the guest claim (issue #69). The two emails to the guest carry
// a one-time secret that is not in the notification row: the producer returns
// the notification's id and the caller hands the secret to Secrets under it.

// GuestInvite is what the invitation email says. It holds no secret.
type GuestInvite struct {
	TokenID    string // the claim token's id: the event the email reports
	IdentityID int64
	Email      string
	Name       string
	Tenant     string // display name
	Sponsor    string // the sponsor's display name
	Population string
	EndsAt     time.Time // end of the guest's term
	Expires    time.Time // when the link stops working
}

// emitOne writes one notification for an address that is reached by email only
// and returns its id ("" when the event was already reported).
func emitOne(tx *store.TenantTx, now time.Time, m Message, to Recipient) (string, error) {
	rows, err := Plan(tx, now, m, to)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}
	if _, err := Write(tx, rows); err != nil {
		return "", err
	}
	return rows[0].ID, nil
}

// GuestInvitation queues the invitation email to the guest.
func GuestInvitation(tx *store.TenantTx, now time.Time, in GuestInvite) (string, error) {
	if in.Email == "" || in.TokenID == "" {
		return "", errors.New("notify: a guest invitation needs an address and a token id")
	}
	to := Recipient{IdentityID: in.IdentityID, Email: in.Email}
	return emitOne(tx, now, Message{Kind: KindGuestInvitation, Key: "guest.invitation:" + in.TokenID,
		Subject: "You are invited to " + in.Tenant,
		Body: lines("Hello "+in.Name+",", "", in.Sponsor+" has invited you to "+in.Tenant+" as a "+in.Population+", until "+when(in.EndsAt)+".",
			"Open the link below to confirm your email address and set up your sign-in. It works once and stops working on "+when(in.Expires)+".")}, to)
}

// ClaimCode queues the 6-digit confirmation code email. key makes the send
// idempotent (the code row's id).
func ClaimCode(tx *store.TenantTx, now time.Time, key string, identityID int64, email, tenant string, ttl time.Duration) (string, error) {
	to := Recipient{IdentityID: identityID, Email: email}
	return emitOne(tx, now, Message{Kind: KindClaimCode, Key: "claim.code:" + key, Subject: "Your confirmation code for " + tenant,
		Body: lines("Use this code to confirm your email address on the "+tenant+" sign-up page.",
			"It works for "+ttl.Round(time.Minute).String()+" and five tries.")}, to)
}

// GuestClaimed tells the sponsor their guest finished setting up their sign-in.
func GuestClaimed(tx *store.TenantTx, now time.Time, s *store.Sponsorship) error {
	to, err := Identity(tx, s.SponsorIdentityID)
	if err != nil {
		return err
	}
	guest, err := personName(tx, s.GuestIdentityID)
	if err != nil {
		return err
	}
	_, err = Emit(tx, now, Message{Kind: KindGuestClaimed, Key: "guest.claimed:" + s.ID,
		Subject: guest + " set up their sign-in",
		Body:    lines(guest + " accepted your invitation and set up their sign-in (" + s.Population + ", until " + when(s.EndsAt) + ")."), Link: linkGuests}, to...)
	return err
}
