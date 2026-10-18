package notify

import (
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Producers for guest sponsorships (issue #65). Each runs in the caller's
// transaction and is idempotent. Reminders before a sponsorship ends are the
// lifecycle warnings' (#159), not repeated here.

const linkGuests = "/access/guests"

// SponsorshipApprovalNeeded tells the holders of sponsorships.approve that a
// sponsorship waits for a second approver. skip are the platform users who
// must not be asked: the one who made it.
func SponsorshipApprovalNeeded(tx *store.TenantTx, now time.Time, s *store.Sponsorship, skip ...string) error {
	to, err := Holders(tx, now, auth.PermSponsorshipsApprove)
	if err != nil {
		return err
	}
	guest, err := personName(tx, s.GuestIdentityID)
	if err != nil {
		return err
	}
	sponsor, err := personName(tx, s.SponsorIdentityID)
	if err != nil {
		return err
	}
	_, err = Emit(tx, now, Message{Kind: KindSponsorshipApproval, Key: "sponsorship.approval_needed:" + s.ID,
		Subject: "Approval needed: " + s.Population + " sponsorship for " + guest,
		Body: lines(sponsor+" wants to sponsor "+guest+" as a "+s.Population+" until "+when(s.EndsAt)+".",
			"Purpose: "+clip(s.Purpose, 300), "It needs a second person to approve it."),
		Link: linkGuests + "?tab=approvals", Skip: skip}, to...)
	return err
}

// SponsorshipDecided tells the sponsor that their sponsorship was approved or
// rejected. by is the deciding platform user, who is not told.
func SponsorshipDecided(tx *store.TenantTx, now time.Time, s *store.Sponsorship, approved bool, by, reason string) error {
	to, err := Identity(tx, s.SponsorIdentityID)
	if err != nil {
		return err
	}
	guest, err := personName(tx, s.GuestIdentityID)
	if err != nil {
		return err
	}
	verb, why := "rejected", ""
	if approved {
		verb = "approved"
	}
	if reason != "" {
		why = "Reason: " + clip(reason, 300)
	}
	m := Message{Kind: KindSponsorshipDecided, Key: "sponsorship.decided:" + s.ID + ":" + verb,
		Subject: "Sponsorship " + verb + ": " + guest, Body: lines("Your sponsorship of "+guest+" was "+verb+".", why), Link: linkGuests}
	if by != "" {
		m.Skip = []string{by}
	}
	_, err = Emit(tx, now, m, to...)
	return err
}

// SponsorshipTransferRequested tells the person asked to take over a
// sponsorship that it waits for them, and until when.
func SponsorshipTransferRequested(tx *store.TenantTx, now time.Time, s *store.Sponsorship) error {
	if s.TransferToIdentityID == nil || s.TransferDeadline == nil {
		return nil
	}
	to, err := Identity(tx, *s.TransferToIdentityID)
	if err != nil {
		return err
	}
	guest, err := personName(tx, s.GuestIdentityID)
	if err != nil {
		return err
	}
	from, err := personName(tx, s.SponsorIdentityID)
	if err != nil {
		return err
	}
	_, err = Emit(tx, now, Message{Kind: KindSponsorshipTransfer,
		Key:     "sponsorship.transfer:" + s.ID + ":" + timeutil.ISO(*s.TransferDeadline),
		Subject: "Take over sponsoring " + guest + "?",
		Body: lines(from+" asked you to sponsor "+guest+" ("+s.Population+", until "+when(s.EndsAt)+").",
			"Accept by "+when(*s.TransferDeadline)+"; otherwise the sponsorship ends then."), Link: linkGuests}, to...)
	return err
}
