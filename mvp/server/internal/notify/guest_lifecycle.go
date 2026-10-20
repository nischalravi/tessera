package notify

import (
	"fmt"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Producers for the guest lifecycle (issue #74). Each runs in the caller's
// transaction and is idempotent: the key names the event, so a sweep that runs
// twice reports it once.

const linkLifecycle = "/governance/guest-lifecycle"

// SponsorshipEndingSponsor reminds a sponsor that a sponsorship of theirs ends
// in about threshold days. The key holds the end date, so a renewal re-arms it.
func SponsorshipEndingSponsor(tx *store.TenantTx, now time.Time, s *store.Sponsorship, threshold int) error {
	to, err := Identity(tx, s.SponsorIdentityID)
	if err != nil {
		return err
	}
	guest, err := personName(tx, s.GuestIdentityID)
	if err != nil {
		return err
	}
	_, err = Emit(tx, now, Message{Kind: KindSponsorshipEnding,
		Key:     "sponsorship.ending:" + s.ID + ":" + timeutil.ISO(s.EndsAt) + ":" + strconv.Itoa(threshold) + ":sponsor",
		Subject: "Your sponsorship of " + guest + " ends in " + strconv.Itoa(threshold) + " days",
		Body: lines("Your "+s.Population+" sponsorship of "+guest+" ends on "+when(s.EndsAt)+".",
			"Renew it now if they still need access; otherwise their access ends then."), Link: linkGuests}, to...)
	return err
}

// GuestRenewalReminder is the reminder to the guest, with the one-time
// "request renewal" link: it returns the notification's id (empty when it was
// reported before) so the caller can hand the link to Secrets under it. The
// guest is reached by email only, like the claim emails.
func GuestRenewalReminder(tx *store.TenantTx, now time.Time, s *store.Sponsorship, name, email, tenant string, threshold int) (string, error) {
	if email == "" {
		return "", nil
	}
	to := Recipient{IdentityID: s.GuestIdentityID, Email: email}
	return emitOne(tx, now, Message{Kind: KindGuestRenewalLink,
		Key:     "sponsorship.ending:" + s.ID + ":" + timeutil.ISO(s.EndsAt) + ":" + strconv.Itoa(threshold) + ":guest",
		Subject: "Your access to " + tenant + " ends on " + s.EndsAt.UTC().Format("2006-01-02"),
		Body: lines("Hello "+firstWord(name)+",", "", "Your access to "+tenant+" as a "+s.Population+" ends on "+when(s.EndsAt)+".",
			"If you still need it, ask your sponsor to renew it with the link below. It works once; nothing changes unless your sponsor agrees.")}, to)
}

func firstWord(s string) string {
	for i, r := range s {
		if r == ' ' {
			return s[:i]
		}
	}
	return s
}

// GuestTaskOpened tells the people who can act (to) that a lifecycle task is
// waiting: a sponsor's departure, a guest's renewal request or a hire.
func GuestTaskOpened(tx *store.TenantTx, now time.Time, taskID, subject string, body string, deadline *time.Time, to ...Recipient) error {
	b := body
	if deadline != nil {
		b = lines(body, "Decide by "+when(*deadline)+".")
	}
	_, err := Emit(tx, now, Message{Kind: KindGuestTask, Key: "guest.task:" + taskID, Subject: subject, Body: b, Link: linkLifecycle}, to...)
	return err
}

// GuestTaskRecipients are the people a sponsorship task asks: the manager of
// the person it concerns (when there is one) and the holders of
// sponsorships.approve, who are the sponsor admins.
func GuestTaskRecipients(tx *store.TenantTx, now time.Time, managerID *int64) ([]Recipient, error) {
	var to []Recipient
	if managerID != nil {
		m, err := Identity(tx, *managerID)
		if err != nil {
			return nil, err
		}
		to = append(to, m...)
	}
	admins, err := Holders(tx, now, auth.PermSponsorshipsApprove)
	if err != nil {
		return nil, err
	}
	return append(to, admins...), nil
}

// GuestStepUp tells the guest and the sponsor that a renewal is held until the
// guest's identity assurance reaches ial.
func GuestStepUp(tx *store.TenantTx, now time.Time, s *store.Sponsorship, ial int) error {
	guest, err := personName(tx, s.GuestIdentityID)
	if err != nil {
		return err
	}
	to, err := Identity(tx, s.SponsorIdentityID)
	if err != nil {
		return err
	}
	g, err := Identity(tx, s.GuestIdentityID)
	if err != nil {
		return err
	}
	_, err = Emit(tx, now, Message{Kind: KindGuestStepUp, Key: "sponsorship.stepup:" + s.ID + ":" + timeutil.ISO(s.UpdatedAt),
		Subject: "Renewal waits for identity verification: " + guest,
		Body: lines(fmt.Sprintf("The renewal of %s's %s sponsorship needs identity assurance level %d.", guest, s.Population, ial),
			"Access is not extended until they have verified their identity at that level."), Link: linkGuests}, append(to, g...)...)
	return err
}
