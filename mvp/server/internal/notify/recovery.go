package notify

import (
	"errors"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Producers for account recovery (issue #73). The recovery link goes to the
// guest's address with a one-time secret supplied at send time (Secrets). The
// notice that someone started, finished or cancelled a recovery goes to every
// channel on file: the guest's own address, each active platform user who is
// that person (inbox and email), and the sponsor.

// RecoveryStage says which step of a recovery a notice reports.
type RecoveryStage string

// Stages of a recovery notice.
const (
	RecoveryStageIssued    RecoveryStage = "issued"
	RecoveryStageCooling   RecoveryStage = "cooling_off"
	RecoveryStageCompleted RecoveryStage = "completed"
	RecoveryStageCancelled RecoveryStage = "cancelled"
)

// GuestRecoveryLink queues the email with the recovery link and returns the
// notification's id so the caller can hand the link to Secrets under it.
func GuestRecoveryLink(tx *store.TenantTx, now time.Time, tokenID string, identityID int64, email, name, tenant string, expires time.Time) (string, error) {
	if email == "" || tokenID == "" {
		return "", errors.New("notify: a recovery link needs an address and a token id")
	}
	to := Recipient{IdentityID: identityID, Email: email}
	return emitOne(tx, now, Message{Kind: KindGuestRecoveryLink, Key: "guest.recovery_link:" + tokenID,
		Subject: "Recover your " + tenant + " account",
		Body: lines("Hello "+firstWord(name)+",", "", "A sponsor or the help desk started recovering your "+tenant+" account.",
			"Open the link below to verify who you are and set up your sign-in again. It works once and stops working on "+when(expires)+".",
			"If you did not ask for this, do not open it; tell your sponsor or the help desk.")}, to)
}

// RecoveryChannels returns every channel on file for a person: their own
// address on the identity and each active platform user who is them.
func RecoveryChannels(tx *store.TenantTx, identityID int64) ([]Recipient, error) {
	ident, err := tx.Identity(identityID)
	if err != nil {
		return nil, err
	}
	users, err := tx.UsersLinkedTo(identityID)
	if err != nil {
		return nil, err
	}
	var out []Recipient
	have := map[string]bool{}
	for _, u := range users {
		r, ok, err := User(tx, u)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out = append(out, r)
		if r.Email != "" {
			have[strings.ToLower(r.Email)] = true
		}
	}
	if e := emailOf(ident.Email); e != "" && !have[strings.ToLower(e)] {
		out = append(out, Recipient{IdentityID: identityID, Email: e})
	}
	return out, nil
}

// GuestRecoveryNotice tells every channel on file (and the sponsor) what
// happened to a recovery. The key makes it idempotent per case and stage.
func GuestRecoveryNotice(tx *store.TenantTx, now time.Time, stage RecoveryStage, c *store.RecoveryCase, sponsorID int64, tenant string, until *time.Time) error {
	to, err := RecoveryChannels(tx, c.IdentityID)
	if err != nil {
		return err
	}
	sponsor, err := Identity(tx, sponsorID)
	if err != nil {
		return err
	}
	to = append(to, sponsor...)
	name, err := personName(tx, c.IdentityID)
	if err != nil {
		return err
	}
	var subject string
	var body string
	switch stage {
	case RecoveryStageIssued:
		subject = "Account recovery started for " + name
		body = lines("Recovery of the "+tenant+" account of "+name+" was started by "+recoveryVia(c.Via)+".",
			"The person must prove who they are again before a new sign-in is set up. If this was not expected, tell the help desk now.")
	case RecoveryStageCooling:
		subject = "Account recovery waiting 24 hours for " + name
		body = lines("The new sign-in for "+name+" at "+tenant+" is on hold because the account has privileged access.",
			"It becomes active on "+whenPtr(until)+". The recovery can be cancelled until then; if it was not expected, tell the help desk now.")
	case RecoveryStageCompleted:
		subject = "Account recovery finished for " + name
		body = lines("A new sign-in is now active for "+name+" at "+tenant+". Earlier sessions were ended.",
			"If this was not expected, tell the help desk now.")
	default:
		subject = "Account recovery cancelled for " + name
		body = lines("The recovery of the " + tenant + " account of " + name + " was cancelled. The earlier sign-in still works.")
	}
	_, err = Emit(tx, now, Message{Kind: KindGuestRecovery, Key: "guest.recovery:" + c.ID + ":" + string(stage), Subject: subject,
		Body: body, Link: linkGuests}, to...)
	return err
}

func recoveryVia(via string) string {
	if via == store.RecoveryViaSponsor {
		return "their sponsor"
	}
	return "the help desk"
}

func whenPtr(t *time.Time) string {
	if t == nil {
		return "the end of the waiting period"
	}
	return when(*t)
}
