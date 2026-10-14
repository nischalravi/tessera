package notify

import (
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Producers for guest self-registration (issue #66). The emails to the visitor
// reach an address nobody has verified, so they say as little as possible and
// carry no secret; each is idempotent by key.

// registrantKind reports whether a kind is one of the emails to a visitor.
func registrantKind(kind string) bool {
	return kind == KindRegistrationReceived || kind == KindRegistrationSignIn || kind == KindRegistrationDenied
}

// RegistrationRequested asks the sponsor to decide a visitor's request (in the
// sponsor's Inbox, and by email unless they turned it off).
func RegistrationRequested(tx *store.TenantTx, now time.Time, r *store.Registration) error {
	if r.GivenName == nil || r.FamilyName == nil || r.Purpose == nil {
		return errors.New("notify: a registration request needs its personal fields")
	}
	to, err := Identity(tx, r.SponsorIdentityID)
	if err != nil {
		return err
	}
	_, err = Emit(tx, now, Message{Kind: KindGuestRegistration, Key: "guest.registration:" + r.ID,
		Subject: "Registration request: " + clip(*r.GivenName+" "+*r.FamilyName, 100),
		Body: lines(clip(*r.GivenName+" "+*r.FamilyName, 100)+" asked you to sponsor their registration until "+when(r.EndsAt)+".",
			"Purpose: "+clip(*r.Purpose, 300), "Nothing is created unless you approve it. If you do not know this person, deny it."),
		Link: "/inbox"}, to...)
	return err
}

// RegistrationReceived tells the visitor their request went to the sponsor.
func RegistrationReceived(tx *store.TenantTx, now time.Time, r *store.Registration, tenant string) error {
	if r.Email == nil {
		return errors.New("notify: a registration needs its address")
	}
	_, err := emitOne(tx, now, Message{Kind: KindRegistrationReceived, Key: "guest.register.received:" + r.ID,
		Subject: "Your registration request for " + tenant,
		Body: lines("We received a request to register this address with "+tenant+".",
			"The person it names has been asked to approve it. If they do, you will get an email with a link to set up your sign-in.",
			"If you did not ask for this, ignore this message: nothing has been created.")}, Recipient{Email: *r.Email})
	return err
}

// RegistrationSignIn tells an address that already belongs to an account to
// sign in instead. key makes it once per address and day.
func RegistrationSignIn(tx *store.TenantTx, now time.Time, key, email, tenant, signInURL string) error {
	_, err := emitOne(tx, now, Message{Kind: KindRegistrationSignIn, Key: "guest.register.signin:" + key,
		Subject: "You already have an account with " + tenant,
		Body: lines("Someone asked to register this address with "+tenant+", but it already has an account.",
			"Sign in instead: "+signInURL, "If it was not you, ignore this message.")}, Recipient{Email: email})
	return err
}

// RegistrationDenied is the neutral answer to a request that was not approved:
// it names nobody and gives no reason.
func RegistrationDenied(tx *store.TenantTx, now time.Time, r *store.Registration, tenant string) error {
	if r.Email == nil {
		return errors.New("notify: a registration needs its address")
	}
	_, err := emitOne(tx, now, Message{Kind: KindRegistrationDenied, Key: "guest.register.denied:" + r.ID,
		Subject: "Your registration request for " + tenant,
		Body:    lines("Your request to register with " + tenant + " was not approved.")}, Recipient{Email: *r.Email})
	return err
}
