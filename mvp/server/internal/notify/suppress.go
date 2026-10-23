package notify

import (
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The suppression list (Admin > Email delivery, schema/0764_email_suppressions.sql): addresses Tessera no longer emails.
// A hard bounce adds one automatically; an administrator can add or lift one. A suppressed address still gets the in-app
// notification, and the delivery log says why its email was not sent.

// MaxSuppressionNote is the longest note on a suppression.
const MaxSuppressionNote = 300

// NormalizeAddress validates one plain address and returns it lower-cased.
func NormalizeAddress(a string) (string, error) {
	a = strings.TrimSpace(a)
	p, err := mail.ParseAddress(a)
	if err != nil || p.Address != a || len(a) > 320 || strings.ContainsAny(a, "\r\n") {
		return "", cfgerr.Refuse(422, "invalid_address", "give one email address, without a display name")
	}
	return strings.ToLower(a), nil
}

// Suppress adds an address (a second request for a suppressed address changes nothing) and audits a new one.
func Suppress(tx *store.TenantTx, address, reason, note, messageID, by string, now time.Time) (bool, error) {
	addr, err := NormalizeAddress(address)
	if err != nil {
		return false, err
	}
	if len(note) > MaxSuppressionNote {
		return false, cfgerr.Refuse(422, "note_too_long", "a note is at most %d characters", MaxSuppressionNote)
	}
	added, err := tx.PutEmailSuppression(&store.EmailSuppressionRow{Address: addr, Reason: reason, Note: strings.TrimSpace(note),
		MessageID: messageID, CreatedBy: by}, now)
	if err != nil || !added {
		return added, err
	}
	return true, tx.Audit(now, by, "email.suppression.add", ojson.Object{{Key: "address", Value: addr}, {Key: "reason", Value: reason},
		{Key: "message_id", Value: messageID}})
}

// Lift removes a suppression and audits it.
func Lift(tx *store.TenantTx, address, by string, now time.Time) error {
	addr, err := NormalizeAddress(address)
	if err != nil {
		return err
	}
	if err := tx.DeleteEmailSuppression(addr); errors.Is(err, store.ErrNotFound) {
		return &Error{404, "suppression_not_found", "that address is not suppressed"}
	} else if err != nil {
		return err
	}
	return tx.Audit(now, by, "email.suppression.lift", ojson.Object{{Key: "address", Value: addr}})
}

// Suppressed reports whether email to address is suppressed.
func Suppressed(tx *store.TenantTx, address string) (bool, error) {
	_, err := tx.EmailSuppression(strings.ToLower(strings.TrimSpace(address)))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
