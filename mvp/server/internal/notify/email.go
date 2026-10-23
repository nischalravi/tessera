package notify

import (
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// RetryEmail sends a message again at once: its notification is made due and
// the message is queued; the dispatcher's next pass makes the attempt (one more,
// whatever the attempts so far). A deferred or failed message can always be sent
// again; a bounced one, and one skipped because its address was suppressed, once the
// suppression is lifted. A message the relay rejected, and an accepted one, are final. It is audited.
func RetryEmail(tx *store.TenantTx, now time.Time, id, actor string) (*store.EmailMessage, error) {
	m, err := tx.EmailMessage(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &Error{http.StatusNotFound, "message_not_found", "email message not found"}
	} else if err != nil {
		return nil, err
	}
	switch m.Status {
	case store.EmailDeferred, store.EmailFailed:
	case store.EmailRejected, store.EmailBounced:
		// a relay's refusal is final; what was not sent because the address is suppressed, and a bounce, can go again once
		// the suppression is lifted
		if m.Status == store.EmailRejected {
			if d, err := tx.NotificationDeliveryOf(m.NotificationID); err != nil {
				return nil, err
			} else if d != store.DeliverySkipped {
				return nil, &Error{http.StatusConflict, "not_retryable", "the relay refused this message for good (it is rejected)"}
			}
		}
		if s, err := Suppressed(tx, m.Recipient); err != nil {
			return nil, err
		} else if s {
			return nil, &Error{http.StatusConflict, "suppressed", "the address is suppressed: lift the suppression first, then send again"}
		}
	default:
		return nil, &Error{http.StatusConflict, "not_retryable", "only a deferred, failed or bounced message can be sent again (this one is " + m.Status + ")"}
	}
	if err := tx.RequeueNotification(m.NotificationID, now); err != nil {
		return nil, err
	}
	m.Status, m.UpdatedAt = store.EmailQueued, now
	if err := tx.SaveEmailMessage(m); err != nil {
		return nil, err
	}
	return m, tx.Audit(now, actor, "email.message.retry", ojson.Object{{Key: "message_id", Value: m.ID},
		{Key: "notification_id", Value: m.NotificationID}, {Key: "kind", Value: m.Kind}})
}
