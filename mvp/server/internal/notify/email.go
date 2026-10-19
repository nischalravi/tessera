package notify

import (
	"errors"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// RetryEmail sends a deferred or failed message again at once: its
// notification is made due and the message is queued; the dispatcher's next
// pass makes the attempt (one more, whatever the attempts so far). Accepted,
// rejected and bounced messages are final. It is audited.
func RetryEmail(tx *store.TenantTx, now time.Time, id, actor string) (*store.EmailMessage, error) {
	m, err := tx.EmailMessage(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &Error{http.StatusNotFound, "message_not_found", "email message not found"}
	} else if err != nil {
		return nil, err
	}
	if m.Status != store.EmailDeferred && m.Status != store.EmailFailed {
		return nil, &Error{http.StatusConflict, "not_retryable", "only a deferred or failed message can be retried (this one is " + m.Status + ")"}
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
