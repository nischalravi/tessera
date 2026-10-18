package admin

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Notifications (design §15.2: every transition queues a notification to all
// tenant admins and the security contacts). The rows are admin_notifications:
// one per recipient, written in the transaction of the transition so a
// rolled-back transition leaves none. A delivery channel (issue #189's
// outbox) reads the rows with delivered_at NULL; until one is configured the
// queue is the record, and the admin banner is the in-product notice.

// Contact is a tenant security contact (Tenant.SecurityContacts).
type Contact struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// ParseContacts reads the tenant's security_contacts JSON. Entries without
// an address are dropped; unreadable JSON yields none.
func ParseContacts(raw string) []Contact {
	var cs []Contact
	if json.Unmarshal([]byte(raw), &cs) != nil {
		return nil
	}
	out := cs[:0]
	for _, c := range cs {
		if strings.TrimSpace(c.Email) != "" {
			out = append(out, c)
		}
	}
	return out
}

// Summarize is a one-line, non-secret description of a request ("Grant
// tenant_admin to Alice"), for notifications and the change-request list.
func Summarize(tx *store.TenantTx, ch *store.AdminChange, now time.Time) string {
	e := (&Service{}).env(tx, now, ch.RequestedBy)
	return e.describe(ch)
}

func (e *env) describe(ch *store.AdminChange) string {
	typ, v, err := decodeStored(ch)
	if err != nil {
		return ch.Type
	}
	return typ.summary(e, v)
}

// name is a user's display name for a message ("unknown user" if the id is
// not this tenant's).
func (e *env) name(id uuid.UUID) string {
	u, err := e.tx.PlatformUser(id)
	if err != nil {
		return "unknown user"
	}
	return u.DisplayName
}

func (e *env) userName(id *uuid.UUID) string {
	if id == nil {
		return "nobody"
	}
	return e.name(*id)
}

// notifyChange queues the notification of a transition.
func (e *env) notifyChange(ch *store.AdminChange, trans string) error {
	what := e.describe(ch)
	var b strings.Builder
	fmt.Fprintf(&b, "Admin change %s: %s\n\n", trans, what)
	fmt.Fprintf(&b, "Type: %s\n", ch.Type)
	fmt.Fprintf(&b, "Requested by: %s at %s\n", e.name(ch.RequestedBy), ch.RequestedAt.UTC().Format(time.RFC3339))
	if ch.TwoPerson {
		fmt.Fprintf(&b, "Approved by: %s\n", e.userName(ch.ApprovedBy))
	} else {
		b.WriteString("Approval: not required for this change\n")
	}
	switch ch.Status {
	case store.ChangePendingApproval:
		fmt.Fprintf(&b, "Awaiting a second admin until %s, then it expires.\n", ch.ExpiresAt.UTC().Format(time.RFC3339))
		b.WriteString(cancelHow)
	case store.ChangeCoolingOff:
		fmt.Fprintf(&b, "Takes effect: %s\n", ch.EffectiveAt.UTC().Format(time.RFC3339))
		b.WriteString(cancelHow)
	case store.ChangeApplied:
		b.WriteString("It has been applied.\n")
	case store.ChangeFailed:
		fmt.Fprintf(&b, "It could not be applied: %s\n", ch.Failure)
	default:
		b.WriteString("No further action is needed.\n")
	}
	fmt.Fprintf(&b, "Request: %s\n", ch.ID)
	return e.queueAll(&ch.ID, nil, "admin.change."+trans, "[Tessera] Admin change "+trans+": "+what, b.String(),
		fmt.Sprintf("change:%s:%s", ch.ID, trans))
}

const cancelHow = "To cancel it, an admin signs in to Tessera, opens Admin > Change requests and chooses Cancel.\n"

// queueAll queues one notification per active tenant admin and per security
// contact, plus one per extra operator id. dedupeBase plus the recipient is
// the idempotence key.
func (e *env) queueAll(change, recovery *uuid.UUID, kind, subject, body, dedupeBase string, operators ...string) error {
	admins, err := e.activeAdmins()
	if err != nil {
		return err
	}
	t, err := e.tenantRecord()
	if err != nil {
		return err
	}
	insert := func(n store.AdminNotification) error {
		n.TenantID, n.ChangeRequestID, n.RecoveryID = e.tx.Tenant(), change, recovery
		n.Kind, n.Subject, n.Body, n.CreatedAt = kind, subject, body, e.now
		_, err := e.tx.InsertAdminNotification(&n)
		return err
	}
	for _, a := range admins {
		id := a.ID
		if err := insert(store.AdminNotification{RecipientType: store.NotifyAdmin, RecipientUserID: &id,
			DedupeKey: dedupeBase + ":admin:" + id.String()}); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, c := range ParseContacts(t.SecurityContacts) {
		addr := strings.ToLower(strings.TrimSpace(c.Email))
		if seen[addr] {
			continue
		}
		seen[addr] = true
		if err := insert(store.AdminNotification{RecipientType: store.NotifyContact, RecipientAddress: addr,
			DedupeKey: dedupeBase + ":contact:" + addr}); err != nil {
			return err
		}
	}
	for _, op := range operators {
		if err := insert(store.AdminNotification{RecipientType: store.NotifyOperator, RecipientAddress: op,
			DedupeKey: dedupeBase + ":operator:" + op}); err != nil {
			return err
		}
	}
	return nil
}
