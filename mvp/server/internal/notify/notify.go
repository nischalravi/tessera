// Package notify is Tessera's notification outbox (issue #189): who is told
// about requests, approvals, reviews and expiries.
//
// A notification is a row in the tenant's outbox. Producers (Emit and the
// functions in producers.go) write it in the same transaction as the domain
// event that causes it, so a rolled-back event leaves none behind. Each row
// is also the user's in-app inbox entry (the top-bar bell) and, when the
// user's preference says so, an email the Dispatcher sends later through a
// pluggable Sender, with retries, backoff and dead letters.
//
// Idempotency: every message has a Key naming the event it reports; the row's
// dedupe key is the Key plus the recipient, unique per tenant, so a repeated
// event or scan never notifies twice.
//
// Preferences: each user chooses off, in_app, email, both or digest per kind
// (Kinds lists them with their defaults). A Mandatory kind, such as a
// security alert, ignores off.
package notify

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Notification kinds.
const (
	KindApprovalNeeded    = "request.approval_needed"
	KindRequestApproved   = "request.approved"
	KindRequestDenied     = "request.denied"
	KindRequestExpiring   = "request.expiring"
	KindApprovalEscalated = "approval.escalated"
	KindApprovalDelegated = "approval.delegated"
	KindReviewLaunched    = "review.launched"
	KindReviewReminder    = "review.reminder"
	KindReviewClosed      = "review.closed"
	KindJITGranted        = "jit.granted"
	KindJITDenied         = "jit.denied"
	KindJITExpiring       = "jit.expiring"
	KindAccessEnding      = "access.ending" // an identity's or grant's end date is near (#159)
	KindSecurityAlert     = "security.alert"
	// guest sponsorships (#65)
	KindSponsorshipApproval = "sponsorship.approval_needed"
	KindSponsorshipDecided  = "sponsorship.decided"
	KindSponsorshipTransfer = "sponsorship.transfer"
	// KindDigest is the daily digest email itself. Users do not choose it.
	KindDigest = "digest"
)

// Channels a user may choose for a kind.
const (
	ChannelOff    = "off"
	ChannelInApp  = "in_app"
	ChannelEmail  = "email"
	ChannelBoth   = "both"
	ChannelDigest = "digest" // in-app, and the kind goes into the daily digest email
)

// Channels lists the channels in display order.
var Channels = []string{ChannelOff, ChannelInApp, ChannelEmail, ChannelBoth, ChannelDigest}

// Kind describes a notification kind.
type Kind struct {
	ID          string
	Label       string
	Description string
	// Mandatory kinds cannot be turned off: off means in_app.
	Mandatory bool
	// Default is the channel of a user who has not chosen one.
	Default string
}

// Kinds are the kinds a user can set preferences for, in display order.
var Kinds = []Kind{
	{KindApprovalNeeded, "Approval needed", "A request is waiting for your approval.", false, ChannelBoth},
	{KindApprovalEscalated, "Approval escalated", "An approval was not decided in time and moved to deciders.", false, ChannelBoth},
	{KindApprovalDelegated, "Approvals delegated to you", "Someone handed their approvals to you for a time.", false, ChannelInApp},
	{KindRequestApproved, "Request approved", "A request you made, or one for you, was approved.", false, ChannelInApp},
	{KindRequestDenied, "Request denied", "A request you made, or one for you, was denied.", false, ChannelInApp},
	{KindRequestExpiring, "Requested access ending", "Access you requested, or hold, ends soon.", false, ChannelInApp},
	{KindReviewLaunched, "Access review launched", "An access review has items for you.", false, ChannelBoth},
	{KindReviewReminder, "Access review reminder", "Review items are still waiting for you.", false, ChannelBoth},
	{KindReviewClosed, "Access review closed", "A review you took part in is complete.", false, ChannelInApp},
	{KindJITGranted, "Just-in-time access granted", "Time-bound access was granted.", false, ChannelInApp},
	{KindJITDenied, "Just-in-time access denied", "A just-in-time request was denied.", false, ChannelInApp},
	{KindJITExpiring, "Just-in-time access ending", "Time-bound access ends within the hour.", false, ChannelInApp},
	{KindAccessEnding, "End date approaching", "An identity's or grant's end date is near.", false, ChannelInApp},
	{KindSponsorshipApproval, "Sponsorship approval needed", "A guest sponsorship is waiting for a second approver.", false, ChannelBoth},
	{KindSponsorshipDecided, "Sponsorship decided", "A sponsorship you made was approved or rejected.", false, ChannelInApp},
	{KindSponsorshipTransfer, "Sponsorship transfer requested", "Someone asked you to take over sponsoring a guest.", false, ChannelBoth},
	{KindSecurityAlert, "Security alerts", "Security-relevant changes. These cannot be turned off.", true, ChannelBoth},
}

// KindByID returns the kind, or false for an unknown one (including KindDigest).
func KindByID(id string) (Kind, bool) {
	for _, k := range Kinds {
		if k.ID == id {
			return k, true
		}
	}
	return Kind{}, false
}

// Limits on what a producer may write.
const (
	MaxSubject = 200
	MaxBody    = 2000
	MaxKey     = 200
)

// route says where a channel delivers: in the inbox, and by email
// immediately or in the digest.
func route(channel string) (inApp bool, email string) {
	switch channel {
	case ChannelInApp:
		return true, ""
	case ChannelEmail:
		return false, store.DeliveryPending
	case ChannelBoth:
		return true, store.DeliveryPending
	case ChannelDigest:
		return true, store.DeliveryDigest
	}
	return false, ""
}

// Recipient is who a notification is for. A user sees it in their inbox; an
// identity that does not sign in is reached by email only.
type Recipient struct {
	UserID     string // platform user id; "" for none
	IdentityID int64  // 0 for none
	Email      string // "" when there is no address
}

func (r Recipient) key() string {
	switch {
	case r.UserID != "":
		return "u:" + r.UserID
	case r.IdentityID != 0:
		return "i:" + strconv.FormatInt(r.IdentityID, 10)
	}
	return "e:" + strings.ToLower(r.Email)
}

// Message is what a producer says. Key names the event it reports and must be
// the same every time that event is reported (for example
// "request.approved:<line id>"): the notification is written once per
// recipient.
type Message struct {
	Kind    string
	Key     string
	Subject string
	Body    string
	Link    string   // an app path ("/inbox"), or empty
	Skip    []string // platform users who must not get it (the actor, the requester)
}

func (m Message) validate() error {
	switch {
	case !isKind(m.Kind):
		return fmt.Errorf("notify: unknown kind %q", m.Kind)
	case m.Key == "" || len(m.Key) > MaxKey:
		return errors.New("notify: a message needs a key of up to 200 characters")
	case strings.TrimSpace(m.Subject) == "":
		return errors.New("notify: a message needs a subject")
	case m.Link != "" && (!strings.HasPrefix(m.Link, "/") || strings.HasPrefix(m.Link, "//") || strings.ContainsAny(m.Link, "\r\n\\")):
		return fmt.Errorf("notify: link %q is not an app path", m.Link)
	}
	return nil
}

func isKind(id string) bool {
	if id == KindDigest {
		return true
	}
	_, ok := KindByID(id)
	return ok
}

// clip shortens s to at most n runes (with an ellipsis), on a rune boundary,
// and drops control characters other than newline.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= ' ' && r != 0x7f {
			return r
		}
		return -1
	}, s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// Plan decides what Emit would write: for each recipient it applies their
// preferences and the idempotency check, and returns the rows to insert. It
// reads only, so a scan can plan in a read-only transaction and Write in a
// separate one.
func Plan(tx *store.TenantTx, now time.Time, m Message, to ...Recipient) ([]*store.Notification, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	kind, _ := KindByID(m.Kind)
	prefs := map[string]map[string]string{} // user -> kind -> channel
	seen := map[string]bool{}
	var out []*store.Notification
	for _, r := range to {
		if r.UserID == "" && r.IdentityID == 0 && r.Email == "" {
			continue
		}
		if r.UserID != "" && slices.Contains(m.Skip, r.UserID) || seen[r.key()] {
			continue
		}
		seen[r.key()] = true
		channel := kind.Default
		if m.Kind == KindDigest {
			channel = ChannelEmail
		}
		if r.UserID != "" && m.Kind != KindDigest {
			p, ok := prefs[r.UserID]
			if !ok {
				list, err := tx.NotificationPrefs(r.UserID)
				if err != nil {
					return nil, err
				}
				p = map[string]string{}
				for _, x := range list {
					p[x.Kind] = x.Channel
				}
				prefs[r.UserID] = p
			}
			if c, ok := p[m.Kind]; ok {
				channel = c
			}
		}
		if channel == ChannelOff && kind.Mandatory {
			channel = ChannelInApp
		}
		if r.UserID == "" {
			channel = ChannelEmail // an identity that does not sign in has no inbox and no settings: email is the only way
		}
		inApp, email := route(channel)
		if email != "" && r.Email == "" {
			email, inApp = "", r.UserID != "" // no address: keep it in the inbox rather than lose it
		}
		if !inApp && email == "" {
			continue
		}
		key := m.Key + "|" + r.key()
		if has, err := tx.HasNotification(key); err != nil {
			return nil, err
		} else if has {
			continue
		}
		n := &store.Notification{ID: uuid.NewString(), Kind: m.Kind, Subject: clip(strings.TrimSpace(m.Subject), MaxSubject),
			Body: clip(strings.TrimSpace(m.Body), MaxBody), Link: m.Link, DedupeKey: key, InApp: inApp, CreatedAt: now,
			Delivery: store.DeliveryNone}
		if r.UserID != "" {
			n.UserID = &r.UserID
		}
		if r.IdentityID != 0 {
			id := r.IdentityID
			n.IdentityID = &id
		}
		if r.Email != "" {
			e := r.Email
			n.Email = &e
		}
		if email != "" {
			n.Delivery = email
			if email == store.DeliveryPending {
				at := now
				n.NextAttemptAt = &at
			}
		}
		out = append(out, n)
	}
	return out, nil
}

// Write inserts planned rows; a row whose dedupe key already exists is left
// alone. It returns how many it wrote.
func Write(tx *store.TenantTx, rows []*store.Notification) (int, error) {
	n := 0
	for _, r := range rows {
		ok, err := tx.InsertNotification(r)
		if err != nil {
			return n, err
		}
		if ok {
			n++
		}
	}
	return n, nil
}

// Emit writes a notification for each recipient in the caller's transaction:
// call it next to the domain event it reports, and it commits or rolls back
// with it. It returns how many it wrote.
func Emit(tx *store.TenantTx, now time.Time, m Message, to ...Recipient) (int, error) {
	rows, err := Plan(tx, now, m, to...)
	if err != nil {
		return 0, err
	}
	return Write(tx, rows)
}

func uuidOf(s string) (uuid.UUID, error) { return uuid.Parse(s) }
