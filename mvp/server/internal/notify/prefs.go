package notify

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Error is a refused request; Code is stable for API clients.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

// MaxMarkRead caps the ids of one mark-as-read call.
const MaxMarkRead = 200

// MaxInbox caps the inbox a call returns.
const MaxInbox = 200

// PrefView is a user's channel for a kind: the saved one, or the default.
type PrefView struct {
	Kind      Kind
	Channel   string
	IsDefault bool
}

// Preferences returns the user's channel for every kind.
func Preferences(tx *store.TenantTx, user string) ([]PrefView, error) {
	saved, err := tx.NotificationPrefs(user)
	if err != nil {
		return nil, err
	}
	by := map[string]string{}
	for _, p := range saved {
		by[p.Kind] = p.Channel
	}
	out := make([]PrefView, 0, len(Kinds))
	for _, k := range Kinds {
		v := PrefView{Kind: k, Channel: k.Default, IsDefault: true}
		if c, ok := by[k.ID]; ok {
			v.Channel, v.IsDefault = c, false
		}
		if k.Mandatory && v.Channel == ChannelOff {
			v.Channel = ChannelInApp
		}
		out = append(out, v)
	}
	return out, nil
}

// SetPreferences saves the user's channel for each kind in changes (kind to
// channel), all or none, and audits it. A kind that cannot be turned off
// refuses off.
func SetPreferences(tx *store.TenantTx, now time.Time, user, actor string, changes map[string]string) error {
	if len(changes) == 0 || len(changes) > len(Kinds) {
		return &Error{http.StatusUnprocessableEntity, "invalid_preferences", "name between 1 and every kind"}
	}
	var done []string
	for kind, channel := range changes {
		k, ok := KindByID(kind)
		switch {
		case !ok:
			return &Error{http.StatusUnprocessableEntity, "unknown_kind", fmt.Sprintf("%q is not a notification kind", kind)}
		case !slices.Contains(Channels, channel):
			return &Error{http.StatusUnprocessableEntity, "invalid_channel", "a channel is off, in_app, email, both or digest"}
		case k.Mandatory && channel == ChannelOff:
			return &Error{http.StatusUnprocessableEntity, "kind_mandatory", k.Label + " cannot be turned off"}
		}
		done = append(done, kind+"="+channel)
	}
	sort.Strings(done)
	for _, d := range done {
		kind, channel, _ := strings.Cut(d, "=")
		if err := tx.PutNotificationPref(user, kind, channel, now); err != nil {
			return err
		}
	}
	return tx.Audit(now, actor, "notification.prefs.put", ojson.Object{{Key: "user_id", Value: user}, {Key: "prefs", Value: done}})
}

// Inbox returns the user's inbox, newest first, and their unread count.
func Inbox(tx *store.TenantTx, user string, unreadOnly bool, limit int) ([]*store.Notification, int, error) {
	if limit <= 0 || limit > MaxInbox {
		limit = 50
	}
	items, err := tx.Notifications(user, unreadOnly, limit)
	if err != nil {
		return nil, 0, err
	}
	unread, err := tx.CountUnreadNotifications(user)
	return items, unread, err
}

// MarkRead marks the user's own notifications read: the ids given, or all of
// them. Ids that are not the user's are ignored (they look missing). It
// audits when it changed anything and returns how many it changed.
func MarkRead(tx *store.TenantTx, now time.Time, user, actor string, ids []string, all bool) (int, error) {
	if !all && (len(ids) == 0 || len(ids) > MaxMarkRead) {
		return 0, &Error{http.StatusUnprocessableEntity, "invalid_ids", fmt.Sprintf("name 1 to %d notifications, or all", MaxMarkRead)}
	}
	var n int
	var err error
	if all {
		n, err = tx.MarkAllNotificationsRead(user, now)
	} else {
		n, err = tx.MarkNotificationsRead(user, ids, now)
	}
	if err != nil || n == 0 {
		return n, err
	}
	return n, tx.Audit(now, actor, "notification.read", ojson.Object{{Key: "user_id", Value: user}, {Key: "count", Value: n}, {Key: "all", Value: all}})
}
