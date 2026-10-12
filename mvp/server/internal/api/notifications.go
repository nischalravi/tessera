package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Notifications (issue #189): the signed-in user's own inbox and preferences.
//
//	GET  /api/notifications             ?unread=1&limit=50: {unread, items}, newest first
//	POST /api/notifications/read        {ids: [...]} or {all: true}: mark read
//	GET  /api/notifications/preferences {email_available, kinds: [{kind, label, description, mandatory, channel, default}]}
//	PUT  /api/notifications/preferences {prefs: {kind: channel}} with channel off, in_app, email, both or digest
//
// Everyone signed in holds auth.self, and every call acts on the caller's own
// notifications only: another user's id is ignored, never an error that says
// it exists. Outbox rows are written by the domain events (requests, JIT,
// reviews) and the dispatcher, never through this API.

func (s *Server) registerNotificationRoutes() {
	self := need(auth.PermAuthenticated)
	s.handle(http.MethodGet, "/api/notifications", read, self, s.listNotifications)
	s.handle(http.MethodPost, "/api/notifications/read", write, self, s.readNotifications)
	s.handle(http.MethodGet, "/api/notifications/preferences", read, self, s.notificationPrefs)
	s.handle(http.MethodPut, "/api/notifications/preferences", write, self, s.putNotificationPrefs)
}

func notifyErr(err error) error {
	if ne, ok := err.(*notify.Error); ok {
		return &readiness.Error{Status: ne.Status, Code: ne.Code, Msg: ne.Msg}
	}
	return err
}

// notifyUser is the signed-in user's id and display name.
func notifyUser(r *http.Request) (id, display string, err error) {
	pr := principal(r)
	if pr == nil || pr.UserID == nil {
		return "", "", &readiness.Error{Status: http.StatusForbidden, Code: "user_required",
			Msg: "notifications belong to a signed-in user"}
	}
	return pr.UserID.String(), pr.Display, nil
}

type notificationView struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	Subject   string     `json:"subject"`
	Body      string     `json:"body"`
	Link      string     `json:"link"`
	CreatedAt time.Time  `json:"created_at"`
	ReadAt    *time.Time `json:"read_at"`
}

func (s *Server) listNotifications(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	user, _, err := notifyUser(r)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > notify.MaxInbox {
			return nil, badRequest("invalid_limit", "limit is 1 to "+strconv.Itoa(notify.MaxInbox))
		}
		limit = n
	}
	items, unread, err := notify.Inbox(store.TxFrom(r.Context()), user, q.Get("unread") == "1", limit)
	if err != nil {
		return nil, err
	}
	out := make([]notificationView, 0, len(items))
	for _, n := range items {
		out = append(out, notificationView{ID: n.ID, Kind: n.Kind, Subject: n.Subject, Body: n.Body, Link: n.Link,
			CreatedAt: n.CreatedAt, ReadAt: n.ReadAt})
	}
	return map[string]any{"unread": unread, "items": out}, nil
}

type markReadBody struct {
	IDs []string `json:"ids"`
	All bool     `json:"all"`
}

func (s *Server) readNotifications(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	user, display, err := notifyUser(r)
	if err != nil {
		return nil, err
	}
	var b markReadBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	n, err := notify.MarkRead(tx, s.clock().UTC(), user, display, b.IDs, b.All)
	if err != nil {
		return nil, notifyErr(err)
	}
	unread, err := tx.CountUnreadNotifications(user)
	if err != nil {
		return nil, err
	}
	return map[string]any{"marked": n, "unread": unread}, nil
}

type prefView struct {
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Mandatory   bool   `json:"mandatory"`
	Channel     string `json:"channel"`
	Default     string `json:"default"`
}

func (s *Server) prefsView(r *http.Request, user string) (any, error) {
	prefs, err := notify.Preferences(store.TxFrom(r.Context()), user)
	if err != nil {
		return nil, err
	}
	kinds := make([]prefView, 0, len(prefs))
	for _, p := range prefs {
		kinds = append(kinds, prefView{Kind: p.Kind.ID, Label: p.Kind.Label, Description: p.Kind.Description,
			Mandatory: p.Kind.Mandatory, Channel: p.Channel, Default: p.Kind.Default})
	}
	return map[string]any{"email_available": s.cfg.EmailMode != "" && s.cfg.EmailMode != config.MailOff,
		"email_dev_sink": s.cfg.EmailMode == config.MailDev, "channels": notify.Channels, "kinds": kinds}, nil
}

func (s *Server) notificationPrefs(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	user, _, err := notifyUser(r)
	if err != nil {
		return nil, err
	}
	return s.prefsView(r, user)
}

type prefsBody struct {
	Prefs map[string]string `json:"prefs"`
}

func (s *Server) putNotificationPrefs(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	user, display, err := notifyUser(r)
	if err != nil {
		return nil, err
	}
	var b prefsBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if err := notify.SetPreferences(store.TxFrom(r.Context()), s.clock().UTC(), user, display, b.Prefs); err != nil {
		return nil, notifyErr(err)
	}
	return s.prefsView(r, user)
}
