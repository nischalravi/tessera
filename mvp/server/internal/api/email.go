package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The email delivery log (issue #189): what happened to each email Tessera
// sent, with the SMTP transaction of every attempt (never the body, never a
// credential).
//
//	GET  /api/email/messages                    ?status=&kind=&recipient=&limit=: newest activity first
//	GET  /api/email/messages/{message_id}       the message with its attempts and transcripts
//	POST /api/email/messages/{message_id}/retry send a deferred or failed message again (audited)
//
// Reading needs email.read, retrying email.manage. "accepted" means the relay
// accepted the message (250 at the end of DATA), not that it reached the
// inbox; "bounced" is reserved for bounce processing, a later step.

func (s *Server) registerEmailRoutes() {
	s.handle(http.MethodGet, "/api/email/messages", read, need(auth.PermEmailRead), s.listEmail)
	s.handle(http.MethodGet, "/api/email/messages/{message_id}", read, need(auth.PermEmailRead), s.getEmail)
	s.handle(http.MethodPost, "/api/email/messages/{message_id}/retry", write, need(auth.PermEmailManage), s.retryEmail)
}

type emailView struct {
	ID             string          `json:"id"`
	NotificationID string          `json:"notification_id"`
	Kind           string          `json:"kind"`
	Recipient      string          `json:"recipient"`
	Subject        string          `json:"subject"`
	MailFrom       *string         `json:"mail_from"`
	RcptTo         *string         `json:"rcpt_to"`
	Status         string          `json:"status"`
	QueueID        *string         `json:"queue_id"`
	AttemptCount   int             `json:"attempt_count"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	Retryable      bool            `json:"retryable"`
	Attempts       json.RawMessage `json:"attempts,omitempty"`
}

func newEmailView(m *store.EmailMessage, detail bool) emailView {
	v := emailView{ID: m.ID, NotificationID: m.NotificationID, Kind: m.Kind, Recipient: m.Recipient, Subject: m.Subject,
		MailFrom: m.MailFrom, RcptTo: m.RcptTo, Status: m.Status, QueueID: m.QueueID, AttemptCount: m.AttemptCount,
		CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt, Retryable: m.Status == store.EmailDeferred || m.Status == store.EmailFailed}
	if detail {
		v.Attempts = m.Attempts
	}
	return v
}

var emailStatuses = []string{store.EmailQueued, store.EmailSending, store.EmailAccepted, store.EmailDeferred, store.EmailRejected,
	store.EmailFailed, store.EmailBounced}

func (s *Server) listEmail(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	q := r.URL.Query()
	f := store.EmailFilter{Status: q.Get("status"), Kind: q.Get("kind"), Recipient: q.Get("recipient"), Limit: 200}
	if f.Status != "" && !slices.Contains(emailStatuses, f.Status) {
		return nil, badRequest("invalid_status", "status is one of "+join(emailStatuses))
	}
	if len(f.Kind) > 100 || len(f.Recipient) > 200 {
		return nil, badRequest("invalid_filter", "kind and recipient are short")
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			return nil, badRequest("invalid_limit", "limit is 1 to 500")
		}
		f.Limit = n
	}
	ms, err := store.TxFrom(r.Context()).EmailMessages(f)
	if err != nil {
		return nil, err
	}
	out := make([]emailView, 0, len(ms))
	for _, m := range ms {
		out = append(out, newEmailView(m, false))
	}
	return map[string]any{"statuses": emailStatuses, "email_mode": s.cfg.EmailMode, "messages": out}, nil
}

func join(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

func (s *Server) getEmail(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	m, err := store.TxFrom(r.Context()).EmailMessage(p.path["message_id"])
	if errors.Is(err, store.ErrNotFound) {
		return nil, &readiness.Error{Status: http.StatusNotFound, Code: "message_not_found", Msg: "email message not found"}
	} else if err != nil {
		return nil, err
	}
	return newEmailView(m, true), nil
}

func (s *Server) retryEmail(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	m, err := notify.RetryEmail(store.TxFrom(r.Context()), s.clock().UTC(), p.path["message_id"], principal(r).Display)
	if err != nil {
		return nil, notifyErr(err)
	}
	return newEmailView(m, true), nil
}
