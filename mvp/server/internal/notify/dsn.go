package notify

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Bounce and delivery-status (DSN) processing (Admin > Email delivery). A relay that cannot deliver a message later sends
// a delivery status notification (RFC 3464: a multipart/report with a message/delivery-status part) to the envelope sender.
// Whatever collects that mailbox posts the raw message to POST /api/email/dsn; Tessera matches each report to the email it
// sent (by the Message-ID it set, which is the notification's id), records it in the delivery log, marks a hard bounce
// "bounced" and suppresses the address so it is not mailed again.

// MaxDSNBytes caps one report.
const MaxDSNBytes = 256 << 10

// OutcomeBounced is the status a hard bounce gives a message.
const OutcomeBounced = store.EmailBounced

// DSNRecipient is one recipient's block of a delivery status report.
type DSNRecipient struct {
	Address    string `json:"recipient"`
	Action     string `json:"action"` // failed | delayed | delivered | relayed | expanded
	Status     string `json:"status"` // the enhanced status code, 5.1.1
	Diagnostic string `json:"diagnostic,omitempty"`
}

// DSN is a parsed report.
type DSN struct {
	// NotificationID is the id in the original message's Message-ID, "" when the report does not carry it.
	NotificationID string
	QueueID        string
	Recipients     []DSNRecipient
}

var statusRE = regexp.MustCompile(`^[245]\.\d{1,3}\.\d{1,3}$`)

// ParseDSN reads a raw report: a whole multipart/report message, or just a message/delivery-status body.
func ParseDSN(raw []byte) (*DSN, error) {
	bad := func(msg string) error { return &Error{http.StatusUnprocessableEntity, "invalid_dsn", msg} }
	if len(raw) > MaxDSNBytes {
		return nil, &Error{http.StatusRequestEntityTooLarge, "dsn_too_large", "a report is at most 256 KiB"}
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, bad("the body is not an email message")
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return nil, bad("the message has no readable Content-Type")
	}
	d := &DSN{}
	switch {
	case strings.HasPrefix(mt, "multipart/"):
		if params["boundary"] == "" {
			return nil, bad("the multipart report has no boundary")
		}
		mr := multipart.NewReader(msg.Body, params["boundary"])
		for i := 0; i < 8; i++ { // a report has three parts
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			pt, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
			body, _ := io.ReadAll(io.LimitReader(p, 128<<10))
			switch pt {
			case "message/delivery-status":
				d.readStatus(body)
			case "message/rfc822", "text/rfc822-headers":
				d.readOriginal(body)
			}
		}
	case mt == "message/delivery-status":
		body, _ := io.ReadAll(io.LimitReader(msg.Body, MaxDSNBytes))
		d.readStatus(body)
	default:
		return nil, bad("send a multipart/report (RFC 3464) message or a message/delivery-status body")
	}
	if len(d.Recipients) == 0 {
		return nil, bad("the report names no recipient")
	}
	return d, nil
}

// fieldValue is a field's value without its type prefix ("rfc822; a@b.example" -> "a@b.example").
func fieldValue(v string) string {
	if i := strings.Index(v, ";"); i >= 0 {
		v = v[i+1:]
	}
	return strings.TrimSpace(v)
}

func (d *DSN) readStatus(body []byte) {
	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(body)))
	for group := 0; group < 64; group++ {
		h, err := r.ReadMIMEHeader()
		if len(h) > 0 {
			if group == 0 { // per-message fields
				if q := strings.TrimSpace(h.Get("X-Postfix-Queue-ID")); q != "" && d.QueueID == "" {
					d.QueueID = clip(q, 64)
				}
			}
			if rcpt := fieldValue(h.Get("Final-Recipient")); rcpt != "" {
				if a, perr := mail.ParseAddress(rcpt); perr == nil {
					action := strings.ToLower(strings.TrimSpace(h.Get("Action")))
					status := strings.TrimSpace(h.Get("Status"))
					if !statusRE.MatchString(status) {
						status = ""
					}
					d.Recipients = append(d.Recipients, DSNRecipient{Address: strings.ToLower(a.Address), Action: clip(action, 20), Status: status,
						Diagnostic: clip(fieldValue(h.Get("Diagnostic-Code")), 200)})
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (d *DSN) readOriginal(body []byte) {
	h, _ := textproto.NewReader(bufio.NewReader(bytes.NewReader(body))).ReadMIMEHeader()
	id := strings.Trim(strings.TrimSpace(h.Get("Message-Id")), "<>")
	if at := strings.Index(id, "@"); at > 0 {
		if u, err := uuid.Parse(id[:at]); err == nil {
			d.NotificationID = u.String()
		}
	}
}

// DSNResult is what one recipient's block did.
type DSNResult struct {
	Recipient  string `json:"recipient"`
	Action     string `json:"action"`
	Status     string `json:"status"`
	Matched    bool   `json:"matched"`
	MessageID  string `json:"message_id,omitempty"`
	Outcome    string `json:"outcome"` // bounced | deferred | delivered | already_recorded | not_matched | recipient_mismatch | ignored
	Suppressed bool   `json:"suppressed"`
}

// ApplyDSN records a report in the delivery log. A failed action with a 5.x.x status is a hard bounce: the message becomes
// bounced and the address is suppressed. A delayed action is recorded and changes no status; a delivered one is recorded
// on the accepted message. A report that names no email of this tenant records nothing (not_matched). One audit event per
// report, in the same transaction.
func ApplyDSN(tx *store.TenantTx, d *DSN, by string, now time.Time) ([]DSNResult, error) {
	var out []DSNResult
	audited := []ojson.Object{}
	for _, rc := range d.Recipients {
		res := DSNResult{Recipient: rc.Address, Action: rc.Action, Status: rc.Status, Outcome: "not_matched"}
		var m *store.EmailMessage
		var err error
		switch {
		case d.NotificationID != "":
			m, err = tx.EmailMessageForNotification(d.NotificationID)
		case d.QueueID != "":
			m, err = tx.EmailMessageByQueueID(d.QueueID)
		default:
			err = store.ErrNotFound
		}
		if errors.Is(err, store.ErrNotFound) {
			out = append(out, res)
			continue
		} else if err != nil {
			return nil, err
		}
		res.Matched, res.MessageID = true, m.ID
		if !strings.EqualFold(m.Recipient, rc.Address) {
			res.Outcome = "recipient_mismatch"
			out = append(out, res)
			continue
		}
		hard := rc.Action == "failed" && strings.HasPrefix(rc.Status, "5.")
		var outcome, note string
		switch {
		case m.Status == OutcomeBounced:
			res.Outcome = "already_recorded"
			out = append(out, res)
			continue
		case hard:
			outcome, res.Outcome = OutcomeBounced, "bounced"
		case rc.Action == "failed" || rc.Action == "delayed":
			outcome, res.Outcome = OutcomeDeferred, "deferred"
		case rc.Action == "delivered" || rc.Action == "relayed" || rc.Action == "expanded":
			outcome, res.Outcome = OutcomeAccepted, "delivered"
		default:
			res.Outcome = "ignored"
			out = append(out, res)
			continue
		}
		note = "delivery status notification: " + rc.Action
		if rc.Status != "" {
			note += " " + rc.Status
		}
		a := &Attempt{Started: now, Finished: now, Outcome: outcome, Banner: "delivery status notification (DSN)", Steps: []Step{},
			RcptTo: rc.Address, Error: ""}
		if outcome != OutcomeAccepted {
			a.Error = clip(note+": "+rc.Diagnostic, MaxFieldLen)
		} else {
			a.Banner = note
		}
		var prev []json.RawMessage
		_ = json.Unmarshal(m.Attempts, &prev)
		raw, err := json.Marshal(a)
		if err != nil {
			return nil, err
		}
		prev = append(prev, raw)
		if len(prev) > 25 {
			prev = prev[len(prev)-25:]
		}
		if m.Attempts, err = json.Marshal(prev); err != nil {
			return nil, err
		}
		if hard {
			m.Status = OutcomeBounced
		}
		m.UpdatedAt = now
		if err := tx.SaveEmailMessage(m); err != nil {
			return nil, err
		}
		if hard {
			if _, err = Suppress(tx, rc.Address, store.SuppressHardBounce, clip("DSN "+rc.Status+" "+rc.Diagnostic, MaxSuppressionNote), m.ID, by, now); err != nil {
				return nil, err
			}
			res.Suppressed = true
		}
		out = append(out, res)
	}
	for _, r := range out {
		audited = append(audited, ojson.Object{{Key: "recipient", Value: r.Recipient}, {Key: "action", Value: r.Action},
			{Key: "status", Value: r.Status}, {Key: "outcome", Value: r.Outcome}, {Key: "message_id", Value: r.MessageID}})
	}
	return out, tx.Audit(now, by, "email.dsn", ojson.Object{{Key: "recipients", Value: audited}})
}
