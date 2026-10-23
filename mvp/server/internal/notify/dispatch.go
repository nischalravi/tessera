package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Actor is the audit actor of dispatcher events.
const Actor = "notify.dispatcher"

// Dispatcher defaults.
const (
	DefaultMaxAttempts = 6
	DefaultDigestHour  = 8
	DefaultBatch       = 50
	DefaultLease       = 5 * time.Minute
)

// DefaultBackoff is the wait after attempt n fails: 30 seconds doubling each
// time, at most an hour.
func DefaultBackoff(attempt int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < attempt && d < time.Hour; i++ {
		d *= 2
	}
	return min(d, time.Hour)
}

// Dispatcher is the background job that sends the outbox's email, builds the
// daily digest and writes the time-driven notifications (Scan).
//
// For each tenant it claims due notifications in one short transaction
// (counting the attempt and leasing the row, so a crash retries after the
// lease and a second dispatcher does not send it twice), sends them outside
// any transaction, and records each outcome, with an audit event, in a second
// one. A failed send is retried after a backoff; after MaxAttempts, or on a
// permanent failure, the notification is a dead letter.
type Dispatcher struct {
	DB *store.DB
	// Sender delivers email; nil means email is off and due email is recorded as skipped.
	Sender Sender
	Clock  timeutil.Clock
	Log    *slog.Logger

	MaxAttempts int                             // default DefaultMaxAttempts
	DigestHour  int                             // UTC hour the daily digest is built from; default DefaultDigestHour
	BaseURL     string                          // TESSERA_PUBLIC_URL: links in emails; empty: none
	Batch       int                             // per tenant per run; default DefaultBatch
	Lease       time.Duration                   // default DefaultLease
	Backoff     func(attempt int) time.Duration // default DefaultBackoff
	// Secrets supplies the one secret line of the guest claim emails (see
	// Secrets); nil makes such notifications dead letters.
	Secrets *Secrets
}

// Stats counts what a run did.
type Stats struct {
	Scanned int // time-driven notifications written
	Digests int
	Sent    int
	Retried int
	Dead    int
	Skipped int
}

func (s *Stats) add(o Stats) {
	s.Scanned += o.Scanned
	s.Digests += o.Digests
	s.Sent += o.Sent
	s.Retried += o.Retried
	s.Dead += o.Dead
	s.Skipped += o.Skipped
}

func (d *Dispatcher) defaults() {
	if d.Clock == nil {
		d.Clock = timeutil.System
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.MaxAttempts <= 0 {
		d.MaxAttempts = DefaultMaxAttempts
	}
	if d.Batch <= 0 {
		d.Batch = DefaultBatch
	}
	if d.Lease <= 0 {
		d.Lease = DefaultLease
	}
	if d.Backoff == nil {
		d.Backoff = DefaultBackoff
	}
}

// LoopName is the dispatcher's name in obs.DefaultLoops (the notifications outbox).
const LoopName = "notifications_outbox"

// Loop runs RunOnce every interval until ctx ends. A failure is logged and
// does not stop the loop.
func (d *Dispatcher) Loop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	obs.DefaultLoops.Register(LoopName, interval, true)
	for {
		if err := obs.DefaultLoops.Run(LoopName, func() error { _, err := d.RunOnce(ctx); return err }); err != nil && ctx.Err() == nil {
			d.Log.Error("notification dispatch failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce runs Tenant for every active tenant; one tenant's failure does not
// stop the others.
func (d *Dispatcher) RunOnce(ctx context.Context) (Stats, error) {
	d.defaults()
	tenants, err := d.DB.ActiveTenants(ctx)
	if err != nil {
		return Stats{}, err
	}
	var total Stats
	var errs []error
	for _, t := range tenants {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		st, err := d.Tenant(ctx, t.ID)
		total.add(st)
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Slug, err))
		}
	}
	return total, errors.Join(errs...)
}

type claimed struct {
	n       *store.Notification
	attempt int    // the attempt number, counted by the claim
	brand   string // the tenant's product name (Admin > Branding), "" for the default
	logo    *emailLogo
}

type outcome struct {
	claimed
	att      *Attempt // the transcript, nil when nothing was sent (skipped)
	delivery string
	next     *time.Time
	err      string
	sent     *time.Time
}

// Tenant runs one pass for one tenant.
func (d *Dispatcher) Tenant(ctx context.Context, t tenancy.ID) (Stats, error) {
	d.defaults()
	var st Stats
	ctx = audit.AsSystem(ctx, Actor)
	now := d.Clock().UTC()

	// 1. the time-driven notifications (planned in a read, written only if any)
	var rows []*store.Notification
	if err := d.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		rows, err = Scan(tx, now)
		return err
	}); err != nil {
		return st, err
	}
	if len(rows) > 0 {
		if err := d.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
			n, err := Write(tx, rows)
			st.Scanned = n
			return err
		}); err != nil {
			return st, err
		}
	}

	// 2. is there anything to send? (a read: most runs stop here)
	var work bool
	if err := d.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		due, err := tx.DueNotifications(now, 1)
		if err != nil {
			return err
		}
		work = len(due) > 0
		if !work && now.Hour() >= d.DigestHour {
			w, err := tx.DigestWaiting()
			work = len(w) > 0
			return err
		}
		return err
	}); err != nil || !work {
		return st, err
	}

	// 3. digests, then claim what is due
	var claims []claimed
	if err := d.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		if now.Hour() >= d.DigestHour {
			n, err := d.buildDigests(tx, now)
			if err != nil {
				return err
			}
			st.Digests = n
		}
		due, err := tx.DueNotifications(now, d.Batch)
		if err != nil {
			return err
		}
		brand, err := tx.BrandName()
		if err != nil {
			return err
		}
		logo, err := d.emailLogo(tx)
		if err != nil {
			return err
		}
		for _, n := range due {
			if err := tx.ClaimNotification(n.ID, n.Attempts, now.Add(d.Lease)); errors.Is(err, store.ErrNotFound) {
				continue // another dispatcher took it
			} else if err != nil {
				return err
			}
			claims = append(claims, claimed{n, n.Attempts + 1, brand, logo})
			if d.Sender != nil && deref(n.Email) != "" {
				if err := d.markSending(tx, n, now); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return st, err
	}

	// 4. send, outside any transaction
	outs := make([]outcome, 0, len(claims))
	for _, c := range claims {
		outs = append(outs, d.send(ctx, c))
	}

	// 5. record every outcome and audit it, atomically
	if len(outs) == 0 {
		return st, nil
	}
	err := d.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		var s Stats
		for _, o := range outs {
			if err := tx.FinishNotification(o.n.ID, o.attempt, o.delivery, o.next, strOrNil(o.err), o.sent); errors.Is(err, store.ErrNotFound) {
				continue // finished elsewhere meanwhile
			} else if err != nil {
				return err
			}
			status := "retry"
			switch o.delivery {
			case store.DeliverySent:
				status, s.Sent = "sent", s.Sent+1
			case store.DeliverySkipped:
				status, s.Skipped = "skipped", s.Skipped+1
			case store.DeliveryDead:
				status, s.Dead = "dead", s.Dead+1
			default:
				s.Retried++
			}
			detail := ojson.Object{{Key: "notification_id", Value: o.n.ID}, {Key: "kind", Value: o.n.Kind},
				{Key: "channel", Value: "email"}, {Key: "status", Value: status}, {Key: "attempt", Value: o.attempt}}
			if o.n.UserID != nil {
				detail = append(detail, ojson.KV{Key: "user_id", Value: *o.n.UserID})
			}
			if o.att != nil {
				mid, err := d.recordAttempt(tx, o)
				if err != nil {
					return err
				}
				detail = append(detail, ojson.KV{Key: "message_id", Value: mid}, ojson.KV{Key: "outcome", Value: o.att.Outcome})
				if o.att.QueueID != "" {
					detail = append(detail, ojson.KV{Key: "queue_id", Value: o.att.QueueID})
				}
			}
			if o.err != "" {
				detail = append(detail, ojson.KV{Key: "error", Value: o.err})
			}
			if o.delivery != store.DeliveryPending {
				d.Secrets.Drop(o.n.ID) // final: the one-time secret is forgotten
			}
			if err := tx.Audit(d.Clock().UTC(), Actor, "notification.send", detail); err != nil {
				return err
			}
		}
		st.add(s)
		return nil
	})
	return st, err
}

func strOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// send makes one attempt and decides the outcome.
func (d *Dispatcher) send(ctx context.Context, c claimed) outcome {
	o := outcome{claimed: c}
	skip := func(why string) outcome {
		o.delivery, o.err = store.DeliverySkipped, why
		return o
	}
	email := ""
	if c.n.Email != nil {
		email = *c.n.Email
	}
	switch {
	case email == "":
		return skip("the recipient has no email address")
	case d.Sender == nil:
		return skip("email is not configured")
	}
	product := "Tessera"
	if c.brand != "" {
		product = c.brand
	}
	body := c.n.Body
	if c.n.Link != "" && d.BaseURL != "" {
		body += "\n\nOpen in " + product + ": " + strings.TrimRight(d.BaseURL, "/") + c.n.Link
	}
	body += "\n\n--\nYou get this because of your notification settings in " + product + "."
	if SecretKind(c.n.Kind) {
		secret, ok := d.Secrets.Get(c.n.ID, d.Clock().UTC())
		if !ok {
			// the secret lived only in memory (a restart, or it expired): never
			// send a message without it, and say how to get a new one
			msg := "the one-time secret is no longer held (restart or expiry); send a new one"
			now := d.Clock().UTC()
			o.att = &Attempt{Started: now, Finished: now, Steps: []Step{}, RcptTo: email, Outcome: OutcomeRejected, Error: msg}
			o.delivery, o.err = store.DeliveryDead, msg
			return o
		}
		body = c.n.Body + "\n\n" + secret + "\n\n--\nIf you were not expecting this message, ignore it: nothing happens until the link or code is used."
	}
	mail := Email{ID: c.n.ID, To: email, Subject: "[" + product + "] " + c.n.Subject, Body: body}
	if c.logo != nil {
		mail.HTML = c.logo.html(product, body)
	}
	var err error
	if rec, ok := d.Sender.(RecordingSender); ok {
		o.att, err = rec.SendRecorded(ctx, mail)
	} else {
		started := time.Now().UTC()
		err = d.Sender.Send(ctx, mail)
		o.att = &Attempt{Started: started, Finished: time.Now().UTC(), Steps: []Step{}, RcptTo: email, Outcome: OutcomeAccepted}
		switch {
		case err == nil:
		case errors.Is(err, ErrPermanent):
			o.att.Outcome = OutcomeRejected
		default:
			o.att.Outcome = OutcomeFailed
		}
		if err != nil {
			o.att.Error = scrub(err, email)
		}
	}
	now := d.Clock().UTC()
	switch {
	case err == nil:
		o.delivery, o.sent = store.DeliverySent, &now
	case errors.Is(err, ErrPermanent) || c.attempt >= d.MaxAttempts:
		o.delivery, o.err = store.DeliveryDead, scrub(err, email)
	default:
		next := now.Add(d.Backoff(c.attempt))
		o.delivery, o.next, o.err = store.DeliveryPending, &next, scrub(err, email)
	}
	if err != nil {
		d.Log.Warn("notification email failed", "id", c.n.ID, "kind", c.n.Kind, "attempt", c.attempt, "status", o.delivery)
	}
	return o
}

// markSending creates the notification's delivery record if it has none and
// marks it sending.
func (d *Dispatcher) markSending(tx *store.TenantTx, n *store.Notification, now time.Time) error {
	m, err := tx.EmailMessageForNotification(n.ID)
	if errors.Is(err, store.ErrNotFound) {
		if err := tx.EnsureEmailMessage(&store.EmailMessage{ID: uuid.NewString(), NotificationID: n.ID, Kind: n.Kind,
			Recipient: deref(n.Email), Subject: n.Subject, CreatedAt: now}); err != nil {
			return err
		}
		m, err = tx.EmailMessageForNotification(n.ID)
	}
	if err != nil {
		return err
	}
	m.Status, m.UpdatedAt = store.EmailSending, now
	return tx.SaveEmailMessage(m)
}

// recordAttempt appends an attempt to the notification's delivery record and
// sets its status, queue id and envelope; it returns the record's id.
func (d *Dispatcher) recordAttempt(tx *store.TenantTx, o outcome) (string, error) {
	m, err := tx.EmailMessageForNotification(o.n.ID)
	if err != nil {
		return "", err
	}
	var prev []json.RawMessage
	if len(m.Attempts) > 0 {
		if err := json.Unmarshal(m.Attempts, &prev); err != nil {
			prev = nil
		}
	}
	raw, err := json.Marshal(o.att)
	if err != nil {
		return "", err
	}
	prev = append(prev, raw)
	if len(prev) > 25 {
		prev = prev[len(prev)-25:]
	}
	if m.Attempts, err = json.Marshal(prev); err != nil {
		return "", err
	}
	m.AttemptCount++
	m.Status = o.att.Outcome
	if o.att.QueueID != "" {
		q := o.att.QueueID
		m.QueueID = &q
	}
	if o.att.MailFrom != "" {
		f := o.att.MailFrom
		m.MailFrom = &f
	}
	if o.att.RcptTo != "" {
		r := o.att.RcptTo
		m.RcptTo = &r
	}
	m.UpdatedAt = d.Clock().UTC()
	return m.ID, tx.SaveEmailMessage(m)
}

// scrub is an error text safe to store and audit: the recipient's address is
// removed and the length bounded.
func scrub(err error, email string) string {
	s := err.Error()
	if email != "" {
		s = strings.ReplaceAll(s, email, "<recipient>")
	}
	return clip(s, 200)
}

// buildDigests writes one digest email per recipient with notifications
// waiting for it, at most one per recipient per day, and marks those
// notifications digested. It returns how many digests it wrote.
func (d *Dispatcher) buildDigests(tx *store.TenantTx, now time.Time) (int, error) {
	waiting, err := tx.DigestWaiting()
	if err != nil {
		return 0, err
	}
	groups := map[string][]*store.Notification{}
	var order []string
	for _, n := range waiting {
		k := "e:" + strings.ToLower(deref(n.Email))
		if n.UserID != nil {
			k = "u:" + *n.UserID
		}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], n)
	}
	sort.Strings(order)
	day := now.Format("2006-01-02")
	made := 0
	for _, k := range order {
		items := groups[k]
		first := items[0]
		var b strings.Builder
		for _, n := range items {
			b.WriteString("- " + n.Subject + " (" + when(n.CreatedAt) + ")\n")
		}
		if d.BaseURL != "" {
			b.WriteString("\nOpen Tessera: " + strings.TrimRight(d.BaseURL, "/") + "/inbox")
		}
		at := now
		row := &store.Notification{ID: uuid.NewString(), UserID: first.UserID, Email: first.Email, Kind: KindDigest,
			Subject: clip("Daily digest: "+strconv.Itoa(len(items))+" notification(s)", MaxSubject), Body: clip(b.String(), MaxBody),
			DedupeKey: "digest:" + k + ":" + day, InApp: false, CreatedAt: now, Delivery: store.DeliveryPending, NextAttemptAt: &at}
		ok, err := tx.InsertNotification(row)
		if err != nil {
			return made, err
		}
		if !ok {
			continue // today's digest for them is already built; these wait for tomorrow's
		}
		for _, n := range items {
			if err := tx.MarkDigested(n.ID); err != nil {
				return made, err
			}
		}
		made++
		detail := ojson.Object{{Key: "notification_id", Value: row.ID}, {Key: "items", Value: len(items)}}
		if first.UserID != nil {
			detail = append(detail, ojson.KV{Key: "user_id", Value: *first.UserID})
		}
		if err := tx.Audit(now, Actor, "notification.digest", detail); err != nil {
			return made, err
		}
	}
	return made, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
