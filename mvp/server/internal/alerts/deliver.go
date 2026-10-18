package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Backoff is the wait before each retry; after the last one a delivery fails.
var Backoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 4 * time.Hour}

// MaxAttempts is how often a delivery is tried.
var MaxAttempts = len(Backoff) + 1

// perTick caps the deliveries sent per tenant per tick.
const perTick = 50

// Service runs the engine and the deliveries for every active tenant.
type Service struct {
	DB     *store.DB
	Sealer *seal.Sealer
	// HTTP must come from internal/safehttp (the SSRF guard).
	HTTP      *http.Client
	Mail      Mailer
	Clock     func() time.Time
	Log       *slog.Logger
	PublicURL string // links in messages
	// DetectEvery is how often detection rules run (default 15 min).
	DetectEvery time.Duration

	lastDetect time.Time
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}

// Run ticks every interval until ctx is done.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.Tick(ctx); err != nil && ctx.Err() == nil && s.Log != nil {
			s.Log.Error("alerts tick failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick evaluates every active tenant, then sends the due deliveries.
func (s *Service) Tick(ctx context.Context) error {
	ctx = audit.WithSystemActor(ctx, Engine)
	now := s.now()
	every := s.DetectEvery
	if every <= 0 {
		every = 15 * time.Minute
	}
	detect := s.lastDetect.IsZero() || now.Sub(s.lastDetect) >= every
	err := s.DB.ForEachActiveTenant(ctx, func(_ context.Context, tx *store.TenantTx) error {
		_, err := Evaluate(tx, now, detect)
		return err
	})
	if detect {
		s.lastDetect = now
	}
	tenants, terr := s.DB.ActiveTenants(ctx)
	if terr != nil {
		return errors.Join(err, terr)
	}
	for _, t := range tenants {
		if derr := s.DeliverTenant(ctx, t.ID, t.Slug); derr != nil {
			err = errors.Join(err, fmt.Errorf("tenant %s: %w", t.Slug, derr))
		}
	}
	return err
}

type attempt struct {
	d   *store.AlertDelivery
	a   *store.Alert
	c   *store.AlertChannel
	err error
}

// DeliverTenant sends a tenant's due deliveries: it reads them, sends outside
// any transaction, then records the outcomes.
func (s *Service) DeliverTenant(ctx context.Context, t tenancy.ID, slug string) error {
	ctx = audit.AsSystem(ctx, Engine)
	now := s.now()
	var work []*attempt
	if err := s.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		due, err := tx.DueAlertDeliveries(now, perTick)
		if err != nil {
			return err
		}
		for _, d := range due {
			a, err := tx.Alert(d.AlertID)
			if err != nil {
				return err
			}
			c, err := tx.AlertChannel(d.ChannelID)
			if err != nil {
				return err
			}
			work = append(work, &attempt{d: d, a: a, c: c})
		}
		return nil
	}); err != nil || len(work) == 0 {
		return err
	}
	for _, w := range work {
		if !w.c.Enabled {
			w.err = errors.New("channel disabled")
			continue
		}
		w.err = s.send(ctx, t, slug, w.c, w.a, false)
	}
	return s.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		for _, w := range work {
			d := w.d
			d.Attempts++
			final := ""
			switch {
			case w.err == nil:
				d.Status, d.SentAt, d.LastError = "sent", &now, nil
				final = "alert.delivered"
			case !w.c.Enabled || d.Attempts >= MaxAttempts:
				msg := truncate(w.err.Error(), 500)
				d.Status, d.LastError = "failed", &msg
				final = "alert.delivery_failed"
			default:
				msg := truncate(w.err.Error(), 500)
				d.LastError, d.NextAttemptAt = &msg, now.Add(Backoff[d.Attempts-1])
			}
			if err := tx.SaveAlertDelivery(d); errors.Is(err, store.ErrNotFound) {
				continue // recorded by another worker
			} else if err != nil {
				return err
			}
			if final != "" {
				det := ojson.Object{{Key: "alert_id", Value: d.AlertID}, {Key: "channel_id", Value: d.ChannelID},
					{Key: "channel", Value: w.c.Name}, {Key: "attempts", Value: d.Attempts}}
				if d.LastError != nil {
					det = append(det, ojson.KV{Key: "error", Value: *d.LastError})
				}
				if err := tx.Audit(now, Engine, final, det); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// TestChannel sends a test message to a channel now and returns the error,
// if any. It runs outside any transaction.
func (s *Service) TestChannel(ctx context.Context, t tenancy.ID, slug string, c *store.AlertChannel) error {
	now := s.now()
	a := &store.Alert{ID: "test", RuleID: "test", DedupKey: "test", Severity: "low", Title: "Test alert from Tessera",
		Detail: json.RawMessage(`{"test":true}`), Status: "open", Count: 1, FirstSeenAt: now, LastSeenAt: now}
	return s.send(ctx, t, slug, c, a, true)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (s *Service) link(a *store.Alert) string {
	if s.PublicURL == "" || a.ID == "test" {
		return ""
	}
	return strings.TrimRight(s.PublicURL, "/") + "/alerts?selected=" + a.ID
}

func (s *Service) send(ctx context.Context, t tenancy.ID, slug string, c *store.AlertChannel, a *store.Alert, test bool) error {
	switch c.Kind {
	case "email":
		if s.Mail == nil {
			return errors.New("email delivery is not configured (TESSERA_NOTIFY)")
		}
		to, err := Recipients(c.Target)
		if err != nil {
			return err
		}
		return s.Mail.Send(ctx, Message{To: to, Subject: subject(a, slug), Text: s.text(a, slug)})
	case "webhook":
		return s.postWebhook(ctx, t, slug, c, a, test)
	}
	return fmt.Errorf("unknown channel kind %q", c.Kind)
}

func subject(a *store.Alert, slug string) string {
	return fmt.Sprintf("[Tessera %s] %s: %s", slug, strings.ToUpper(a.Severity), a.Title)
}

func (s *Service) text(a *store.Alert, slug string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\nSeverity: %s\nRule: %s\nTenant: %s\nFirst seen: %s\nLast seen: %s\nOccurrences: %d\n",
		a.Title, a.Severity, a.RuleID, slug, a.FirstSeenAt.Format(time.RFC3339), a.LastSeenAt.Format(time.RFC3339), a.Count)
	if l := s.link(a); l != "" {
		fmt.Fprintf(&b, "\nOpen in Tessera: %s\n", l)
	}
	return b.String()
}

// WebhookPayload is what a webhook receives. "text" makes it a valid Slack
// and Microsoft Teams incoming-webhook message.
type WebhookPayload struct {
	Text   string       `json:"text"`
	Tenant string       `json:"tenant"`
	Test   bool         `json:"test,omitempty"`
	Alert  WebhookAlert `json:"alert"`
}

// WebhookAlert is the alert in a webhook payload.
type WebhookAlert struct {
	ID          string          `json:"id"`
	Rule        string          `json:"rule"`
	Severity    string          `json:"severity"`
	Title       string          `json:"title"`
	Status      string          `json:"status"`
	Count       int             `json:"count"`
	FirstSeenAt time.Time       `json:"first_seen_at"`
	LastSeenAt  time.Time       `json:"last_seen_at"`
	Detail      json.RawMessage `json:"detail"`
	URL         string          `json:"url,omitempty"`
}

// Signature is the X-Tessera-Signature value for a body sent at ts:
// "t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">".
func Signature(secret []byte, ts time.Time, body []byte) string {
	t := strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(t + "."))
	mac.Write(body)
	return "t=" + t + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) postWebhook(ctx context.Context, t tenancy.ID, slug string, c *store.AlertChannel, a *store.Alert, test bool) error {
	if s.HTTP == nil {
		return errors.New("webhook delivery is not configured")
	}
	if s.Sealer == nil || len(c.SecretSealed) == 0 {
		return errors.New("the channel has no signing secret")
	}
	secret, err := s.Sealer.Open(c.SecretSealed, SecretAAD(t, c.ID))
	if err != nil {
		return errors.New("the channel's signing secret cannot be opened")
	}
	detail := a.Detail
	if len(detail) == 0 {
		detail = json.RawMessage("{}")
	}
	body, err := json.Marshal(WebhookPayload{
		Text:   fmt.Sprintf("[%s] %s (Tessera %s)", strings.ToUpper(a.Severity), a.Title, slug),
		Tenant: slug, Test: test,
		Alert: WebhookAlert{ID: a.ID, Rule: a.RuleID, Severity: a.Severity, Title: a.Title, Status: a.Status, Count: a.Count,
			FirstSeenAt: a.FirstSeenAt, LastSeenAt: a.LastSeenAt, Detail: detail, URL: s.link(a)},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Tessera-Alerts/1")
	req.Header.Set("X-Tessera-Signature", Signature(secret, s.now(), body))
	req.Header.Set("X-Tessera-Alert", a.ID)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook: HTTP %d", resp.StatusCode)
	}
	return nil
}
