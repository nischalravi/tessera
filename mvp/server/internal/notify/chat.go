package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The tenant's chat workspace (Admin > Notifications, schema/0761_tenant_chat_webhook.sql): a Slack or Microsoft Teams
// incoming webhook that gets one message per event of the kinds chosen. The webhook URL is a credential, so it is sealed
// under the KEK and never shown; every post goes through the SSRF-guarded client (internal/safehttp) and only to the
// provider's own hosts.

// Chat providers.
const (
	ProviderSlack = "slack"
	ProviderTeams = "teams"
)

// Providers lists the chat providers.
var Providers = []string{ProviderSlack, ProviderTeams}

// chatHosts are the hosts a provider's incoming webhooks live on (a leading dot matches any subdomain).
var chatHosts = map[string][]string{
	ProviderSlack: {"hooks.slack.com", "hooks.slack-gov.com"},
	ProviderTeams: {".webhook.office.com", "outlook.office.com", "outlook.office365.com", ".logic.azure.com", ".environment.api.powerplatform.com", ".api.powerplatform.com"},
}

// ChatMaxFailures is how many times one event is tried before the dispatcher gives it up.
const ChatMaxFailures = 5

// chatBatch is how many notifications one pass looks at.
const chatBatch = 100

// chatLag is how far behind the clock the posting cursor stays: a notification is posted once its transaction has had this
// long to commit, so one written at the cursor's own instant is never passed over.
const chatLag = 5 * time.Second

// ChatEnv is what the chat settings need from the running server.
type ChatEnv struct {
	Sealer *seal.Sealer
	// AnyHost lifts the provider host list (development with the loopback exception, so a local test receiver works); the
	// guarded client still refuses every internal address in production.
	AnyHost bool
}

// ChatAAD binds a tenant's sealed webhook URL to the tenant, table and column.
func ChatAAD(t tenancy.ID) []byte { return seal.AAD(t, "tenant_chat_webhook", "webhook_sealed") }

// CheckWebhookURL validates a webhook URL for a provider and returns its host.
func (e ChatEnv) CheckWebhookURL(provider, raw string) (string, error) {
	refuse := func(code, msg string) (string, error) { return "", cfgerr.Refuse(422, code, "%s", msg) }
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || len(raw) > 2000 || u.User != nil || u.Fragment != "" {
		return refuse("invalid_webhook", "the webhook is an absolute https URL without credentials")
	}
	host := strings.ToLower(u.Hostname())
	if e.AnyHost {
		if u.Scheme != "https" && u.Scheme != "http" {
			return refuse("invalid_webhook", "the webhook is an http or https URL")
		}
		return host, nil
	}
	if u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") {
		return refuse("invalid_webhook", "the webhook is an https URL on port 443")
	}
	allowed := false
	for _, h := range chatHosts[provider] {
		if h == host || strings.HasPrefix(h, ".") && strings.HasSuffix(host, h) {
			allowed = true
		}
	}
	if !allowed {
		return refuse("invalid_webhook_host", fmt.Sprintf("a %s webhook is on %s", providerName(provider), strings.Join(chatHosts[provider], ", ")))
	}
	return host, nil
}

func providerName(p string) string {
	if p == ProviderTeams {
		return "Microsoft Teams"
	}
	return "Slack"
}

// ChatSpec is what an administrator saves.
type ChatSpec struct {
	Provider string   `json:"provider"`
	Enabled  bool     `json:"enabled"`
	URL      string   `json:"webhook_url"` // write-only; empty keeps the stored one
	Kinds    []string `json:"kinds"`
}

// ChatState is the tenant's chat workspace as the API shows it: everything but the URL.
type ChatState struct {
	Configured bool       `json:"configured"`
	Provider   string     `json:"provider"`
	Enabled    bool       `json:"enabled"`
	HasWebhook bool       `json:"has_webhook"`
	Host       string     `json:"webhook_host"`
	Kinds      []string   `json:"kinds"`
	FailCount  int        `json:"fail_count"`
	LastError  string     `json:"last_error"`
	LastPostAt *time.Time `json:"last_post_at"`
	Version    int        `json:"version"`
	UpdatedBy  string     `json:"updated_by,omitempty"`
}

// DefaultChatKinds are the kinds a newly saved workspace receives.
var DefaultChatKinds = []string{KindApprovalNeeded, KindApprovalEscalated, KindSecurityAlert}

// LoadChat returns the tenant's chat state; the zero state (Version 0) when none is saved.
func LoadChat(tx *store.TenantTx) (ChatState, error) {
	c, err := tx.ChatWebhook()
	if errors.Is(err, store.ErrNotFound) {
		return ChatState{Provider: ProviderSlack, Kinds: slices.Clone(DefaultChatKinds)}, nil
	} else if err != nil {
		return ChatState{}, err
	}
	var kinds []string
	if err := json.Unmarshal([]byte(c.Kinds), &kinds); err != nil {
		return ChatState{}, err
	}
	if kinds == nil {
		kinds = []string{}
	}
	return ChatState{Configured: true, Provider: c.Provider, Enabled: c.Enabled, HasWebhook: len(c.WebhookSealed) > 0, Host: c.WebhookHost,
		Kinds: kinds, FailCount: c.FailCount, LastError: c.LastError, LastPostAt: c.LastPostAt, Version: c.Version, UpdatedBy: c.UpdatedBy}, nil
}

// SaveChat validates and replaces the tenant's chat workspace. A webhook URL is needed the first time and when the provider
// changes (a Slack URL is no Teams URL); otherwise empty keeps the stored one. The audit event names the provider and host,
// never the URL.
func SaveChat(tx *store.TenantTx, env ChatEnv, s ChatSpec, ver int, by string, now time.Time) error {
	old, err := tx.ChatWebhook()
	have := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	cur := 0
	if have {
		cur = old.Version
	}
	if ver != cur {
		return cfgerr.Conflict(ver, cur)
	}
	if !slices.Contains(Providers, s.Provider) {
		return cfgerr.Refuse(422, "invalid_provider", "the provider is slack or teams")
	}
	kinds := []string{}
	for _, k := range s.Kinds {
		if _, ok := KindByID(k); !ok {
			return cfgerr.Refuse(422, "unknown_kind", "%q is not a notification kind", k)
		}
		if !slices.Contains(kinds, k) {
			kinds = append(kinds, k)
		}
	}
	if s.Enabled && len(kinds) == 0 {
		return cfgerr.Refuse(422, "no_kinds", "choose at least one kind to post")
	}
	row := &store.ChatWebhookRow{Provider: s.Provider, Enabled: s.Enabled, UpdatedBy: by}
	switch {
	case strings.TrimSpace(s.URL) != "":
		if env.Sealer == nil {
			return errors.New("notify: no key to seal the webhook with")
		}
		if row.WebhookHost, err = env.CheckWebhookURL(s.Provider, s.URL); err != nil {
			return err
		}
		if row.WebhookSealed, err = env.Sealer.Seal([]byte(strings.TrimSpace(s.URL)), ChatAAD(tx.Tenant())); err != nil {
			return err
		}
	case have && old.Provider == s.Provider:
		row.WebhookSealed, row.WebhookHost = old.WebhookSealed, old.WebhookHost
	default:
		return cfgerr.Refuse(422, "webhook_required", "paste the %s incoming webhook URL", providerName(s.Provider))
	}
	raw, _ := json.Marshal(kinds)
	row.Kinds = string(raw)
	if err := tx.PutChatWebhook(row, now); err != nil {
		return err
	}
	return tx.Audit(now, by, "chat.webhook.update", ojson.Object{{Key: "provider", Value: s.Provider}, {Key: "enabled", Value: s.Enabled},
		{Key: "host", Value: row.WebhookHost}, {Key: "webhook", Value: map[bool]string{true: "replaced", false: "kept"}[strings.TrimSpace(s.URL) != ""]},
		{Key: "kinds", Value: kinds}, {Key: "version", Value: cur + 1}})
}

// DeleteChat removes the tenant's chat workspace.
func DeleteChat(tx *store.TenantTx, ver int, by string, now time.Time) error {
	c, err := tx.ChatWebhook()
	if errors.Is(err, store.ErrNotFound) {
		return &Error{http.StatusNotFound, "chat_not_found", "the tenant has no chat workspace"}
	} else if err != nil {
		return err
	}
	if ver != c.Version {
		return cfgerr.Conflict(ver, c.Version)
	}
	if err := tx.DeleteChatWebhook(); err != nil {
		return err
	}
	return tx.Audit(now, by, "chat.webhook.delete", ojson.Object{{Key: "provider", Value: c.Provider}, {Key: "host", Value: c.WebhookHost}})
}

// slackText escapes what Slack reads as markup, so a notification cannot mention a channel or inject a link.
func slackText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// chatPayload is the JSON body a provider's webhook takes.
func chatPayload(provider, subject, body, link string) ([]byte, error) {
	if provider == ProviderTeams {
		blocks := []map[string]any{{"type": "TextBlock", "text": subject, "weight": "Bolder", "wrap": true}}
		if body != "" {
			blocks = append(blocks, map[string]any{"type": "TextBlock", "text": body, "wrap": true})
		}
		if link != "" {
			blocks = append(blocks, map[string]any{"type": "TextBlock", "text": link, "wrap": true})
		}
		return json.Marshal(map[string]any{"type": "message", "attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": nil,
			"content": map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": blocks}}}})
	}
	text := "*" + slackText(subject) + "*"
	if body != "" {
		text += "\n" + slackText(body)
	}
	if link != "" {
		text += "\n" + slackText(link)
	}
	return json.Marshal(map[string]string{"text": text})
}

// postChat sends one message to a webhook through the guarded client and reports what happened, scrubbed of the URL.
func postChat(ctx context.Context, hc *http.Client, provider, rawURL string, payload []byte) error {
	if hc == nil {
		return errors.New("chat delivery is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(payload))
	if err != nil {
		return errors.New("webhook: bad URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Tessera-Notifications/1")
	resp, err := hc.Do(req)
	if err != nil {
		// the URL is the credential: the error never carries more than scheme://host
		return errors.New("webhook: " + safehttp.ScrubError(err, rawURL))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook: HTTP %d", resp.StatusCode)
	}
	return nil
}

// TestChat posts a test message through the saved webhook and records nothing but an audit event.
func TestChat(ctx context.Context, tx *store.TenantTx, env ChatEnv, hc *http.Client, product, by string, now time.Time) error {
	c, err := tx.ChatWebhook()
	if errors.Is(err, store.ErrNotFound) {
		return &Error{http.StatusNotFound, "chat_not_found", "save a chat workspace first"}
	} else if err != nil {
		return err
	}
	raw, err := openChat(env, tx.Tenant(), c)
	if err != nil {
		return &Error{http.StatusConflict, "chat_unusable", err.Error()}
	}
	payload, err := chatPayload(c.Provider, "Test message from "+product, "This message tests the "+providerName(c.Provider)+" webhook you saved. Nothing else is needed.", "")
	if err != nil {
		return err
	}
	perr := postChat(ctx, hc, c.Provider, raw, payload)
	d := ojson.Object{{Key: "provider", Value: c.Provider}, {Key: "host", Value: c.WebhookHost}, {Key: "ok", Value: perr == nil}}
	if perr != nil {
		d = append(d, ojson.KV{Key: "error", Value: clip(perr.Error(), 200)})
	}
	if err := tx.Audit(now, by, "chat.webhook.test", d); err != nil {
		return err
	}
	if perr != nil {
		return &Error{http.StatusBadGateway, "chat_post_failed", clip(perr.Error(), 200)}
	}
	return nil
}

func openChat(env ChatEnv, t tenancy.ID, c *store.ChatWebhookRow) (string, error) {
	if env.Sealer == nil {
		return "", errors.New("the chat webhook cannot be opened: no key")
	}
	b, err := env.Sealer.Open(c.WebhookSealed, ChatAAD(t))
	if err != nil {
		return "", errors.New("the chat webhook cannot be opened (wrong KEK)")
	}
	return string(b), nil
}

// eventKey is a notification's event: its dedupe key without the recipient.
func eventKey(n *store.Notification) string {
	if i := strings.LastIndex(n.DedupeKey, "|"); i >= 0 {
		return n.DedupeKey[:i]
	}
	return n.DedupeKey
}

// chatCursor is where the posting stands.
type chatCursor struct {
	at, id, key string // the last notification looked at, and the event last posted
	fails       int
	lastErr     string
}

func (c *chatCursor) pass(n *store.Notification) { c.at, c.id = store.T(n.CreatedAt), n.ID }

// chatPass posts the notifications created since the cursor, one message per event, and moves the cursor. An event that
// fails stays at the cursor and is tried again next pass; after ChatMaxFailures it is dropped (audited) so one bad event
// cannot hold the rest back.
func (d *Dispatcher) chatPass(ctx context.Context, t tenancy.ID) error {
	var c *store.ChatWebhookRow
	var rows []*store.Notification
	var product string
	if err := d.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		if c, err = tx.ChatWebhook(); errors.Is(err, store.ErrNotFound) {
			c = nil
			return nil
		} else if err != nil || !c.Enabled {
			return err
		}
		if rows, err = tx.NotificationsAfter(c.CursorAt, c.CursorID, d.Clock().UTC().Add(-chatLag), chatBatch); err != nil {
			return err
		}
		product, err = tx.BrandName()
		return err
	}); err != nil || c == nil || !c.Enabled || len(rows) == 0 {
		return err
	}
	var kinds []string
	if err := json.Unmarshal([]byte(c.Kinds), &kinds); err != nil {
		return err
	}
	if product == "" {
		product = "Tessera"
	}
	cur := chatCursor{at: c.CursorAt, id: c.CursorID, key: c.CursorKey, fails: c.FailCount, lastErr: c.LastError}
	raw, err := openChat(ChatEnv{Sealer: d.Relay.Sealer}, t, c)
	if err != nil {
		cur.lastErr = err.Error()
		return d.chatSave(ctx, t, c, cur, nil, false)
	}
	for _, n := range rows {
		key := eventKey(n)
		if !slices.Contains(kinds, n.Kind) || key == cur.key {
			cur.pass(n)
			continue
		}
		link := ""
		if n.Link != "" && d.BaseURL != "" {
			link = strings.TrimRight(d.BaseURL, "/") + n.Link
		}
		payload, err := chatPayload(c.Provider, "["+product+"] "+n.Subject, n.Body, link)
		if err == nil {
			err = postChat(ctx, d.HTTP, c.Provider, raw, payload)
		}
		if err == nil {
			cur.pass(n)
			cur.key, cur.fails, cur.lastErr = key, 0, ""
			if err := d.chatSave(ctx, t, c, cur, n, true); err != nil {
				return err
			}
			continue
		}
		cur.fails++
		cur.lastErr = clip(err.Error(), 280)
		if cur.fails < ChatMaxFailures {
			return d.chatSave(ctx, t, c, cur, nil, false) // the event stays at the cursor: tried again next pass
		}
		cur.pass(n) // given up
		cur.key, cur.fails = key, 0
		if err := d.chatSave(ctx, t, c, cur, n, false); err != nil {
			return err
		}
	}
	if cur.at != c.CursorAt || cur.id != c.CursorID {
		return d.chatSave(ctx, t, c, cur, nil, false)
	}
	return nil
}

// chatSave records where the posting stands and, for a post or a dropped event, audits it.
func (d *Dispatcher) chatSave(ctx context.Context, t tenancy.ID, c *store.ChatWebhookRow, cur chatCursor, n *store.Notification, posted bool) error {
	ctx = audit.AsSystem(ctx, Actor)
	return d.DB.InTenant(ctx, t, func(tx *store.TenantTx) error {
		now := d.Clock().UTC()
		upd := &store.ChatWebhookRow{CursorAt: cur.at, CursorID: cur.id, CursorKey: cur.key, FailCount: cur.fails, LastError: cur.lastErr}
		if posted {
			upd.LastPostAt = &now
		}
		if err := tx.SetChatProgress(upd); errors.Is(err, store.ErrNotFound) {
			return nil // removed meanwhile
		} else if err != nil {
			return err
		}
		if n == nil {
			return nil
		}
		detail := ojson.Object{{Key: "notification_id", Value: n.ID}, {Key: "kind", Value: n.Kind}, {Key: "channel", Value: "chat"},
			{Key: "provider", Value: c.Provider}, {Key: "status", Value: map[bool]string{true: "sent", false: "dropped"}[posted]}}
		if !posted {
			detail = append(detail, ojson.KV{Key: "error", Value: cur.lastErr})
		}
		return tx.Audit(now, Actor, "notification.chat", detail)
	})
}
