package rules

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
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/engine"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// HookTimeout is how long a webhook may take (design §10.3: 2 s).
const HookTimeout = 2 * time.Second

// maxHookReply bounds what is read of a webhook's answer.
const maxHookReply = 64 << 10

// Notification is one email a rule sends.
type Notification struct {
	Tenant   tenancy.ID
	RuleID   string
	Identity int64 // the identity to tell
	Email    string
	Subject  string
	Body     string
}

// Notifier delivers a rule's email. The default writes a log line (TESSERA_NOTIFY=log):
// Tessera has no mail transport yet.
type Notifier func(ctx context.Context, n Notification) error

// Runtime is what rules need from outside the database: the membership engine
// (for membership questions), the outbound HTTP client (a safehttp client; nil
// means webhooks cannot be called), the sealer for webhook secrets, and the
// email notifier.
type Runtime struct {
	Engine *engine.Engine
	// HTTP must come from internal/safehttp. Nil: webhook rules cannot be saved
	// and a hook that is called fails.
	HTTP   *http.Client
	Sealer *seal.Sealer
	Notify Notifier
	Log    *slog.Logger
	// AllowHTTP lets a webhook URL use plain http (dev loopback only, where the
	// safehttp client allows it).
	AllowHTTP bool
	// Timeout overrides HookTimeout (tests).
	Timeout time.Duration
}

func (rt *Runtime) engine() *engine.Engine {
	if rt != nil && rt.Engine != nil {
		return rt.Engine
	}
	return defaultEngine
}

var defaultEngine = engine.New(0)

func (rt *Runtime) log() *slog.Logger {
	if rt != nil && rt.Log != nil {
		return rt.Log
	}
	return slog.Default()
}

func (rt *Runtime) timeout() time.Duration {
	if rt != nil && rt.Timeout > 0 {
		return rt.Timeout
	}
	return HookTimeout
}

// notify delivers n through the notifier, or logs it. The log line has the
// rule and identity ids only: no address, no text.
func (rt *Runtime) notify(ctx context.Context, n Notification) error {
	if rt != nil && rt.Notify != nil {
		return rt.Notify(ctx, n)
	}
	rt.log().InfoContext(ctx, "group rule notification", "tenant", n.Tenant.String(), "rule", n.RuleID, "identity", n.Identity)
	return nil
}

// ---------------------------------------------------------------- webhooks

// secretAAD binds a sealed webhook secret to its tenant and rule.
func secretAAD(tenant tenancy.ID, rule string) []byte {
	return seal.AAD(tenant, "grp_rules", "secret_enc", rule)
}

// newSecret makes a rule's webhook signing secret and seals it.
func (rt *Runtime) newSecret(tenant tenancy.ID, rule string) (plain string, sealed []byte, err error) {
	if rt == nil || rt.Sealer == nil || rt.HTTP == nil {
		return "", nil, conflict("webhooks_unavailable", "this deployment has no outbound client or key to call webhooks with")
	}
	plain = seal.RandomSecret(32)
	sealed, err = rt.Sealer.Seal([]byte(plain), secretAAD(tenant, rule))
	return plain, sealed, err
}

// hookReply is what a hook may answer: allow false vetoes, with a message.
type hookReply struct {
	Allow   *bool  `json:"allow"`
	Message string `json:"message"`
}

// post sends the payload to the rule's hook, signed with its secret:
//
//	Tessera-Timestamp: <unix seconds>
//	Tessera-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">
//
// and returns the answer's status and (bounded) body. The client is a safehttp
// client: https only (plain http in dev), no private addresses, no redirects off the host.
func (rt *Runtime) post(ctx context.Context, tenant tenancy.ID, c *Compiled, payload any, now time.Time) (int, []byte, error) {
	if rt == nil || rt.HTTP == nil || rt.Sealer == nil || len(c.Rule.SecretEnc) == 0 {
		return 0, nil, errors.New("webhooks are unavailable")
	}
	secret, err := rt.Sealer.Open(c.Rule.SecretEnc, secretAAD(tenant, c.Rule.ID))
	if err != nil {
		return 0, nil, errors.New("the rule's secret cannot be opened")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, rt.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Spec.Params.URL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Tessera-Timestamp", ts)
	req.Header.Set("Tessera-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("Tessera-Rule", c.Rule.ID)
	resp, err := rt.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxHookReply))
	return resp.StatusCode, reply, err
}

// hookPayload is what a hook is told.
type hookPayload struct {
	Rule       string     `json:"rule"`
	Name       string     `json:"name"`
	Event      string     `json:"event"`
	Seq        int64      `json:"seq,omitempty"`
	OccurredAt time.Time  `json:"occurred_at"`
	Group      *hookGroup `json:"group,omitempty"`
	Identity   *int64     `json:"identity,omitempty"`
	Actor      *int64     `json:"actor,omitempty"`
	Source     string     `json:"source,omitempty"`
	Object     string     `json:"object,omitempty"` // the id of what was created
	Veto       bool       `json:"veto"`             // true: the answer can refuse the change
}

type hookGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func payloadOf(c *Compiled, ev *fireEvent) hookPayload {
	p := hookPayload{Rule: c.Rule.ID, Name: c.Rule.Name, Event: ev.Type, Seq: ev.Seq, OccurredAt: ev.At, Identity: ev.Identity,
		Actor: ev.Actor, Source: ev.Source, Object: ev.Created, Veto: c.Spec.Params.Veto}
	if ev.Group != nil {
		p.Group = &hookGroup{ID: string(ev.Group.ID), Name: ev.Group.Name}
	}
	return p
}

// hookVerdict calls a veto hook and returns the message of a veto ("" to
// allow). A hook that fails (no answer, a non-2xx status, an unreadable
// answer) vetoes unless the rule says fail_open: the default is fail closed.
func (rt *Runtime) hookVerdict(ctx context.Context, tenant tenancy.ID, c *Compiled, ev *fireEvent, now time.Time) string {
	status, body, err := rt.post(ctx, tenant, c, payloadOf(c, ev), now)
	unavailable := fmt.Sprintf("the approval hook of rule %q did not answer, so the change is refused", c.Rule.Name)
	var reply hookReply
	switch {
	case err != nil || status < 200 || status > 299:
		rt.log().WarnContext(ctx, "group rule hook failed", "rule", c.Rule.ID, "status", status, "failed", err != nil)
	case len(bytes.TrimSpace(body)) > 0 && json.Unmarshal(body, &reply) != nil:
		rt.log().WarnContext(ctx, "group rule hook answered with something unreadable", "rule", c.Rule.ID)
	default:
		if reply.Allow != nil && !*reply.Allow {
			if reply.Message != "" {
				return truncate(reply.Message, maxMessage)
			}
			return fmt.Sprintf("the approval hook of rule %q refused the change", c.Rule.Name)
		}
		return ""
	}
	if c.Spec.Params.FailOpen {
		return ""
	}
	return unavailable
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// tenantOf is the tenant of a transaction, for the sealed secret's AAD.
func tenantOf(tx *store.TenantTx) tenancy.ID { return tx.Tenant() }
