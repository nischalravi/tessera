package alerts

import (
	"errors"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// MaxRecipients caps an email channel's addresses.
const MaxRecipients = 20

// ChannelSpec is a channel's settings.
type ChannelSpec struct {
	Name        string
	Kind        string // email | webhook (fixed after creation)
	Target      string // comma-separated addresses, or the webhook URL
	MinSeverity string
	Enabled     bool
	// RotateSecret issues a new webhook signing secret.
	RotateSecret bool
}

// SecretAAD binds a channel's sealed secret to its tenant and row.
func SecretAAD(t tenancy.ID, channelID string) []byte {
	return seal.AAD(t, "alert_channels", "secret_sealed", channelID)
}

// Recipients parses an email channel's target.
func Recipients(target string) ([]string, error) {
	list, err := mail.ParseAddressList(target)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Address)
	}
	return out, nil
}

func (s *ChannelSpec) check(dev bool) error {
	s.Name, s.Target = strings.TrimSpace(s.Name), strings.TrimSpace(s.Target)
	if s.Name == "" || len(s.Name) > 100 {
		return refuse(422, "invalid_name", "the name is 1 to 100 characters")
	}
	if !slices.Contains(Severities, s.MinSeverity) {
		return refuse(422, "invalid_severity", "min_severity is low, medium, high or critical")
	}
	switch s.Kind {
	case "email":
		rs, err := Recipients(s.Target)
		if err != nil || len(rs) == 0 || len(rs) > MaxRecipients {
			return refuse(422, "invalid_target", "give 1 to %d email addresses, separated by commas", MaxRecipients)
		}
		s.Target = strings.Join(rs, ", ")
	case "webhook":
		u, err := url.Parse(s.Target)
		if err != nil || u.Host == "" || u.User != nil || len(s.Target) > 2000 {
			return refuse(422, "invalid_target", "the webhook URL must be an absolute https URL without credentials")
		}
		// safehttp enforces the same at send time, after DNS resolution
		if u.Scheme != "https" && !(dev && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
			return refuse(422, "invalid_target", "the webhook URL must use https")
		}
	default:
		return refuse(422, "invalid_kind", "kind is email or webhook")
	}
	return nil
}

// CreateChannel adds a channel. For a webhook it returns the signing secret,
// shown once; only its sealed form is stored.
func CreateChannel(tx *store.TenantTx, sealer *seal.Sealer, s ChannelSpec, dev bool, by Actor, now time.Time) (*store.AlertChannel, string, error) {
	if err := s.check(dev); err != nil {
		return nil, "", err
	}
	c := &store.AlertChannel{ID: uuid.NewString(), Name: s.Name, Kind: s.Kind, Target: s.Target, MinSeverity: s.MinSeverity,
		Enabled: s.Enabled, CreatedBy: &by.UserID, CreatedAt: now, UpdatedAt: now}
	secret, err := newSecret(tx, sealer, c)
	if err != nil {
		return nil, "", err
	}
	if err := tx.InsertAlertChannel(c); err != nil {
		return nil, "", err
	}
	return c, secret, tx.Audit(now, by.Display, "alert.channel.created", channelAudit(c, secret != ""))
}

// UpdateChannel replaces a channel's settings; its kind cannot change.
func UpdateChannel(tx *store.TenantTx, sealer *seal.Sealer, id string, s ChannelSpec, dev bool, by Actor, now time.Time) (*store.AlertChannel, string, error) {
	c, err := tx.AlertChannel(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", refuse(404, "channel_not_found", "channel not found")
	} else if err != nil {
		return nil, "", err
	}
	if s.Kind == "" {
		s.Kind = c.Kind
	}
	if s.Kind != c.Kind {
		return nil, "", refuse(422, "invalid_kind", "a channel's kind cannot change")
	}
	if err := s.check(dev); err != nil {
		return nil, "", err
	}
	// The signing secret is bound to the channel row, not to the receiver: a
	// webhook that moves to another origin (scheme, host, port) must get a new
	// secret, or the old receiver's signed payloads could be replayed to it
	// and the new host would hold signatures made with the old secret
	// (#332, as #315). A path-only change keeps the secret.
	from, to := "", ""
	if c.Kind == "webhook" {
		from, to = safehttp.Origin(c.Target), safehttp.Origin(s.Target)
		if from != to && !s.RotateSecret && len(c.SecretSealed) > 0 {
			return nil, "", refuse(422, "credential_required",
				"changing the webhook's origin (scheme, host, port) needs a new signing secret: set rotate_secret")
		}
	}
	c.Name, c.Target, c.MinSeverity, c.Enabled, c.UpdatedAt = s.Name, s.Target, s.MinSeverity, s.Enabled, now
	secret := ""
	if s.RotateSecret {
		if secret, err = newSecret(tx, sealer, c); err != nil {
			return nil, "", err
		}
	}
	if err := tx.UpdateAlertChannel(c); err != nil {
		return nil, "", err
	}
	d := channelAudit(c, secret != "")
	if from != to {
		d = append(d, ojson.KV{Key: "previous_origin", Value: from}, ojson.KV{Key: "origin", Value: to})
	}
	return c, secret, tx.Audit(now, by.Display, "alert.channel.updated", d)
}

func newSecret(tx *store.TenantTx, sealer *seal.Sealer, c *store.AlertChannel) (string, error) {
	if c.Kind != "webhook" {
		c.SecretSealed = nil
		return "", nil
	}
	if sealer == nil {
		return "", errors.New("alerts: no sealer for webhook secrets")
	}
	secret := "whsec_" + seal.RandomSecret(32)
	sealed, err := sealer.Seal([]byte(secret), SecretAAD(tx.Tenant(), c.ID))
	if err != nil {
		return "", err
	}
	c.SecretSealed = sealed
	return secret, nil
}

// channelAudit never includes the target URL's query (it may carry a token)
// nor the secret.
func channelAudit(c *store.AlertChannel, newSecret bool) ojson.Object {
	target := c.Target
	if c.Kind == "webhook" {
		if u, err := url.Parse(c.Target); err == nil {
			target = u.Scheme + "://" + u.Host
		}
	}
	return ojson.Object{{Key: "channel_id", Value: c.ID}, {Key: "name", Value: c.Name}, {Key: "kind", Value: c.Kind},
		{Key: "target", Value: target}, {Key: "min_severity", Value: c.MinSeverity}, {Key: "enabled", Value: c.Enabled},
		{Key: "secret_rotated", Value: newSecret}}
}

func mailParse(s string) (string, error) {
	a, err := mail.ParseAddress(s)
	if err != nil {
		return "", err
	}
	return a.Address, nil
}
