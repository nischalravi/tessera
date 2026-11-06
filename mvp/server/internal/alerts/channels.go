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
	// Secret is a signing secret the caller chose (a webhook only): a configuration proposal (issue #719) cannot read the
	// one the server would generate, so it brings its own. Empty: the server generates one when it makes or rotates it.
	Secret string
}

// MinSigningSecret and MaxSigningSecret bound a caller-chosen webhook signing secret.
const (
	MinSigningSecret = 16
	MaxSigningSecret = 256
)

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
		if safehttp.IsMetadataHost(u.Hostname()) {
			return refuse(422, "invalid_target", "the webhook URL must not point at a cloud metadata service")
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
	if err := s.checkSecret(); err != nil {
		return nil, "", err
	}
	c := &store.AlertChannel{ID: uuid.NewString(), Name: s.Name, Kind: s.Kind, Target: s.Target, MinSeverity: s.MinSeverity,
		Enabled: s.Enabled, CreatedBy: &by.UserID, CreatedAt: now, UpdatedAt: now}
	secret, err := newSecret(tx, sealer, c, s.Secret)
	if err != nil {
		return nil, "", err
	}
	if err := tx.InsertAlertChannel(c); err != nil {
		return nil, "", err
	}
	return c, secret, tx.Audit(now, by.Display, "alert.channel.created", channelAudit(c, secret != "" || s.Secret != ""))
}

// CheckChannel validates a new channel (id "") or a change to channel id as CreateChannel or UpdateChannel would, without
// writing anything (issue #719: a proposal is checked at submit and again at apply).
func CheckChannel(tx *store.TenantTx, id string, s ChannelSpec, dev bool) error {
	if id == "" {
		if err := s.check(dev); err != nil {
			return err
		}
		return s.checkSecret()
	}
	_, _, _, _, err := prepareUpdate(tx, id, s, dev)
	return err
}

// checkSecret refuses a caller-chosen signing secret that is too short, too long or on a channel that signs nothing.
func (s *ChannelSpec) checkSecret() error {
	if s.Secret == "" {
		return nil
	}
	if s.Kind != "webhook" {
		return refuse(422, "invalid_secret", "only a webhook has a signing secret")
	}
	if len(s.Secret) < MinSigningSecret || len(s.Secret) > MaxSigningSecret {
		return refuse(422, "invalid_secret", "the signing secret is %d to %d characters", MinSigningSecret, MaxSigningSecret)
	}
	return nil
}

// UpdateChannel replaces a channel's settings; its kind cannot change.
func UpdateChannel(tx *store.TenantTx, sealer *seal.Sealer, id string, s ChannelSpec, dev bool, by Actor, now time.Time) (*store.AlertChannel, string, error) {
	c, s, from, to, err := prepareUpdate(tx, id, s, dev)
	if err != nil {
		return nil, "", err
	}
	c.Name, c.Target, c.MinSeverity, c.Enabled, c.UpdatedAt = s.Name, s.Target, s.MinSeverity, s.Enabled, now
	secret := ""
	if s.RotateSecret || s.Secret != "" {
		if secret, err = newSecret(tx, sealer, c, s.Secret); err != nil {
			return nil, "", err
		}
	}
	if err := tx.UpdateAlertChannel(c); err != nil {
		return nil, "", err
	}
	d := channelAudit(c, s.RotateSecret || s.Secret != "")
	if from != to {
		d = append(d, ojson.KV{Key: "previous_origin", Value: from}, ojson.KV{Key: "origin", Value: to})
	}
	return c, secret, tx.Audit(now, by.Display, "alert.channel.updated", d)
}

// prepareUpdate loads channel id and runs every check UpdateChannel makes before it writes; it returns the channel and the
// origin it is moving from and to.
func prepareUpdate(tx *store.TenantTx, id string, s ChannelSpec, dev bool) (*store.AlertChannel, ChannelSpec, string, string, error) {
	c, err := tx.AlertChannel(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, s, "", "", refuse(404, "channel_not_found", "channel not found")
	} else if err != nil {
		return nil, s, "", "", err
	}
	if s.Kind == "" {
		s.Kind = c.Kind
	}
	if s.Kind != c.Kind {
		return nil, s, "", "", refuse(422, "invalid_kind", "a channel's kind cannot change")
	}
	if err := s.check(dev); err != nil {
		return nil, s, "", "", err
	}
	if err := s.checkSecret(); err != nil {
		return nil, s, "", "", err
	}
	// The signing secret is bound to the channel row, not to the receiver: a
	// webhook that moves to another origin (scheme, host, port) must get a new
	// secret, or the old receiver's signed payloads could be replayed to it
	// and the new host would hold signatures made with the old secret
	// (#332, as #315). A path-only change keeps the secret.
	from, to := "", ""
	if c.Kind == "webhook" {
		from, to = safehttp.OriginKey(c.Target), safehttp.OriginKey(s.Target)
		if from != to && !s.RotateSecret && s.Secret == "" && len(c.SecretSealed) > 0 {
			return nil, s, "", "", refuse(422, "credential_required",
				"changing the webhook's origin (scheme, host, port) needs a new signing secret: set rotate_secret")
		}
	}
	return c, s, from, to, nil
}

func newSecret(tx *store.TenantTx, sealer *seal.Sealer, c *store.AlertChannel, chosen string) (string, error) {
	if c.Kind != "webhook" {
		c.SecretSealed = nil
		return "", nil
	}
	if sealer == nil {
		return "", errors.New("alerts: no sealer for webhook secrets")
	}
	secret, shown := chosen, ""
	if secret == "" {
		secret = "whsec_" + seal.RandomSecret(32)
		shown = secret // a generated secret is shown once; a chosen one the caller already knows
	}
	sealed, err := sealer.Seal([]byte(secret), SecretAAD(tx.Tenant(), c.ID))
	if err != nil {
		return "", err
	}
	c.SecretSealed = sealed
	return shown, nil
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
