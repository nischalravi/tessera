package alerts

import (
	"errors"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/urlshape"
)

// CodeURLNonASCIIAuthority is the error code of a webhook URL whose scheme or host is not ASCII (as in readiness).
const CodeURLNonASCIIAuthority = "url_non_ascii_authority"

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

	// keepsTarget is set by an update whose target is the stored one and that does not enable a disabled row: a row saved
	// before the ASCII-host rule (#939) can then still be disabled or renamed; the rule applies to every target that is new
	// or changed, and to enabling one (#943).
	keepsTarget bool
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
		if !s.keepsTarget && urlshape.NonASCIIHead(s.Target) {
			return refuse(422, CodeURLNonASCIIAuthority, "a URL's scheme and host must be ASCII; give an international host name as punycode (xn--)")
		}
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

// DeleteChannel removes a channel, enabled or not, with its delivery rows and its sealed secret after two admins
// approved it (alerts.channel.delete, issue #968), and records alert.channel.deleted with the change id in the same
// transaction. A channel is how security alerts reach people, so deleting it is never a single admin's call.
func DeleteChannel(tx *store.TenantTx, id, changeID string, now time.Time) error {
	c, err := tx.AlertChannel(id)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, "channel_not_found", "channel not found")
	} else if err != nil {
		return err
	}
	if err := tx.DeleteAlertChannel(id); err != nil {
		return err
	}
	return recordChange(tx, "alert.channel.deleted", append(channelAudit(c, false), ojson.KV{Key: "change_id", Value: changeID}), changeID, now)
}

// DisableChannel turns an enabled channel off after two admins approved it (alerts.channel.disable): a disabled
// channel delivers nothing. Audited as alert.channel.disabled with the change id, in the same transaction.
func DisableChannel(tx *store.TenantTx, id, changeID string, now time.Time) error {
	c, err := tx.AlertChannel(id)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, "channel_not_found", "channel not found")
	} else if err != nil {
		return err
	}
	if !c.Enabled {
		return refuse(409, "channel_disabled", "the channel is already disabled")
	}
	c.Enabled, c.UpdatedAt = false, now
	if err := tx.UpdateAlertChannel(c); err != nil {
		return err
	}
	return recordChange(tx, "alert.channel.disabled", append(channelAudit(c, false), ojson.KV{Key: "change_id", Value: changeID}), changeID, now)
}

// recordChange audits an applied admin change request, targeting the request, in the applying transaction.
func recordChange(tx *store.TenantTx, action string, d ojson.Object, changeID string, now time.Time) error {
	_, err := audit.Record(tx.Context(), tx, action, d, audit.At(now), audit.Target("admin_change", changeID))
	return err
}

// SeverityRaises reports whether next is a higher min_severity than cur: fewer alerts reach the channel. An unknown
// value is not a raise (the check that follows refuses it).
func SeverityRaises(cur, next string) bool {
	i, j := slices.Index(Severities, cur), slices.Index(Severities, next)
	return i >= 0 && j > i
}

// TargetChanged reports whether target differs from the channel's own (an email list is compared as it is stored). An
// address list that does not parse is not a change: the update's own check refuses it.
func TargetChanged(c *store.AlertChannel, target string) bool {
	t := strings.TrimSpace(target)
	if c.Kind == "email" {
		rs, err := Recipients(t)
		if err != nil || len(rs) == 0 {
			return false
		}
		t = strings.Join(rs, ", ")
	}
	return t != c.Target
}

// CheckRetarget validates a new recipient list for email channel c as the update would (1 to MaxRecipients addresses)
// and returns it normalized. It refuses a webhook (its URL carries a token and never goes in a plain change request)
// and a list that equals the current one. The change request runs it when filed, when approved and when applied, so a
// request that could never apply is refused up front.
func CheckRetarget(c *store.AlertChannel, target string, dev bool) (string, error) {
	if c.Kind != "email" {
		return "", refuse(422, "invalid_kind", "only an email channel's recipients are changed here; a webhook URL carries a token")
	}
	sp := ChannelSpec{Name: c.Name, Kind: c.Kind, Target: target, MinSeverity: c.MinSeverity, Enabled: true}
	if err := sp.check(dev); err != nil {
		return "", err
	}
	if sp.Target == c.Target {
		return "", refuse(409, "target_unchanged", "the channel already sends there")
	}
	return sp.Target, nil
}

// RetargetChannel sends an email channel's alerts to other recipients after two admins approved it
// (alerts.channel.target). A webhook URL carries a token in its path, so it is never put in a plain change request: it
// moves through a configuration proposal, which seals it (config.proposal). Audited as alert.channel.updated with the
// change id, in the same transaction.
func RetargetChannel(tx *store.TenantTx, id, target, changeID string, dev bool, now time.Time) error {
	c, err := tx.AlertChannel(id)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, "channel_not_found", "channel not found")
	} else if err != nil {
		return err
	}
	t, err := CheckRetarget(c, target, dev)
	if err != nil {
		return err
	}
	c.Target, c.UpdatedAt = t, now
	if err := tx.UpdateAlertChannel(c); err != nil {
		return err
	}
	return recordChange(tx, "alert.channel.updated", append(channelAudit(c, false), ojson.KV{Key: "change_id", Value: changeID}), changeID, now)
}

// RotateChannelSecret replaces a webhook's signing secret with secret after two admins approved it
// (alerts.channel.rotate_secret). The secret is sealed under the channel's own AAD; the audit entry records that it
// changed, with the change id, never its value.
func RotateChannelSecret(tx *store.TenantTx, sealer *seal.Sealer, id, secret, changeID string, now time.Time) error {
	c, err := tx.AlertChannel(id)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, "channel_not_found", "channel not found")
	} else if err != nil {
		return err
	}
	if c.Kind != "webhook" {
		return refuse(422, "invalid_secret", "only a webhook has a signing secret")
	}
	if len(secret) < MinSigningSecret || len(secret) > MaxSigningSecret {
		return refuse(422, "invalid_secret", "the signing secret is %d to %d characters", MinSigningSecret, MaxSigningSecret)
	}
	if sealer == nil {
		return errors.New("alerts: no sealer for webhook secrets")
	}
	if c.SecretSealed, err = sealer.Seal([]byte(secret), SecretAAD(tx.Tenant(), c.ID)); err != nil {
		return err
	}
	c.UpdatedAt = now
	if err := tx.UpdateAlertChannel(c); err != nil {
		return err
	}
	return recordChange(tx, "alert.channel.updated", append(channelAudit(c, true), ojson.KV{Key: "change_id", Value: changeID}), changeID, now)
}

// RaiseChannelSeverity raises a channel's min_severity after two admins approved it (alerts.channel.severity): the
// channel then receives fewer alerts. Audited as alert.channel.updated with the change id and the previous severity.
func RaiseChannelSeverity(tx *store.TenantTx, id, severity, changeID string, now time.Time) error {
	c, err := tx.AlertChannel(id)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(404, "channel_not_found", "channel not found")
	} else if err != nil {
		return err
	}
	if !SeverityRaises(c.MinSeverity, severity) {
		return refuse(409, "severity_not_raised", "the new min_severity is not higher than the current one")
	}
	prev := c.MinSeverity
	c.MinSeverity, c.UpdatedAt = severity, now
	if err := tx.UpdateAlertChannel(c); err != nil {
		return err
	}
	return recordChange(tx, "alert.channel.updated",
		append(channelAudit(c, false), ojson.KV{Key: "change_id", Value: changeID}, ojson.KV{Key: "previous_min_severity", Value: prev}), changeID, now)
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
	// Enabling a disabled row is a new use of its target: the host can never be dialed, so the rule applies again.
	s.keepsTarget = s.Target == c.Target && (c.Enabled || !s.Enabled)
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
