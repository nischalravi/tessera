package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Alert channels are how security alerts reach people, so anything that stops or redirects them takes two admins
// (issue #968), as loosening a security rule does: the requester proposes, a different admin approves what the payload
// hash says. Enabling a channel, lowering min_severity and renaming stay a plain PUT /api/alerts/channels/{id}.
//
//	alerts.channel.disable   turn an enabled channel off
//	alerts.channel.delete    delete a channel, enabled or not, with its deliveries and sealed secret
//	alerts.channel.target    send an email channel's alerts to other recipients (a webhook URL carries a token, so a new
//	                         one goes through a configuration proposal, which seals it)
//	alerts.channel.severity  raise min_severity (the channel then receives fewer alerts)
//	alerts.channel.rotate_secret  replace a webhook's signing secret (a receiver that verifies signatures rejects what is
//	                         signed with the new one until it holds it). The requester chooses the secret and sends it as
//	                         client_secret: it is sealed apart from the payload, never shown, and cleared when the request ends
//
// A summary names the channel (name and type) and the old and new value of the field that changes, never a secret. It
// is kept as it read when the request is applied (admin_change_summaries), so a reviewer reading history later still sees
// the true old value and the name of a channel that is gone (issue #977).
const (
	TypeAlertChannelDisable  = "alerts.channel.disable"
	TypeAlertChannelDelete   = "alerts.channel.delete"
	TypeAlertChannelTarget   = "alerts.channel.target"
	TypeAlertChannelSeverity = "alerts.channel.severity"
	TypeAlertChannelRotate   = "alerts.channel.rotate_secret"
)

type alertChannelPayload struct {
	ChannelID string `json:"channel_id"`
}

type alertChannelTargetPayload struct {
	ChannelID string `json:"channel_id"`
	Target    string `json:"target"`
}

type alertChannelSeverityPayload struct {
	ChannelID   string `json:"channel_id"`
	MinSeverity string `json:"min_severity"`
}

func init() {
	changeTypes[TypeAlertChannelDisable] = typed(TypeAlertChannelDisable, nil, planChannelDisable, applyChannelDisable,
		func(e *env, v *alertChannelPayload) string {
			return "Disable alert channel " + channelLabel(e, v.ChannelID) + ": enabled \u2192 disabled"
		})
	changeTypes[TypeAlertChannelDelete] = typed(TypeAlertChannelDelete, nil, planChannelDelete, applyChannelDelete,
		func(e *env, v *alertChannelPayload) string {
			return "Delete alert channel " + channelLabel(e, v.ChannelID)
		})
	changeTypes[TypeAlertChannelTarget] = typed(TypeAlertChannelTarget, nil, planChannelTarget, applyChannelTarget,
		func(e *env, v *alertChannelTargetPayload) string {
			from := "?"
			if c, err := e.tx.AlertChannel(v.ChannelID); err == nil && c.Kind == "email" {
				from = c.Target
			}
			return "Change where alert channel " + channelLabel(e, v.ChannelID) + " sends: " + clip(from) + " \u2192 " + clip(v.Target)
		})
	changeTypes[TypeAlertChannelSeverity] = typed(TypeAlertChannelSeverity, nil, planChannelSeverity, applyChannelSeverity,
		func(e *env, v *alertChannelSeverityPayload) string {
			from := "?"
			if c, err := e.tx.AlertChannel(v.ChannelID); err == nil {
				from = c.MinSeverity
			}
			return "Raise the minimum severity of alert channel " + channelLabel(e, v.ChannelID) + ": " + from + " \u2192 " + v.MinSeverity
		})
	rot := typed(TypeAlertChannelRotate, nil, planChannelRotate, applyChannelRotate,
		func(e *env, v *alertChannelPayload) string {
			return "Replace the signing secret of alert channel " + channelLabel(e, v.ChannelID) + ": current \u2192 new (not shown)"
		})
	rot.submitSecret = func(e *env, v any, id uuid.UUID, secret string) ([]byte, error) {
		switch {
		case secret == "":
			return nil, invalid("client_secret is required: the new signing secret, %d to %d characters", alerts.MinSigningSecret, alerts.MaxSigningSecret)
		case len(secret) < alerts.MinSigningSecret || len(secret) > alerts.MaxSigningSecret:
			return nil, invalid("client_secret must be %d to %d characters", alerts.MinSigningSecret, alerts.MaxSigningSecret)
		case e.svc.Sealer == nil:
			return nil, newErr(503, "sealer_unavailable", "no key-encryption key is configured to seal the signing secret")
		}
		c, err := alertChannelOf(e, v.(*alertChannelPayload).ChannelID)
		if err != nil {
			return nil, err
		}
		// The sealed blob also holds the fingerprint of the secret the channel has now, so a rotation filed before
		// another rotation or a move to a new URL (which always brings its own secret) can never overwrite it.
		b, err := json.Marshal(sealedRotation{Secret: secret, Base: secretBase(c)}) // #nosec G117 -- sealed on the next lines, never stored or logged in the clear
		if err != nil {
			return nil, err
		}
		return e.svc.Sealer.Seal(b, secretAAD(e.tx.Tenant(), id))
	}
	changeTypes[TypeAlertChannelRotate] = rot
	for _, t := range []string{TypeAlertChannelDisable, TypeAlertChannelDelete, TypeAlertChannelTarget, TypeAlertChannelSeverity, TypeAlertChannelRotate} {
		changeTypes[t].keepSummary = true
	}
}

// sealedRotation is the plaintext of an alerts.channel.rotate_secret request's secret_enc: the new secret and the
// fingerprint of the channel's sealed secret when the request was filed. It never leaves the admin package.
type sealedRotation struct {
	Secret string `json:"secret"`
	Base   string `json:"base"`
}

// secretBase fingerprints a channel's current sealed signing secret (a hash of the ciphertext, which is fresh on every
// seal, so it changes whenever the secret is replaced, including by a move to another origin).
func secretBase(c *store.AlertChannel) string {
	h := sha256.Sum256(c.SecretSealed)
	return hex.EncodeToString(h[:])
}

// openRotation opens the sealed rotation of ch into the env, for the re-plan at approve and apply.
func (e *env) openRotation(ch *store.AdminChange) error {
	if len(ch.SecretEnc) == 0 {
		return conflict(ReasonPayloadTampered, "the sealed signing secret of the request is missing")
	}
	if e.svc.Sealer == nil {
		return newErr(503, "sealer_unavailable", "no key-encryption key is configured to open the signing secret")
	}
	b, err := e.svc.Sealer.Open(ch.SecretEnc, secretAAD(e.tx.Tenant(), ch.ID))
	if err != nil {
		return conflict(ReasonPayloadTampered, "the sealed signing secret of the request does not open")
	}
	var r sealedRotation
	if json.Unmarshal(b, &r) != nil || r.Secret == "" || r.Base == "" {
		return conflict(ReasonPayloadTampered, "the sealed signing secret of the request does not open")
	}
	e.rotation, e.change = &r, ch.ID
	return nil
}

// channelLabel names a channel in a summary: its name and type, or the id when the channel is gone. The name is the
// admin's own text, so it is quoted and clipped; no secret or target URL is ever part of it.
func channelLabel(e *env, id string) string {
	c, err := e.tx.AlertChannel(id)
	if err != nil {
		return id
	}
	return fmt.Sprintf("%q (%s, %s)", clip(c.Name), c.Kind, c.ID)
}

func clip(s string) string {
	if r := []rune(s); len(r) > 80 {
		return string(r[:80]) + "\u2026"
	}
	return s
}

func alertChannelOf(e *env, id string) (*store.AlertChannel, error) {
	c, err := e.tx.AlertChannel(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalid("no alert channel %s", id)
	}
	return c, err
}

func planChannelDisable(e *env, v *alertChannelPayload) (plan, error) {
	c, err := alertChannelOf(e, v.ChannelID)
	if err != nil {
		return plan{}, err
	}
	if !c.Enabled {
		return plan{}, invalid("alert channel %s is already disabled", v.ChannelID)
	}
	return plan{twoPerson: true, target: c.ID}, nil
}

func applyChannelDisable(e *env, ch *store.AdminChange, v *alertChannelPayload) error {
	if _, err := planChannelDisable(e, v); err != nil {
		return err
	}
	return alerts.DisableChannel(e.tx, v.ChannelID, ch.ID.String(), e.now)
}

func planChannelDelete(e *env, v *alertChannelPayload) (plan, error) {
	c, err := alertChannelOf(e, v.ChannelID)
	if err != nil {
		return plan{}, err
	}
	return plan{twoPerson: true, target: c.ID}, nil
}

func applyChannelDelete(e *env, ch *store.AdminChange, v *alertChannelPayload) error {
	if _, err := planChannelDelete(e, v); err != nil {
		return err
	}
	return alerts.DeleteChannel(e.tx, v.ChannelID, ch.ID.String(), e.now)
}

func planChannelTarget(e *env, v *alertChannelTargetPayload) (plan, error) {
	c, err := alertChannelOf(e, v.ChannelID)
	if err != nil {
		return plan{}, err
	}
	if c.Kind != "email" {
		return plan{}, invalid("a webhook URL carries a token, so it is never put in a change request: add a channel with the new URL and file %s for this one, or have a machine client propose it (POST /api/proposals/alert-channels/%s)", TypeAlertChannelDelete, c.ID)
	}
	if _, err := alerts.CheckRetarget(c, v.Target, !e.svc.Prod); err != nil {
		var re *alerts.Error
		if errors.As(err, &re) {
			return plan{}, invalid("%s", re.Msg)
		}
		return plan{}, err
	}
	return plan{twoPerson: true, target: c.ID}, nil
}

func applyChannelTarget(e *env, ch *store.AdminChange, v *alertChannelTargetPayload) error {
	if _, err := planChannelTarget(e, v); err != nil {
		return err
	}
	return alerts.RetargetChannel(e.tx, v.ChannelID, v.Target, ch.ID.String(), !e.svc.Prod, e.now)
}

func planChannelSeverity(e *env, v *alertChannelSeverityPayload) (plan, error) {
	c, err := alertChannelOf(e, v.ChannelID)
	if err != nil {
		return plan{}, err
	}
	if !alerts.SeverityRaises(c.MinSeverity, v.MinSeverity) {
		return plan{}, invalid("this does not raise min_severity (now %s): change it with PUT /api/alerts/channels/%s", c.MinSeverity, v.ChannelID)
	}
	return plan{twoPerson: true, target: c.ID}, nil
}

func applyChannelSeverity(e *env, ch *store.AdminChange, v *alertChannelSeverityPayload) error {
	if _, err := planChannelSeverity(e, v); err != nil {
		return err
	}
	return alerts.RaiseChannelSeverity(e.tx, v.ChannelID, v.MinSeverity, ch.ID.String(), e.now)
}

func planChannelRotate(e *env, v *alertChannelPayload) (plan, error) {
	c, err := alertChannelOf(e, v.ChannelID)
	if err != nil {
		return plan{}, err
	}
	if c.Kind != "webhook" {
		return plan{}, invalid("only a webhook has a signing secret")
	}
	if e.rotation != nil && !seal.Equal([]byte(e.rotation.Base), []byte(secretBase(c))) {
		return plan{}, conflict("stale_base", "the channel's signing secret was replaced since this request was filed "+
			"(another rotation, or a new URL with its own secret): file a new request")
	}
	return plan{twoPerson: true, target: c.ID}, nil
}

func applyChannelRotate(e *env, ch *store.AdminChange, v *alertChannelPayload) error {
	if e.rotation == nil {
		if err := e.openRotation(ch); err != nil {
			return err
		}
	}
	if _, err := planChannelRotate(e, v); err != nil {
		return err
	}
	return alerts.RotateChannelSecret(e.tx, e.svc.Sealer, v.ChannelID, e.rotation.Secret, ch.ID.String(), e.now)
}
