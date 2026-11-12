package admin

import (
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
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
const (
	TypeAlertChannelDisable  = "alerts.channel.disable"
	TypeAlertChannelDelete   = "alerts.channel.delete"
	TypeAlertChannelTarget   = "alerts.channel.target"
	TypeAlertChannelSeverity = "alerts.channel.severity"
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
		func(_ *env, v *alertChannelPayload) string { return "Disable alert channel " + v.ChannelID })
	changeTypes[TypeAlertChannelDelete] = typed(TypeAlertChannelDelete, nil, planChannelDelete, applyChannelDelete,
		func(_ *env, v *alertChannelPayload) string { return "Delete alert channel " + v.ChannelID })
	changeTypes[TypeAlertChannelTarget] = typed(TypeAlertChannelTarget, nil, planChannelTarget, applyChannelTarget,
		func(_ *env, v *alertChannelTargetPayload) string {
			return "Change where alert channel " + v.ChannelID + " sends"
		})
	changeTypes[TypeAlertChannelSeverity] = typed(TypeAlertChannelSeverity, nil, planChannelSeverity, applyChannelSeverity,
		func(_ *env, v *alertChannelSeverityPayload) string {
			return "Raise the minimum severity of alert channel " + v.ChannelID + " to " + v.MinSeverity
		})
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
		return plan{}, invalid("a webhook URL carries a token: change it with a configuration proposal (POST /api/proposals/alert-channels/%s)", c.ID)
	}
	if !alerts.TargetChanged(c, v.Target) {
		return plan{}, invalid("the channel already sends there, or the target is not valid")
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
