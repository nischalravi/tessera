package admin

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeLPSettingsUpdate changes the least-privilege loop's settings (issue #661, LP-5; design
// docs/design/least-privilege-loop.md sections 3 and 5.1): its mode, the caps, the announce and finalize periods
// and the kill switch. Tightening takes one admin and applies at once (a lower mode, a smaller cap, a longer
// period, pausing). Loosening takes two: a stronger mode, a larger cap, a shorter period, a lower auto threshold,
// and resuming a paused loop. The requester proposes, a different admin approves what the payload hash says
// (self-approval is refused, as for every change). Pausing alone, by one person, is POST /api/lp/pause.
const TypeLPSettingsUpdate = "lp.settings.update"

func init() {
	changeTypes[TypeLPSettingsUpdate] = typed(TypeLPSettingsUpdate, nil, planLP, applyLP,
		func(_ *env, v *lp.SettingsUpdate) string {
			var parts []string
			if v.Mode != nil {
				parts = append(parts, "mode "+*v.Mode)
			}
			if v.Paused != nil {
				parts = append(parts, map[bool]string{true: "pause", false: "resume"}[*v.Paused])
			}
			for _, c := range []struct {
				name string
				v    *int
			}{{"cap per run", v.CapPerRun}, {"cap per day", v.CapPerDay}, {"cap per account", v.CapPerAccount},
				{"cap per principal", v.CapPerPrincipal}, {"announce days", v.AnnounceDays}, {"finalize days", v.FinalizeDays},
				{"auto threshold days", v.AutoMinDays}} {
				if c.v != nil {
					parts = append(parts, fmt.Sprintf("%s %d", c.name, *c.v))
				}
			}
			return "Change the least-privilege loop (" + strings.Join(parts, ", ") + ")"
		})
}

func lpErr(err error) error {
	var le *lp.Error
	if errors.As(err, &le) {
		return newErr(le.Status, le.Code, "%s", le.Msg)
	}
	return err
}

func planLP(e *env, v *lp.SettingsUpdate) (plan, error) {
	cur, err := e.tx.LPSettings()
	if err != nil {
		return plan{}, err
	}
	_, loosens, err := lp.Plan(cur, v)
	if err != nil {
		return plan{}, lpErr(err)
	}
	return plan{twoPerson: loosens, target: "lp"}, nil
}

func applyLP(e *env, ch *store.AdminChange, v *lp.SettingsUpdate) error {
	cur, err := e.tx.LPSettings()
	if err != nil {
		return err
	}
	// planned again against the settings of now, so a request that went stale while it waited is refused
	next, _, err := lp.Plan(cur, v)
	if err != nil {
		return lpErr(err)
	}
	by := ch.RequestedBy.String()
	if ch.ApprovedBy != nil {
		by = ch.ApprovedBy.String()
	}
	if next.Paused && !cur.Paused {
		next.PausedBy, next.PausedAt = ch.RequestedBy.String(), &e.now
	}
	next.UpdatedBy = by
	if err := e.tx.PutLPSettings(next, e.now); err != nil {
		return err
	}
	detail := ojson.Object{{Key: "change_id", Value: ch.ID.String()}, {Key: "requested_by", Value: ch.RequestedBy.String()},
		{Key: "mode", Value: next.Mode}, {Key: "paused", Value: next.Paused}, {Key: "cap_per_run", Value: next.CapPerRun},
		{Key: "cap_per_day", Value: next.CapPerDay}, {Key: "cap_per_account", Value: next.CapPerAccount},
		{Key: "cap_per_principal", Value: next.CapPerPrincipal}, {Key: "announce_days", Value: next.AnnounceDays},
		{Key: "finalize_days", Value: next.FinalizeDays}, {Key: "auto_min_days", Value: next.AutoMinDays}}
	if ch.ApprovedBy != nil {
		detail = append(detail, ojson.KV{Key: "approved_by", Value: ch.ApprovedBy.String()})
	}
	_, err = audit.Record(e.tx.Context(), e.tx, "lp.settings_updated", detail, audit.At(e.now), audit.Target("admin_change", ch.ID.String()))
	return err
}
