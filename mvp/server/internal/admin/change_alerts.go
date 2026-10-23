package admin

import (
	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeAlertRuleLoosen loosens a security alert rule (issue #521): disable it, lower its severity, raise its
// threshold or shorten its window. The alert is the only control on some tampering (every schedule paused, a
// provisioning failure, an OAuth app grant), so one admin must not switch it off alone: the requester proposes, a
// different admin approves what the payload hash says. Tightening a rule, and any change to another rule, stay a
// plain PUT /api/alerts/rules/{id} (with a step-up).
const TypeAlertRuleLoosen = "alerts.rule.loosen"

type alertRulePayload struct {
	RuleID        string `json:"rule_id"`
	Enabled       bool   `json:"enabled"`
	Severity      string `json:"severity"`
	Threshold     int    `json:"threshold"`
	WindowMinutes int    `json:"window_minutes"`
}

func (v *alertRulePayload) spec() alerts.RuleSpec {
	return alerts.RuleSpec{Enabled: v.Enabled, Severity: v.Severity, Threshold: v.Threshold, WindowMinutes: v.WindowMinutes}
}

func init() {
	changeTypes[TypeAlertRuleLoosen] = typed(TypeAlertRuleLoosen, nil, planAlertRule, applyAlertRule,
		func(_ *env, v *alertRulePayload) string { return "Loosen alert rule " + v.RuleID })
}

func planAlertRule(e *env, v *alertRulePayload) (plan, error) {
	if err := alerts.CheckRule(v.RuleID, v.spec()); err != nil {
		return plan{}, invalid("%v", err)
	}
	cur, err := alerts.EffectiveRule(e.tx, v.RuleID)
	if err != nil {
		return plan{}, err
	}
	if !alerts.IsSecurityRule(v.RuleID) {
		return plan{}, invalid("rule %s is not a security rule: change it with PUT /api/alerts/rules/%s", v.RuleID, v.RuleID)
	}
	if !alerts.Loosens(*cur, v.spec()) {
		return plan{}, invalid("this does not loosen the rule: change it with PUT /api/alerts/rules/%s", v.RuleID)
	}
	return plan{twoPerson: true, target: v.RuleID}, nil
}

func applyAlertRule(e *env, ch *store.AdminChange, v *alertRulePayload) error {
	if _, err := planAlertRule(e, v); err != nil {
		return err
	}
	return alerts.SetRule(e.tx, v.RuleID, v.spec(), alerts.Actor{UserID: e.by.String(), Display: "admin change " + ch.ID.String()}, e.now)
}
