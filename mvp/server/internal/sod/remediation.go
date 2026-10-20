package sod

import (
	"encoding/json"
	"errors"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Remediation configuration (issue #298): what a violation offers. A risk with
// options of its own offers those; otherwise it offers its ruleset's options;
// with neither it offers all four. An escalation goes to the approver its
// ruleset names, or to the risk's owner.

// Where a risk's remediation options come from.
const (
	SourceRisk    = "risk"
	SourceRuleset = "ruleset"
	SourceDefault = "default"
)

// Remediation is the effective remediation of one risk.
type Remediation struct {
	// Explicit is the options offered when not all four are; empty offers all.
	Explicit   []string
	Source     string
	EscalateTo *int64 // the ruleset's approver, if one is set
}

// Offers reports whether the risk offers option.
func (r Remediation) Offers(option string) bool { return Offers(r.Explicit, option) }

// Target is who an escalation of the risk goes to: the ruleset's approver, else the risk owner.
func (r Remediation) Target(risk *store.SodRisk) *int64 {
	if r.EscalateTo != nil {
		return r.EscalateTo
	}
	return risk.OwnerID
}

// List is the offered options in display order.
func (r Remediation) List() []string {
	out := []string{}
	for _, o := range RemediationOptions {
		if r.Offers(o) {
			out = append(out, o)
		}
	}
	return out
}

// RemediationIndex gives each risk its effective remediation.
type RemediationIndex struct {
	risk    map[string][]string
	ruleset map[string]*store.SodRulesetRemediation
	rsOf    map[string]string // risk id -> ruleset id
}

// LoadRemediation reads the tenant's remediation configuration once.
func LoadRemediation(tx *store.TenantTx) (*RemediationIndex, error) {
	idx := &RemediationIndex{risk: map[string][]string{}, ruleset: map[string]*store.SodRulesetRemediation{}, rsOf: map[string]string{}}
	opts, err := tx.SodRiskOptions()
	if err != nil {
		return nil, err
	}
	for _, o := range opts {
		idx.risk[o.RiskID] = append(idx.risk[o.RiskID], o.Option)
	}
	rows, err := tx.SodRulesetRemediations()
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		idx.ruleset[r.RulesetID] = r
	}
	risks, err := tx.SodRisks()
	if err != nil {
		return nil, err
	}
	for _, r := range risks {
		idx.rsOf[r.ID] = r.RulesetID
	}
	return idx, nil
}

// Ruleset returns a ruleset's stored defaults, or nil.
func (i *RemediationIndex) Ruleset(rulesetID string) *store.SodRulesetRemediation {
	return i.ruleset[rulesetID]
}

// EscalateTo is the approver a ruleset names for escalations, or nil.
func (i *RemediationIndex) EscalateTo(rulesetID string) *int64 {
	if r := i.ruleset[rulesetID]; r != nil {
		return r.EscalateTo
	}
	return nil
}

// RulesetOptions decodes a ruleset's stored options (empty: all four).
func RulesetOptions(r *store.SodRulesetRemediation) []string {
	if r == nil {
		return nil
	}
	var out []string
	if json.Unmarshal([]byte(r.Options), &out) != nil {
		return nil
	}
	return orderOptions(out)
}

// For returns the effective remediation of a risk.
func (i *RemediationIndex) For(riskID string) Remediation {
	rr := i.ruleset[i.rsOf[riskID]]
	out := Remediation{Source: SourceDefault}
	if rr != nil {
		out.EscalateTo = rr.EscalateTo
	}
	if own := orderOptions(i.risk[riskID]); len(own) > 0 {
		out.Explicit, out.Source = own, SourceRisk
	} else if rs := RulesetOptions(rr); len(rs) > 0 {
		out.Explicit, out.Source = rs, SourceRuleset
	}
	return out
}

// RemediationOf returns one risk's effective remediation.
func RemediationOf(tx *store.TenantTx, riskID string) (Remediation, error) {
	idx, err := LoadRemediation(tx)
	if err != nil {
		return Remediation{}, err
	}
	return idx.For(riskID), nil
}

// RulesetRemediationInput is a ruleset's remediation defaults.
type RulesetRemediationInput struct {
	Options    []string // none, or all four: the ruleset offers all
	EscalateTo *int64   // nil: escalations go to the risk owner
}

// SetRulesetRemediation sets which remediations a ruleset's risks offer unless
// they say otherwise, and who an escalation goes to. It is audited in the same
// transaction.
func (w *Writer) SetRulesetRemediation(rulesetID string, in RulesetRemediationInput) (*store.SodRulesetRemediation, error) {
	rs, err := w.Tx.SodRuleset(rulesetID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(404, "ruleset_not_found", "ruleset not found")
	} else if err != nil {
		return nil, err
	}
	if rs.Status != store.SodActive {
		return nil, refuse(409, "ruleset_retired", "%s is retired", rs.Name)
	}
	opts, err := normalizeOptions(in.Options)
	if err != nil {
		return nil, err
	}
	if in.EscalateTo != nil {
		who, err := w.Tx.Identity(*in.EscalateTo)
		if errors.Is(err, store.ErrNotFound) {
			return nil, refuse(422, "approver_not_found", "the escalation approver is not a known identity")
		} else if err != nil {
			return nil, err
		}
		if who.Status != "active" {
			return nil, refuse(422, "approver_not_active", "%s is not active", who.Name)
		}
	}
	row := &store.SodRulesetRemediation{RulesetID: rs.ID, Options: string(mustJSON(append([]string{}, opts...))), EscalateTo: in.EscalateTo,
		UpdatedBy: w.By.Display, UpdatedAt: w.Now}
	if err := w.Tx.PutSodRulesetRemediation(row); err != nil {
		return nil, err
	}
	offered := opts
	if len(offered) == 0 {
		offered = RemediationOptions
	}
	d := ojson.Object{{Key: "ruleset_id", Value: rs.ID}, {Key: "key", Value: rs.Key}, {Key: "remediation", Value: offered}}
	if in.EscalateTo != nil {
		d = append(d, ojson.KV{Key: "escalate_to", Value: *in.EscalateTo})
	}
	return row, w.audit("sod.ruleset.remediation", d)
}
