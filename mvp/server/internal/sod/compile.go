package sod

import (
	"encoding/json"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Compile returns the risks the tenant's enabled rulesets check: active risks
// with at least two active functions, in ruleset and risk order.
func Compile(tx *store.TenantTx) ([]*Risk, error) {
	rulesets, err := tx.SodRulesets()
	if err != nil {
		return nil, err
	}
	fns, err := tx.SodFunctions()
	if err != nil {
		return nil, err
	}
	risks, err := tx.SodRisks()
	if err != nil {
		return nil, err
	}
	links, err := tx.SodRiskFunctions()
	if err != nil {
		return nil, err
	}
	optRows, err := tx.SodRiskOptions()
	if err != nil {
		return nil, err
	}
	optsOf := map[string][]string{}
	for _, o := range optRows {
		optsOf[o.RiskID] = append(optsOf[o.RiskID], o.Option)
	}
	rsByID := map[string]*store.SodRuleset{}
	for _, r := range rulesets {
		if r.Enabled && r.Status == store.SodActive {
			rsByID[r.ID] = r
		}
	}
	compiled := map[string]*Function{}
	for _, f := range fns {
		if f.Status != store.SodActive {
			continue
		}
		var sels []Selector
		if err := json.Unmarshal([]byte(f.Selectors), &sels); err != nil {
			return nil, fmt.Errorf("sod: stored function %s: %w", f.ID, err)
		}
		compiled[f.ID] = &Function{ID: f.ID, Key: f.Key, Name: f.Name, Selectors: sels}
	}
	linked := map[string][]*Function{}
	for _, l := range links {
		if f := compiled[l.FunctionID]; f != nil {
			linked[l.RiskID] = append(linked[l.RiskID], f)
		}
	}
	var out []*Risk
	for _, r := range risks {
		rs := rsByID[r.RulesetID]
		if rs == nil || r.Status != store.SodActive || len(linked[r.ID]) < 2 {
			continue
		}
		var subj Subjects
		if err := json.Unmarshal([]byte(r.Subjects), &subj); err != nil {
			return nil, fmt.Errorf("sod: stored risk %s: %w", r.ID, err)
		}
		out = append(out, &Risk{ID: r.ID, Key: r.Key, Name: r.Name, Description: r.Description, Priority: r.Priority,
			BusinessProcess: r.BusinessProcess, OwnerID: r.OwnerID, Version: r.Version,
			Ruleset: RulesetRef{rs.ID, rs.Key, rs.Name}, Functions: linked[r.ID], Subjects: subj, Remediation: orderOptions(optsOf[r.ID])})
	}
	return out, nil
}

// CompileBundle compiles a bundle without storing it: the risks a tenant that
// has no stored rulesets is checked against (its legacy YAML policies). Ids
// are the keys, since nothing is stored.
func CompileBundle(b *Bundle) []*Risk {
	if !b.Ruleset.Enabled {
		return nil
	}
	fns := map[string]*Function{}
	for _, d := range b.Functions {
		fns[d.Key] = &Function{ID: d.Key, Key: d.Key, Name: d.Name, Selectors: d.Selectors}
	}
	var out []*Risk
	for _, d := range b.Risks {
		r := &Risk{ID: d.Key, Key: d.Key, Name: d.Name, Description: d.Description, Priority: d.Priority,
			BusinessProcess: d.BusinessProcess, Version: 1, Ruleset: RulesetRef{b.Ruleset.Key, b.Ruleset.Key, b.Ruleset.Name}}
		if d.Subjects != nil {
			r.Subjects = *d.Subjects
		}
		r.Remediation = d.Remediation
		for _, k := range d.Functions {
			if f := fns[k]; f != nil {
				r.Functions = append(r.Functions, f)
			}
		}
		if len(r.Functions) >= 2 {
			out = append(out, r)
		}
	}
	return out
}

// Load returns the risks to check: the tenant's stored rulesets, or, when it
// has none yet, the fallback bundle (its legacy YAML SoD policies; nil for none).
func Load(tx *store.TenantTx, fallback *Bundle) ([]*Risk, error) {
	n, err := tx.CountSodRulesets()
	if err != nil {
		return nil, err
	}
	if n == 0 && fallback != nil {
		return CompileBundle(fallback), nil
	}
	return Compile(tx)
}
