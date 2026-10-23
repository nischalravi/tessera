// Package idrules holds the identity rules a tenant tunes in Admin > Identity rules (schema/0766_identity_rules.sql):
// the order the connector resolver correlates a reference to a person, the authoritative source of each person
// attribute and how long a machine identity may go unused before it counts as dormant. The engines read them through
// Load, so the page cannot drift from what they do.
package idrules

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Correlation keys, in the order the engine used before this was configurable.
const (
	KeyExternalID = "external_id"
	KeyEmail      = "email"
)

// CorrelationKeys are the keys a reference can be matched on.
var CorrelationKeys = []string{KeyExternalID, KeyEmail}

// Attributes are the person attributes a tenant can give an authoritative source.
var Attributes = []string{"name", "email", "department", "title"}

// Dormancy limits (days) and the default, the machine-identity threshold of internal/nhi.
const (
	DefaultDormantDays = 30
	MinDormantDays     = 1
	MaxDormantDays     = 3650
)

// Rules are a tenant's identity rules.
type Rules struct {
	CorrelationOrder   []string          `json:"correlation_order"`
	Authoritative      map[string]string `json:"authoritative"`
	DormantServiceDays int               `json:"dormant_service_days"`
	DormantAIAgentDays int               `json:"dormant_ai_agent_days"`
}

// Defaults are the rules of a tenant that saved none.
func Defaults() Rules {
	return Rules{CorrelationOrder: slices.Clone(CorrelationKeys), Authoritative: map[string]string{},
		DormantServiceDays: DefaultDormantDays, DormantAIAgentDays: DefaultDormantDays}
}

// DormantDays is the threshold for an identity type ("service" or "ai_agent"; anything else gets the default).
func (r Rules) DormantDays(identityType string) int {
	if identityType == "ai_agent" {
		return r.DormantAIAgentDays
	}
	return r.DormantServiceDays
}

// Load returns the tenant's rules and their version (0 for the defaults).
func Load(tx *store.TenantTx) (Rules, int, error) {
	row, err := tx.IdentityRules()
	if errors.Is(err, store.ErrNotFound) {
		return Defaults(), 0, nil
	} else if err != nil {
		return Rules{}, 0, err
	}
	r := Rules{DormantServiceDays: row.DormantServiceDays, DormantAIAgentDays: row.DormantAIAgentDays}
	if err := json.Unmarshal([]byte(row.CorrelationOrder), &r.CorrelationOrder); err != nil {
		return Rules{}, 0, fmt.Errorf("idrules: stored correlation order: %w", err)
	}
	if err := json.Unmarshal([]byte(row.Authoritative), &r.Authoritative); err != nil {
		return Rules{}, 0, fmt.Errorf("idrules: stored authoritative sources: %w", err)
	}
	if r.Authoritative == nil {
		r.Authoritative = map[string]string{}
	}
	return r, row.Version, nil
}

var systemRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// Systems lists the systems a tenant's live connections read from: what an authoritative source may name.
func Systems(tx *store.TenantTx) ([]string, error) {
	conns, err := tx.Connections()
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, c := range conns {
		if c.RetiredAt == nil && !slices.Contains(out, c.System) {
			out = append(out, c.System)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Check refuses rules the engines cannot run; systems are the live connection systems.
func (r Rules) Check(systems []string) error {
	if len(r.CorrelationOrder) == 0 {
		return cfgerr.Refuse(422, "invalid_correlation_order", "keep at least one correlation key: %v", CorrelationKeys)
	}
	seen := map[string]bool{}
	for _, k := range r.CorrelationOrder {
		if !slices.Contains(CorrelationKeys, k) || seen[k] {
			return cfgerr.Refuse(422, "invalid_correlation_order", "the correlation order lists each of %v at most once", CorrelationKeys)
		}
		seen[k] = true
	}
	for a, sys := range r.Authoritative {
		switch {
		case !slices.Contains(Attributes, a):
			return cfgerr.Refuse(422, "invalid_attribute", "an authoritative source is set for one of %v", Attributes)
		case !systemRE.MatchString(sys):
			return cfgerr.Refuse(422, "invalid_source", "the source of %s is a connection system name", a)
		case !slices.Contains(systems, sys):
			return cfgerr.Refuse(422, "unknown_source", "%q is not the system of a connection of this tenant", sys)
		}
	}
	for name, d := range map[string]int{"dormant_service_days": r.DormantServiceDays, "dormant_ai_agent_days": r.DormantAIAgentDays} {
		if d < MinDormantDays || d > MaxDormantDays {
			return cfgerr.Refuse(422, "invalid_dormancy", "%s is %d to %d days", name, MinDormantDays, MaxDormantDays)
		}
	}
	return nil
}

func detail(r Rules) ojson.Object {
	auth := ojson.Object{}
	for _, a := range Attributes {
		if sys, ok := r.Authoritative[a]; ok {
			auth = append(auth, ojson.KV{Key: a, Value: sys})
		}
	}
	return ojson.Object{{Key: "correlation_order", Value: r.CorrelationOrder}, {Key: "authoritative", Value: auth},
		{Key: "dormant_service_days", Value: r.DormantServiceDays}, {Key: "dormant_ai_agent_days", Value: r.DormantAIAgentDays}}
}

// Save replaces the tenant's rules. ver is the version the caller read (0 for the defaults); a different current version
// is a conflict. The change is audited in the same transaction, with the old values.
func Save(tx *store.TenantTx, r Rules, ver int, by string, now time.Time) (Rules, int, error) {
	systems, err := Systems(tx)
	if err != nil {
		return Rules{}, 0, err
	}
	if r.Authoritative == nil {
		r.Authoritative = map[string]string{}
	}
	if err := r.Check(systems); err != nil {
		return Rules{}, 0, err
	}
	old, cur, err := Load(tx)
	if err != nil {
		return Rules{}, 0, err
	}
	if ver != cur {
		return Rules{}, 0, cfgerr.Conflict(ver, cur)
	}
	order, _ := json.Marshal(r.CorrelationOrder)
	auth, _ := json.Marshal(r.Authoritative)
	row := &store.IdentityRulesRow{CorrelationOrder: string(order), Authoritative: string(auth), DormantServiceDays: r.DormantServiceDays,
		DormantAIAgentDays: r.DormantAIAgentDays, UpdatedBy: by}
	if err := tx.PutIdentityRules(row, now); err != nil {
		return Rules{}, 0, err
	}
	d := append(detail(r), ojson.KV{Key: "previous", Value: detail(old)}, ojson.KV{Key: "version", Value: cur + 1})
	if err := tx.Audit(now, by, "identity.rules.update", d); err != nil {
		return Rules{}, 0, err
	}
	return r, cur + 1, nil
}
