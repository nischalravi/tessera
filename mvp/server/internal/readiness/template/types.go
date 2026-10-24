// Package template loads, lints and resolves the deployment-readiness
// checklist templates (design §3) and merges tenant overlays under the
// no-downgrade rule (§3.5).
//
// A template is a versioned list of checklist items for one connector type.
// Every template extends the shared base template. Items declare a level, how
// they are verified, a remediation hint, dependencies and applicability in a
// closed vocabulary: there is no expression language.
package template

import "slices"

// Level is how strongly an item gates activation.
type Level string

// Item levels.
const (
	Required    Level = "required"    // blocks activation
	Recommended Level = "recommended" // must pass, or be skipped with a reason
	Optional    Level = "optional"    // informational; never blocks
)

// Rank orders levels: optional < recommended < required. Unknown levels rank -1.
func (l Level) Rank() int {
	switch l {
	case Optional:
		return 0
	case Recommended:
		return 1
	case Required:
		return 2
	}
	return -1
}

// Valid reports whether l is a known level.
func (l Level) Valid() bool { return l.Rank() >= 0 }

// VerifyKind is how an item is proven.
type VerifyKind string

// Verification kinds (§3.3).
const (
	Attestation VerifyKind = "attestation" // a named person confirms it, with a note
	Live        VerifyKind = "live"        // a read-only check against the system
	Data        VerifyKind = "data"        // a check over the staged dry-run snapshot
)

// Verify is one way an item is proven. All of an item's verifications must pass.
type Verify struct {
	Kind   VerifyKind     `yaml:"kind" json:"kind"`
	Check  string         `yaml:"check,omitempty" json:"check,omitempty"`
	Params map[string]any `yaml:"params,omitempty" json:"params,omitempty"`
	// OnUnsupported names the alternative that stands in for a live check the
	// system cannot answer (it reports "unsupported"). The only value is
	// "attestation". A failing result is never replaced by it.
	OnUnsupported VerifyKind `yaml:"on_unsupported,omitempty" json:"on_unsupported,omitempty"`
}

// Remediation tells the user how to fix a failing item.
type Remediation struct {
	Hint string `yaml:"hint" json:"hint"`
	Link string `yaml:"link,omitempty" json:"link,omitempty"`
}

// AppliesWhen restricts when an item applies. Only these keys exist; all are
// ANDed, and an empty list means "no constraint".
type AppliesWhen struct {
	WriteMode               []string `yaml:"write_mode,omitempty" json:"write_mode,omitempty"`
	Role                    []string `yaml:"role,omitempty" json:"role,omitempty"`
	TenantHasConnectionType []string `yaml:"tenant_has_connection_type,omitempty" json:"tenant_has_connection_type,omitempty"`
	ConfigFlag              string   `yaml:"config_flag,omitempty" json:"config_flag,omitempty"`
}

// Item is one checklist item.
type Item struct {
	ID          string       `yaml:"id" json:"id"`
	Title       string       `yaml:"title" json:"title"`
	Category    string       `yaml:"category" json:"category"`
	Level       Level        `yaml:"level" json:"level"`
	Why         string       `yaml:"why" json:"why"`
	Verify      []Verify     `yaml:"verify" json:"verify"`
	Remediation Remediation  `yaml:"remediation" json:"remediation"`
	DependsOn   []string     `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	AppliesWhen *AppliesWhen `yaml:"applies_when,omitempty" json:"applies_when,omitempty"`
	// ConfigFields are the typed-config fields the item's evidence depends
	// on (§4.5). Empty means every field: any config change makes it stale.
	ConfigFields []string `yaml:"config_fields,omitempty" json:"config_fields,omitempty"`

	// TemplateLevel is the level before any overlay raised it (set on resolve).
	TemplateLevel Level `yaml:"-" json:"template_level,omitempty"`
	// Source is "base", the template id, or "overlay" for custom items.
	Source string `yaml:"-" json:"source,omitempty"`
}

// HasKind reports whether the item has a verification of kind k.
func (it *Item) HasKind(k VerifyKind) bool {
	return slices.ContainsFunc(it.Verify, func(v Verify) bool { return v.Kind == k })
}

// HasLiveAlternative reports whether a live verification of the item may be
// replaced by an attestation when the system reports it unsupported.
func (it *Item) HasLiveAlternative() bool {
	return slices.ContainsFunc(it.Verify, func(v Verify) bool { return v.Kind == Live && v.OnUnsupported == Attestation })
}

// OnlyAttestation reports whether every verification is an attestation.
func (it *Item) OnlyAttestation() bool {
	return len(it.Verify) > 0 && !slices.ContainsFunc(it.Verify, func(v Verify) bool { return v.Kind != Attestation })
}

// Template is one parsed template file.
type Template struct {
	ID             string   `yaml:"template"`
	Version        string   `yaml:"version"`
	Extends        string   `yaml:"extends,omitempty"`
	DisplayName    string   `yaml:"display_name"`
	ConnectorTypes []string `yaml:"connector_types"`
	Role           string   `yaml:"role,omitempty"`
	// Inventory marks a source that reports findings, snapshots or contractor
	// records rather than an account population: the staged account data checks
	// (key, fill and correlation rates) do not apply to it.
	Inventory             bool                `yaml:"inventory,omitempty"`
	DefaultCorrelationKey string              `yaml:"default_correlation_key,omitempty"`
	DefaultHRIDAttribute  string              `yaml:"default_hr_id_attribute,omitempty"`
	HostAllowlist         []string            `yaml:"host_allowlist,omitempty"`
	RequiredAttributes    map[string][]string `yaml:"required_attributes,omitempty"`
	RecommendedAttributes map[string][]string `yaml:"recommended_attributes,omitempty"`
	Thresholds            map[string]float64  `yaml:"thresholds,omitempty"`
	Items                 []Item              `yaml:"items"`
}

// Resolved is a connector template merged with the base template (and, when
// an overlay was applied, with the tenant's additions).
type Resolved struct {
	ID                    string              `json:"id"`
	Version               string              `json:"version"`
	DisplayName           string              `json:"display_name"`
	ConnectorTypes        []string            `json:"connector_types"`
	Role                  string              `json:"role"`
	Inventory             bool                `json:"inventory,omitempty"`
	DefaultCorrelationKey string              `json:"default_correlation_key"`
	DefaultHRIDAttribute  string              `json:"default_hr_id_attribute"`
	HostAllowlist         []string            `json:"host_allowlist,omitempty"`
	RequiredAttributes    map[string][]string `json:"required_attributes"`
	RecommendedAttributes map[string][]string `json:"recommended_attributes"`
	Thresholds            map[string]float64  `json:"thresholds"`
	Items                 []Item              `json:"items"`
	OverlayVersion        int                 `json:"overlay_version"`
}

// Pin is the "template@major.minor" a connection revision pins (§3.5).
func (r *Resolved) Pin() string { return r.ID + "@" + majorMinor(r.Version) }

// Item returns the item with the given id.
func (r *Resolved) Item(id string) (*Item, bool) {
	for i := range r.Items {
		if r.Items[i].ID == id {
			return &r.Items[i], true
		}
	}
	return nil, false
}

// Threshold returns a threshold value, or def when the template has none.
func (r *Resolved) Threshold(key string, def float64) float64 {
	if v, ok := r.Thresholds[key]; ok {
		return v
	}
	return def
}

// Counts is the per-level item count of a resolved template (§3.14).
type Counts struct {
	Items, Required, Recommended, Optional int
}

// Count tallies items by level.
func (r *Resolved) Count() Counts {
	var c Counts
	for _, it := range r.Items {
		c.Items++
		switch it.Level {
		case Required:
			c.Required++
		case Recommended:
			c.Recommended++
		case Optional:
			c.Optional++
		}
	}
	return c
}
