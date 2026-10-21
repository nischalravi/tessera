package orgs

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Organization settings (issue #298): who owns an organization, the policies
// that apply to its people, and where the hierarchy comes from. The tree itself
// stays derived from the HR data; this is what administrators add to it.
//
//   - Owners: people named as the organization's owners. They replace the owners
//     derived from the reporting lines for as long as one of them is active.
//   - Policies: a default approval workflow (stages) for a request line whose
//     catalog item has no approval policy of its own, and request settings
//     overrides, both for beneficiaries in the organization. An override can only
//     tighten the tenant's request settings (a justification that is required, a
//     longer minimum, a shorter default or maximum duration).
//   - Hierarchy source: which ingested source the hierarchy is built from.

// Limits of the settings, kept equal to internal/requests (a test checks).
const (
	MaxStages        = 4
	MaxHours         = 24 * 365
	MaxJustification = 1000
	MaxEscalateHours = 24 * 30
)

// Policies are an organization's policies. Nil is "not set".
type Policies struct {
	// DefaultStages are approval stages (manager, owner, decider, in order).
	DefaultStages        []string `json:"default_stages"`
	DefaultEscalateHours *float64 `json:"default_escalate_hours"`
	// Request settings overrides: tighten-only.
	JustificationRequired  *bool    `json:"justification_required"`
	JustificationMinLength *int     `json:"justification_min_length"`
	DefaultHours           *float64 `json:"default_hours"`
	MaxHours               *float64 `json:"max_hours"`
}

// Settings are one organization's settings.
type Settings struct {
	OrgID    string   `json:"org_id"`
	Owners   []int64  `json:"owner_ids"`
	Policies Policies `json:"policies"`
}

// Hierarchy sources.
const (
	SourceHRDepartment = "hr_department" // the department of every ingested person
)

// HierarchySource is where the hierarchy comes from.
type HierarchySource struct {
	Source string `json:"source"`
	// System, when set, limits the hierarchy to the people ingested from that source.
	System *string `json:"system"`
}

var orgIDRE = regexp.MustCompile(`^(root|dept-none|dept-[0-9a-f]{10})$`)

// ValidID reports whether id has the form of an organization id.
func ValidID(id string) bool { return orgIDRE.MatchString(id) }

// Exists reports whether id names an organization of the tenant's tree.
func Exists(tx *store.TenantTx, rootName string, id string) (bool, error) {
	all, err := tx.Identities()
	if err != nil {
		return false, err
	}
	opts, err := Load(tx)
	if err != nil {
		return false, err
	}
	_, ok := GetWith(rootName, all, id, opts)
	return ok, nil
}

// Load reads the options the tree is built with: assigned owners and the hierarchy source.
func Load(tx *store.TenantTx) (Options, error) {
	opts := Options{Owners: map[string][]int64{}}
	rows, err := tx.OrgOwners()
	if err != nil {
		return opts, err
	}
	for _, r := range rows {
		opts.Owners[r.OrgID] = append(opts.Owners[r.OrgID], r.IdentityID)
	}
	src, _, err := LoadSource(tx)
	if err != nil {
		return opts, err
	}
	if src.System != nil {
		opts.System = *src.System
	}
	return opts, nil
}

// Check validates policies from the API.
func (p Policies) Check() error {
	if p.DefaultStages != nil {
		seen := map[string]bool{}
		if len(p.DefaultStages) == 0 || len(p.DefaultStages) > MaxStages {
			return cfgerr.Refuse(422, "invalid_stages", "a default workflow has 1 to %d stages", MaxStages)
		}
		for _, k := range p.DefaultStages {
			if k != store.StageManager && k != store.StageOwner && k != store.StageDecider {
				return cfgerr.Refuse(422, "invalid_stages", "stages are manager, owner or decider")
			}
			if seen[k] {
				return cfgerr.Refuse(422, "invalid_stages", "each kind of stage appears once")
			}
			seen[k] = true
		}
	}
	switch {
	case p.DefaultEscalateHours != nil && p.DefaultStages == nil:
		return cfgerr.Refuse(422, "escalation_without_workflow", "escalation belongs to a default workflow; set the stages too")
	case p.DefaultEscalateHours != nil && !(*p.DefaultEscalateHours > 0 && *p.DefaultEscalateHours <= MaxEscalateHours):
		return cfgerr.Refuse(422, "invalid_escalation", "escalation is after 0 to %d hours", MaxEscalateHours)
	case p.JustificationRequired != nil && !*p.JustificationRequired:
		return cfgerr.Refuse(422, "override_cannot_loosen", "an organization can require a justification, not waive it; leave it unset")
	case p.JustificationMinLength != nil && (*p.JustificationMinLength < 1 || *p.JustificationMinLength > MaxJustification):
		return cfgerr.Refuse(422, "invalid_justification_min", "the minimum justification length is between 1 and %d characters", MaxJustification)
	case p.DefaultHours != nil && !(*p.DefaultHours > 0 && *p.DefaultHours <= MaxHours):
		return cfgerr.Refuse(422, "invalid_default_hours", "the default duration is between 0 and %d hours", MaxHours)
	case p.MaxHours != nil && !(*p.MaxHours > 0 && *p.MaxHours <= MaxHours):
		return cfgerr.Refuse(422, "invalid_max_hours", "the maximum duration is between 0 and %d hours", MaxHours)
	case p.DefaultHours != nil && p.MaxHours != nil && *p.DefaultHours > *p.MaxHours:
		return cfgerr.Refuse(422, "default_above_max", "the default duration cannot exceed the maximum")
	}
	return nil
}

// IsZero reports whether no policy is set.
func (p Policies) IsZero() bool {
	return p.DefaultStages == nil && p.DefaultEscalateHours == nil && p.JustificationRequired == nil &&
		p.JustificationMinLength == nil && p.DefaultHours == nil && p.MaxHours == nil
}

func policiesFromRow(r *store.OrgSettingsRow) Policies {
	return Policies{DefaultStages: r.DefaultStages, DefaultEscalateHours: r.DefaultEscalateHours,
		JustificationRequired: r.JustificationReq, JustificationMinLength: r.JustificationMin, DefaultHours: r.DefaultHours,
		MaxHours: r.MaxHours}
}

// LoadPolicies returns an organization's policies and their version (0 and the zero value if none).
func LoadPolicies(tx *store.TenantTx, orgID string) (Policies, int, error) {
	r, err := tx.OrgSettings(orgID)
	if store.ErrNoSettings(err) {
		return Policies{}, 0, nil
	} else if err != nil {
		return Policies{}, 0, err
	}
	return policiesFromRow(r), r.Version, nil
}

// AllPolicies returns the policies of every organization that has some, by id.
func AllPolicies(tx *store.TenantTx) (map[string]Policies, error) {
	rows, err := tx.OrgSettingsList()
	if err != nil {
		return nil, err
	}
	out := make(map[string]Policies, len(rows))
	for _, r := range rows {
		out[r.OrgID] = policiesFromRow(r)
	}
	return out, nil
}

// OrgOf is the id of the organization a person is in (the department's).
func OrgOf(i *store.Identity) string {
	if i.Type == "human" && i.Department != nil && strings.TrimSpace(*i.Department) != "" {
		return DeptID(*i.Department)
	}
	return NoDepartmentID
}

// PoliciesFor returns the policies that apply to a person: those of their
// organization (and none for a machine identity).
func PoliciesFor(tx *store.TenantTx, i *store.Identity) (Policies, error) {
	if i.Type != "human" {
		return Policies{}, nil
	}
	p, _, err := LoadPolicies(tx, OrgOf(i))
	return p, err
}

// num renders a number for the audit event, which carries no floats.
func num(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

func policiesDetail(p Policies) ojson.Object {
	d := ojson.Object{}
	if p.DefaultStages != nil {
		d = append(d, ojson.KV{Key: "default_stages", Value: p.DefaultStages})
	}
	add := func(k string, v any) { d = append(d, ojson.KV{Key: k, Value: v}) }
	if p.DefaultEscalateHours != nil {
		add("default_escalate_hours", num(*p.DefaultEscalateHours))
	}
	if p.JustificationRequired != nil {
		add("justification_required", *p.JustificationRequired)
	}
	if p.JustificationMinLength != nil {
		add("justification_min_length", *p.JustificationMinLength)
	}
	if p.DefaultHours != nil {
		add("default_hours", num(*p.DefaultHours))
	}
	if p.MaxHours != nil {
		add("max_hours", num(*p.MaxHours))
	}
	return d
}

// SaveSettings replaces an organization's owners and policies. ver is the
// policies version the caller read (0 if none); a different current version is a
// conflict. Owners must be active people of the tenant. The change is audited in
// the same transaction, with the old values.
func SaveSettings(tx *store.TenantTx, s Settings, ver int, by string, now time.Time) (Settings, int, error) {
	if err := s.Policies.Check(); err != nil {
		return Settings{}, 0, err
	}
	if len(s.Owners) > MaxOwners {
		return Settings{}, 0, cfgerr.Refuse(422, "too_many_owners", "an organization has at most %d owners", MaxOwners)
	}
	seen := map[int64]bool{}
	for _, id := range s.Owners {
		if seen[id] {
			return Settings{}, 0, cfgerr.Refuse(422, "duplicate_owner", "an owner is named once")
		}
		seen[id] = true
		i, err := tx.Identity(id)
		if errors.Is(err, store.ErrNotFound) {
			return Settings{}, 0, cfgerr.Refuse(422, "unknown_owner", "owner %d is not an identity in this organization", id)
		} else if err != nil {
			return Settings{}, 0, err
		}
		if i.Status != "active" || i.Type != "human" {
			return Settings{}, 0, cfgerr.Refuse(422, "owner_not_active", "%s is not an active person", i.Name)
		}
	}
	oldPol, cur, err := LoadPolicies(tx, s.OrgID)
	if err != nil {
		return Settings{}, 0, err
	}
	if ver != cur {
		return Settings{}, 0, cfgerr.Conflict(ver, cur)
	}
	oldOwners, err := tx.OrgOwners()
	if err != nil {
		return Settings{}, 0, err
	}
	var prev []int64
	for _, o := range oldOwners {
		if o.OrgID == s.OrgID {
			prev = append(prev, o.IdentityID)
		}
	}
	if err := tx.ReplaceOrgOwners(s.OrgID, s.Owners); err != nil {
		return Settings{}, 0, err
	}
	row := &store.OrgSettingsRow{OrgID: s.OrgID, DefaultStages: s.Policies.DefaultStages, DefaultEscalateHours: s.Policies.DefaultEscalateHours,
		JustificationReq: s.Policies.JustificationRequired, JustificationMin: s.Policies.JustificationMinLength,
		DefaultHours: s.Policies.DefaultHours, MaxHours: s.Policies.MaxHours, UpdatedBy: by}
	if err := tx.PutOrgSettings(row, now); err != nil {
		return Settings{}, 0, err
	}
	if prev == nil {
		prev = []int64{}
	}
	owners := s.Owners
	if owners == nil {
		owners = []int64{}
	}
	d := ojson.Object{{Key: "org_id", Value: s.OrgID}, {Key: "owner_ids", Value: owners}, {Key: "policies", Value: policiesDetail(s.Policies)},
		{Key: "previous", Value: ojson.Object{{Key: "owner_ids", Value: prev}, {Key: "policies", Value: policiesDetail(oldPol)}}},
		{Key: "version", Value: cur + 1}}
	if err := tx.Audit(now, by, "org.settings.update", d); err != nil {
		return Settings{}, 0, err
	}
	s.Owners = owners
	return s, cur + 1, nil
}

// LoadSource returns the hierarchy source and its version (0 for the default).
func LoadSource(tx *store.TenantTx) (HierarchySource, int, error) {
	r, err := tx.OrgHierarchySource()
	if store.ErrNoSettings(err) {
		return HierarchySource{Source: SourceHRDepartment}, 0, nil
	} else if err != nil {
		return HierarchySource{}, 0, err
	}
	return HierarchySource{Source: r.Source, System: r.System}, r.Version, nil
}

// Sources lists the ingested sources people come from (what System may name).
func Sources(tx *store.TenantTx) ([]string, error) {
	all, err := tx.Identities()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, i := range all {
		if i.Type == "human" && i.Source != nil && *i.Source != "" && !slices.Contains(out, *i.Source) {
			out = append(out, *i.Source)
		}
	}
	slices.Sort(out)
	if out == nil {
		out = []string{}
	}
	return out, nil
}

func sourceDetail(s HierarchySource) ojson.Object {
	sys := ""
	if s.System != nil {
		sys = *s.System
	}
	return ojson.Object{{Key: "source", Value: s.Source}, {Key: "system", Value: sys}}
}

// SaveSource replaces the hierarchy source. System must be a source people were
// ingested from. ver is the version the caller read; a different current version
// is a conflict. Audited in the same transaction, with the old values.
func SaveSource(tx *store.TenantTx, s HierarchySource, ver int, by string, now time.Time) (HierarchySource, int, error) {
	if s.Source != SourceHRDepartment {
		return HierarchySource{}, 0, cfgerr.Refuse(422, "invalid_source", "the hierarchy source is %s", SourceHRDepartment)
	}
	if s.System != nil {
		sys := strings.TrimSpace(*s.System)
		s.System = &sys
		if sys == "" {
			s.System = nil
		}
	}
	if s.System != nil {
		known, err := Sources(tx)
		if err != nil {
			return HierarchySource{}, 0, err
		}
		if !slices.Contains(known, *s.System) {
			return HierarchySource{}, 0, cfgerr.Refuse(422, "unknown_system", "%q is not a source people are ingested from", *s.System)
		}
	}
	old, cur, err := LoadSource(tx)
	if err != nil {
		return HierarchySource{}, 0, err
	}
	if ver != cur {
		return HierarchySource{}, 0, cfgerr.Conflict(ver, cur)
	}
	if err := tx.PutOrgHierarchySource(&store.OrgHierarchySourceRow{Source: s.Source, System: s.System, UpdatedBy: by}, now); err != nil {
		return HierarchySource{}, 0, err
	}
	d := append(sourceDetail(s), ojson.KV{Key: "previous", Value: sourceDetail(old)}, ojson.KV{Key: "version", Value: cur + 1})
	if err := tx.Audit(now, by, "org.hierarchy_source.update", d); err != nil {
		return HierarchySource{}, 0, err
	}
	return s, cur + 1, nil
}
