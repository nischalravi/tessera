package reviews

import (
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/orgs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Review types (issue #298, "Campaign configuration per review type"). A
// review type says who reviews a grant: the user's manager, or the owner of the
// application, the entitlement, the role, the organization, or of a service
// account (the ownership model of issue #167). Each type has its own settings:
// which owner reviews (or one named person), a fallback reviewer for grants whose
// owner cannot be reached, and what happens to items nobody decided by the due
// date. A review template runs as one type (review_template_types); a template
// with no type is the original all-purpose schedule, whose reviewers are the
// user's manager, the machine identity's owner or the security lead.

// The review types.
const (
	TypeUserManager       = "user_manager"
	TypeApplicationOwner  = "application_owner"
	TypeEntitlementOwner  = "entitlement_owner"
	TypeRoleOwner         = "role_owner"
	TypeOrganizationOwner = "organization_owner"
	TypeServiceAccount    = "service_account"
)

// TypeInfo describes a review type for the API and the UI.
type TypeInfo struct {
	Type  string `json:"type"`
	Label string `json:"label"`
	// Reviewer says, in words, who reviews by default.
	Reviewer string `json:"reviewer"`
	// Scope says which grants the type reviews.
	Scope string `json:"scope"`
}

// Types lists the review types, in the order the UI shows them.
var Types = []TypeInfo{
	{TypeUserManager, "User manager", "the person's manager", "grants of people"},
	{TypeApplicationOwner, "Application owner", "the owner of the application the grant is in", "all grants, by application"},
	{TypeEntitlementOwner, "Entitlement owner", "the owner of the group or resource granted", "all grants, by entitlement"},
	{TypeRoleOwner, "Role owner", "the owner of the business role", "role memberships"},
	{TypeOrganizationOwner, "Organization owner", "an owner of the person's organization", "all grants, by organization"},
	{TypeServiceAccount, "Service account", "the owner of the machine identity", "grants of machine identities and agents"},
}

// IsType reports whether t is a review type.
func IsType(t string) bool {
	return slices.ContainsFunc(Types, func(i TypeInfo) bool { return i.Type == t })
}

// Reviewer sources and incomplete-review outcomes.
const (
	SourceOwner         = "owner"
	SourceOwnerOrBackup = "owner_or_backup"
	SourceFixed         = "fixed"

	IncompleteRevoke   = "revoke"   // revoke what nobody decided
	IncompleteEscalate = "escalate" // the fallback reviewer gets it for EscalationDays, then revoke
	IncompleteKeep     = "keep"     // leave the access, close the review as incomplete
)

// TypeSettings are one review type's settings.
type TypeSettings struct {
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
	// ReviewerSource: owner (the primary owner), owner_or_backup (the primary,
	// else the backup) or fixed (ReviewerID reviews everything of the type). For
	// the user manager type the owner is the manager.
	ReviewerSource string `json:"reviewer_source"`
	ReviewerID     *int64 `json:"reviewer_id"`
	// FallbackID reviews what has no reachable reviewer (no owner, or not active).
	FallbackID     *int64 `json:"fallback_reviewer_id"`
	OnIncomplete   string `json:"on_incomplete"`
	EscalationDays int    `json:"escalation_days"`
}

// DefaultTypeSettings is what a type the tenant never configured gets: enabled,
// the owner or else the backup, no fallback (the security lead, as before), and
// revoke what nobody decided, as every schedule did before.
func DefaultTypeSettings(t string) TypeSettings {
	return TypeSettings{Type: t, Enabled: true, ReviewerSource: SourceOwnerOrBackup, OnIncomplete: IncompleteRevoke, EscalationDays: 7}
}

// Check validates settings from the API (not the people: CheckPeople does).
func (s TypeSettings) Check() error {
	switch {
	case !IsType(s.Type):
		return cfgerr.Refuse(404, "review_type_not_found", "unknown review type %q", s.Type)
	case s.ReviewerSource != SourceOwner && s.ReviewerSource != SourceOwnerOrBackup && s.ReviewerSource != SourceFixed:
		return cfgerr.Refuse(422, "invalid_reviewer_source", "reviewers are %s, %s or %s", SourceOwner, SourceOwnerOrBackup, SourceFixed)
	case s.ReviewerSource == SourceFixed && s.ReviewerID == nil:
		return cfgerr.Refuse(422, "reviewer_required", "a fixed reviewer needs reviewer_id")
	case s.OnIncomplete != IncompleteRevoke && s.OnIncomplete != IncompleteEscalate && s.OnIncomplete != IncompleteKeep:
		return cfgerr.Refuse(422, "invalid_on_incomplete", "an incomplete review is %s, %s or %s", IncompleteRevoke, IncompleteEscalate, IncompleteKeep)
	case s.OnIncomplete == IncompleteEscalate && s.FallbackID == nil:
		return cfgerr.Refuse(422, "fallback_required", "escalation goes to the fallback reviewer; name one")
	case s.EscalationDays < 1 || s.EscalationDays > 30:
		return cfgerr.Refuse(422, "invalid_escalation_days", "escalation lasts 1 to 30 days")
	}
	return nil
}

// reviewerPerson checks that id names an active person of the tenant.
func reviewerPerson(tx *store.TenantTx, id *int64, field string) error {
	if id == nil {
		return nil
	}
	i, err := tx.Identity(*id)
	if errors.Is(err, store.ErrNotFound) {
		return cfgerr.Refuse(422, "unknown_"+field, "%s is not an identity in this organization", field)
	} else if err != nil {
		return err
	}
	if i.Status != "active" || i.Type != "human" {
		return cfgerr.Refuse(422, field+"_not_active", "%s is an active person", field)
	}
	return nil
}

// LoadType returns a type's settings and the version they were saved at (0 for the defaults).
func LoadType(tx *store.TenantTx, t string) (TypeSettings, int, error) {
	row, err := tx.ReviewTypeSettings(t)
	if store.ErrNoSettings(err) {
		return DefaultTypeSettings(t), 0, nil
	} else if err != nil {
		return TypeSettings{}, 0, err
	}
	return typeFromRow(row), row.Version, nil
}

func typeFromRow(r *store.ReviewTypeSettingsRow) TypeSettings {
	return TypeSettings{Type: r.ReviewType, Enabled: r.Enabled, ReviewerSource: r.ReviewerSource, ReviewerID: r.ReviewerIdentityID,
		FallbackID: r.FallbackReviewerID, OnIncomplete: r.OnIncomplete, EscalationDays: r.EscalationDays}
}

// TypeVersion is a type's settings with the version they were saved at.
type TypeVersion struct {
	TypeSettings
	Version int
}

// LoadTypes returns every type's settings, defaults filled in, in Types order.
func LoadTypes(tx *store.TenantTx) ([]TypeVersion, error) {
	rows, err := tx.ReviewTypeSettingsList()
	if err != nil {
		return nil, err
	}
	saved := map[string]*store.ReviewTypeSettingsRow{}
	for _, r := range rows {
		saved[r.ReviewType] = r
	}
	out := make([]TypeVersion, 0, len(Types))
	for _, ti := range Types {
		if r := saved[ti.Type]; r != nil {
			out = append(out, TypeVersion{typeFromRow(r), r.Version})
		} else {
			out = append(out, TypeVersion{DefaultTypeSettings(ti.Type), 0})
		}
	}
	return out, nil
}

func typeDetail(s TypeSettings) ojson.Object {
	d := ojson.Object{{Key: "review_type", Value: s.Type}, {Key: "enabled", Value: s.Enabled},
		{Key: "reviewer_source", Value: s.ReviewerSource}, {Key: "on_incomplete", Value: s.OnIncomplete},
		{Key: "escalation_days", Value: s.EscalationDays}}
	if s.ReviewerID != nil {
		d = append(d, ojson.KV{Key: "reviewer_id", Value: *s.ReviewerID})
	}
	if s.FallbackID != nil {
		d = append(d, ojson.KV{Key: "fallback_reviewer_id", Value: *s.FallbackID})
	}
	return d
}

// SaveType replaces one type's settings. ver is the version the caller read
// (0 if it read the defaults); a different current version is a conflict. The
// change is audited in the same transaction, with the old values.
func SaveType(tx *store.TenantTx, s TypeSettings, ver int, by string, now time.Time) (TypeSettings, int, error) {
	if err := s.Check(); err != nil {
		return TypeSettings{}, 0, err
	}
	if err := reviewerPerson(tx, s.ReviewerID, "reviewer"); err != nil {
		return TypeSettings{}, 0, err
	}
	if err := reviewerPerson(tx, s.FallbackID, "fallback_reviewer"); err != nil {
		return TypeSettings{}, 0, err
	}
	old, cur, err := LoadType(tx, s.Type)
	if err != nil {
		return TypeSettings{}, 0, err
	}
	if ver != cur {
		return TypeSettings{}, 0, cfgerr.Conflict(ver, cur)
	}
	if s.ReviewerSource != SourceFixed {
		s.ReviewerID = nil // kept only while it is used
	}
	row := &store.ReviewTypeSettingsRow{ReviewType: s.Type, Enabled: s.Enabled, ReviewerSource: s.ReviewerSource,
		ReviewerIdentityID: s.ReviewerID, FallbackReviewerID: s.FallbackID, OnIncomplete: s.OnIncomplete,
		EscalationDays: s.EscalationDays, UpdatedBy: by}
	if err := tx.PutReviewTypeSettings(row, now); err != nil {
		return TypeSettings{}, 0, err
	}
	d := append(typeDetail(s), ojson.KV{Key: "previous", Value: typeDetail(old)}, ojson.KV{Key: "version", Value: cur + 1})
	if err := tx.Audit(now, by, "review.type.update", d); err != nil {
		return TypeSettings{}, 0, err
	}
	return s, cur + 1, nil
}

// ---------------------------------------------------------------- reviewers

// Resolver picks the reviewer of a grant under a review type's settings.
// Build it once per campaign: it reads the ownership table and the
// organizations' owners up front.
type Resolver struct {
	Settings TypeSettings
	people   map[int64]*store.Identity
	own      map[string]*store.Ownership // kind/key
	orgOwner map[string][]int64
}

func ownKey(kind, key string) string { return kind + "/" + key }

// NewResolver reads what the type's reviewers are chosen from. people is the
// tenant's identities by id (store.TenantTx.IdentityMap).
func NewResolver(tx *store.TenantTx, set TypeSettings, people map[int64]*store.Identity) (*Resolver, error) {
	r := &Resolver{Settings: set, people: people, own: map[string]*store.Ownership{}}
	rows, err := tx.Ownerships("")
	if err != nil {
		return nil, err
	}
	for _, o := range rows {
		r.own[ownKey(o.Kind, o.Key)] = o
	}
	if set.Type == TypeOrganizationOwner {
		all := make([]*store.Identity, 0, len(people))
		for _, i := range people {
			all = append(all, i)
		}
		opts, err := orgs.Load(tx)
		if err != nil {
			return nil, err
		}
		r.orgOwner = orgs.OwnerIDs(opts, all)
	}
	return r, nil
}

func (r *Resolver) active(id *int64) *store.Identity {
	if id == nil {
		return nil
	}
	if i := r.people[*id]; i != nil && i.Status == "active" {
		return i
	}
	return nil
}

// pick applies the reviewer source to an owner and a backup, then the fallback.
func (r *Resolver) pick(primary, backup *int64) *store.Identity {
	s := r.Settings
	if s.ReviewerSource == SourceFixed {
		if i := r.active(s.ReviewerID); i != nil {
			return i
		}
		return r.active(s.FallbackID)
	}
	if i := r.active(primary); i != nil {
		return i
	}
	if s.ReviewerSource == SourceOwnerOrBackup {
		if i := r.active(backup); i != nil {
			return i
		}
	}
	return r.active(s.FallbackID)
}

func (r *Resolver) owned(kind, key string) (primary, backup *int64) {
	if o := r.own[ownKey(kind, key)]; o != nil {
		return o.PrimaryID, o.BackupID
	}
	return nil, nil
}

// Includes reports whether the type reviews the person's or machine
// identity's grants at all: the user manager type reviews people and the
// service account type reviews machine identities and agents.
func (r *Resolver) Includes(ident *store.Identity) bool {
	switch r.Settings.Type {
	case TypeUserManager:
		return ident.Type == "human"
	case TypeServiceAccount:
		return ident.Type != "human"
	}
	return true
}

// ForGrant is the reviewer of ident's grant of dst, or nil when nobody is
// reachable (the caller then keeps its default reviewer).
func (r *Resolver) ForGrant(ident *store.Identity, dst *graph.Node) *store.Identity {
	switch r.Settings.Type {
	case TypeUserManager:
		return r.pick(ident.ManagerID, nil)
	case TypeServiceAccount:
		p, b := r.owned(store.OwnedIdentity, strconv.FormatInt(ident.ID, 10))
		if p == nil {
			p = ident.OwnerID
		}
		return r.pick(p, b)
	case TypeApplicationOwner:
		p, b := r.owned(store.OwnedApp, dst.System)
		return r.pick(p, b)
	case TypeEntitlementOwner:
		p, b := r.owned(store.OwnedGroup, strconv.FormatInt(dst.ID, 10))
		if dst.Kind == "resource" {
			p, b = r.owned(store.OwnedResource, strconv.FormatInt(dst.ID, 10))
		}
		return r.pick(p, b)
	case TypeOrganizationOwner:
		owners := r.orgOwner[orgOf(ident)]
		var p, b *int64
		if len(owners) > 0 {
			p = &owners[0]
		}
		if len(owners) > 1 {
			b = &owners[1]
		}
		return r.pick(p, b)
	}
	return nil // role_owner reviews memberships (ForRole)
}

// ForRole is the reviewer of ident's membership of a business role.
func (r *Resolver) ForRole(role *store.BusinessRole) *store.Identity {
	if r.Settings.Type != TypeRoleOwner {
		return nil
	}
	return r.pick(role.OwnerIdentityID, nil)
}

func orgOf(ident *store.Identity) string {
	if ident.Department != nil && *ident.Department != "" {
		return orgs.DeptID(*ident.Department)
	}
	return orgs.NoDepartmentID
}

// ---------------------------------------------------------------- templates

// TemplateType returns the review type a template runs as ("" for the
// original all-purpose schedule).
func TemplateType(tx *store.TenantTx, templateID string) (string, error) {
	t, err := tx.TemplateReviewType(templateID)
	if store.ErrNoSettings(err) {
		return "", nil
	}
	return t, err
}

// SetTemplateType sets, or with "" clears, the type a template runs as. The
// type must exist and be enabled.
func SetTemplateType(tx *store.TenantTx, templateID, reviewType string) error {
	if reviewType == "" {
		return tx.ClearTemplateReviewType(templateID)
	}
	if !IsType(reviewType) {
		return specErr("invalid_review_type", "review_type is one of the review types")
	}
	set, _, err := LoadType(tx, reviewType)
	if err != nil {
		return err
	}
	if !set.Enabled {
		return specErr("review_type_disabled", "the %s review type is turned off", reviewType)
	}
	return tx.SetTemplateReviewType(templateID, reviewType)
}

// closeOut is what happens to a launch's undecided items at the due date.
type closeOut struct {
	How            string // revoke | escalate | keep
	EscalateTo     *int64
	EscalationDays int
}

// closeOutOf is the close-out a template's launch follows: its review type's
// settings when it has a type, else the template's own.
func closeOutOf(tx *store.TenantTx, t *store.ReviewTemplate) (closeOut, error) {
	typ, err := TemplateType(tx, t.ID)
	if err != nil {
		return closeOut{}, err
	}
	if typ == "" {
		return closeOut{How: t.CloseOut, EscalateTo: t.EscalationIdentityID, EscalationDays: t.EscalationDays}, nil
	}
	set, _, err := LoadType(tx, typ)
	if err != nil {
		return closeOut{}, err
	}
	co := closeOut{How: set.OnIncomplete, EscalateTo: set.FallbackID, EscalationDays: set.EscalationDays}
	if co.How == IncompleteEscalate && co.EscalateTo == nil {
		co.How = IncompleteRevoke // the table forbids it; revoking is what every review did before
	}
	return co, nil
}
