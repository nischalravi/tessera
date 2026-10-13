// Package affiliations holds the rules for the relationships between a person
// and the organization (guest design K1, §3 and §8.1, issue #64): which kinds
// exist, how a person's lifecycle state is derived from them, and the admin
// operations that add and end one.
//
// A person is one identity with many affiliations. The derived state here is
// a pure function of the affiliations and the clock; the stored worker type,
// sponsor and lifecycle of a person are identity_lifecycle's (issue #159).
//
// Every function that writes works inside the caller's tenant transaction,
// which also carries the audit event.
package affiliations

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// State is a person's lifecycle state as far as affiliations determine it
// (design §8.1). Claim states (invited, pending_claim), suspension, rejection,
// deprovisioning and purge are not derivable from affiliations; later PRs own them.
type State string

// Derived states.
const (
	StateNone     State = "unaffiliated" // no affiliation at all (machine identities, new rows)
	StateProspect State = "prospective"  // only affiliations that have not started
	StateActive   State = "active"
	StateExpiring State = "expiring" // every active affiliation ends within the notice window
	StateExpired  State = "expired"  // all affiliations ended
	StateRevoked  State = "revoked"  // the last affiliation to end was revoked
	StateMerged   State = "merged"
)

// Limits and defaults.
const (
	DefaultNotice = 14 * 24 * time.Hour // "expiring" window; the sponsor reminders (30, 14, 3 days) come with GU-11
	MaxReason     = 500
	MaxOrgUnit    = 100
	maxBackdate   = 31 * 24 * time.Hour
	maxAheadYears = 1
)

const (
	humanType      = "human"
	identityMerged = store.IdentityStatusMerged
	manualSource   = store.AffSourceManual
)

// Types lists the affiliation types in display order.
var Types = []string{store.AffEmployee, store.AffStudent, store.AffApplicant, store.AffAdmit, store.AffPrehire,
	store.AffContractor, store.AffGuestVisitor, store.AffVolunteer, store.AffPartner, store.AffAlum, store.AffRetiree}

// manualTypes are the types an administrator may add by hand. Employee,
// student, applicant, admit and prehire come only from the HRIS or SIS feed:
// a typed-in record never grants a relationship an authoritative source owns.
var manualTypes = []string{store.AffContractor, store.AffGuestVisitor, store.AffVolunteer, store.AffPartner,
	store.AffAlum, store.AffRetiree}

// needsEnd are the types whose relationship must have an end date (K8).
var needsEnd = []string{store.AffContractor, store.AffGuestVisitor, store.AffVolunteer, store.AffPartner}

// typeMaxDays bounds a type further than its population does.
var typeMaxDays = map[string]int{store.AffGuestVisitor: 30}

// populationOf maps a type to the population whose limits apply to it.
var populationOf = map[string]string{
	store.AffContractor: "guest", store.AffGuestVisitor: "guest", store.AffVolunteer: "guest",
	store.AffApplicant: "applicant", store.AffAdmit: "applicant", store.AffPrehire: "prehire", store.AffPartner: "partner",
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ValidType reports whether t is an affiliation type.
func ValidType(t string) bool { return has(Types, t) }

// MaxDurationDays is the longest a relationship of type t may run when its
// population allows populationMax days: some types are capped lower (a
// visitor, 30 days).
func MaxDurationDays(t string, populationMax int) int {
	if m, ok := typeMaxDays[t]; ok && m < populationMax {
		return m
	}
	return populationMax
}

// PopulationFor is the population key whose limits apply to a type ("" for
// types that have none).
func PopulationFor(t string) string { return populationOf[t] }

// Effective is an affiliation's status at now: a stored "active" whose end has
// passed reads as ended (nothing sweeps it until GU-11), and a stored
// "pending" or "active" whose start is ahead reads as pending.
func Effective(a *store.Affiliation, now time.Time) string {
	switch a.Status {
	case store.AffEnded, store.AffRevoked:
		return a.Status
	}
	if a.EndsAt != nil && !a.EndsAt.After(now) {
		return store.AffEnded
	}
	if a.StartsAt.After(now) {
		return store.AffPending
	}
	return store.AffActive
}

// Derive returns the lifecycle state implied by a person's affiliations at
// now. An identity merged into another is "merged" whatever it holds (design
// §8.1). An identity is active while at least one affiliation is active, and
// expiring when every active affiliation ends within notice.
func Derive(identityStatus string, affs []*store.Affiliation, now time.Time, notice time.Duration) State {
	if identityStatus == identityMerged {
		return StateMerged
	}
	if len(affs) == 0 {
		return StateNone
	}
	var active, pending int
	soon := true // every active affiliation ends within notice
	var last *store.Affiliation
	var lastEnd time.Time
	for _, a := range affs {
		switch Effective(a, now) {
		case store.AffActive:
			active++
			if a.EndsAt == nil || a.EndsAt.After(now.Add(notice)) {
				soon = false
			}
		case store.AffPending:
			pending++
		default:
			end := a.StartsAt
			if a.EndsAt != nil {
				end = *a.EndsAt
			}
			if last == nil || end.After(lastEnd) {
				last, lastEnd = a, end
			}
		}
	}
	switch {
	case active > 0 && soon:
		return StateExpiring
	case active > 0:
		return StateActive
	case pending > 0:
		return StateProspect
	case last != nil && last.Status == store.AffRevoked:
		return StateRevoked
	}
	return StateExpired
}

// Error is a refused change; Code is stable for API clients.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(status int, code, msg string) error { return &Error{Status: status, Code: code, Msg: msg} }

// AddInput is a manual affiliation. Zero StartsAt means now.
type AddInput struct {
	IdentityID int64
	Type       string
	OrgUnit    string
	Population string // empty: the type's default
	StartsAt   time.Time
	EndsAt     *time.Time
	Reason     string
	By         string // the signed-in user's id
}

// Add records a manual affiliation for a person. The type must be one an
// administrator may add, the person must be a human who has not been merged
// away, guest-like types need an end date, and the end is capped by the
// population's maximum duration.
func Add(c *store.TenantTx, in AddInput, now time.Time) (*store.Affiliation, error) {
	reason := strings.TrimSpace(in.Reason)
	switch {
	case reason == "" || utf8.RuneCountInString(reason) > MaxReason:
		return nil, refuse(http.StatusUnprocessableEntity, "invalid_reason", "a reason of 1 to 500 characters is required")
	case !ValidType(in.Type):
		return nil, refuse(http.StatusUnprocessableEntity, "invalid_type", "unknown affiliation type")
	case !has(manualTypes, in.Type):
		return nil, refuse(http.StatusUnprocessableEntity, "type_not_manual",
			in.Type+" affiliations come from the HR or student system, not from an administrator")
	}
	unit := strings.TrimSpace(in.OrgUnit)
	if utf8.RuneCountInString(unit) > MaxOrgUnit {
		return nil, refuse(http.StatusUnprocessableEntity, "invalid_org_unit", "organization unit is too long")
	}
	who, err := c.Identity(in.IdentityID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(http.StatusNotFound, "not_found", "identity not found")
	}
	if err != nil {
		return nil, err
	}
	switch {
	case who.Type != humanType:
		return nil, refuse(http.StatusUnprocessableEntity, "not_a_person", "affiliations belong to people, not machine identities")
	case who.Status == identityMerged:
		return nil, refuse(http.StatusConflict, "identity_merged", "this identity was merged into another; add the affiliation there")
	}
	starts := in.StartsAt.UTC()
	if starts.IsZero() {
		starts = now
	}
	if starts.Before(now.Add(-maxBackdate)) || starts.After(now.AddDate(maxAheadYears, 0, 0)) {
		return nil, refuse(http.StatusUnprocessableEntity, "invalid_start", "the start must be within 31 days back and a year ahead")
	}
	var ends *time.Time
	if in.EndsAt != nil {
		e := in.EndsAt.UTC()
		ends = &e
		if !e.After(starts) || !e.After(now) {
			return nil, refuse(http.StatusUnprocessableEntity, "invalid_end", "the end must be after the start and in the future")
		}
	} else if has(needsEnd, in.Type) {
		return nil, refuse(http.StatusUnprocessableEntity, "end_required", in.Type+" affiliations need an end date")
	}
	pop := in.Population
	if pop == "" {
		pop = PopulationFor(in.Type)
	}
	a := &store.Affiliation{ID: uuid.NewString(), IdentityID: in.IdentityID, Type: in.Type, Source: manualSource,
		StartsAt: starts, EndsAt: ends, Status: store.AffActive, CreatedAt: now}
	if unit != "" {
		a.OrgUnit = &unit
	}
	if in.By != "" {
		by := in.By
		a.CreatedBy = &by
	}
	if starts.After(now) {
		a.Status = store.AffPending
	}
	if pop != "" {
		p, err := c.GuestPopulation(pop)
		if errors.Is(err, store.ErrNotFound) {
			return nil, refuse(http.StatusUnprocessableEntity, "unknown_population", "unknown population")
		}
		if err != nil {
			return nil, err
		}
		if ends != nil {
			if ends.After(starts.AddDate(0, 0, MaxDurationDays(in.Type, p.MaxDurationDays))) {
				return nil, refuse(http.StatusUnprocessableEntity, "exceeds_maximum", "the end is later than the maximum duration allowed for this population")
			}
		}
		a.Population = &pop
	}
	if err := c.InsertAffiliation(a); err != nil {
		return nil, err
	}
	return a, nil
}

// End ends a pending or active affiliation now. One that had not started is
// revoked (it never ran); one that was running is ended, at the earlier of
// now and its planned end.
func End(c *store.TenantTx, id, reason, by string, now time.Time) (*store.Affiliation, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || utf8.RuneCountInString(reason) > MaxReason {
		return nil, refuse(http.StatusUnprocessableEntity, "invalid_reason", "a reason of 1 to 500 characters is required")
	}
	a, err := c.Affiliation(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(http.StatusNotFound, "not_found", "affiliation not found")
	}
	if err != nil {
		return nil, err
	}
	if a.Status != store.AffPending && a.Status != store.AffActive {
		return nil, refuse(http.StatusConflict, "already_ended", "this affiliation has already ended")
	}
	if !has(manualTypes, a.Type) {
		return nil, refuse(http.StatusUnprocessableEntity, "type_not_manual",
			a.Type+" affiliations end in the HR or student system, not by an administrator")
	}
	status, end := store.AffEnded, now
	if a.StartsAt.After(now) {
		status, end = store.AffRevoked, a.StartsAt
	} else if a.EndsAt != nil && a.EndsAt.Before(end) {
		end = *a.EndsAt
	}
	var byp *string
	if by != "" {
		byp = &by
	}
	if err := c.EndAffiliation(id, status, end, byp, reason); err != nil {
		return nil, err
	}
	return c.Affiliation(id)
}

// SponsoredInput is the relationship a sponsorship grants (issue #65).
type SponsoredInput struct {
	IdentityID    int64
	Type          string // a type with a population: contractor, guest_visitor, volunteer, partner
	SponsorshipID string
	OrgUnit       string
	StartsAt      time.Time
	EndsAt        time.Time
	By            string // the signed-in user's id
}

// AddSponsored records the affiliation of an activated sponsorship (source
// 'sponsorship', source_ref the sponsorship). It stays pending until the
// guest's claim completes (GU-6). The sponsorship's policy has already bounded
// the dates, so only the shape is checked here.
func AddSponsored(c *store.TenantTx, in SponsoredInput, now time.Time) (*store.Affiliation, error) {
	pop := PopulationFor(in.Type)
	if !has(needsEnd, in.Type) || pop == "" || in.SponsorshipID == "" {
		return nil, refuse(http.StatusUnprocessableEntity, "invalid_type", "a sponsorship grants a contractor, visitor, volunteer or partner affiliation")
	}
	if !in.EndsAt.After(in.StartsAt) {
		return nil, refuse(http.StatusUnprocessableEntity, "invalid_end", "the end must be after the start")
	}
	ends, ref := in.EndsAt.UTC(), in.SponsorshipID
	a := &store.Affiliation{ID: uuid.NewString(), IdentityID: in.IdentityID, Type: in.Type, Source: store.AffSourceSponsorship,
		SourceRef: &ref, Population: &pop, StartsAt: in.StartsAt.UTC(), EndsAt: &ends, Status: store.AffPending, CreatedAt: now}
	if u := strings.TrimSpace(in.OrgUnit); u != "" && utf8.RuneCountInString(u) <= MaxOrgUnit {
		a.OrgUnit = &u
	}
	if in.By != "" {
		by := in.By
		a.CreatedBy = &by
	}
	return a, c.InsertAffiliation(a)
}

// ForSponsorship returns the affiliation a sponsorship wrote, or nil.
func ForSponsorship(c *store.TenantTx, identityID int64, sponsorshipID string) (*store.Affiliation, error) {
	affs, err := c.AffiliationsFor(identityID)
	if err != nil {
		return nil, err
	}
	for _, a := range affs {
		if a.Source == store.AffSourceSponsorship && a.SourceRef != nil && *a.SourceRef == sponsorshipID {
			return a, nil
		}
	}
	return nil, nil
}

// EndSponsored ends the affiliation of a sponsorship now (revoked if it never
// started). It does nothing when there is none or it has ended already.
func EndSponsored(c *store.TenantTx, identityID int64, sponsorshipID, reason, by string, now time.Time) error {
	a, err := ForSponsorship(c, identityID, sponsorshipID)
	if err != nil || a == nil || (a.Status != store.AffPending && a.Status != store.AffActive) {
		return err
	}
	status, end := store.AffEnded, now
	if a.StartsAt.After(now) {
		status, end = store.AffRevoked, a.StartsAt
	} else if a.EndsAt != nil && a.EndsAt.Before(end) {
		end = *a.EndsAt
	}
	var byp *string
	if by != "" {
		byp = &by
	}
	return c.EndAffiliation(a.ID, status, end, byp, reason)
}

// MoveSponsoredEnd moves the planned end of a sponsorship's affiliation (a renewal).
func MoveSponsoredEnd(c *store.TenantTx, identityID int64, sponsorshipID string, to time.Time) error {
	a, err := ForSponsorship(c, identityID, sponsorshipID)
	if err != nil || a == nil {
		return err
	}
	return c.SetAffiliationEnd(a.ID, to.UTC())
}
