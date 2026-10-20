// Package sponsorship is the sponsor's side of guest accounts (design §4.3
// and §8, issue #65 / GU-2): a sponsor invites a guest, the sponsor policy
// decides, a second person approves where the policy asks, and the
// sponsorship runs until it ends, is renewed or is transferred.
//
// The sponsorship is the record of the sponsor's decision (who, why, which
// population and access bundle, for how long, who approved, under which
// policy version). While it is live it writes the guest's affiliation
// (internal/identity/affiliations, source "sponsorship") and lifecycle
// (internal/lifecycle): worker type of the population, the sponsor of the
// sponsorship that ends last, and the latest end date. A person stays active
// until their last live sponsorship ends (the Michigan rule); ending the last
// one runs the lifecycle's leaver path.
//
// An invitation is self-asserted intake (K3): it always creates a NEW
// identity (status invited) with an unverified, sponsor-asserted email
// identifier and an intake record. It never links to an existing person and
// never says whether the email matches one, except that nobody can sponsor
// themselves. Linking and merging are GU-5. When the sponsorship becomes
// active the claim link and the guest's email are issued (internal/guests/claim,
// GU-6) and the invitation reads "sent"; without TESSERA_PUBLIC_URL it stays "ready". The access bundle is stored
// on the sponsorship; granting it is GU-12. Sponsor leaver transfers are GU-11.
//
// Every function works in the caller's tenant transaction, which also
// carries the audit event.
package sponsorship

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/affiliations"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/match"
	"github.com/nischalravi/tessera/mvp/server/internal/lifecycle"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Limits.
const (
	MaxName    = 100
	MaxPurpose = 500
	MaxReason  = requests.MaxReason
	MaxBundle  = 20
	// Sweeper is the actor of sweep events.
	Sweeper = "sponsorship.sweeper"
	// SourceSor is the system of record of a sponsor-asserted source record.
	SourceSor = "sponsorship"
)

// Error is a refused change; Code is stable for API clients.
type Error = requests.Error

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Actor is the signed-in user acting.
type Actor struct {
	UserID     uuid.UUID
	Display    string
	IdentityID *int64 // the person the user is, if linked
	Approver   bool   // holds sponsorships.approve
}

func (a Actor) lc() lifecycle.Actor {
	return lifecycle.Actor{UserID: a.UserID, Display: a.Display, IdentityID: a.IdentityID}
}

func (a Actor) uid() *string {
	if a.UserID == uuid.Nil {
		return nil
	}
	s := a.UserID.String()
	return &s
}

// Is reports whether the actor is the person.
func (a Actor) Is(id int64) bool { return a.IdentityID != nil && *a.IdentityID == id }

// Service decides and records sponsorships under one policy.
type Service struct {
	Policy *Policy
	Keyer  *identifiers.Keyer
	// Claim issues the guest's claim link and invitation email when a
	// sponsorship becomes active (GU-6) and revokes it when the sponsorship
	// ends. Nil, or not Ready: the invitation stays "ready" and nothing is sent.
	Claim *claim.Service
	// Matcher looks for the invited person among the people already known
	// (GU-5). It only records what it finds for a reviewer: an invitation is
	// self-asserted, never links, and nothing the sponsor sees depends on it.
	// Nil: no matching.
	Matcher *match.Matcher
}

// New returns a Service with the default policy.
func New(k *identifiers.Keyer) *Service { return &Service{Policy: DefaultPolicy(), Keyer: k} }

// BundleItem is one catalog item of an access bundle, as stored on the
// sponsorship (the bundle is granted by GU-12).
type BundleItem struct {
	GroupID    int64  `json:"group_id"`
	System     string `json:"system"`
	Name       string `json:"name"`
	Risk       string `json:"risk"`
	Privileged bool   `json:"privileged"`
}

// Sensitive reports whether an item is privileged or high-risk: the
// sponsor policy forbids it without IAL 2.
func (b BundleItem) Sensitive() bool { return b.Privileged || b.Risk == "high" }

// ParseBundle reads a sponsorship's stored bundle.
func ParseBundle(raw string) []BundleItem {
	var out []BundleItem
	if json.Unmarshal([]byte(raw), &out) != nil || out == nil {
		return []BundleItem{}
	}
	return out
}

// Invite is one invitation: who the sponsor vouches for, for what, how long.
type Invite struct {
	GivenName   string
	FamilyName  string
	Email       string
	Population  string
	Purpose     string
	StartsAt    time.Time // zero: now
	EndsAt      time.Time
	Bundle      []int64 // group ids of requestable catalog items
	RequiredIAL *int    // nil: the population's default, raised to the bundle's need
}

// Carry counts what a batch has used up so far, so a dry run judges row 51
// as the execution would.
type Carry struct {
	Live    map[string]int
	Invites int
}

func (c *Carry) bump(pop string) {
	if c.Live == nil {
		c.Live = map[string]int{}
	}
	c.Live[pop]++
	c.Invites++
}

// Plan is a checked invitation: the decision and the resolved terms.
type Plan struct {
	Decision    Decision
	Population  Population
	Starts      time.Time
	Ends        time.Time
	Bundle      []BundleItem
	RequiredIAL int
	RequiredAAL int
	MaxDays     int
	Given       string
	Family      string
	Purpose     string
	Email       string // normalized
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

func cleanText(s string, max int, required bool) (string, bool) {
	s = strings.TrimSpace(s)
	switch {
	case s == "" && required, utf8.RuneCountInString(s) > max, !utf8.ValidString(s), hasControl(s):
		return "", false
	}
	return s, true
}

func (s *Service) denied(code, msg string) *Plan {
	return &Plan{Decision: Decision{Code: code, Message: msg, Version: s.Policy.Version, Rules: []string{"forbid:invalid-input"}}}
}

// sponsorOf is the person the signed-in user is.
func sponsorOf(tx *store.TenantTx, by Actor) (*store.Identity, error) {
	if by.IdentityID == nil {
		return nil, refuse(422, "sponsor_identity_required", "your sign-in is not linked to a person, so you cannot sponsor guests")
	}
	sp, err := tx.Identity(*by.IdentityID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, refuse(422, "sponsor_identity_required", "your sign-in is not linked to a person, so you cannot sponsor guests")
	}
	return sp, err
}

// workerOf is the sponsor's lifecycle facts: "" for no row (an employee).
func workerOf(tx *store.TenantTx, id int64) (worker string, ended bool, err error) {
	l, err := tx.LifecycleFor(id)
	if errors.Is(err, store.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return l.WorkerType, l.EndedAt != nil, nil
}

func resolveBundle(tx *store.TenantTx, ids []int64) ([]BundleItem, *Decision, error) {
	out := make([]BundleItem, 0, len(ids))
	seen := map[int64]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		g, err := tx.Group(id)
		if errors.Is(err, store.ErrNotFound) {
			return nil, &Decision{Code: "bundle_item_not_requestable", Message: "an item of the bundle is not in the access catalog"}, nil
		} else if err != nil {
			return nil, nil, err
		}
		it, err := tx.CatalogItemForGroup(id)
		if errors.Is(err, store.ErrNotFound) || err == nil && !it.Requestable {
			return nil, &Decision{Code: "bundle_item_not_requestable", Message: g.System + ":" + g.Name + " is not requestable in the access catalog"}, nil
		} else if err != nil {
			return nil, nil, err
		}
		if len(it.EligibleTypes) > 0 && !slices.Contains(it.EligibleTypes, "human") {
			return nil, &Decision{Code: "bundle_item_ineligible", Message: g.System + ":" + g.Name + " is not open to people"}, nil
		}
		out = append(out, BundleItem{GroupID: g.ID, System: g.System, Name: g.Name, Risk: it.Risk, Privileged: g.Privileged})
	}
	return out, nil, nil
}

// sameEmail reports whether a person is known by this email: their record's
// address, or any identifier of theirs with the same keyed hash.
func (s *Service) sameEmail(tx *store.TenantTx, who *store.Identity, norm string) (bool, error) {
	if who.Email != nil {
		if n, err := identifiers.Normalize(store.IdentEmail, *who.Email); err == nil && n == norm {
			return true, nil
		}
	}
	xs, err := tx.IdentifiersFor(who.ID)
	if err != nil {
		return false, err
	}
	for _, x := range xs {
		if x.Type != store.IdentEmail {
			continue
		}
		if x.ValueNorm != nil && *x.ValueNorm == norm {
			return true, nil
		}
		if s.Keyer != nil {
			if _, mac, err := s.Keyer.Digest(tx.Tenant(), store.IdentEmail, x.Issuer, norm); err == nil && mac == x.ValueHMAC {
				return true, nil
			}
		}
	}
	return false, nil
}

// Check decides an invitation without writing anything. existing is the
// guest when they are already a person (SponsorExisting), nil for a new
// invitation. carry (may be nil) is what the batch has used so far.
func (s *Service) Check(tx *store.TenantTx, by Actor, in Invite, existing *store.Identity, carry *Carry, now time.Time) (*Plan, error) {
	sp, err := sponsorOf(tx, by)
	if err != nil {
		return nil, err
	}
	pop, ok := PopulationOf(in.Population)
	if !ok {
		return s.denied("unknown_population", "population is visitor, contractor, volunteer or partner"), nil
	}
	p := &Plan{Population: pop}
	var good bool
	if p.Given, good = cleanText(in.GivenName, MaxName, existing == nil); !good {
		return s.denied("invalid_name", "a given name of 1 to 100 characters is required"), nil
	}
	if p.Family, good = cleanText(in.FamilyName, MaxName, false); !good {
		return s.denied("invalid_name", "the family name is at most 100 characters"), nil
	}
	if p.Purpose, good = cleanText(in.Purpose, MaxPurpose, true); !good {
		return s.denied("invalid_purpose", "a purpose of 1 to 500 characters is required"), nil
	}
	if existing == nil {
		if p.Email, err = identifiers.Normalize(store.IdentEmail, in.Email); err != nil {
			return s.denied("invalid_email", err.Error()), nil
		}
	}
	if len(in.Bundle) > MaxBundle {
		return s.denied("bundle_too_large", fmt.Sprintf("a bundle has at most %d items", MaxBundle)), nil
	}
	if in.RequiredIAL != nil && (*in.RequiredIAL < 0 || *in.RequiredIAL > 2) {
		return s.denied("invalid_ial", "the required IAL is 0, 1 or 2"), nil
	}
	gp, err := tx.GuestPopulation(pop.Group)
	if errors.Is(err, store.ErrNotFound) {
		return s.denied("unknown_population", "this population is not configured for the tenant"), nil
	} else if err != nil {
		return nil, err
	}
	p.MaxDays = affiliations.MaxDurationDays(pop.AffType, gp.MaxDurationDays)
	p.Starts, p.Ends = in.StartsAt.UTC(), in.EndsAt.UTC()
	if in.StartsAt.IsZero() {
		p.Starts = now
	}
	if in.EndsAt.IsZero() {
		return s.denied("invalid_dates", "an end date is required"), nil
	}
	var bad *Decision
	if p.Bundle, bad, err = resolveBundle(tx, in.Bundle); err != nil {
		return nil, err
	} else if bad != nil {
		bad.Version, bad.Rules = s.Policy.Version, []string{"forbid:bundle-in-catalog"}
		p.Decision = *bad
		return p, nil
	}
	sensitive := slices.ContainsFunc(p.Bundle, BundleItem.Sensitive)
	p.RequiredAAL = gp.DefaultAAL
	p.RequiredIAL = max(gp.DefaultIAL, s.Policy.DefaultIAL[pop.Key])
	evalIAL := p.RequiredIAL
	switch {
	case in.RequiredIAL != nil:
		p.RequiredIAL = max(p.RequiredIAL, *in.RequiredIAL)
		evalIAL = *in.RequiredIAL // the sponsor's own statement is what the policy judges
		if !sensitive {
			evalIAL = p.RequiredIAL
		}
	case sensitive:
		p.RequiredIAL = max(p.RequiredIAL, s.Policy.SensitiveBundleMinIAL)
		evalIAL = p.RequiredIAL
	}
	worker, ended, err := workerOf(tx, sp.ID)
	if err != nil {
		return nil, err
	}
	req := Request{Sponsor: sp, SponsorWorkerType: worker, SponsorEnded: ended, Population: pop.Key, Starts: p.Starts,
		Ends: p.Ends, Now: now, MaxDays: p.MaxDays, Inviting: existing == nil, SensitiveBundle: sensitive, RequiredIAL: evalIAL}
	if existing != nil {
		req.GuestIdentityID = existing.ID
		if code, msg := notSponsorable(tx, existing); code != "" && existing.ID != sp.ID {
			p.Decision = s.Policy.forbid(nil, "sponsorable-guest", code, msg)
			return p, nil
		}
	} else if same, err := s.sameEmail(tx, sp, p.Email); err != nil {
		return nil, err
	} else if same {
		req.GuestIdentityID = sp.ID // the self-sponsor rule decides, in its place in the order
	}
	if req.LiveCount, err = tx.CountLiveSponsorships(sp.ID, pop.Key, ""); err != nil {
		return nil, err
	}
	if existing == nil {
		if req.InvitesToday, err = tx.CountInvitesSince(sp.ID, now.Add(-24*time.Hour)); err != nil {
			return nil, err
		}
	}
	if carry != nil {
		req.LiveCount += carry.Live[pop.Key]
		req.InvitesToday += carry.Invites
	}
	p.Decision = s.Policy.Evaluate(req)
	return p, nil
}

// notSponsorable says why an existing person cannot be taken on as a guest:
// only people who are not employees or students, and have not left.
func notSponsorable(tx *store.TenantTx, guest *store.Identity) (code, msg string) {
	switch {
	case guest.Type != "human":
		return "guest_not_sponsorable", "only people can be sponsored"
	case guest.Status != "active" && guest.Status != "invited":
		return "guest_not_sponsorable", "this person is no longer with the organization"
	}
	if l, err := tx.LifecycleFor(guest.ID); err == nil && (l.WorkerType == store.WorkerEmployee || l.EndedAt != nil) {
		return "guest_not_sponsorable", "this person is an employee or their term has ended"
	}
	if affs, err := tx.AffiliationsFor(guest.ID); err == nil {
		for _, a := range affs {
			if a.Source == store.AffSourceHRIS || a.Source == store.AffSourceSIS {
				return "guest_not_sponsorable", "this person comes from the HR or student system"
			}
		}
	}
	return "", ""
}

// timeNote renders a time for history notes.
func timeNote(t time.Time) string { return timeutil.ISO(t) }

func detail(sp *store.Sponsorship, extra ...ojson.KV) ojson.Object {
	d := ojson.Object{{Key: "sponsorship_id", Value: sp.ID}, {Key: "guest_identity_id", Value: sp.GuestIdentityID},
		{Key: "sponsor_identity_id", Value: sp.SponsorIdentityID}, {Key: "population", Value: sp.Population},
		{Key: "status", Value: sp.Status}, {Key: "starts_at", Value: timeNote(sp.StartsAt)},
		{Key: "ends_at", Value: timeNote(sp.EndsAt)}, {Key: "policy_version", Value: sp.PolicyVersion}}
	return append(d, extra...)
}

func rulesKV(d Decision) ojson.KV { return ojson.KV{Key: "rules", Value: d.Rules} }

// CanSponsor reports whether the person may sponsor at all under the policy.
func (s *Service) CanSponsor(tx *store.TenantTx, identityID int64) (bool, error) {
	sp, err := tx.Identity(identityID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	worker, ended, err := workerOf(tx, sp.ID)
	if err != nil {
		return false, err
	}
	return s.Policy.Eligible(sp, worker, ended), nil
}

// MaxDays is the longest a term of the population may run under the tenant's
// settings, for display.
func MaxDays(pop Population, gp *store.GuestPopulation) int {
	return affiliations.MaxDurationDays(pop.AffType, gp.MaxDurationDays)
}
