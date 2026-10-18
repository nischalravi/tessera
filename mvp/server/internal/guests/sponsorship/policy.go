package sponsorship

import (
	"crypto/sha256"
	_ "embed" // the default policy file
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The sponsor policy (design §4.3). Its rules are the semantics of the
// design's Cedar fragment (contractor-sponsors, no-self-sponsor,
// sensitive-bundles-need-ial2, plus the limits and approval rules), written as
// a Go evaluator until Cedar lands (GU-2 in the plan). The rule values live in
// a versioned file; the version is a hash of the file's bytes, so a changed
// policy is a new version, and every decision carries the version it was made
// under (on the sponsorship, in its history and in the audit event).

//go:embed default_policy.json
var defaultPolicyJSON []byte

// Policy is a parsed sponsor policy.
type Policy struct {
	ID                    string         `json:"id"`
	MaxActive             map[string]int `json:"max_active_per_population"`
	MaxInvitesPerDay      int            `json:"max_invites_per_day"`
	IneligibleWorkerTypes []string       `json:"ineligible_worker_types"`
	Approval              struct {
		Populations         []string `json:"populations"`
		WhenBundleSensitive bool     `json:"when_bundle_sensitive"`
	} `json:"approval_required"`
	SensitiveBundleMinIAL int            `json:"sensitive_bundle_min_ial"`
	DefaultIAL            map[string]int `json:"default_ial"`
	TransferDeadlineDays  int            `json:"transfer_deadline_days"`
	MaxStartAheadDays     int            `json:"max_start_ahead_days"`

	// Version names this exact policy: "<id>@<first 12 hex of sha256 of the file>".
	Version string `json:"-"`
}

// Population describes how a sponsorship population maps onto the identity
// model: the affiliation type it writes (GU-1), the guest_populations row
// that bounds it, and the worker type of the lifecycle it drives (#159).
type Population struct {
	Key        string
	AffType    string
	Group      string // guest_populations key
	WorkerType string
}

// Populations are the sponsorship populations in display order. Visitors and
// volunteers are guests; contractors and partners keep their own worker type.
var Populations = []Population{
	{store.PopVisitor, store.AffGuestVisitor, "guest", store.WorkerGuest},
	{store.PopContractor, store.AffContractor, "guest", store.WorkerContractor},
	{store.PopVolunteer, store.AffVolunteer, "guest", store.WorkerGuest},
	{store.PopPartner, store.AffPartner, "partner", store.WorkerPartner},
}

// PopulationOf returns the population for key.
func PopulationOf(key string) (Population, bool) {
	for _, p := range Populations {
		if p.Key == key {
			return p, true
		}
	}
	return Population{}, false
}

// LoadPolicy parses and validates a policy file.
func LoadPolicy(raw []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("sponsor policy: %w", err)
	}
	if p.ID == "" || p.MaxInvitesPerDay <= 0 || p.TransferDeadlineDays <= 0 || p.MaxStartAheadDays <= 0 ||
		p.SensitiveBundleMinIAL < 0 || p.SensitiveBundleMinIAL > 2 {
		return nil, fmt.Errorf("sponsor policy: id, limits and the transfer deadline must be set")
	}
	for _, pop := range Populations {
		if p.MaxActive[pop.Key] <= 0 {
			return nil, fmt.Errorf("sponsor policy: no limit for population %s", pop.Key)
		}
		if ial, ok := p.DefaultIAL[pop.Key]; !ok || ial < 0 || ial > 2 {
			return nil, fmt.Errorf("sponsor policy: no valid default IAL for population %s", pop.Key)
		}
	}
	sum := sha256.Sum256(raw)
	p.Version = p.ID + "@" + hex.EncodeToString(sum[:])[:12]
	return &p, nil
}

// DefaultPolicy is the policy Tessera ships.
func DefaultPolicy() *Policy {
	p, err := LoadPolicy(defaultPolicyJSON)
	if err != nil {
		panic(err) // the embedded file is checked by TestSponsorPolicy_DefaultsAndVersion
	}
	return p
}

// Request is what the policy decides on: a sponsor taking on (or continuing,
// transferring) one guest's sponsorship. Counts are of the sponsor's other
// sponsorships, so a renewal never counts against itself.
type Request struct {
	Sponsor           *store.Identity
	SponsorWorkerType string // "" for a person with no lifecycle row (an employee)
	SponsorEnded      bool   // the sponsor's own term has ended
	GuestIdentityID   int64  // 0 when the guest does not exist yet
	Population        string
	Starts, Ends      time.Time
	Now               time.Time
	MaxDays           int // the longest a term may run, from the population settings
	LiveCount         int // the sponsor's other live sponsorships of the population
	InvitesToday      int // invitations made in the last 24 hours (0 unless inviting)
	Inviting          bool
	SensitiveBundle   bool
	RequiredIAL       int
}

// Decision is the policy's answer. Version is always set, to the policy that
// decided; Rules lists the rules that applied, forbid or permit.
type Decision struct {
	Allowed       bool     `json:"allowed"`
	Code          string   `json:"code,omitempty"`
	Message       string   `json:"message,omitempty"`
	NeedsApproval bool     `json:"needs_approval"`
	Version       string   `json:"policy_version"`
	Rules         []string `json:"rules"`
}

func (p *Policy) forbid(rules []string, rule, code, msg string) Decision {
	return Decision{Code: code, Message: msg, Version: p.Version, Rules: append(rules, "forbid:"+rule)}
}

// Eligible reports whether a person may sponsor at all: an active person with
// a running employee term (or none). Guests, contractors, interns, partners,
// vendors and people who have not claimed their account cannot.
func (p *Policy) Eligible(sp *store.Identity, workerType string, ended bool) bool {
	return sp != nil && sp.Type == "human" && sp.Status == "active" && !ended && !slices.Contains(p.IneligibleWorkerTypes, workerType)
}

// Evaluate applies the policy. The first rule that forbids decides, in the
// order below; otherwise the request is permitted, with NeedsApproval set when
// a second person must approve it.
func (p *Policy) Evaluate(r Request) Decision {
	var rules []string
	pop, ok := PopulationOf(r.Population)
	if !ok {
		return p.forbid(rules, "known-population", "unknown_population", "population is visitor, contractor, volunteer or partner")
	}
	if !p.Eligible(r.Sponsor, r.SponsorWorkerType, r.SponsorEnded) {
		return p.forbid(rules, "eligible-sponsors", "sponsor_not_eligible",
			"only active employees can sponsor guests; guests, contractors, interns, partners, vendors and people who have not claimed their account cannot")
	}
	rules = append(rules, "permit:eligible-sponsors")
	if r.GuestIdentityID != 0 && r.GuestIdentityID == r.Sponsor.ID {
		return p.forbid(rules, "no-self-sponsor", "cannot_sponsor_self", "nobody sponsors themselves")
	}
	rules = append(rules, "permit:no-self-sponsor")
	switch {
	case !r.Ends.After(r.Starts) || !r.Ends.After(r.Now):
		return p.forbid(rules, "valid-dates", "invalid_dates", "the end must be after the start and in the future")
	case r.Starts.After(r.Now.AddDate(0, 0, p.MaxStartAheadDays)):
		return p.forbid(rules, "valid-dates", "invalid_dates",
			fmt.Sprintf("the start is at most %d days ahead", p.MaxStartAheadDays))
	case r.Ends.After(r.Starts.AddDate(0, 0, r.MaxDays)):
		return p.forbid(rules, "max-duration", "exceeds_max_duration",
			fmt.Sprintf("a %s sponsorship runs at most %d days", pop.Key, r.MaxDays))
	}
	rules = append(rules, "permit:max-duration")
	if limit := p.MaxActive[pop.Key]; r.LiveCount >= limit {
		return p.forbid(rules, "max-active-sponsorships", "sponsor_limit_reached",
			fmt.Sprintf("you sponsor %d %s guests already, the most allowed", r.LiveCount, pop.Key))
	}
	rules = append(rules, "permit:max-active-sponsorships")
	if r.Inviting {
		if r.InvitesToday >= p.MaxInvitesPerDay {
			return p.forbid(rules, "max-invites-per-day", "daily_invite_limit",
				fmt.Sprintf("at most %d invitations a day", p.MaxInvitesPerDay))
		}
		rules = append(rules, "permit:max-invites-per-day")
	}
	if r.SensitiveBundle && r.RequiredIAL < p.SensitiveBundleMinIAL {
		return p.forbid(rules, "sensitive-bundles-need-ial2", "bundle_needs_ial2",
			fmt.Sprintf("a bundle with privileged or high-risk access needs identity assurance IAL %d or higher", p.SensitiveBundleMinIAL))
	}
	rules = append(rules, "permit:sensitive-bundles-need-ial2")
	d := Decision{Allowed: true, Version: p.Version, Rules: rules}
	if slices.Contains(p.Approval.Populations, r.Population) && (!p.Approval.WhenBundleSensitive || r.SensitiveBundle) {
		d.NeedsApproval = true
		d.Rules = append(d.Rules, "require:second-approver")
	}
	return d
}
