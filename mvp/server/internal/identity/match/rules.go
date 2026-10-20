package match

import (
	"slices"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
)

// Mode is how much an intake record may do on its own (design §5.2).
type Mode string

// Matching modes.
const (
	Authoritative Mode = "authoritative" // HRIS, SIS, VMS contractor id, partner SCIM externalId
	SelfAsserted  Mode = "self_asserted" // sponsor invites, self-registration, partner invites: never auto-links
	Federated     Mode = "federated"     // first login from a home IdP
)

// Tier is how confident a match is (design §5.3).
type Tier string

// Tiers.
const (
	TierA Tier = "A" // exact
	TierB Tier = "B" // strong
	TierC Tier = "C" // possible
	TierD Tier = "D" // none
)

func (t Tier) rank() int {
	switch t {
	case TierA:
		return 0
	case TierB:
		return 1
	case TierC:
		return 2
	}
	return 3
}

// Outcome is what the matcher does with a result.
type Outcome string

// Outcomes.
const (
	OutcomeAutoLink  Outcome = "auto_link"
	OutcomeReview    Outcome = "review"    // a reviewer decides
	OutcomeSuspected Outcome = "suspected" // self-asserted: flagged for a reviewer, nothing linked
	OutcomeNew       Outcome = "new"
)

// Rule names, stable: they are stored with every result.
const (
	RuleSignedIn     = "signed_in_as_candidate"   // A: link by sign-in
	RuleSourceLinked = "source_record_linked"     // A: the same (sor, sorid) is already linked
	RuleAuthIdent    = "authoritative_identifier" // A: the same authoritative identifier in two sources that share it
	RuleFederated    = "federated_binding"        // A: the same (issuer, subject) is already bound
	RuleEmailDOBName = "verified_email_dob_name"  // B
	RuleNameDOB      = "name_dob"                 // C
	RuleEmailOnly    = "verified_email"           // C
	RulePhoneOnly    = "verified_phone"           // C
)

// Thresholds of §5.3. Tenants may override them in Config.
const (
	DefaultNameStrong   = 0.92
	DefaultNamePossible = 0.85
)

// Config is the tenant's matching settings.
type Config struct {
	// AutoLinkTierB lets an authoritative intake auto-link a Tier B match to a
	// candidate that also has an authoritative source (§5.2). Off by default.
	AutoLinkTierB bool
	// RequireReviewTierA sends even exact matches to the review queue.
	RequireReviewTierA bool
	NameStrong         float64 // 0 means DefaultNameStrong
	NamePossible       float64 // 0 means DefaultNamePossible
}

func (c Config) strong() float64 {
	if c.NameStrong > 0 {
		return c.NameStrong
	}
	return DefaultNameStrong
}

func (c Config) possible() float64 {
	if c.NamePossible > 0 {
		return c.NamePossible
	}
	return DefaultNamePossible
}

// Contact is an email address or phone number, normalized, with whether the
// person proved they control it.
type Contact struct {
	Norm     string
	Verified bool
}

// Ident is a typed identifier by its keyed hash: the matcher never sees the value.
type Ident struct {
	Type          string
	Issuer        string
	HMAC          string
	Authoritative bool // verified by an authoritative source
}

// Source names one record of one system of record.
type Source struct{ SOR, SORID string }

// DOB is a date of birth as keyed hashes: Exact is the hash of the date as
// given, Swapped the hash of the date with day and month exchanged (empty when
// the day is above 12), so a transposed entry still compares equal.
type DOB struct{ Exact, Swapped string }

// Intake is the record being matched.
type Intake struct {
	Mode        Mode
	Names       []Name
	Emails      []Contact
	Phones      []Contact
	DOB         DOB
	Identifiers []Ident
	Source      Source
	// SignedInAs is the person the claimant authenticated as during the claim
	// (0 for none): proof of possession, the one thing that links a
	// self-asserted intake without a reviewer.
	SignedInAs int64
}

// Candidate is a person the intake may be.
type Candidate struct {
	ID            int64
	Names         []Name
	Emails        []Contact
	Phones        []Contact
	DOBKey        string // keyed hash of the date of birth, "" when none is held
	Identifiers   []Ident
	Sources       []Source
	Authoritative bool // the person has a record from an authoritative source
}

// Fired is one rule that matched, with what it compared (masked).
type Fired struct {
	Rule     string            `json:"rule"`
	Tier     Tier              `json:"tier"`
	Score    float64           `json:"score"`
	Why      string            `json:"why"`
	Compared map[string]string `json:"compared,omitempty"`
}

// Result is the verdict on one candidate.
type Result struct {
	CandidateID int64
	Tier        Tier
	Score       float64
	Fired       []Fired
	Outcome     Outcome
	// BothAuthoritative: the intake and the candidate both come from
	// authoritative sources, which is what lets Tier B auto-link.
	BothAuthoritative bool
}

// Verdict is the outcome for an intake: the results by strength, best first.
type Verdict struct {
	Tier    Tier // of the best result; TierD with no results
	Outcome Outcome
	Results []Result
}

// Evaluate compares an intake with the candidates and decides what to do.
// Candidates with no rule fired are left out; with none left the verdict is
// Tier D, a new person.
func Evaluate(in Intake, cands []Candidate, cfg Config) Verdict {
	var res []Result
	for _, c := range cands {
		if r, ok := evaluate(in, c, cfg); ok {
			res = append(res, r)
		}
	}
	sort.SliceStable(res, func(i, j int) bool {
		if pi, pj := has(res[i].Fired, RuleSignedIn), has(res[j].Fired, RuleSignedIn); pi != pj {
			return pi // proof of possession outranks everything
		}
		if ri, rj := res[i].Tier.rank(), res[j].Tier.rank(); ri != rj {
			return ri < rj
		}
		if res[i].Score != res[j].Score {
			return res[i].Score > res[j].Score
		}
		return res[i].CandidateID < res[j].CandidateID
	})
	v := Verdict{Tier: TierD, Outcome: OutcomeNew, Results: res}
	for i := range res {
		res[i].Outcome = decide(in.Mode, res[i], cfg)
		// two equally good candidates are ambiguous: never link on a guess
		tied := i > 0 && res[i-1].Tier == res[i].Tier || i+1 < len(res) && res[i+1].Tier == res[i].Tier
		if res[i].Outcome == OutcomeAutoLink && tied && !has(res[i].Fired, RuleSignedIn) {
			res[i].Outcome = demoted(in.Mode)
		}
	}
	if len(res) > 0 {
		v.Tier, v.Outcome = res[0].Tier, res[0].Outcome
	}
	return v
}

func demoted(m Mode) Outcome {
	if m == Authoritative {
		return OutcomeReview
	}
	return OutcomeSuspected
}

func has(fired []Fired, rule string) bool {
	return slices.ContainsFunc(fired, func(f Fired) bool { return f.Rule == rule })
}

// decide is the table of §5.2.
func decide(mode Mode, r Result, cfg Config) Outcome {
	switch {
	case has(r.Fired, RuleSignedIn):
		return OutcomeAutoLink // proof of possession links in any mode
	case r.Tier == TierD:
		return OutcomeNew
	}
	switch mode {
	case Authoritative:
		switch r.Tier {
		case TierA:
			if cfg.RequireReviewTierA {
				return OutcomeReview
			}
			return OutcomeAutoLink
		case TierB:
			if cfg.AutoLinkTierB && r.BothAuthoritative {
				return OutcomeAutoLink
			}
		}
		return OutcomeReview
	case Federated:
		if has(r.Fired, RuleFederated) && !cfg.RequireReviewTierA {
			return OutcomeAutoLink
		}
	}
	return OutcomeSuspected
}

func evaluate(in Intake, c Candidate, cfg Config) (Result, bool) {
	var fired []Fired
	add := func(f Fired) { fired = append(fired, f) }

	// ---- Tier A
	if in.SignedInAs != 0 && in.SignedInAs == c.ID {
		add(Fired{Rule: RuleSignedIn, Tier: TierA, Score: 1, Why: "the claimant signed in as this person"})
	}
	if in.Source.SOR != "" && slices.Contains(c.Sources, in.Source) {
		add(Fired{Rule: RuleSourceLinked, Tier: TierA, Score: 1, Why: "this source record is already linked to the person",
			Compared: map[string]string{"source": MaskID(in.Source.SOR + "/" + in.Source.SORID)}})
	}
	for _, x := range in.Identifiers {
		for _, y := range c.Identifiers {
			if x.HMAC == "" || x.Type != y.Type || x.Issuer != y.Issuer || x.HMAC != y.HMAC {
				continue
			}
			switch {
			case identifiers.Federated(x.Type):
				add(Fired{Rule: RuleFederated, Tier: TierA, Score: 1, Why: "the same federated subject is already bound to the person",
					Compared: map[string]string{x.Type: MaskID(x.Issuer)}})
			case x.Authoritative && y.Authoritative && authoritativeType(x.Type):
				add(Fired{Rule: RuleAuthIdent, Tier: TierA, Score: 1, Why: "an authoritative identifier shared by two sources is the same",
					Compared: map[string]string{x.Type: MaskID(x.Issuer)}})
			}
		}
	}

	// ---- attributes for B and C
	name := NameScore(in.Names, c.Names)
	dob := dobMatch(in.DOB, c.DOBKey)
	email := sharedContact(in.Emails, c.Emails, in.Mode, MaskEmail)
	phone := sharedContact(in.Phones, c.Phones, in.Mode, MaskPhone)

	if email != "" && dob != "" && name >= cfg.strong() {
		add(Fired{Rule: RuleEmailDOBName, Tier: TierB, Score: name, Why: "the same verified email address and date of birth, and a very similar name",
			Compared: map[string]string{"email": email, "date_of_birth": dob, "name": maskNames(in.Names) + " ~ " + maskNames(c.Names)}})
	}
	if dob != "" && name >= cfg.possible() {
		add(Fired{Rule: RuleNameDOB, Tier: TierC, Score: name, Why: "a similar name and the same date of birth",
			Compared: map[string]string{"date_of_birth": dob, "name": maskNames(in.Names) + " ~ " + maskNames(c.Names)}})
	}
	if email != "" {
		add(Fired{Rule: RuleEmailOnly, Tier: TierC, Score: 0.6, Why: "the same verified email address",
			Compared: map[string]string{"email": email}})
	}
	if phone != "" {
		add(Fired{Rule: RulePhoneOnly, Tier: TierC, Score: 0.5, Why: "the same verified phone number",
			Compared: map[string]string{"phone": phone}})
	}
	if len(fired) == 0 {
		return Result{}, false
	}
	best := TierD
	score := 0.0
	for _, f := range fired {
		if f.Tier.rank() < best.rank() {
			best = f.Tier
		}
	}
	for _, f := range fired {
		if f.Tier == best && f.Score > score {
			score = f.Score
		}
	}
	return Result{CandidateID: c.ID, Tier: best, Score: score, Fired: fired, BothAuthoritative: in.Mode == Authoritative && c.Authoritative}, true
}

func authoritativeType(typ string) bool {
	switch typ {
	case "employee_id", "student_id", "applicant_id", "netid":
		return true
	}
	return false
}

// dobMatch says how the dates of birth compare: "same", "same (day and month
// exchanged)" or "" for no match or no date.
func dobMatch(in DOB, key string) string {
	switch {
	case key == "" || in.Exact == "":
		return ""
	case in.Exact == key:
		return "same"
	case in.Swapped != "" && in.Swapped == key:
		return "same (day and month exchanged)"
	}
	return ""
}

// sharedContact returns the masked contact two sides share, or "". The
// candidate's must be verified; the intake's must be too, except for a
// self-asserted or federated intake, where a match is only ever a suspicion.
func sharedContact(a, b []Contact, mode Mode, mask func(string) string) string {
	for _, x := range a {
		if x.Norm == "" || (mode == Authoritative && !x.Verified) {
			continue
		}
		for _, y := range b {
			if y.Verified && strings.EqualFold(x.Norm, y.Norm) {
				return mask(x.Norm)
			}
		}
	}
	return ""
}

func maskNames(ns []Name) string {
	if len(ns) == 0 {
		return ""
	}
	return MaskName(strings.TrimSpace(ns[0].Given + " " + ns[0].Family))
}

// NationalIDRule is the extension point for a national-identifier rule (a keyed
// hash of an SSN, SIN or NI number and the same date of birth, Tier B). It is
// not implemented: whether Tessera keeps such a hash is an open question
// (design §13.4). A tenant that decides to would compute the hash with
// identifiers.Keyer (type national_id_hmac, which is hash-only), add it to
// Intake.Identifiers and Candidate.Identifiers, and add a case to evaluate that
// fires a Tier B Fired{Rule: NationalIDRule} when the hashes and the dates
// of birth agree.
const NationalIDRule = "national_id_dob"

// ---------------------------------------------------------------- masking

// MaskName keeps each name's first letter: "Alice Smith" is "A**** S****".
func MaskName(s string) string {
	parts := strings.Fields(s)
	for i, p := range parts {
		r := []rune(p)
		parts[i] = string(r[:1]) + strings.Repeat("*", min(len(r)-1, 6))
	}
	return strings.Join(parts, " ")
}

// MaskEmail keeps the first letter of the local part and the domain.
func MaskEmail(s string) string {
	at := strings.LastIndexByte(s, '@')
	if at <= 0 {
		return MaskID(s)
	}
	r := []rune(s[:at])
	return string(r[:1]) + "***" + s[at:]
}

// MaskPhone keeps the last four digits.
func MaskPhone(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return "***"
	}
	return "***" + string(r[len(r)-4:])
}

// MaskID keeps the first two and last two characters.
func MaskID(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return "***"
	}
	return string(r[:2]) + "***" + string(r[len(r)-2:])
}
