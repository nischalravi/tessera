package match

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Authoritative systems of record: a person who has a record from one of
// them is an authoritative candidate (design §5.2).
var authoritativeSORs = []string{"hris", "sis", "vms", "partner_scim"}

// Subject is an intake record as the callers know it, before it is hashed.
type Subject struct {
	Mode                     Mode
	Given, Family, Preferred string
	Emails                   []string
	// EmailsVerified: the sender vouches that it controls the addresses (an
	// authoritative source does). A sponsor's invitation does not.
	EmailsVerified bool
	Phones         []string
	DOB            string // YYYY-MM-DD, or ""
	Identifiers    []RawIdent
	SOR, SORID     string
	SignedInAs     int64 // the person the claimant authenticated as
	// Exclude is the provisional person the intake itself created: never its own candidate.
	Exclude int64
}

// RawIdent is an identifier the intake carries, before its keyed hash is computed.
type RawIdent struct {
	Type, Issuer, Value string
	Authoritative       bool
}

// Matcher builds intakes and candidates and stores what the rules decide.
type Matcher struct {
	Keyer *identifiers.Keyer
}

// New returns a Matcher over k, the tenant identifier key.
func New(k *identifiers.Keyer) *Matcher { return &Matcher{Keyer: k} }

const dobPurpose = "match-dob"

// DOBKeys returns the keyed hashes of a date of birth (YYYY-MM-DD): the date
// as given and the date with day and month exchanged ("" when the day is above
// 12, or the date is not valid). Source records keep the first one as
// "dob_key"; the matcher compares both.
func (m *Matcher) DOBKeys(tx *store.TenantTx, dob string) (DOB, error) {
	dob = strings.TrimSpace(dob)
	if dob == "" {
		return DOB{}, nil
	}
	t, err := time.Parse("2006-01-02", dob)
	if err != nil {
		return DOB{}, errors.New("match: date of birth must be YYYY-MM-DD")
	}
	exact, err := m.Keyer.MAC(tx.Tenant(), dobPurpose, t.Format("2006-01-02"))
	if err != nil {
		return DOB{}, err
	}
	out := DOB{Exact: exact}
	if t.Day() <= 12 && t.Day() != int(t.Month()) {
		sw := time.Date(t.Year(), time.Month(t.Day()), int(t.Month()), 0, 0, 0, 0, time.UTC)
		if out.Swapped, err = m.Keyer.MAC(tx.Tenant(), dobPurpose, sw.Format("2006-01-02")); err != nil {
			return DOB{}, err
		}
	}
	return out, nil
}

// Intake hashes a Subject into what the rules compare.
func (m *Matcher) Intake(tx *store.TenantTx, s Subject) (Intake, error) {
	in := Intake{Mode: s.Mode, Names: []Name{{Given: s.Given, Family: s.Family, Preferred: s.Preferred}},
		Source: Source{SOR: s.SOR, SORID: s.SORID}, SignedInAs: s.SignedInAs}
	for _, e := range s.Emails {
		if n, err := identifiers.Normalize(store.IdentEmail, e); err == nil {
			in.Emails = append(in.Emails, Contact{Norm: n, Verified: s.EmailsVerified})
		}
	}
	for _, p := range s.Phones {
		if n, err := identifiers.Normalize(store.IdentPhone, p); err == nil {
			in.Phones = append(in.Phones, Contact{Norm: n, Verified: s.EmailsVerified})
		}
	}
	var err error
	if in.DOB, err = m.DOBKeys(tx, s.DOB); err != nil {
		return in, err
	}
	for _, x := range s.Identifiers {
		_, mac, err := m.Keyer.Digest(tx.Tenant(), x.Type, x.Issuer, x.Value)
		if err != nil {
			continue // a malformed identifier is not evidence
		}
		in.Identifiers = append(in.Identifiers, Ident{Type: x.Type, Issuer: x.Issuer, HMAC: mac, Authoritative: x.Authoritative})
	}
	return in, nil
}

// Pool is the set of people an intake can match, loaded once and reused by a
// batch (a bulk invitation matches hundreds of rows against the same people).
// People who are provisional (invited, not yet claimed) or merged are not in it:
// there is nothing to take over.
type Pool struct {
	cands  []Candidate
	loaded bool
}

// Candidates loads the pool on first use.
func (p *Pool) Candidates(tx *store.TenantTx) ([]Candidate, error) {
	if p.loaded {
		return p.cands, nil
	}
	c, err := LoadCandidates(tx)
	if err != nil {
		return nil, err
	}
	p.cands, p.loaded = c, true
	return c, nil
}

// LoadCandidates reads every person an intake could be: human identities that
// are not provisional or merged.
func LoadCandidates(tx *store.TenantTx) ([]Candidate, error) {
	people, err := tx.Identities()
	if err != nil {
		return nil, err
	}
	srcs, err := tx.SourceRecords()
	if err != nil {
		return nil, err
	}
	idents, err := tx.Identifiers()
	if err != nil {
		return nil, err
	}
	bySrc, byIdent := map[int64][]*store.SourceRecord{}, map[int64][]*store.Identifier{}
	for _, s := range srcs {
		if s.IdentityID != nil && s.Status == store.RecordActive {
			bySrc[*s.IdentityID] = append(bySrc[*s.IdentityID], s)
		}
	}
	for _, x := range idents {
		if x.Status == store.RecordActive {
			byIdent[x.IdentityID] = append(byIdent[x.IdentityID], x)
		}
	}
	var out []Candidate
	for _, p := range people {
		if p.Type != "human" || p.Status == store.IdentityStatusMerged || p.Status == "invited" {
			continue
		}
		c := Candidate{ID: p.ID, Names: []Name{SplitName(p.Name)}}
		for _, s := range bySrc[p.ID] {
			c.Sources = append(c.Sources, Source{SOR: s.SOR, SORID: s.SORID})
			if slices.Contains(authoritativeSORs, s.SOR) {
				c.Authoritative = true
			}
			var a struct {
				Given     string `json:"given_name"`
				Family    string `json:"family_name"`
				Preferred string `json:"preferred_name"`
				DOBKey    string `json:"dob_key"`
			}
			if json.Unmarshal([]byte(s.Attributes), &a) == nil {
				if a.Given != "" || a.Family != "" {
					c.Names = append(c.Names, Name{Given: a.Given, Family: a.Family, Preferred: a.Preferred})
				} else if a.Preferred != "" {
					c.Names[0].Preferred = a.Preferred
				}
				if a.DOBKey != "" {
					c.DOBKey = a.DOBKey
				}
			}
		}
		haveEmail := false
		for _, x := range byIdent[p.ID] {
			verified := x.VerifiedAt != nil
			auth := x.VerifiedBy != nil && *x.VerifiedBy == store.VerifiedBySource
			switch {
			case x.Type == store.IdentEmail && x.ValueNorm != nil:
				c.Emails = append(c.Emails, Contact{Norm: *x.ValueNorm, Verified: verified})
				haveEmail = haveEmail || verified
			case x.Type == store.IdentPhone && x.ValueNorm != nil:
				c.Phones = append(c.Phones, Contact{Norm: *x.ValueNorm, Verified: verified})
			}
			c.Identifiers = append(c.Identifiers, Ident{Type: x.Type, Issuer: x.Issuer, HMAC: x.ValueHMAC, Authoritative: auth})
			if auth {
				c.Authoritative = true
			}
		}
		// a directory person from before identifiers existed: the address the HR system holds is verified
		if !haveEmail && p.Email != nil && c.Authoritative {
			if n, err := identifiers.Normalize(store.IdentEmail, *p.Email); err == nil {
				c.Emails = append(c.Emails, Contact{Norm: n, Verified: true})
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// Settings reads the tenant's matching settings as rule configuration.
func Settings(tx *store.TenantTx) (Config, error) {
	s, err := tx.MatchingSettings()
	return Config{AutoLinkTierB: s.AutoLinkTierB, RequireReviewTierA: s.RequireReviewTierA}, err
}

// Stored is what Run wrote.
type Stored struct {
	Verdict Verdict
	Rows    []*store.MatchResult
}

type rulesDoc struct {
	Mode  Mode    `json:"mode"`
	Score float64 `json:"score"`
	Rules []Fired `json:"rules"`
}

// Run matches an intake against the people Tessera knows and stores the
// results (design §5.3: the rules fired, the attributes compared, masked, and
// the score). subject is the provisional person the intake created (0 for
// none). The intake's status becomes "review" when a reviewer has something to
// look at and "resolved" otherwise. An auto-link outcome is stored as already
// linked and returned in Verdict: the caller performs the link in the same
// transaction (internal/identity/merge).
//
// Matching never tells anyone but the reviewer what it found, and a
// self-asserted intake is never linked here.
func (m *Matcher) Run(tx *store.TenantTx, pool *Pool, intakeID string, s Subject, now time.Time) (*Stored, error) {
	in, err := m.Intake(tx, s)
	if err != nil {
		return nil, err
	}
	cfg, err := Settings(tx)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		pool = &Pool{}
	}
	all, err := pool.Candidates(tx)
	if err != nil {
		return nil, err
	}
	cands := all
	if s.Exclude != 0 {
		cands = slices.DeleteFunc(slices.Clone(all), func(c Candidate) bool { return c.ID == s.Exclude })
	}
	v := Evaluate(in, cands, cfg)
	out := &Stored{Verdict: v}
	var subject *int64
	if s.Exclude != 0 {
		id := s.Exclude
		subject = &id
	}
	put := func(r *store.MatchResult) error {
		out.Rows = append(out.Rows, r)
		return tx.InsertMatchResult(r)
	}
	if len(v.Results) == 0 {
		doc, err := json.Marshal(rulesDoc{Mode: s.Mode, Rules: []Fired{}})
		if err != nil {
			return nil, err
		}
		d := store.MatchOutcomeNew
		if err := put(&store.MatchResult{ID: uuid.NewString(), IntakeID: intakeID, SubjectID: subject, Tier: string(TierD), Rules: string(doc),
			Outcome: store.MatchOutcomeNew, Status: store.MatchNewPerson, Decision: &d, DecidedAt: &now, CreatedAt: now}); err != nil {
			return nil, err
		}
	}
	review := false
	for _, r := range v.Results {
		doc, err := json.Marshal(rulesDoc{Mode: s.Mode, Score: r.Score, Rules: r.Fired})
		if err != nil {
			return nil, err
		}
		cid := r.CandidateID
		row := &store.MatchResult{ID: uuid.NewString(), IntakeID: intakeID, SubjectID: subject, CandidateID: &cid, Tier: string(r.Tier),
			Score: r.Score, Rules: string(doc), Outcome: string(r.Outcome), Status: store.MatchReview, CreatedAt: now}
		switch r.Outcome {
		case OutcomeAutoLink:
			d := store.MatchOutcomeAutoLink
			row.Status, row.Decision, row.DecidedAt = store.MatchLinked, &d, &now
		case OutcomeSuspected:
			d := store.MatchOutcomeSuspected
			row.Decision = &d
			review = true
		default:
			review = true
		}
		if err := put(row); err != nil {
			return nil, err
		}
	}
	status := store.IntakeResolved
	if review {
		status = store.IntakeReview
	}
	if err := tx.SetIntakeStatus(intakeID, status); err != nil {
		return nil, err
	}
	// the ledger entry names no attribute value: the tier, the rules and the counts
	var names []string
	for _, r := range v.Results {
		for _, f := range r.Fired {
			if !slices.Contains(names, f.Rule) {
				names = append(names, f.Rule)
			}
		}
	}
	return out, tx.Audit(now, "identity.matcher", "identity.match", ojson.Object{{Key: "intake_id", Value: intakeID},
		{Key: "mode", Value: string(s.Mode)}, {Key: "tier", Value: string(v.Tier)}, {Key: "outcome", Value: string(v.Outcome)},
		{Key: "candidates", Value: len(v.Results)}, {Key: "rules", Value: names}})
}
