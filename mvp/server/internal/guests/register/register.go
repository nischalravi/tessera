// Package register is guest self-registration with sponsor approval (guest
// accounts design §3, §6.4, threat T16, issue #66).
//
// A visitor fills in a public form naming a sponsor (picked from a name-only
// search, or by the code the sponsor shared). The form creates a request, not a
// person: no identity, account or claim token exists until the sponsor
// approves. Approval runs the ordinary invitation path (sponsorship.Invite, so
// the sponsor policy decides and the claim link is issued the same way as for a
// sponsor invitation); denial and expiry create nothing and tell the visitor
// nothing but "not approved".
//
// Submit never says what it did: a new request, an address that already has an
// account (which gets a "sign in" email), an unknown sponsor and a repeated
// request all end the same for the caller.
package register

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/sponsorship"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/identifiers"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Limits and defaults.
const (
	MaxName    = 100
	MaxPurpose = 500
	MaxEmail   = 320
	MaxCode    = 32
	// DefaultTTL is how long a request waits for its sponsor.
	DefaultTTL = 14 * 24 * time.Hour
	// DefaultRetention is how long a denied or expired request keeps its
	// personal data before it is reduced to a tombstone.
	DefaultRetention = 30 * 24 * time.Hour
	// DefaultCodeTTL is how long a sponsor's code works.
	DefaultCodeTTL = 30 * 24 * time.Hour
	// MaxTermDays caps how far ahead a visitor may ask to start and for how long.
	MaxTermDays = 365
	// MaxSearch is how many sponsor names a search returns.
	MaxSearch = 20
	// MinQuery is the shortest search: one letter would list everybody.
	MinQuery = 2
	// Sweeper is the actor of sweep events.
	Sweeper = "registration.sweeper"
	// Channel is the intake channel of an approved registration.
	Channel = "self_registration"

	codeAlphabet  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // 32 symbols, no I or O
	codeLen       = 10
	handlePurpose = "register-sponsor"
	codePurpose   = "register-code"
)

// Error is a refused request; Code is stable for API clients.
type Error = requests.Error

func refuse(status int, code, format string, args ...any) error {
	return &Error{Status: status, Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Challenger is the bot challenge (Cloudflare Turnstile or equivalent). Verify
// reports whether the token the page obtained proves a human; an error means
// the verifier could not be asked, which refuses the request.
type Challenger interface {
	Verify(ctx context.Context, token, clientIP string) (bool, error)
}

// AllowAll is the dev and test challenge: it accepts everything. The API uses
// it only outside production.
type AllowAll struct{}

func (AllowAll) Verify(context.Context, string, string) (bool, error) { return true, nil }

// Fake accepts exactly one token (tests, and a dev setup that wants to see the
// page refuse a bot).
type Fake struct{ Token string }

func (f Fake) Verify(_ context.Context, token, _ string) (bool, error) { return token == f.Token, nil }

// Service decides and records registrations.
type Service struct {
	Guests    *sponsorship.Service
	Keyer     *identifiers.Keyer
	Challenge Challenger
	// TenantName is the tenant's display name for the emails.
	TenantName func(context.Context, tenancy.ID) string
	// SignInURL is where the "you already have an account" email sends the
	// visitor (the public URL of the app).
	SignInURL string
	TTL       time.Duration // 0: DefaultTTL
	Retention time.Duration // 0: DefaultRetention
	CodeTTL   time.Duration // 0: DefaultCodeTTL
}

// Ready reports whether registration can run: a key for the hashes and a
// challenge.
func (s *Service) Ready() bool {
	return s != nil && s.Keyer != nil && s.Guests != nil && s.Challenge != nil
}

func (s *Service) ttl() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return DefaultTTL
}

func (s *Service) retention() time.Duration {
	if s.Retention > 0 {
		return s.Retention
	}
	return DefaultRetention
}

func (s *Service) tenantName(ctx context.Context, t tenancy.ID) string {
	if s.TenantName != nil {
		if n := s.TenantName(ctx, t); n != "" {
			return n
		}
	}
	return "your organization"
}

// ---------------------------------------------------------------- sponsors

// handleOf is the opaque handle of a sponsor: a keyed hash, so it says nothing
// about the person's id or address and cannot be computed without the key.
func (s *Service) handleOf(t tenancy.ID, id int64) (string, error) {
	mac, err := s.Keyer.MAC(t, handlePurpose, strconv.FormatInt(id, 10))
	if err != nil {
		return "", err
	}
	return mac[:32], nil
}

// SponsorChoice is what the public search shows of a sponsor: a name and an
// opaque handle, nothing else.
type SponsorChoice struct {
	Name   string `json:"name"`
	Handle string `json:"handle"`
}

// SearchSponsors returns the people whose name contains q and who may sponsor.
// A query shorter than MinQuery returns nothing.
func (s *Service) SearchSponsors(tx *store.TenantTx, q string) ([]SponsorChoice, error) {
	out := []SponsorChoice{}
	if utf8.RuneCountInString(strings.TrimSpace(q)) < MinQuery || len(q) > 100 {
		return out, nil
	}
	cs, err := tx.SponsorCandidates(q, 100)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		if len(out) == MaxSearch {
			break
		}
		if ok, err := s.Guests.CanSponsor(tx, c.ID); err != nil {
			return nil, err
		} else if !ok {
			continue
		}
		h, err := s.handleOf(tx.Tenant(), c.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, SponsorChoice{Name: c.Name, Handle: h})
	}
	return out, nil
}

// sponsorByHandle resolves a handle, or 0.
func (s *Service) sponsorByHandle(tx *store.TenantTx, handle string) (int64, error) {
	if len(handle) != 32 {
		return 0, nil
	}
	cs, err := tx.SponsorCandidates("", 5000)
	if err != nil {
		return 0, err
	}
	for _, c := range cs {
		h, err := s.handleOf(tx.Tenant(), c.ID)
		if err != nil {
			return 0, err
		}
		if h == handle {
			return c.ID, nil
		}
	}
	return 0, nil
}

// normalizeCode upper-cases a code and drops the separators a person types.
func normalizeCode(c string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToUpper(r)
	}, c)
}

func (s *Service) codeHash(t tenancy.ID, code string) (string, error) {
	return s.Keyer.MAC(t, codePurpose, normalizeCode(code))
}

func newCode() (string, error) {
	b := make([]byte, codeLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = codeAlphabet[b[i]&31]
	}
	return string(b[:5]) + "-" + string(b[5:]), nil
}

// NewCode makes the sponsor a code to share (the earlier one stops working).
// The code is returned once; only its keyed hash is stored.
func (s *Service) NewCode(tx *store.TenantTx, by sponsorship.Actor, now time.Time) (string, time.Time, error) {
	if !s.Ready() {
		return "", time.Time{}, refuse(503, "registration_unavailable", "registration needs the identifier key")
	}
	if by.IdentityID == nil {
		return "", time.Time{}, refuse(422, "sponsor_identity_required", "your sign-in is not linked to a person, so you cannot sponsor guests")
	}
	if ok, err := s.Guests.CanSponsor(tx, *by.IdentityID); err != nil {
		return "", time.Time{}, err
	} else if !ok {
		return "", time.Time{}, refuse(422, "sponsor_not_eligible", "you are not eligible to sponsor guests")
	}
	code, err := newCode()
	if err != nil {
		return "", time.Time{}, err
	}
	hash, err := s.codeHash(tx.Tenant(), code)
	if err != nil {
		return "", time.Time{}, err
	}
	d := s.CodeTTL
	if d <= 0 {
		d = DefaultCodeTTL
	}
	expires := now.Add(d)
	revoked, err := tx.RevokeSponsorCodes(*by.IdentityID, now)
	if err != nil {
		return "", time.Time{}, err
	}
	id := uuid.NewString()
	if err := tx.InsertSponsorCode(&store.SponsorCode{ID: id, SponsorIdentityID: *by.IdentityID, CodeHash: hash, ExpiresAt: expires, CreatedAt: now}); err != nil {
		return "", time.Time{}, err
	}
	return code, expires, tx.Audit(now, by.Display, "guest.sponsor_code.create", ojson.Object{{Key: "code_id", Value: id},
		{Key: "sponsor_identity_id", Value: *by.IdentityID}, {Key: "revoked", Value: revoked}})
}

// ---------------------------------------------------------------- submit

// Request is a visitor's form.
type Request struct {
	GivenName  string
	FamilyName string
	Email      string
	Purpose    string
	StartsAt   time.Time // zero: now
	EndsAt     time.Time
	Handle     string // the sponsor, from the search
	Code       string // or the code the sponsor shared (wins when both are given)
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) })
}

func clean(s string, max int, required bool) (string, bool) {
	s = strings.TrimSpace(s)
	if (required && s == "") || utf8.RuneCountInString(s) > max || hasControl(s) || !utf8.ValidString(s) {
		return "", false
	}
	return s, true
}

// Validate checks the form's own fields (never the sponsor or the address's
// standing) and returns the cleaned request, or a 400 invalid_request.
func (s *Service) Validate(in Request, now time.Time) (Request, error) {
	var ok bool
	bad := func(field string) (Request, error) {
		return Request{}, refuse(400, "invalid_request", "%s is missing or not valid", field)
	}
	out := in
	if out.GivenName, ok = clean(in.GivenName, MaxName, true); !ok {
		return bad("given_name")
	}
	if out.FamilyName, ok = clean(in.FamilyName, MaxName, false); !ok {
		return bad("family_name")
	}
	if out.Purpose, ok = clean(in.Purpose, MaxPurpose, true); !ok {
		return bad("purpose")
	}
	if len(in.Email) > MaxEmail {
		return bad("email")
	}
	norm, err := identifiers.Normalize(store.IdentEmail, in.Email)
	if err != nil {
		return bad("email")
	}
	out.Email = norm
	if len(in.Handle) > 64 || len(in.Code) > MaxCode || (strings.TrimSpace(in.Handle) == "" && strings.TrimSpace(in.Code) == "") {
		return bad("sponsor")
	}
	limit := now.Add(MaxTermDays * 24 * time.Hour)
	if out.StartsAt.IsZero() || out.StartsAt.Before(now) {
		out.StartsAt = now
	}
	if out.StartsAt.After(limit) || !out.EndsAt.After(out.StartsAt) || out.EndsAt.After(out.StartsAt.Add(MaxTermDays*24*time.Hour)) {
		return bad("dates")
	}
	return out, nil
}

// Outcome is what Submit did. It is for the ledger and the tests, never for
// the caller: every outcome is answered the same.
type Outcome string

const (
	OutcomeCreated        Outcome = "created"
	OutcomeExistingEmail  Outcome = "existing_email"
	OutcomeUnknownSponsor Outcome = "unknown_sponsor"
	OutcomeDuplicate      Outcome = "duplicate"
)

// Submit handles a validated form in the caller's tenant transaction. It
// creates a pending request and mails the sponsor and the visitor; for an
// address that already belongs to someone it mails "sign in" and creates
// nothing; for an unknown, ineligible or unreachable sponsor it creates
// nothing and mails nothing. It never creates an identity, an account or a
// claim token.
func (s *Service) Submit(tx *store.TenantTx, in Request, now time.Time) (Outcome, error) {
	if !s.Ready() {
		return "", refuse(503, "registration_unavailable", "registration needs the identifier key")
	}
	mac, err := s.Keyer.MAC(tx.Tenant(), "register-email", in.Email)
	if err != nil {
		return "", err
	}
	known, err := tx.IdentityKnownByEmail(in.Email)
	if err != nil {
		return "", err
	}
	if known {
		// K3: never link, never create; the address's owner is told to sign in
		if err := notify.RegistrationSignIn(tx, now, mac+":"+now.UTC().Format("2006-01-02"), in.Email,
			s.tenantName(tx.Context(), tx.Tenant()), s.SignInURL); err != nil {
			return "", err
		}
		return OutcomeExistingEmail, s.audit(tx, now, "guest.registration.refused", "", ojson.Object{{Key: "reason", Value: "existing_identity"}}, store.OutcomeDenied)
	}
	sponsor, via, err := s.sponsorOf(tx, in, now)
	if err != nil {
		return "", err
	}
	if sponsor == 0 {
		return OutcomeUnknownSponsor, s.audit(tx, now, "guest.registration.refused", "", ojson.Object{{Key: "reason", Value: "unknown_sponsor"}}, store.OutcomeDenied)
	}
	if dup, err := tx.HasPendingRegistration(sponsor, mac); err != nil {
		return "", err
	} else if dup {
		return OutcomeDuplicate, s.audit(tx, now, "guest.registration.refused", "", ojson.Object{{Key: "reason", Value: "duplicate"}}, store.OutcomeDenied)
	}
	r := &store.Registration{ID: uuid.NewString(), SponsorIdentityID: sponsor, Via: via, GivenName: &in.GivenName, FamilyName: &in.FamilyName,
		Email: &in.Email, Purpose: &in.Purpose, EmailHMAC: mac, StartsAt: in.StartsAt, EndsAt: in.EndsAt, ExpiresAt: now.Add(s.ttl()), CreatedAt: now}
	if err := tx.InsertRegistration(r); err != nil {
		return "", err
	}
	if err := notify.RegistrationRequested(tx, now, r); err != nil {
		return "", err
	}
	if err := notify.RegistrationReceived(tx, now, r, s.tenantName(tx.Context(), tx.Tenant())); err != nil {
		return "", err
	}
	return OutcomeCreated, s.audit(tx, now, "guest.registration.submit", r.ID, ojson.Object{{Key: "registration_id", Value: r.ID},
		{Key: "sponsor_identity_id", Value: sponsor}, {Key: "via", Value: via}, {Key: "expires_at", Value: r.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")}}, store.OutcomeSuccess)
}

// sponsorOf resolves the sponsor the form names and checks the policy lets
// them sponsor; 0 for none.
func (s *Service) sponsorOf(tx *store.TenantTx, in Request, now time.Time) (int64, string, error) {
	var id int64
	via := store.RegViaSearch
	if strings.TrimSpace(in.Code) != "" {
		via = store.RegViaCode
		h, err := s.codeHash(tx.Tenant(), in.Code)
		if err != nil {
			return 0, "", err
		}
		c, err := tx.SponsorCodeByHash(h, now)
		if errors.Is(err, store.ErrNotFound) {
			return 0, via, nil
		} else if err != nil {
			return 0, "", err
		}
		id = c.SponsorIdentityID
	} else {
		var err error
		if id, err = s.sponsorByHandle(tx, strings.TrimSpace(in.Handle)); err != nil || id == 0 {
			return 0, via, err
		}
	}
	ok, err := s.Guests.CanSponsor(tx, id)
	if err != nil || !ok {
		return 0, via, err
	}
	return id, via, nil
}

// audit records a registration event; it never carries a name, an address or a code.
func (s *Service) audit(tx *store.TenantTx, now time.Time, action, id string, detail ojson.Object, outcome string) error {
	if id == "" {
		id = "-"
	}
	_, err := audit.Record(tx.Context(), tx, action, detail, audit.At(now), audit.Target("guest_registration", id), audit.Outcome(outcome))
	return err
}
