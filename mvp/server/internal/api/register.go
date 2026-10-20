package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/register"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/ratelimit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Guest self-registration (guest accounts design §3, §6.4, issue #66).
//
// Public, under /public/t/{slug}, with no session:
//
//	GET  register/sponsors?q=   {"sponsors":[{name, handle}]}: names only, an opaque handle each, at least 2 letters
//	POST register               {given_name, family_name, email, purpose, starts_at, ends_at, sponsor, code, challenge_token}
//
// POST register answers the same 202 whether the request was recorded, the
// address already has an account (it is mailed "sign in"), the sponsor is not
// known or the request repeats one that waits. It creates a request for the
// sponsor to decide and nothing else: no identity, no account, no claim link.
//
// For the signed-in sponsor (guests.sponsor):
//
//	GET  /api/guest-registrations                          the requests waiting for me
//	POST /api/guest-registrations/{id}/approve  {population, ends_at}  the guest is created and invited
//	POST /api/guest-registrations/{id}/deny     {reason}               a neutral email goes to the visitor
//	POST /api/guest-registrations/code                      a code to share instead of being searched for
//
// Only the sponsor a request names can decide it.

// registerLimits are the §6.4 limits (token buckets: burst N, refill one per window/N).
type registerLimits struct {
	ip, search, email *ratelimit.Limiter
}

func newRegisterLimits() *registerLimits {
	const keys = 10000
	return &registerLimits{
		ip:     ratelimit.New(ratelimit.ClassIP, 12*time.Minute, 5, keys),       // 5 per IP per hour
		search: ratelimit.New(ratelimit.ClassIP, 2*time.Second, 30, keys),       // 30 searches per IP, then one per 2 s
		email:  ratelimit.New(ratelimit.ClassDestination, 8*time.Hour, 3, keys), // 3 per address per day, so no one mails a stranger in a loop
	}
}

func (s *Server) registerRegistrationRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	s.handle(G, "/public/t/{slug}/register/sponsors", noTenant, publicRoute, s.registerSponsors)
	s.handle(P, "/public/t/{slug}/register", noTenant, publicRoute, s.registerSubmit)
	sponsor := needStepUp(auth.PermGuestsSponsor, auth.StepUpPolicy)
	s.handle(G, "/api/guest-registrations", read, need(auth.PermGuestsSponsor), s.listRegistrations)
	// the literal route first: routes match in registration order
	s.handle(P, "/api/guest-registrations/code", write, sponsor, s.newSponsorCode)
	s.handle(P, "/api/guest-registrations/{registration_id}/approve", write, sponsor, s.approveRegistration)
	s.handle(P, "/api/guest-registrations/{registration_id}/deny", write, sponsor, s.denyRegistration)
}

// registerAnswer is the one response of POST register.
var registerAnswer = ojson.Object{{Key: "status", Value: "ok"},
	{Key: "message", Value: "Check your email. If we can act on your request, we have sent you a message."}}

type registerBody struct {
	GivenName      string `json:"given_name"`
	FamilyName     string `json:"family_name"`
	Email          string `json:"email"`
	Purpose        string `json:"purpose"`
	StartsAt       string `json:"starts_at"`
	EndsAt         string `json:"ends_at"`
	Sponsor        string `json:"sponsor"`
	Code           string `json:"code"`
	ChallengeToken string `json:"challenge_token"`
}

// parseDay reads an RFC 3339 time or a plain date. A plain end date means the
// end of that day.
func parseDay(s string, end bool) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), true
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, false
	}
	if end {
		t = t.Add(24*time.Hour - time.Second)
	}
	return t.UTC(), true
}

func (s *Server) registerSubmit(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	begin := time.Now()
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	var b registerBody
	if resp, ok := s.claimBody(w, r, &b); !ok {
		return resp, nil
	}
	defer s.claimFloor(r.Context(), begin)
	if !s.reg.Ready() || !s.claimReady() { // an approved guest could not be invited
		return statusBody{http.StatusServiceUnavailable, ojson.Object{{Key: "error", Value: "registration_unavailable"}}}, nil
	}
	ip := s.rateKey(r)
	if !s.regLim.ip.AllowAt(ip, c.now) {
		return s.claimThrottled(c, "register_ip", 12*time.Minute)
	}
	// the challenge is about the caller, not the target: refusing it says nothing about anyone
	if human, err := s.reg.Challenge.Verify(r.Context(), b.ChallengeToken, ip.String()); err != nil || !human {
		if err != nil {
			s.log.Warn("registration challenge could not be verified", "err", err)
		}
		return statusBody{http.StatusForbidden, ojson.Object{{Key: "error", Value: "challenge_failed"}}}, nil
	}
	starts, ok1 := parseDay(b.StartsAt, false)
	ends, ok2 := parseDay(b.EndsAt, true)
	in, verr := register.Request{}, error(nil)
	if ok1 && ok2 {
		in, verr = s.reg.Validate(register.Request{GivenName: b.GivenName, FamilyName: b.FamilyName, Email: b.Email, Purpose: b.Purpose,
			StartsAt: starts, EndsAt: ends, Handle: b.Sponsor, Code: b.Code}, c.now)
	} else {
		verr = &register.Error{Status: http.StatusBadRequest, Code: "invalid_request", Msg: "dates are not valid"}
	}
	if verr != nil {
		return nil, reqErr(verr)
	}
	if !c.ok {
		return statusBody{http.StatusAccepted, registerAnswer}, nil
	}
	err = s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		mac, err := s.reg.Keyer.MAC(tx.Tenant(), "register-email", in.Email)
		if err != nil {
			return err
		}
		if !s.regLim.email.AllowAt(ratelimit.DestinationKey(mac), c.now) {
			return claim.Audit(tx, c.now, "claim.throttled", ojson.Object{{Key: "scope", Value: "register_email"}}, store.OutcomeDenied)
		}
		_, err = s.reg.Submit(tx, in, c.now)
		return err
	})
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusAccepted, registerAnswer}, nil
}

func (s *Server) registerSponsors(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	empty := ojson.Object{{Key: "sponsors", Value: []register.SponsorChoice{}}}
	if !c.ok || !s.reg.Ready() {
		return empty, nil
	}
	if !s.regLim.search.AllowAt(s.rateKey(r), c.now) {
		return s.claimThrottled(c, "register_search", 2*time.Second)
	}
	var out []register.SponsorChoice
	err = s.store.ReadTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		var err error
		out, err = s.reg.SearchSponsors(tx, qs(p, "q"))
		return err
	})
	if err != nil {
		return nil, err
	}
	return ojson.Object{{Key: "sponsors", Value: out}}, nil
}

// ---------------------------------------------------------------- the sponsor's side

type registrationView struct {
	ID         string  `json:"id"`
	GivenName  *string `json:"given_name"`
	FamilyName *string `json:"family_name"`
	Email      *string `json:"email"`
	Purpose    *string `json:"purpose"`
	Via        string  `json:"via"`
	StartsAt   string  `json:"starts_at"`
	EndsAt     string  `json:"ends_at"`
	ExpiresAt  string  `json:"expires_at"`
	CreatedAt  string  `json:"created_at"`
}

func viewRegistration(r *store.Registration) registrationView {
	return registrationView{ID: r.ID, GivenName: r.GivenName, FamilyName: r.FamilyName, Email: r.Email, Purpose: r.Purpose, Via: r.Via,
		StartsAt: timeutil.ISO(r.StartsAt), EndsAt: timeutil.ISO(r.EndsAt), ExpiresAt: timeutil.ISO(r.ExpiresAt), CreatedAt: timeutil.ISO(r.CreatedAt)}
}

func (s *Server) listRegistrations(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, err
	}
	rs, err := s.reg.Pending(store.TxFrom(r.Context()), act, s.clock().UTC())
	if err != nil {
		return nil, err
	}
	out := make([]registrationView, 0, len(rs))
	for _, x := range rs {
		out = append(out, viewRegistration(x))
	}
	return struct {
		Registrations []registrationView `json:"registrations"`
	}{out}, nil
}

type approveRegistrationBody struct {
	Population string     `json:"population"`
	EndsAt     *time.Time `json:"ends_at"`
}

func (s *Server) approveRegistration(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	if err := s.keyed(); err != nil {
		return nil, err
	}
	var b approveRegistrationBody
	if err := decodeBody(r, &b, true); err != nil {
		return nil, err
	}
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, err
	}
	in := register.Approval{Population: b.Population}
	if b.EndsAt != nil {
		in.EndsAt = b.EndsAt.UTC()
	}
	res, err := s.reg.Approve(store.TxFrom(r.Context()), act, p.path["registration_id"], in, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return struct {
		ID              string `json:"id"`
		Status          string `json:"status"`
		GuestIdentityID int64  `json:"guest_identity_id"`
		SponsorshipID   string `json:"sponsorship_id"`
	}{p.path["registration_id"], store.RegApproved, res.Guest.ID, res.Sponsorship.ID}, nil
}

type denyRegistrationBody struct {
	Reason string `json:"reason"`
}

func (s *Server) denyRegistration(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	var b denyRegistrationBody
	if err := decodeBody(r, &b, true); err != nil {
		return nil, err
	}
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, err
	}
	if err := s.reg.Deny(store.TxFrom(r.Context()), act, p.path["registration_id"], b.Reason, s.clock().UTC()); err != nil {
		return nil, reqErr(err)
	}
	return struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}{p.path["registration_id"], store.RegDenied}, nil
}

func (s *Server) newSponsorCode(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	act, err := s.sponsorActor(r)
	if err != nil {
		return nil, err
	}
	code, expires, err := s.reg.NewCode(store.TxFrom(r.Context()), act, s.clock().UTC())
	if err != nil {
		return nil, reqErr(err)
	}
	return statusBody{http.StatusCreated, struct {
		Code      string `json:"code"`
		ExpiresAt string `json:"expires_at"`
	}{code, timeutil.ISO(expires)}}, nil
}
