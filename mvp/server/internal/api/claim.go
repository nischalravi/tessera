package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	authnorm "github.com/nischalravi/tessera/mvp/server/internal/auth/normalize"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/oidcrp"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/claim"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/credential"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/terms"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/ratelimit"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// The public claim API (guest accounts design §6, §9.2, issue #69), under
// /public/t/{slug}/claim. A guest reaches it from the emailed link, with no
// Tessera session:
//
//	POST start             {token, key}   exchange the link's token for a claim session (cookie), once
//	POST verify/send                       mail a 6-digit code to the invited address
//	POST verify/check      {code}          check it (5 tries, 10 minutes)
//	GET  status                            the step and what the page may show
//	POST existing-account  {answer}        "do you already have an account?" (asked of everyone; "yes" answers {redirect} to a sign-in as that person)
//	GET  terms                             step 5: the terms documents still to accept, and the attribute-release consent screen
//	POST terms/accept {documents}          accept the documents shown ({id, sha256}); before the credential
//	POST consent {attributes}              federated sign-ins: the attributes the guest agrees to release
//	POST credential                        set up the sign-in: answers {redirect} to the authority (409 terms_required / consent_required until step 5 is done)
//	POST resend            {email}         "send me a new link"
//
// The authority's redirect comes back to the OIDC callback of the sign-in
// machinery (/api/auth/oidc/{connection_id}/callback) with the login purpose
// "claim"; it completes the claim there (claim_complete.go) and sends the
// browser back to /claim.
//
// Every route is registered noTenant: the tenant comes from the slug, and the
// handler opens its own tenant transaction, so audit keeps working (the
// http.request event goes to the tenant's chain as an anonymous caller; the
// domain events are written in the same transactions as the changes). Every
// response carries Cache-Control: no-store and Referrer-Policy: no-referrer.
// After start, every request needs the session cookie and a proof signed with
// the key the page bound at start (claim/proof.go).

// claimMinDuration is the floor of start and resend: the same time for a link
// that exists and one that does not (design §6.4).
const claimMinDuration = 300 * time.Millisecond

// claimLimits are the §6.4 limits. They are token buckets (burst N, refill one
// per window/N), so "3 per 10 minutes" is a burst of 3 that refills over 10 minutes.
type claimLimits struct {
	startIP, startTenant, sendSession, sendDestHour, sendDestDay, resendEmail *ratelimit.Limiter
}

func newClaimLimits() *claimLimits {
	const keys = 10000
	return &claimLimits{
		startIP:      ratelimit.New(ratelimit.ClassIP, time.Minute, 10, keys),               // 10 per IP per 10 minutes
		startTenant:  ratelimit.New(ratelimit.ClassTenant, 600*time.Millisecond, 100, keys), // 100 per tenant per minute
		sendSession:  ratelimit.New(ratelimit.ClassSession, 200*time.Second, 3, keys),       // 3 per session per 10 minutes
		sendDestHour: ratelimit.New(ratelimit.ClassDestination, 12*time.Minute, 5, keys),    // 5 per destination per hour
		sendDestDay:  ratelimit.New(ratelimit.ClassDestination, 144*time.Minute, 10, keys),  // 10 per destination per day
		resendEmail:  ratelimit.New(ratelimit.ClassDestination, 8*time.Hour, 3, keys),       // 3 per address per day
	}
}

func (s *Server) registerClaimRoutes() {
	const G, P = http.MethodGet, http.MethodPost
	s.handle(P, "/public/t/{slug}/claim/start", noTenant, publicRoute, s.claimStart)
	s.handle(P, "/public/t/{slug}/claim/verify/send", noTenant, publicRoute, s.claimVerifySend)
	s.handle(P, "/public/t/{slug}/claim/verify/check", noTenant, publicRoute, s.claimVerifyCheck)
	s.handle(G, "/public/t/{slug}/claim/status", noTenant, publicRoute, s.claimStatus)
	s.handle(P, "/public/t/{slug}/claim/existing-account", noTenant, publicRoute, s.claimExistingAccount)
	s.handle(G, "/public/t/{slug}/claim/terms", noTenant, publicRoute, s.claimTerms)
	s.handle(P, "/public/t/{slug}/claim/terms/accept", noTenant, publicRoute, s.claimTermsAccept)
	s.handle(P, "/public/t/{slug}/claim/consent", noTenant, publicRoute, s.claimConsent)
	s.handle(P, "/public/t/{slug}/claim/credential", noTenant, publicRoute, s.claimCredential)
	s.handle(P, "/public/t/{slug}/claim/resend", noTenant, publicRoute, s.claimResend)
}

// ClaimCookieName is the claim-session cookie; InsecureClaimCookieName is its
// dev-only form without Secure (and so without the __Host- prefix), used
// where the login cookie is (TESSERA_COOKIE_SECURE=false).
const (
	ClaimCookieName         = "__Host-tessera_claim"
	InsecureClaimCookieName = "tessera_claim"
)

func (s *Server) claimCookieName() string {
	if s.cfg.InsecureCookie {
		return InsecureClaimCookieName
	}
	return ClaimCookieName
}

// claimCookie is the session cookie: HttpOnly, SameSite=Lax, Path=/ (the
// __Host- prefix needs it), Secure except in the dev-only insecure mode.
func (s *Server) claimCookie(value string, maxAge int) *http.Cookie {
	// #nosec G124 -- Secure is false only for the dev-only insecure-cookie mode (config allows it only in dev on localhost)
	return &http.Cookie{Name: s.claimCookieName(), Value: value, Path: "/", Secure: !s.cfg.InsecureCookie, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
}

// ---------------------------------------------------------------- plumbing

// claimReq is what every claim handler starts from.
type claimReq struct {
	t   store.Tenant
	ok  bool // an active tenant of that slug exists
	ctx context.Context
	now time.Time
	// bodyHash is claim.BodyHash of the raw request body, which the proof signs
	bodyHash string
}

func (s *Server) claimReady() bool { return s.claimSvc != nil && s.claimSvc.Ready() }

// claimBegin sets the response headers, resolves the tenant from the slug and
// attributes the request's audit events to that tenant's chain (anonymously).
func (s *Server) claimBegin(w http.ResponseWriter, r *http.Request, p *params) (*claimReq, error) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	c := &claimReq{ctx: r.Context(), now: s.clock().UTC()}
	// The proof signs the body, so read it once here (the request is already
	// capped at MaxBodyBytes) and hand the same bytes to the JSON decoder.
	raw, rerr := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	c.bodyHash = claim.BodyHash(raw)
	if rerr != nil {
		c.bodyHash = "" // matches no signed digest: the proof fails
	}
	t, ok, err := s.activeTenant(r.Context(), p.path["slug"])
	if err != nil {
		return nil, err
	}
	c.t, c.ok = t, ok && s.claimReady()
	if c.ok {
		c.ctx = audit.SetPrincipal(r.Context(), audit.Principal{Tenant: t.ID, Actor: store.AuditActor{Type: store.ActorAnonymous}})
		audit.SetAnonymous(r.Context(), "public_route")
	}
	return c, nil
}

// claimBody checks a POST's content type and Origin (a browser always sends
// Origin on a POST; the proof is the stronger check) and decodes its JSON body.
// A nil result means the request was refused and the response is written.
func (s *Server) claimBody(w http.ResponseWriter, r *http.Request, v any) (any, bool) {
	if hasBody(r) && !jsonContentType(r) {
		return statusBody{http.StatusUnsupportedMediaType, ojson.Object{{Key: "error", Value: "unsupported_media_type"}}}, false
	}
	if err := auth.CheckOrigin(r, s.csrfOrigins()); err != nil {
		return statusBody{http.StatusForbidden, ojson.Object{{Key: "error", Value: "csrf_failed"}}}, false
	}
	if v == nil {
		return nil, true
	}
	if err := decodeBody(r, v, false); err != nil {
		return statusBody{http.StatusBadRequest, ojson.Object{{Key: "error", Value: "invalid_request"}}}, false
	}
	return nil, true
}

// claimSessionDenied is the one answer for every way a request can lack a valid
// session: no cookie, an unknown or expired one, a missing or bad proof, an
// unknown tenant.
func claimSessionDenied() statusBody {
	return statusBody{http.StatusUnauthorized, ojson.Object{{Key: "error", Value: "session_required"}}}
}

// claimSession authenticates a session request: cookie, idle and absolute
// lifetime, proof of the bound key. It returns the session, or the response to send.
func (s *Server) claimSession(r *http.Request, c *claimReq) (*store.ClaimSession, *statusBody, error) {
	deny := claimSessionDenied()
	ck, err := r.Cookie(s.claimCookieName())
	if !c.ok || err != nil || ck.Value == "" {
		return nil, &deny, nil
	}
	var sess *store.ClaimSession
	err = s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		x, err := s.claimSvc.Lookup(tx, ck.Value, c.now)
		if errors.Is(err, claim.ErrNoSession) {
			return nil
		}
		if err != nil {
			return err
		}
		if perr := s.claimSvc.VerifyProof(tx, x, r.Header.Get(claim.ProofHeader), r.Method, r.URL.Path, c.bodyHash, c.now); perr != nil {
			if !claim.IsProofError(perr) {
				return perr
			}
			// a cookie without the key: audited, without any secret
			return claim.Audit(tx, c.now, "claim.proof.rejected", ojson.Object{{Key: "intake_id", Value: x.IntakeID},
				{Key: "reason", Value: claim.Reason(perr)}}, store.OutcomeFailure)
		}
		if err := s.claimSvc.Touch(tx, x, c.now); err != nil {
			return err
		}
		sess = x
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if sess == nil {
		return nil, &deny, nil
	}
	return sess, nil, nil
}

// claimThrottled audits a throttle event (never with a token or code) and answers 429.
func (s *Server) claimThrottled(c *claimReq, scope string, retry time.Duration) (any, error) {
	if c.ok {
		if err := s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
			return claim.Audit(tx, c.now, "claim.throttled", ojson.Object{{Key: "scope", Value: scope}}, store.OutcomeDenied)
		}); err != nil {
			return nil, err
		}
	}
	return throttledBody(retry), nil
}

func throttledBody(every time.Duration) statusBody {
	return statusBody{http.StatusTooManyRequests, ojson.Object{{Key: "error", Value: "rate_limited"}, {Key: "retry_after", Value: max(int(every/time.Second), 1)}}}
}

// claimFloor waits until d has passed since begin: the minimum duration of the
// calls whose speed could otherwise tell a real link from a made-up one.
func (s *Server) claimFloor(ctx context.Context, begin time.Time) {
	d := s.cfg.ClaimMinDuration
	if d == 0 {
		d = claimMinDuration
	}
	if left := d - time.Since(begin); left > 0 {
		t := time.NewTimer(left)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
		}
	}
}

// claimStatusBody is what the claim page may know: nothing else.
func (s *Server) claimStatusBody(tx *store.TenantTx, sess *store.ClaimSession) (ojson.Object, error) {
	st, err := s.claimSvc.StatusOf(tx, sess)
	if err != nil {
		return nil, err
	}
	pending := st.Pending
	if st.Step == claim.StepCredential {
		// step 5 first: terms, then the attribute-release consent, then the credential
		due, err := s.claimSvc.OutstandingTerms(tx, sess, s.clock().UTC())
		if err != nil {
			return nil, err
		}
		consent, err := s.claimSvc.ConsentPending(tx, sess, s.authorityKind())
		if err != nil {
			return nil, err
		}
		switch {
		case len(due) > 0:
			pending = "terms"
		case consent:
			pending = "consent"
		default:
			if _, _, ok, err := s.claimAuthority(tx); err != nil {
				return nil, err
			} else if !ok {
				pending = "organization"
			}
		}
	}
	out := ojson.Object{{Key: "step", Value: st.Step}, {Key: "steps", Value: claim.Steps}, {Key: "first_name", Value: st.FirstName},
		{Key: "tenant", Value: st.Tenant}, {Key: "sponsor", Value: st.Sponsor}, {Key: "population", Value: st.Population},
		{Key: "ends_at", Value: rt3339(st.EndsAt)}, {Key: "pending", Value: pending}, {Key: "complete", Value: st.Step == claim.StepComplete}}
	if claim.IsRecovery(sess) {
		out = append(out, ojson.KV{Key: "purpose", Value: "recovery"}) // the claim page says "recover your account"
	}
	return out, nil
}

// claimAuthority returns the credential authority and the tenant connection it
// works through, or ok=false when none is configured for the tenant.
func (s *Server) claimAuthority(tx *store.TenantTx) (credential.Authority, *store.IdPConnection, bool, error) {
	a := s.cfg.Credential
	if a == nil || s.rp == nil {
		return nil, nil, false, nil
	}
	cs, err := loginConnections(tx)
	if err != nil {
		return nil, nil, false, err
	}
	for _, c := range cs {
		// OIDC only: the claim needs a phishing-resistant sign-in, and OAuth 2.0
		// sessions are AAL1 and never phishing resistant, and a claim signs in through the OIDC callback
		if c.Protocol == "oidc" && c.Profile == a.Profile() {
			return a, c, true, nil
		}
	}
	return nil, nil, false, nil
}

// tenantName is a tenant's display name, cached for a few minutes.
type nameCache struct {
	mu sync.Mutex
	m  map[tenancy.ID]nameEntry
}

type nameEntry struct {
	name string
	at   time.Time
}

func (s *Server) tenantName(ctx context.Context, id tenancy.ID) string {
	s.names.mu.Lock()
	if e, ok := s.names.m[id]; ok && time.Since(e.at) < 5*time.Minute {
		s.names.mu.Unlock()
		return e.name
	}
	s.names.mu.Unlock()
	var name string
	if err := s.store.ReadSystem(ctx, "claim tenant name", func(st *store.SystemTx) error {
		t, err := st.TenantByID(id)
		name = t.Name
		return err
	}); err != nil {
		return ""
	}
	s.names.mu.Lock()
	if s.names.m == nil {
		s.names.m = map[tenancy.ID]nameEntry{}
	}
	s.names.m[id] = nameEntry{name, time.Now()}
	s.names.mu.Unlock()
	return name
}

// ---------------------------------------------------------------- start

type claimStartBody struct {
	Token string          `json:"token"`
	Key   json.RawMessage `json:"key"`
}

var claimCheckLink = ojson.Object{{Key: "next", Value: "check_link"}}

// claimStart is POST start. A token that is unknown, expired, used or revoked
// gets the same 200 {"next":"check_link"} after the same minimum time.
func (s *Server) claimStart(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	begin := time.Now()
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	var b claimStartBody
	if resp, ok := s.claimBody(w, r, &b); !ok {
		return resp, nil
	}
	if !s.claimLim.startIP.AllowAt(s.rateKey(r), c.now) {
		return s.claimThrottled(c, "start_ip", 10*time.Minute)
	}
	if c.ok && !s.claimLim.startTenant.AllowAt(ratelimit.TenantKey(c.t.ID.String()), c.now) {
		return s.claimThrottled(c, "start_tenant", time.Minute)
	}
	var replays *claim.Replays
	if s.claimSvc != nil {
		replays = s.claimSvc.Replays
	}
	pub, canonical, jkt, kerr := claim.ParseKey(b.Key)
	var proof claim.Proof
	var perr error
	if kerr == nil {
		proof, perr = claim.Verify(pub, r.Header.Get(claim.ProofHeader), r.Method, r.URL.Path, "", c.bodyHash, c.now, replays)
	}
	if kerr != nil || len(b.Token) == 0 || len(b.Token) > 256 || perr != nil {
		// a malformed request is refused before any token is touched, whatever the token is
		return statusBody{http.StatusBadRequest, ojson.Object{{Key: "error", Value: "invalid_request"}}}, nil
	}
	defer s.claimFloor(r.Context(), begin)
	if !c.ok {
		return statusBody{http.StatusOK, claimCheckLink}, nil
	}
	var started *claim.Started
	var status ojson.Object
	err = s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		if err := claim.UseProof(tx, proof, c.now); errors.Is(err, claim.ErrProofReplay) {
			// a replayed start: the token is not touched; the caller hears what everyone hears
			return claim.Audit(tx, c.now, "claim.start.refused", ojson.Object{{Key: "reason", Value: "proof_replay"}}, store.OutcomeFailure)
		} else if err != nil {
			return err
		}
		st, reason, err := s.claimSvc.Start(tx, b.Token, canonical, jkt, c.now)
		if err != nil {
			return err
		}
		if reason != "" {
			// the reason is for the ledger; the caller is never told
			return claim.Audit(tx, c.now, "claim.start.refused", ojson.Object{{Key: "reason", Value: reason}}, store.OutcomeFailure)
		}
		started = st
		status, err = s.claimStatusBody(tx, st.Session)
		return err
	})
	if err != nil {
		return nil, err
	}
	if started == nil {
		return statusBody{http.StatusOK, claimCheckLink}, nil
	}
	http.SetCookie(w, s.claimCookie(started.Cookie, int(s.claimSvc.AbsoluteLifetime()/time.Second)))
	return ojson.Object{{Key: "next", Value: started.Session.Step}, {Key: "nonce", Value: started.Nonce}, {Key: "status", Value: status}}, nil
}

// ---------------------------------------------------------------- verify

var claimCodeRequested = ojson.Object{{Key: "status", Value: "ok"},
	{Key: "message", Value: "If the address is valid, we have sent a code. It can take a minute to arrive."}}

// claimVerifySend is POST verify/send: the same answer whether a code was
// written, throttled, or not needed.
func (s *Server) claimVerifySend(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	if resp, ok := s.claimBody(w, r, nil); !ok {
		return resp, nil
	}
	sess, deny, err := s.claimSession(r, c)
	if err != nil || deny != nil {
		return orDeny(deny, err)
	}
	var throttled string
	err = s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		cur, err := tx.ClaimSession(sess.IDHash)
		if err != nil {
			return err
		}
		guest, err := tx.Identity(cur.IdentityID)
		if err != nil {
			return err
		}
		dest := cur.IDHash
		if guest.Email != nil {
			if dest, err = s.claimSvc.ContactHash(tx.Tenant(), *guest.Email); err != nil {
				return err
			}
		}
		switch {
		case !s.claimLim.sendSession.AllowAt(ratelimit.SessionKey(cur.IDHash), c.now):
			throttled = "send_session"
		case !s.claimLim.sendDestHour.AllowAt(ratelimit.DestinationKey(dest), c.now):
			throttled = "send_destination_hour"
		case !s.claimLim.sendDestDay.AllowAt(ratelimit.DestinationKey(dest), c.now):
			throttled = "send_destination_day"
		}
		if throttled != "" {
			return claim.Audit(tx, c.now, "claim.throttled", ojson.Object{{Key: "scope", Value: throttled}, {Key: "intake_id", Value: cur.IntakeID}}, store.OutcomeDenied)
		}
		_, err = s.claimSvc.SendCode(tx, cur, c.now)
		return err
	})
	if err != nil {
		return nil, err
	}
	return claimCodeRequested, nil
}

func orDeny(deny *statusBody, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return *deny, nil
}

type claimCodeBody struct {
	Code string `json:"code"`
}

// claimVerifyCheck is POST verify/check: any failure is the same generic answer.
func (s *Server) claimVerifyCheck(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	var b claimCodeBody
	if resp, ok := s.claimBody(w, r, &b); !ok {
		return resp, nil
	}
	sess, deny, err := s.claimSession(r, c)
	if err != nil || deny != nil {
		return orDeny(deny, err)
	}
	var res claim.CodeCheck
	var next string
	err = s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		cur, err := tx.ClaimSession(sess.IDHash)
		if err != nil {
			return err
		}
		if res, err = s.claimSvc.CheckCode(tx, cur, b.Code, c.now); err != nil {
			return err
		}
		next = cur.Step
		if !res.OK {
			return claim.Audit(tx, c.now, "claim.code.failed", ojson.Object{{Key: "intake_id", Value: cur.IntakeID},
				{Key: "reason", Value: res.Reason}}, store.OutcomeFailure)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !res.OK {
		return statusBody{http.StatusUnprocessableEntity, ojson.Object{{Key: "error", Value: "code_invalid"},
			{Key: "message", Value: "That code did not work. Check it, or ask for a new one."}}}, nil
	}
	return ojson.Object{{Key: "ok", Value: true}, {Key: "step", Value: next}}, nil
}

// ---------------------------------------------------------------- status, existing account

func (s *Server) claimStatus(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	sess, deny, err := s.claimSession(r, c)
	if err != nil || deny != nil {
		return orDeny(deny, err)
	}
	var out ojson.Object
	err = s.store.ReadTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		cur, err := tx.ClaimSession(sess.IDHash)
		if err != nil {
			return err
		}
		out, err = s.claimStatusBody(tx, cur)
		return err
	})
	return out, err
}

type claimExistingBody struct {
	Answer string `json:"answer"`
}

// claimExistingAccount is POST existing-account: "do you already have an
// account?", asked of every claimant. A "no" moves on to the credential. A "yes"
// starts a sign-in with the tenant's identity provider (purpose claim, recorded
// as a claim link); the callback links the claim to the person who signed in
// when they are one of the people the matcher thought this invitation might be
// (§6.5), and otherwise the claim goes on at the credential step. The answer
// is the same whatever the matcher found: the claimant is never told whether a
// match exists, and a "yes" always gets a sign-in.
func (s *Server) claimExistingAccount(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	var b claimExistingBody
	if resp, ok := s.claimBody(w, r, &b); !ok {
		return resp, nil
	}
	sess, deny, err := s.claimSession(r, c)
	if err != nil || deny != nil {
		return orDeny(deny, err)
	}
	// 1. read: the tenant's sign-in connection and what the claim asks of it
	var conn *store.IdPConnection
	aal := 1
	if b.Answer == "yes" {
		err = s.store.ReadTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
			cur, err := tx.ClaimSession(sess.IDHash)
			if err != nil || cur.Step != claim.StepExistingAccount {
				return err // a wrong step is refused below, with the other refusals
			}
			cs, err := loginConnections(tx)
			if err != nil {
				return err
			}
			conn = claimSignInConnection(cs)
			if _, a, err := s.claimSvc.Requirements(tx, cur); err == nil {
				aal = a
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	// 2. outside any transaction: the authorization URL
	var cookie, authURL string
	var txn *store.LoginTransaction
	if conn != nil && s.rp != nil {
		if cookie, txn, authURL, err = s.claimSignIn(c, conn, aal); err != nil {
			s.log.Warn("claim: the existing-account sign-in could not start", "request_id", audit.RequestID(c.ctx))
			authURL = "" // the claim goes on without it
		}
	}
	// 3. write: the answer, and the login transaction with the claim link that tells the callback what it is for
	var rerr error
	err = s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		cur, err := tx.ClaimSession(sess.IDHash)
		if err != nil {
			return err
		}
		if err := s.claimSvc.ExistingAccount(tx, cur, b.Answer, c.now); err != nil {
			var ce *claim.Error
			if errors.As(err, &ce) {
				rerr = ce
				return nil
			}
			return err
		}
		if authURL == "" {
			return nil
		}
		if err := tx.InsertLoginTransaction(txn); err != nil {
			return err
		}
		return tx.InsertClaimLink(&store.ClaimLink{ID: uuid.NewString(), SessionIDHash: cur.IDHash, IntakeID: cur.IntakeID,
			LoginTxnID: txn.ID.String(), CreatedAt: c.now})
	})
	if err != nil {
		return nil, err
	}
	var ce *claim.Error
	if errors.As(rerr, &ce) {
		return statusBody{ce.Status, ojson.Object{{Key: "error", Value: ce.Code}}}, nil
	}
	out := ojson.Object{{Key: "ok", Value: true}, {Key: "step", Value: claim.StepCredential}}
	switch {
	case authURL != "":
		http.SetCookie(w, s.loginCookie(cookie, int(loginTxnTTL/time.Second)))
		out = append(out, ojson.KV{Key: "status", Value: "redirect"}, ojson.KV{Key: "redirect", Value: authURL})
	case b.Answer == "yes":
		// nothing to sign in to here: the answer is kept for the reviewers and the claim goes on
		out = append(out, ojson.KV{Key: "message", Value: "Thank you. An administrator will follow up about your existing account. You can carry on setting up this one."})
	}
	return out, nil
}

// claimSignInConnection picks the connection for a claim's sign-in as an
// existing person: the default one, or the only one, among the OIDC
// connections. A claim asks for a phishing-resistant level and OAuth 2.0
// sessions are AAL1 (its callback refuses the claim purpose anyway); a claim
// signs in through the OIDC callback, not SAML. Nil: none.
func claimSignInConnection(cs []*store.IdPConnection) *store.IdPConnection {
	var oidc []*store.IdPConnection
	for _, x := range cs {
		if x.Protocol == "oidc" {
			oidc = append(oidc, x)
		}
	}
	for _, x := range oidc {
		if x.IsDefault || len(oidc) == 1 {
			return x
		}
	}
	return nil
}

// claimSignIn builds the sign-in as an existing person: a login transaction
// (purpose claim, a fresh authentication at the sponsorship's assurance level)
// and the authorization URL. Nothing is written; the caller stores the
// transaction with the claim link.
func (s *Server) claimSignIn(c *claimReq, conn *store.IdPConnection, aal int) (cookie string, txn *store.LoginTransaction, authURL string, err error) {
	rc, err := s.rpConnection(c.t.ID, conn)
	if err != nil {
		return "", nil, "", err
	}
	required := claimACR(aal)
	cookie, state, nonce, verifier := seal.RandomSecret(32), seal.RandomSecret(32), seal.RandomSecret(32), seal.RandomSecret(48)
	stateHash := seal.SHA256Hex([]byte(state))
	maxAge := claimMaxAge
	req, claims := requestedAuthn(conn, required)
	txn = &store.LoginTransaction{ID: uuid.New(), CookieHash: seal.SHA256Hex([]byte(cookie)), IdPConnectionID: conn.ID,
		Purpose: "claim", StateHash: &stateHash, Nonce: &nonce, RequiredTesseraACR: &required, MaxAge: &maxAge,
		ReturnTo: "/claim", CreatedAt: c.now, ExpiresAt: c.now.Add(loginTxnTTL)}
	if txn.PKCEVerifierEnc, err = s.cfg.Sealer.Seal([]byte(verifier), verifierAAD(c.t.ID, txn.ID)); err != nil {
		return "", nil, "", err
	}
	authURL, err = s.rp.AuthURL(c.ctx, rc, oidcrp.AuthRequest{RedirectURI: s.redirectURI(conn.ID), State: state, Nonce: nonce,
		Verifier: verifier, ACRValues: req.ACRValues, MaxAge: &maxAge, Prompt: "login", Claims: claims})
	if err != nil {
		return "", nil, "", err
	}
	return cookie, txn, authURL, nil
}

// ---------------------------------------------------------------- credential

var claimPendingOrg = ojson.Object{{Key: "status", Value: "pending"}, {Key: "pending", Value: "organization"},
	{Key: "message", Value: "Your organization will finish setting up your sign-in. We will email you when it is ready."}}

// claimCredential is POST credential: it registers the guest with the
// credential authority and answers {redirect} to its sign-in. With no authority
// set up, the claim stays pending.
func (s *Server) claimCredential(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	if resp, ok := s.claimBody(w, r, nil); !ok {
		return resp, nil
	}
	sess, deny, err := s.claimSession(r, c)
	if err != nil || deny != nil {
		return orDeny(deny, err)
	}
	// 1. read: is the step open, which authority and connection, who is the guest
	var (
		authority credential.Authority
		conn      *store.IdPConnection
		guest     *store.Identity
		aal       int
		wrongStep bool
		haveAuth  bool
		gate      string // step 5 is not done: terms_required or consent_required
	)
	err = s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		cur, err := tx.ClaimSession(sess.IDHash)
		if err != nil {
			return err
		}
		if cur.Step != claim.StepCredential {
			wrongStep = true
			return nil
		}
		// acceptance comes before a credential is bound (§7.4)
		if gate, err = s.step5Gate(tx, cur, c.now); err != nil || gate != "" {
			return err
		}
		if authority, conn, haveAuth, err = s.claimAuthority(tx); err != nil {
			return err
		}
		if !haveAuth {
			return s.claimSvc.RecordCredentialPending(tx, cur, "no_authority", c.now)
		}
		if _, aal, err = s.claimSvc.Requirements(tx, cur); err != nil {
			return err
		}
		guest, err = tx.Identity(cur.IdentityID)
		return err
	})
	if err != nil {
		return nil, err
	}
	switch {
	case wrongStep:
		return statusBody{http.StatusConflict, ojson.Object{{Key: "error", Value: "wrong_step"}}}, nil
	case gate != "":
		return statusBody{http.StatusConflict, ojson.Object{{Key: "error", Value: gate}}}, nil
	case !haveAuth:
		return claimPendingOrg, nil
	}
	// 2. outside any transaction: the authority and the authorization URL
	rc, err := s.rpConnection(c.t.ID, conn)
	if err != nil {
		return nil, err
	}
	email := ""
	if guest.Email != nil {
		email = *guest.Email
	}
	reg, err := authority.Register(c.ctx, credential.Connection{Issuer: rc.Issuer, ClientID: rc.ClientID, ClientSecret: rc.ClientSecret},
		credential.Guest{Tenant: c.t.Slug, Ref: strings.TrimPrefix(guest.ExternalID, "guest:"), Email: email, Name: guest.Name})
	if err != nil {
		s.log.Warn("claim: the credential authority refused", "authority", authority.Kind(), "request_id", audit.RequestID(c.ctx))
		if aerr := s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
			return claim.Audit(tx, c.now, "claim.credential.failed", ojson.Object{{Key: "intake_id", Value: sess.IntakeID},
				{Key: "reason", Value: "authority_unavailable"}, {Key: "authority", Value: authority.Kind()}}, store.OutcomeFailure)
		}); aerr != nil {
			return nil, aerr
		}
		return statusBody{http.StatusBadGateway, ojson.Object{{Key: "error", Value: "authority_unavailable"},
			{Key: "message", Value: "We could not reach the sign-in service. Try again in a moment."}}}, nil
	}
	required := claimACR(aal)
	cookie, state, nonce, verifier := seal.RandomSecret(32), seal.RandomSecret(32), seal.RandomSecret(32), seal.RandomSecret(48)
	stateHash := seal.SHA256Hex([]byte(state))
	maxAge := claimMaxAge
	req, claims := requestedAuthn(conn, required)
	txn := &store.LoginTransaction{ID: uuid.New(), CookieHash: seal.SHA256Hex([]byte(cookie)), IdPConnectionID: conn.ID,
		Purpose: "claim", StateHash: &stateHash, Nonce: &nonce, RequiredTesseraACR: &required, MaxAge: &maxAge,
		ReturnTo: "/claim", CreatedAt: c.now, ExpiresAt: c.now.Add(loginTxnTTL)}
	if txn.PKCEVerifierEnc, err = s.cfg.Sealer.Seal([]byte(verifier), verifierAAD(c.t.ID, txn.ID)); err != nil {
		return nil, err
	}
	authURL, err := s.rp.AuthURL(c.ctx, rc, oidcrp.AuthRequest{RedirectURI: s.redirectURI(conn.ID), State: state, Nonce: nonce,
		Verifier: verifier, ACRValues: req.ACRValues, MaxAge: &maxAge, Prompt: "login", Claims: claims, LoginHint: reg.LoginHint})
	if err != nil {
		return statusBody{http.StatusBadGateway, ojson.Object{{Key: "error", Value: "authority_unavailable"}}}, nil
	}
	// 3. write: the login transaction and the claim's record of what to expect
	err = s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		cur, err := tx.ClaimSession(sess.IDHash)
		if err != nil {
			return err
		}
		if err := tx.InsertLoginTransaction(txn); err != nil {
			return err
		}
		return s.claimSvc.RecordCredentialStart(tx, cur, authority.Kind(), reg.Subject, txn.ID.String(), c.now)
	})
	if err != nil {
		return nil, err
	}
	http.SetCookie(w, s.loginCookie(cookie, int(loginTxnTTL/time.Second)))
	return ojson.Object{{Key: "status", Value: "redirect"}, {Key: "redirect", Value: authURL}}, nil
}

// claimMaxAge is the max_age of a claim sign-in: it must be fresh (the IdP is
// also told prompt=login).
const claimMaxAge = int64(600)

// claimACR is the Tessera ACR a claim asks the authority for, from the
// sponsorship's required authenticator assurance level.
func claimACR(aal int) string {
	switch {
	case aal >= 3:
		return authnorm.ACRPhrh
	case aal == 2:
		return authnorm.ACRAAL2
	}
	return authnorm.ACRAAL1
}

// ---------------------------------------------------------------- resend

var claimResent = ojson.Object{{Key: "message", Value: "If an invitation exists for this address, we have sent a new link."}}

type claimResendBody struct {
	Email string `json:"email"`
}

// claimResend is POST resend: the same answer and the same minimum duration
// whether or not an invitation exists, and whether or not it was throttled.
func (s *Server) claimResend(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	begin := time.Now()
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	var b claimResendBody
	if resp, ok := s.claimBody(w, r, &b); !ok {
		return resp, nil
	}
	defer s.claimFloor(r.Context(), begin)
	if !c.ok || len(b.Email) > 320 {
		return claimResent, nil
	}
	err = s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		mac, err := s.claimSvc.ContactHash(tx.Tenant(), b.Email)
		if err != nil {
			return nil // not an address
		}
		if !s.claimLim.resendEmail.AllowAt(ratelimit.DestinationKey(mac), c.now) {
			return claim.Audit(tx, c.now, "claim.throttled", ojson.Object{{Key: "scope", Value: "resend_email"}}, store.OutcomeDenied)
		}
		ss, err := s.claimSvc.FindByEmail(tx, b.Email)
		if err != nil || ss == nil {
			return err
		}
		_, err = s.claimSvc.Issue(tx, ss, "requested", c.now)
		var ce *claim.Error
		if errors.As(err, &ce) {
			return nil // nothing to send; the answer is the same
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return claimResent, nil
}

// ---------------------------------------------------------------- step 5: terms and consent

// authorityKind is the kind of the tenant's credential authority ("" when none).
func (s *Server) authorityKind() string {
	if s.cfg.Credential == nil {
		return ""
	}
	return s.cfg.Credential.Kind()
}

// step5Gate says why the credential cannot start: terms_required while a
// document that applies is not accepted, consent_required while the
// attribute-release screen of a federated sign-in is not answered; "" when step
// 5 is done.
func (s *Server) step5Gate(tx *store.TenantTx, sess *store.ClaimSession, now time.Time) (string, error) {
	due, err := s.claimSvc.OutstandingTerms(tx, sess, now)
	if err != nil {
		return "", err
	}
	if len(due) > 0 {
		return "terms_required", nil
	}
	pending, err := s.claimSvc.ConsentPending(tx, sess, s.authorityKind())
	if pending {
		return "consent_required", err
	}
	return "", err
}

type claimConsentView struct {
	Applies    bool              `json:"applies"`
	Given      bool              `json:"given"`
	Authority  string            `json:"authority,omitempty"`
	Attributes []terms.Attribute `json:"attributes"`
}

// claimTerms is GET terms: the documents the claimant still has to read and
// accept (the text and its hash, which the acceptance must echo) and the
// consent screen. Nothing else.
func (s *Server) claimTerms(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	sess, deny, err := s.claimSession(r, c)
	if err != nil || deny != nil {
		return orDeny(deny, err)
	}
	var out ojson.Object
	err = s.store.ReadTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		cur, err := tx.ClaimSession(sess.IDHash)
		if err != nil {
			return err
		}
		due, err := s.claimSvc.OutstandingTerms(tx, cur, c.now)
		if err != nil {
			return err
		}
		consent := claimConsentView{Attributes: []terms.Attribute{}}
		if kind := s.authorityKind(); terms.ConsentApplies(kind) {
			given, err := terms.ConsentGiven(tx, cur.IDHash)
			if err != nil {
				return err
			}
			consent = claimConsentView{Applies: true, Given: given, Authority: kind, Attributes: terms.Attributes}
		}
		out = ojson.Object{{Key: "step", Value: cur.Step}, {Key: "terms", Value: viewRequirements(due, true)}, {Key: "consent", Value: consent}}
		return nil
	})
	return out, err
}

type claimAcceptBody struct {
	Documents []terms.Shown `json:"documents"`
}

// claimTermsAccept is POST terms/accept.
func (s *Server) claimTermsAccept(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	var b claimAcceptBody
	if resp, ok := s.claimBody(w, r, &b); !ok {
		return resp, nil
	}
	sess, deny, err := s.claimSession(r, c)
	if err != nil || deny != nil {
		return orDeny(deny, err)
	}
	var refused *claim.Error
	var left int
	err = s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		cur, err := tx.ClaimSession(sess.IDHash)
		if err != nil {
			return err
		}
		if _, err := s.claimSvc.AcceptTerms(tx, cur, b.Documents, s.claimSvc.ClientHash(c.t.ID, "ip", s.rateKey(r).String()),
			s.claimSvc.ClientHash(c.t.ID, "ua", r.UserAgent()), c.now); err != nil {
			if errors.As(err, &refused) {
				return nil // nothing was written; the refusal is answered below
			}
			return err
		}
		due, err := s.claimSvc.OutstandingTerms(tx, cur, c.now)
		left = len(due)
		return err
	})
	if err != nil {
		return nil, err
	}
	if refused != nil {
		return statusBody{refused.Status, ojson.Object{{Key: "error", Value: refused.Code}}}, nil
	}
	return ojson.Object{{Key: "ok", Value: true}, {Key: "remaining", Value: left}}, nil
}

type claimConsentBody struct {
	Attributes []string `json:"attributes"`
}

// claimConsent is POST consent: the attributes the claimant agrees to release.
func (s *Server) claimConsent(w http.ResponseWriter, r *http.Request, p *params) (any, error) {
	c, err := s.claimBegin(w, r, p)
	if err != nil {
		return nil, err
	}
	var b claimConsentBody
	if resp, ok := s.claimBody(w, r, &b); !ok {
		return resp, nil
	}
	sess, deny, err := s.claimSession(r, c)
	if err != nil || deny != nil {
		return orDeny(deny, err)
	}
	var refused *claim.Error
	err = s.store.InTenant(c.ctx, c.t.ID, func(tx *store.TenantTx) error {
		cur, err := tx.ClaimSession(sess.IDHash)
		if err != nil {
			return err
		}
		if err := s.claimSvc.RecordConsent(tx, cur, s.authorityKind(), b.Attributes, c.now); err != nil {
			if errors.As(err, &refused) {
				return nil
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if refused != nil {
		return statusBody{refused.Status, ojson.Object{{Key: "error", Value: refused.Code}}}, nil
	}
	return ojson.Object{{Key: "ok", Value: true}}, nil
}
