package devidp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Endpoint paths, relative to the issuer.
const (
	pathAuthorize = "/authorize"
	pathToken     = "/token"
	pathJWKS      = "/jwks"
	pathUserinfo  = "/userinfo"
	pathLogout    = "/logout"
	jwtBearerType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" // #nosec G101 -- a URN, not a credential
)

var (
	// A S256 code_challenge is base64url(SHA-256), always 43 characters.
	challengeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	// RFC 7636 §4.1 code_verifier.
	verifierRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	maxAgeRE   = regexp.MustCompile(`^[0-9]{1,9}$`)
)

// clientAssertionAlgs are the algorithms accepted for private_key_jwt.
var clientAssertionAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256, jose.EdDSA}

// pendingAuthz is a validated authorization request waiting for the user.
type pendingAuthz struct {
	clientID      string
	redirectURI   string
	state         string
	nonce         string
	codeChallenge string
	scope         []string
	req           requested
	maxAge        int
	hasMaxAge     bool
	loginHint     string
	fault         Fault
	github        bool // GitHub-style OAuth 2.0 (github.go): no ID token
}

// authCode is what an authorization code is redeemed for.
type authCode struct {
	authz    pendingAuthz
	user     User
	method   Method
	profile  Profile
	authTime time.Time
	sid      string
}

// idpSession is the dev IdP's own single sign-on session.
type idpSession struct {
	sid      string
	user     User
	method   Method
	profile  Profile
	authTime time.Time
}

// accessGrant backs an opaque access token, usable only at /userinfo.
type accessGrant struct {
	claims map[string]any
}

// discovery is the OpenID Provider metadata (OIDC Discovery 1.0 §3, RFC 8414,
// RFC 9207).
type discovery struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	JWKSURI                                string   `json:"jwks_uri"`
	UserinfoEndpoint                       string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                     string   `json:"end_session_endpoint"`
	ScopesSupported                        []string `json:"scopes_supported"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	ResponseModesSupported                 []string `json:"response_modes_supported"`
	GrantTypesSupported                    []string `json:"grant_types_supported"`
	SubjectTypesSupported                  []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported       []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgsSupported  []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	CodeChallengeMethodsSupported          []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                        []string `json:"claims_supported"`
	ClaimsParameterSupported               bool     `json:"claims_parameter_supported"`
	ACRValuesSupported                     []string `json:"acr_values_supported"`
	PromptValuesSupported                  []string `json:"prompt_values_supported"`
	RequestParameterSupported              bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported           bool     `json:"request_uri_parameter_supported"`
	AuthorizationResponseIssParamSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	algs := make([]string, len(clientAssertionAlgs))
	for i, a := range clientAssertionAlgs {
		algs[i] = string(a)
	}
	writeJSON(w, http.StatusOK, discovery{
		Issuer:                                 s.issuer,
		AuthorizationEndpoint:                  s.issuer + pathAuthorize,
		TokenEndpoint:                          s.issuer + pathToken,
		JWKSURI:                                s.issuer + pathJWKS,
		UserinfoEndpoint:                       s.issuer + pathUserinfo,
		EndSessionEndpoint:                     s.issuer + pathLogout,
		ScopesSupported:                        []string{"openid", "email", "profile", "groups"},
		ResponseTypesSupported:                 []string{"code"},
		ResponseModesSupported:                 []string{"query"},
		GrantTypesSupported:                    []string{"authorization_code"},
		SubjectTypesSupported:                  []string{"public", "pairwise"},
		IDTokenSigningAlgValuesSupported:       []string{string(jose.RS256)},
		TokenEndpointAuthMethodsSupported:      []string{"client_secret_basic", "private_key_jwt"},
		TokenEndpointAuthSigningAlgsSupported:  algs,
		CodeChallengeMethodsSupported:          []string{"S256"},
		ClaimsSupported:                        []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "sid", "acr", "amr", "acrs", "email", "email_verified", "name", "preferred_username", "groups", "roles", "device_managed", "device_compliant", "oid", "tid", "at_hash"},
		ClaimsParameterSupported:               true,
		ACRValuesSupported:                     acrValuesSupported,
		PromptValuesSupported:                  []string{"none", "login"},
		RequestParameterSupported:              false,
		RequestURIParameterSupported:           false,
		AuthorizationResponseIssParamSupported: true,
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.JWKS())
}

// handleAuthorize validates an authorization request (OIDC Core §3.1.2) and
// either completes it from the SSO session or shows the sign-in page.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := s.now()
	// Until client_id and redirect_uri are known good, errors are shown here
	// and never redirected (RFC 6749 §4.1.2.1).
	c := s.clients[q.Get("client_id")]
	if c == nil || len(q["client_id"]) != 1 {
		s.errorPage(w, http.StatusBadRequest, "Unknown or repeated client_id.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if len(q["redirect_uri"]) != 1 || !absoluteHTTP(redirectURI) || !c.redirectAllowed(redirectURI) {
		s.errorPage(w, http.StatusBadRequest, "redirect_uri is missing, repeated or not registered for this client.")
		return
	}
	p, code, desc := s.parseAuthz(q, c, redirectURI)
	if code != "" {
		s.redirectError(w, r, redirectURI, q.Get("state"), code, desc)
		return
	}
	prompt := strings.Fields(q.Get("prompt"))
	sess, ok := s.session(r, now)
	reauth := !ok || slices.Contains(prompt, "login") ||
		(p.hasMaxAge && (p.maxAge == 0 || now.Sub(sess.authTime) > time.Duration(p.maxAge)*time.Second)) ||
		(p.loginHint != "" && !sess.user.matchesHint(p.loginHint))
	if !reauth {
		s.issueCode(w, r, p, authCode{user: sess.user, method: sess.method, profile: sess.profile,
			authTime: sess.authTime, sid: sess.sid}, http.StatusFound)
		return
	}
	if slices.Contains(prompt, "none") {
		s.redirectError(w, r, redirectURI, p.state, "login_required", "the user must sign in")
		return
	}
	id := rand.Text()
	if err := s.pending.put(id, p, now.Add(pendingTTL), now); err != nil {
		s.errorPage(w, http.StatusServiceUnavailable, "Too many sign-ins in progress.")
		return
	}
	s.renderSignIn(w, id, p)
}

// parseAuthz checks every parameter after client_id and redirect_uri. On
// failure it returns an OAuth error code and description.
func (s *Server) parseAuthz(q url.Values, c *Client, redirectURI string) (pendingAuthz, string, string) {
	p := pendingAuthz{clientID: c.ID, redirectURI: redirectURI}
	for k, v := range q {
		if len(v) > 1 {
			return p, "invalid_request", "parameter " + k + " is repeated"
		}
	}
	p.state = q.Get("state")
	switch {
	case q.Has("request"):
		return p, "request_not_supported", "request objects are not supported"
	case q.Has("request_uri"):
		return p, "request_uri_not_supported", "request_uri is not supported"
	case q.Get("response_type") != "code":
		return p, "unsupported_response_type", "only response_type=code is supported"
	case q.Has("response_mode") && q.Get("response_mode") != "query":
		return p, "invalid_request", "only response_mode=query is supported"
	case p.state == "":
		return p, "invalid_request", "state is required"
	case q.Get("nonce") == "":
		return p, "invalid_request", "nonce is required"
	case q.Get("code_challenge_method") != "S256" || !challengeRE.MatchString(q.Get("code_challenge")):
		return p, "invalid_request", "PKCE is required: code_challenge with code_challenge_method=S256"
	}
	p.scope = strings.Fields(q.Get("scope"))
	if !slices.Contains(p.scope, "openid") {
		return p, "invalid_scope", "scope must include openid"
	}
	p.nonce = q.Get("nonce")
	p.codeChallenge = q.Get("code_challenge")
	p.loginHint = q.Get("login_hint")
	p.req.acrValues = strings.Fields(q.Get("acr_values"))
	if q.Has("max_age") {
		v := q.Get("max_age")
		n, err := strconv.Atoi(v)
		if !maxAgeRE.MatchString(v) || err != nil || n > maxMaxAge {
			return p, "invalid_request", "max_age must be a non-negative number of seconds"
		}
		p.maxAge, p.hasMaxAge = n, true
	}
	prompt := strings.Fields(q.Get("prompt"))
	for _, v := range prompt {
		if !slices.Contains([]string{"none", "login", "consent", "select_account"}, v) {
			return p, "invalid_request", "unknown prompt value"
		}
	}
	if slices.Contains(prompt, "none") && len(prompt) > 1 {
		return p, "invalid_request", "prompt=none cannot be combined with other values"
	}
	if q.Has("claims") {
		acrs, err := parseClaimsACRS(q.Get("claims"))
		if err != nil {
			return p, "invalid_request", "claims: " + err.Error()
		}
		p.req.entraACRS = acrs
	}
	p.fault = s.currentFault()
	if q.Has("fault") {
		if !s.faults {
			return p, "invalid_request", "fault injection is disabled"
		}
		f, err := ParseFault(q.Get("fault"))
		if err != nil {
			return p, "invalid_request", err.Error()
		}
		if slices.Contains(SAMLFaults(), f) || slices.Contains(GitHubFaults(), f) {
			return p, "invalid_request", fmt.Sprintf("fault %q is a SAML fault; it does not apply to OIDC", f)
		}
		p.fault = f
	}
	if err := faultApplies(p.fault, p, prompt); err != nil {
		return p, "invalid_request", err.Error()
	}
	return p, "", ""
}

// faultApplies refuses a fault in a request where it would not be a defect:
// acr_unrequested only means something when phr/phrh (or an Entra auth
// context) was NOT requested, and sub_change_on_stepup only on a
// re-authentication (prompt=login or max_age).
func faultApplies(f Fault, p pendingAuthz, prompt []string) error {
	switch f {
	case FaultACRUnrequested:
		if slices.Contains(p.req.acrValues, OktaACRPhr) || slices.Contains(p.req.acrValues, OktaACRPhrh) || len(p.req.entraACRS) > 0 {
			return errors.New("fault acr_unrequested needs a request that does not ask for phr, phrh or an acrs context")
		}
	case FaultSubChangeStepUp:
		if !slices.Contains(prompt, "login") && !p.hasMaxAge {
			return errors.New("fault sub_change_on_stepup needs a step-up request (prompt=login or max_age)")
		}
	}
	return nil
}

// parseClaimsACRS reads id_token.acrs.values from an OIDC claims parameter
// (Entra's way of requesting a Conditional Access authentication context).
func parseClaimsACRS(v string) ([]string, error) {
	var c struct {
		IDToken map[string]*struct {
			Essential bool     `json:"essential"`
			Values    []string `json:"values"`
			Value     string   `json:"value"`
		} `json:"id_token"`
	}
	if len(v) > 4096 {
		return nil, errors.New("too long")
	}
	if err := json.Unmarshal([]byte(v), &c); err != nil {
		return nil, errors.New("not a JSON object")
	}
	a := c.IDToken["acrs"]
	if a == nil {
		return nil, nil
	}
	if a.Value != "" {
		return []string{a.Value}, nil
	}
	return a.Values, nil
}

// matchesHint reports whether login_hint names the user: the subject, the
// email, or the Entra oid. The hint only preselects the user on the page and
// forces the page when the SSO session belongs to someone else; subject
// checks are the relying party's job (see the sub_change_on_stepup fault).
func (u *User) matchesHint(hint string) bool {
	return strings.EqualFold(hint, u.Sub) || strings.EqualFold(hint, u.Email) || strings.EqualFold(hint, EntraObjectID(u.Sub))
}

// handleAuthorizeSubmit completes the sign-in page.
func (s *Server) handleAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, http.StatusBadRequest, "Malformed form.")
		return
	}
	f := r.PostForm
	p, ok := s.pending.take(f.Get("req"), now)
	if !ok {
		s.errorPage(w, http.StatusBadRequest, "This sign-in request is unknown or expired. Start again from the application.")
		return
	}
	if f.Get("action") == "cancel" {
		s.redirectError(w, r, p.redirectURI, p.state, "access_denied", "the user cancelled the sign-in")
		return
	}
	sub, m, _ := strings.Cut(f.Get("choice"), " ")
	method := Method(m)
	profile := Profile(f.Get("profile"))
	user := s.findUser(sub)
	switch {
	case user == nil:
		s.errorPage(w, http.StatusBadRequest, "Unknown user.")
		return
	case !user.has(method):
		s.errorPage(w, http.StatusBadRequest, "That user has no such authenticator.")
		return
	case !p.github && !slices.Contains(Profiles(), profile):
		s.errorPage(w, http.StatusBadRequest, "Unknown profile.")
		return
	}
	sess := idpSession{sid: rand.Text(), user: *user, method: method, profile: profile, authTime: now}
	cookie := rand.Text()
	if err := s.sessions.put(cookie, sess, now.Add(sessionTTL), now); err != nil {
		s.errorPage(w, http.StatusServiceUnavailable, "Too many sessions.")
		return
	}
	s.setSessionCookie(w, cookie, int(sessionTTL/time.Second))
	s.log.Info("devidp sign-in", "sub", user.Sub, "method", method, "profile", profile, "client_id", p.clientID)
	s.issueCode(w, r, p, authCode{user: *user, method: method, profile: profile, authTime: now, sid: sess.sid}, http.StatusSeeOther)
}

// setSessionCookie sets (or, with maxAge -1, clears) the IdP session cookie.
// It is Secure when the issuer is https; the local dev IdP is served over
// plain http on loopback, where a Secure cookie would not be stored by every
// browser.
func (s *Server) setSessionCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: value, Path: "/", HttpOnly: true, MaxAge: maxAge, // #nosec G124 -- Secure follows the issuer scheme (loopback http in dev)
		Secure: strings.HasPrefix(s.issuer, "https://"), SameSite: http.SameSiteLaxMode})
}

func (s *Server) session(r *http.Request, now time.Time) (idpSession, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return idpSession{}, false
	}
	return s.sessions.get(c.Value, now)
}

// issueCode stores a single-use code and redirects back to the client.
func (s *Server) issueCode(w http.ResponseWriter, r *http.Request, p pendingAuthz, ac authCode, status int) {
	now := s.now()
	ac.authz = p
	code := rand.Text()
	if err := s.codes.put(code, ac, now.Add(codeTTL), now); err != nil {
		s.redirectError(w, r, p.redirectURI, p.state, "temporarily_unavailable", "too many outstanding codes")
		return
	}
	v := url.Values{"code": {code}, "state": {p.state}}
	if p.fault != FaultNoIssParam {
		v.Set("iss", s.issuer)
	}
	http.Redirect(w, r, withParams(p.redirectURI, v), status)
}

// redirectError sends an OAuth error to a validated redirect_uri, with the
// RFC 9207 iss parameter.
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	v := url.Values{"error": {code}, "error_description": {desc}, "iss": {s.issuer}}
	if state != "" {
		v.Set("state", state)
	}
	status := http.StatusFound
	if r.Method == http.MethodPost {
		status = http.StatusSeeOther
	}
	http.Redirect(w, r, withParams(redirectURI, v), status) // #nosec G710 -- redirectURI was matched against the client's registered URIs
}

func withParams(base string, add url.Values) string {
	u, err := url.Parse(base)
	if err != nil {
		return base // unreachable: redirect URIs are validated before use
	}
	v, _ := url.ParseQuery(u.RawQuery)
	for k, vals := range add {
		v[k] = vals
	}
	u.RawQuery = v.Encode()
	return u.String()
}

func absoluteHTTP(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.Fragment == "" && u.User == nil
}

// tokenResponse is RFC 6749 §5.1 plus the OIDC id_token.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

// handleToken redeems an authorization code (RFC 6749 §4.1.3, RFC 7636 §4.6).
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	f := r.PostForm
	for k, v := range f {
		if len(v) > 1 {
			tokenError(w, http.StatusBadRequest, "invalid_request", "parameter "+k+" is repeated")
			return
		}
	}
	c, status, code, desc := s.authenticateClient(r, f, now)
	if c == nil {
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="devidp"`)
		}
		tokenError(w, status, code, desc)
		return
	}
	if f.Get("grant_type") != "authorization_code" {
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	ac, ok := s.codes.take(f.Get("code"), now)
	switch {
	case !ok:
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the code is unknown, expired or already used")
		return
	case ac.authz.clientID != c.ID:
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the code was issued to another client")
		return
	case f.Get("redirect_uri") != ac.authz.redirectURI:
		tokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	case !pkceOK(f.Get("code_verifier"), ac.authz.codeChallenge):
		tokenError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match the code_challenge")
		return
	}
	at := rand.Text() + rand.Text()
	idt, claims, err := s.mintIDToken(ac, at, now)
	if err != nil {
		s.log.Error("devidp: minting the ID token", "err", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "could not sign the ID token")
		return
	}
	if err := s.tokens.put(at, accessGrant{claims: userinfoClaims(claims)}, now.Add(accessTokenTTL), now); err != nil {
		tokenError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many tokens")
		return
	}
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokenResponse{AccessToken: at, TokenType: "Bearer",
		ExpiresIn: int(accessTokenTTL / time.Second), IDToken: idt, Scope: strings.Join(ac.authz.scope, " ")})
}

// pkceOK checks code_verifier against the S256 challenge (RFC 7636 §4.6).
func pkceOK(verifier, challenge string) bool {
	if !verifierRE.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

// authenticateClient implements client_secret_basic and private_key_jwt. On
// failure the client is nil and the status, error code and description say why.
func (s *Server) authenticateClient(r *http.Request, f url.Values, now time.Time) (*Client, int, string, string) {
	user, pass, basic := r.BasicAuth()
	assertion := f.Get("client_assertion")
	switch {
	case f.Has("client_secret"):
		return nil, http.StatusBadRequest, "invalid_request", "client_secret_post is not supported; use client_secret_basic or private_key_jwt"
	case basic && assertion != "":
		return nil, http.StatusBadRequest, "invalid_request", "use exactly one client authentication method"
	case basic:
		id, err1 := url.QueryUnescape(user)
		secret, err2 := url.QueryUnescape(pass)
		c := s.clients[id]
		if err1 != nil || err2 != nil || c == nil || c.Secret == "" ||
			subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1 ||
			(f.Get("client_id") != "" && f.Get("client_id") != id) {
			return nil, http.StatusUnauthorized, "invalid_client", "client authentication failed"
		}
		return c, 0, "", ""
	case assertion != "":
		if f.Get("client_assertion_type") != jwtBearerType {
			return nil, http.StatusUnauthorized, "invalid_client", "client_assertion_type must be " + jwtBearerType
		}
		c, err := s.verifyClientAssertion(assertion, f.Get("client_id"), now)
		if err != nil {
			s.log.Info("devidp: client assertion refused", "err", err)
			return nil, http.StatusUnauthorized, "invalid_client", "client authentication failed"
		}
		return c, 0, "", ""
	}
	return nil, http.StatusUnauthorized, "invalid_client", "client authentication is required"
}

// verifyClientAssertion checks a private_key_jwt assertion (RFC 7523 §3):
// signature by a registered key, iss = sub = client_id, aud names the token
// endpoint or the issuer, exp at most five minutes away, and a fresh jti.
func (s *Server) verifyClientAssertion(assertion, clientID string, now time.Time) (*Client, error) {
	if len(assertion) > 8<<10 {
		return nil, errors.New("assertion too large")
	}
	tok, err := jwt.ParseSigned(assertion, clientAssertionAlgs)
	if err != nil {
		return nil, err
	}
	var unverified jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, err
	}
	c := s.clients[unverified.Issuer]
	if c == nil || c.JWKS == nil || (clientID != "" && clientID != c.ID) {
		return nil, errors.New("unknown client or no registered keys")
	}
	keys := c.JWKS.Keys
	if kid := tok.Headers[0].KeyID; kid != "" {
		keys = c.JWKS.Key(kid)
	}
	var cl jwt.Claims
	verified := false
	for _, k := range keys {
		if tok.Claims(k, &cl) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("no registered key verifies the signature")
	}
	// aud must be exactly the token endpoint, single-valued, as Okta and
	// Entra require (and draft-ietf-oauth-rfc7523bis recommends).
	if len(cl.Audience) != 1 || cl.Audience[0] != s.issuer+pathToken {
		return nil, errors.New("aud must be the token endpoint URL, single-valued")
	}
	if err := cl.ValidateWithLeeway(jwt.Expected{Issuer: c.ID, Subject: c.ID, Time: now}, time.Minute); err != nil {
		return nil, err
	}
	if cl.Expiry == nil || cl.Expiry.Time().After(now.Add(5*time.Minute+time.Minute)) || cl.ID == "" {
		return nil, errors.New("exp must be within five minutes and jti is required")
	}
	fresh, err := s.jtis.putNew(c.ID+"\x00"+cl.ID, struct{}{}, cl.Expiry.Time().Add(time.Minute), now)
	if err != nil {
		return nil, err
	}
	if !fresh {
		return nil, errors.New("jti replayed")
	}
	return c, nil
}

// mintIDToken builds and signs the ID token for a redeemed code, applying the
// code's fault, if any. It also returns the claims (as issued).
func (s *Server) mintIDToken(ac authCode, accessToken string, now time.Time) (string, map[string]any, error) {
	p := ac.authz
	a := ac.profile.assuranceFor(ac.method, p.req)
	iat := now
	exp := now.Add(idTokenTTL)
	authTime := ac.authTime
	atHash := sha256.Sum256([]byte(accessToken))
	claims := map[string]any{
		"iss":            s.issuer,
		"aud":            p.clientID,
		"nonce":          p.nonce,
		"sid":            ac.sid,
		"amr":            a.amr,
		"email":          ac.user.Email,
		"email_verified": true,
		"name":           ac.user.Name,
		"at_hash":        base64.RawURLEncoding.EncodeToString(atHash[:16]),
	}
	sub := ac.user.Sub
	if p.fault == FaultSubChangeStepUp {
		sub += faultSubSuffix
	}
	if ac.profile == ProfileEntra {
		// Entra: sub is pairwise per application; oid + tid identify the user.
		claims["sub"] = EntraPairwiseSub(sub, p.clientID)
		claims["oid"] = EntraObjectID(sub)
		claims["tid"] = EntraTenantID(ac.user.Tenant)
		claims["preferred_username"] = ac.user.Email
		claims["ver"] = "2.0"
	} else {
		claims["sub"] = sub
	}
	if a.acr != "" {
		claims["acr"] = a.acr
	}
	if a.acrs != nil {
		claims["acrs"] = a.acrs
	}
	if len(ac.user.Groups) > 0 {
		claims["groups"] = ac.user.Groups
	}
	if len(ac.user.Roles) > 0 {
		claims["roles"] = ac.user.Roles
	}
	if d := ac.user.Device; d != nil {
		if d.Managed != nil {
			claims["device_managed"] = *d.Managed
		}
		if d.Compliant != nil {
			claims["device_compliant"] = *d.Compliant
		}
	}
	switch p.fault {
	case FaultWrongIss:
		claims["iss"] = s.issuer + faultIssSuffix
	case FaultWrongAud:
		claims["aud"] = faultAudPrefix + p.clientID
	case FaultExpired:
		iat = now.Add(-expiredAge + time.Minute)
		exp = iat.Add(idTokenTTL)
		// auth_time stays the real sign-in time even though it is after iat:
		// moving it back 9 minutes would also break max_age (a second defect).
	case FaultFutureIat:
		iat = now.Add(futureIatSkew)
		exp = iat.Add(idTokenTTL)
	case FaultNonceMismatch:
		claims["nonce"] = "devidp-wrong-" + rand.Text()
	case FaultStaleAuthTime:
		authTime = now.Add(-staleAuthTimeAge)
	case FaultACRUnrequested:
		if ac.profile == ProfileEntra {
			claims["acrs"] = []string{"c1"}
		} else {
			claims["acr"] = OktaACRPhr
		}
	}
	claims["iat"] = iat.Unix()
	claims["exp"] = exp.Unix()
	if p.fault != FaultMissingAuthTime {
		claims["auth_time"] = authTime.Unix()
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", nil, err
	}
	tok, err := s.sign(payload, p.fault)
	return tok, claims, err
}

// sign produces the compact JWS, applying signature-level faults.
func (s *Server) sign(payload []byte, fault Fault) (string, error) {
	b64 := base64.RawURLEncoding.EncodeToString
	if fault == FaultAlgNone {
		return b64([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + b64(payload) + ".", nil
	}
	key := jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: s.key, KeyID: s.kid}}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	switch fault {
	case FaultHS256WithPubkey:
		key = jose.SigningKey{Algorithm: jose.HS256, Key: jose.JSONWebKey{Key: s.pubPEM, KeyID: s.kid}}
	case FaultKidUnknown:
		key.Key = jose.JSONWebKey{Key: s.key, KeyID: faultUnknownKid}
	case FaultJKUHeader:
		// Signed by a different (attacker) key under the real kid, with jku
		// pointing at a JWKS that holds that key: an RP that ignores jku
		// rejects the signature, one that follows jku accepts it.
		key.Key = jose.JSONWebKey{Key: s.attackerKey, KeyID: s.kid}
		opts = opts.WithHeader("jku", s.issuer+faultJKUPath)
	}
	signer, err := jose.NewSigner(key, opts)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		return "", err
	}
	if fault == FaultBadSignature {
		i := strings.LastIndexByte(out, '.')
		sig, err := base64.RawURLEncoding.DecodeString(out[i+1:])
		if err != nil {
			return "", err
		}
		sig[len(sig)/2] ^= 0x01
		out = out[:i+1] + b64(sig)
	}
	return out, nil
}

// userinfoClaims is the /userinfo view of an ID token's claims. It ignores
// the requested scopes; relying parties must not depend on that.
func userinfoClaims(c map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"sub", "email", "email_verified", "name", "preferred_username", "groups", "roles", "oid", "tid"} {
		if v, ok := c[k]; ok {
			out[k] = v
		}
	}
	return out
}

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	scheme, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	g, ok := s.tokens.get(tok, s.now())
	if !strings.EqualFold(scheme, "Bearer") || tok == "" || !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	writeJSON(w, http.StatusOK, g.claims)
}

// handleLogout is the RP-initiated logout endpoint. It ends the IdP session
// and redirects only to a registered post_logout_redirect_uri (of any client).
// id_token_hint is not checked: acceptable for a dev IdP, not for a real one.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.del(c.Value)
	}
	s.setSessionCookie(w, "", -1)
	q := r.URL.Query()
	if target := q.Get("post_logout_redirect_uri"); target != "" {
		for _, c := range s.clients {
			if slices.Contains(c.PostLogoutRedirectURIs, target) {
				v := url.Values{}
				if st := q.Get("state"); st != "" {
					v.Set("state", st)
				}
				http.Redirect(w, r, withParams(target, v), http.StatusFound) // #nosec G710 -- target is a registered post-logout URI
				return
			}
		}
	}
	s.renderMessage(w, http.StatusOK, "Signed out", "You are signed out of the Tessera dev IdP.")
}

type faultBody struct {
	Fault Fault `json:"fault"`
}

func (s *Server) handleGetFault(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, faultBody{Fault: s.currentFault()})
}

// handleSetFault sets the fault for every later authorization; an empty
// fault clears it. Enabled only with Config.Faults (DEVIDP_FAULTS=1).
func (s *Server) handleSetFault(w http.ResponseWriter, r *http.Request) {
	var b faultBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "body must be {\"fault\": \"…\"}"})
		return
	}
	if err := s.SetFault(b.Fault); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func tokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
